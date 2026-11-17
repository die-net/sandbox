# Spikes on design.md's top risks

Run on 2026-11-17 against design.md at edc744f. The spike code is throwaway and uncommitted, under `spikes/`. **Ran** means I ran it and saw the output quoted. **Inferred** means I didn't.

| Spike | Risk | Result |
|---|---|---|
| L1 bubblewrap descriptor passthrough | 1, 2 | All six checks pass on bubblewrap 0.12.0 |
| L2 Firefox headless under legwork's filter | 3 (Linux) | Renders under `strict` and `nested`, pixel-identical to unsandboxed. No pref or trmnlp change needed. |
| M1 Seatbelt per-port deny | 4.3, 9 | Fails. A port deny after a broad `localhost` allow holds for about half of all ports, and `localhost` also matches the host's LAN address. Single-port allows are reliable. |
| M2 Firefox under `sandbox-exec` | 3 (macOS) | Renders under a deny-default profile, byte-identical to unsandboxed. Needs `CFFIXED_USER_HOME`, three `MOZ_DISABLE_*` switches, two Apple Mach services, no IOKit. One allowed loopback port works. |
| M3 LaunchServices under the Firefox profile | 7 (Seatbelt "no LaunchServices") | Holds. Seatbelt's `lsopen` operation gates opening apps and URLs, and a deny-default profile refuses it even with every LaunchServices Mach service allowed. Allowing `launchservicesd` lookup for Firefox is safe as long as `lsopen` is never allowed. |

## Linux host

A throwaway Lima VM, deleted afterwards:
- Debian 13 on arm64, kernel `6.12.115+deb13.1-cloud-arm64`
- `bubblewrap 0.12.0`, `firefox-esr 153.7.0esr`, `strace` from apt
- No AppArmor userns restriction, and no host mounts

```
limactl create --name=sbx-spike --cpus=4 --memory=4 --set '.mounts=[]' --tty=false template:debian-13
limactl start sbx-spike
limactl shell sbx-spike -- sudo apt-get install -y bubblewrap firefox-esr strace golang-go netcat-openbsd curl
```

Binaries were cross-built on the Mac with Go 1.27.3 (`GOOS=linux GOARCH=arm64 CGO_ENABLED=0`) and copied in with `limactl copy`.

## L1. Descriptor passthrough via bubblewrap

**Setup.** `spikes/l1/main.go` has three roles in one binary.
- **`parent`** makes the descriptors, then starts bubblewrap with the options on fd 3:
  - a `SOCK_SEQPACKET` control socketpair
  - a lifeline pipe
  - an `--info-fd` pipe
  - a temp file as an "extra file"
- **`stage`** is pid 1 inside the sandbox. It lists its fds, then binds `127.0.0.1:3128` and sends the listener out with `SCM_RIGHTS`, along with a lying `pid=4242`. It closes the control socket, starts the command with only stdio plus the extra file as fd 3, and exits when the lifeline reads EOF.
- **`cmd`** lists its fds, sends a line through the listener, tries outbound TCP and UDP, then sleeps.

```
bwrap --args 3 -- /home/aaron.guest/l1 stage
# fd 3 holds, NUL-separated:
--unshare-all --as-pid-1 --die-with-parent --info-fd 4 --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp
# ExtraFiles: 3=args 4=info(write end) 5=control 6=lifeline(read end) 7=extra file
./l1 parent none | lifeline | sigkill        # the sigkill run is killed from a script with kill -9
```

The command must follow `--` in bubblewrap's own argv. Putting it inside the `--args` body gives a usage error. legwork already does it the right way (read: `sandbox_linux.go:218`).

**What happened (ran):**

- **(a) Passes.**
  - pid 1 got exactly `0 1 2 5->socket 6->pipe 7->/tmp/l1-extra…`, and the extra file read back its contents.
  - bubblewrap consumed and closed fd 3 (`--args`) and fd 4 (`--info-fd`) before the exec, so neither reached pid 1.
  - Unnamed fds kept their numbers.
- **(b) Passes.** `--info-fd` gave `{"child-pid": 6858}`, and `/proc/6858/status` read `NSpid: 6858 1`, which is the host pid of pid 1.
- **(c) Passes.**
  - The parent received the listener (`127.0.0.1:3128`), `Accept`ed, and swapped a line each way with the command inside.
  - The parent never needed the `pid=4242` in the message.
  - After pid 1 closed its end, the parent read `EOF` on the control socket, so bubblewrap's monitor process holds no copy of it.
- **(d) Passes.** The command's fds were `0 1 2 3->extra`: no control socket, no lifeline, no info fd.
  - My spike's first version closed fds 3 and 4 in pid 1 "to be safe". By then those numbers were Go's own epoll descriptor, and the runtime crashed with `epollwait on fd 4 failed with 9`.
  - Design note: the stage must never close fds by number after Go starts. It should mark the inherited ones close-on-exec, or `close_range` before the runtime opens anything, which isn't possible in Go.
- **(e) Passes, both ways.**
  - Closing the lifeline write end: pid 1 read EOF and exited, bubblewrap exited 1, and `pgrep` found no `l1 stage` or `exe cmd` left.
  - `kill -9` on the parent: bubblewrap, pid 1 and the command were all gone a second later.
  - There was no `Pdeathsig` anywhere in the spike.
- **(f) Passes.** Inside `--unshare-all`, the only interface was `lo` (up). TCP to `1.1.1.1:443` and to the VM's gateways (`10.0.2.2:22`, `192.168.5.2:22`), and UDP to `1.1.1.1:53`, all failed with `network is unreachable`.

**What it changes:**
- Risk 1 is retired for bubblewrap 0.12.0. Debian 13's version is the floor tested, and legwork's 0.8 minimum is untested.
- The 4.4 control-socket, info-fd and lifeline design holds as written.
- Add the close-by-number caveat to 4.4.

## L2. Firefox headless under legwork's filter

**Setup.**
- legwork's `cmd/legwork-sandbox` at 3f09858, built for linux/arm64 with `-o` outside the legwork tree. The legwork tree was left unchanged.
- Home and working dir: `~/l2home`, with a fresh profile per run.
- A local page with text, a red div, and `navigator.onLine` written into the page by script.
- `strace -f` wraps the whole thing.
- Script: `spikes/l2/` (`l2.sh` as run in the VM).

```
strace -f -qq -o $R/strace [unshare --user --map-current-user --net --] \
  legwork-sandbox --home ~/l2home --dir ~/l2home --kernel strict|nested -- \
  firefox-esr --headless --no-remote --profile ~/l2home/prof --screenshot ~/l2home/shot.png \
  --window-size=800,480 file:///home/aaron.guest/l2home/page.html
```

**What happened (ran):**

| Run | Screenshot | Refused by our filter (strace) |
|---|---|---|
| unsandboxed | yes, 2 s | none |
| `strict` | yes, 2 s | `clone(CLONE_NEWUSER)` EPERM (Firefox's probe), `clone3` ENOSYS (glibc falls back to `clone`), `quotactl` ENOSYS, netlink `socket` EAFNOSUPPORT |
| `strict`, `MOZ_ASSUME_USER_NS=0 MOZ_CRASHREPORTER_DISABLE=1` | yes, 2 s | the `clone` probe is gone. The rest are the same. |
| `nested` | yes, 2 s | `clone3`, `quotactl`, netlink |
| `strict` plus `network.manage-offline-status=false` in `user.js` | yes | same |
| `strict` inside a loopback-only netns (`unshare --net`) | yes | same |

- **Pixels.** The unsandboxed, `strict`, `strict`+pref and `strict`+netns PNGs are byte-identical (md5 `7fc62b617736a012d4f189ec27fe8959`). All show `onLine=true`. Refusing netlink doesn't make Firefox go offline, even with no network at all.
- **Firefox's own sandbox stays on.**
  - Under `strict`, its processes installed 12 seccomp filters, against 11 unsandboxed. The extra one is ours.
  - Its broker took 55 SIGSYS traps either way.
  - Only its user-namespace layer drops out, as bug 1756236 describes.
- **ptrace.** No ptrace or `process_vm_readv` showed up refused. The crash reporter never ran.
- **An environment leak.** `XDG_RUNTIME_DIR=/run/user/502` reached Firefox, and dconf failed to create `/run/user/502/dconf`, read-only under the cover. legwork's `commandEnv` sets `HOME`, `TMPDIR` and four `XDG_*` variables, but not `XDG_RUNTIME_DIR` (read: `sandbox_linux.go:559`).
- **Not run:** geckodriver and Marionette inside the sandbox. geckodriver isn't in Debian's archive, and I didn't download it. Marionette is TCP on loopback, which `strict` allows (inferred).

**What it changes:**
- Risk 3 is retired for Linux. `strict` is enough for headless Firefox, and `nested` isn't needed.
- Keep `MOZ_ASSUME_USER_NS=0`, which silences the probe. `MOZ_CRASHREPORTER_DISABLE=1` is harmless.
- Drop the `network.manage-offline-status` question.
- The library sets `XDG_RUNTIME_DIR` to a directory of the sandbox's own, or unsets it, along with the other `XDG_*`.

## M1. Seatbelt per-port deny on this Mac

**Setup.**
- macOS 27.0.1 (26A434), arm64.
- A Python listener on `127.0.0.1` and `::1` for each port, and a Python client.
- One small profile per case. Most use an `(allow default)` base with `(deny network-outbound)`, then the rules below. The scan in `scan5.sh` repeats the main case with a `(deny default)` base.
- Files: `spikes/m1/`.

```
(allow network-outbound (remote ip "localhost:*"))
(deny network-outbound (remote ip "localhost:18081"))      ; broad-deny.sb
/usr/bin/sandbox-exec -f broad-deny.sb /usr/bin/python3 -I client.py 127.0.0.1 18081
bash scan.sh '(remote ip "localhost:%s")' $(seq 18070 18105)   # one profile per port, deny that port
bash scan3.sh $(seq 18070 18105) 3128 8080 49152 60000         # profile allowing only that port
```

**What happened (ran):**

- **The per-port deny is unreliable.**
  - It worked for 18081, 8080, 3128, 9229, 18256 and 18400 over both `127.0.0.1` and `::1`.
  - It was ignored for 18080, 18082, 18084 and 18100.
  - Across 18070-18105, it held for 16 of 36 ports and the rest connected.
  - The pattern is the same on every rerun and with a `(deny default)` base (`scan5.sh`). It changes with the filter's form: `(remote tcp ...)` gives a different but equally mixed pattern.
  - `(require-all (remote ip "localhost:*") (require-not (remote ip "localhost:P")))` denied nothing at all.
  - I didn't find the cause. The rule order is the same in every case, so "last match wins" doesn't hold for port filters under a wildcard.
- **`localhost` means the host's own addresses, not loopback only.**
  - Under the broad allow, a connection to the Mac's LAN address `192.0.2.76` succeeded.
  - `127.0.0.2`, which isn't configured, was refused.
  - So moving `serve` off loopback onto its LAN address doesn't take it out of reach.
- **Single-port allows are reliable.** With a profile allowing only `localhost:P` (`scan3.sh`), all 40 ports tested were reachable themselves and refused every other port.
  - Each port's own connection was tested over `127.0.0.1`, and the refused other port over `::1`. Both families were checked both ways for 18082.
  - The host's LAN address on that port was also allowed, which matches the point above.
- `(deny network-outbound)` alone refused everything, LAN address included.

**What it changes:**
- Neither mitigation in 4.3 works. The port deny holds for only some ports. Moving `serve` off loopback is undone because `localhost` matches the LAN address.
- Under `BroadLoopback`, a recipe reaches every TCP listener on any of the host's own addresses, `serve`'s included. This needs a decision, below.
- `NetworkNone` with the parent's listener port, and with fixed `Loopback` ports, stands on solid ground. So trmnlp taking fixed WebDriver ports is the real fix, and it moves up.

## M2. Headless Firefox under `sandbox-exec` on this Mac

### The first attempt and its cause

The first attempt (Firefox 152.0.4, run by a Sonnet subagent) hung even with no sandbox: the parent spun at about 100% CPU and never wrote a screenshot. The parent session found the cause.
- `~/Library/Application Support/Firefox` is protected by TCC on macOS 27, and reading it without Full Disk Access fails with EPERM.
- Firefox 152 reads it even when `-profile` points elsewhere, and spins when it can't (playwright#42768, fixed upstream in Firefox 158).
- It wasn't the agent session, since the same command hangs in Terminal.app.
- The `sandbox_extension_issue_file_to_process … Operation not permitted` line is noise. It prints on every run, including the ones that work.

The fix is `CFFIXED_USER_HOME` pointed at an empty directory. Cocoa resolves `~/Library` from it, while `$HOME` alone doesn't move `~/Library`.

### Setup

- Firefox 160.0, which auto-updated before the rerun, from `/Applications/Firefox.app`, on macOS 27.0.1 (26A434), Apple silicon.
- The user's own Firefox was running throughout. Every run used a fresh `-profile` under its own run dir, plus `-no-remote`.
- `spikes/m2/run.sh NAME [PROFILE] [ENV…]` runs `env -i` with only these set:
  - `PATH=/usr/bin:/bin`
  - `HOME`, `CFFIXED_USER_HOME` and `TMPDIR` pointing into `NAME/`
  - `MOZ_HEADLESS=1`, `MOZ_CRASHREPORTER_DISABLE=1`
- It then runs `[sandbox-exec -D M2=… -D RUN=… -f PROFILE] firefox --headless -no-remote -profile NAME/prof --screenshot NAME/shot.png --window-size=800,480 file://…/page.html`.
- On timeout it kills only its own Firefox pid and that pid's descendants.
- `try.sh` wraps `run.sh` in `log stream --predicate 'sender == "Sandbox" …'`, and `summarize.sh` lists the unique denials by process.
- `page.html` has an `h1`, text in Helvetica and a red div.

### Results (ran)

**Baseline.** Unsandboxed, with `CFFIXED_USER_HOME` set, Firefox wrote an 800x480 PNG in about 1 s, with md5 `d8b414fc…`, the same on every run. Firefox created `Library/Application Support/Firefox` and `Library/Caches/Firefox` under the fake home.
- With `HOME` alone, Firefox 160 also rendered, since the upstream fix is in.
- That run left the fake home empty, so it used the real `~/Library` instead.
- I checked that `~/Library/Caches/Firefox` wasn't modified. `~/Library/Application Support/Firefox` can't be listed, because TCC blocks it.

**Building the profile.** It started from `(deny default)` plus exec and read of the app bundle, read-write on the run dir, and read of the page. I widened it only from the deny log over four rounds (`p0.sb` to `p4.sb`). `p4.sb` rendered an image byte-identical to the baseline.

**Child processes.** All of them run the same `plugin-container` binary. A process already inside a profile can't apply another, so these fail with `sandbox_init() failed … Operation not permitted` (`forbidden-sandbox-reinit` in the log). Each `MOZ_DISABLE_*` switch was tried alone, on top of `MOZ_DISABLE_CONTENT_SANDBOX=1`:

| Child | Unswitched | Switch that fixes it |
|---|---|---|
| content (tab) | crash loop: 523 `sandbox_init` failures in 25 s, each exiting on SIGSEGV, no screenshot | `MOZ_DISABLE_CONTENT_SANDBOX=1` |
| socket | fails init, SIGSEGV; the render still completes | `MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1` |
| RDD | fails init, SIGSEGV; the render still completes | `MOZ_DISABLE_RDD_SANDBOX=1` |
| GPU, utility, GMP | never started for this page | `MOZ_DISABLE_GPU_SANDBOX`, `MOZ_DISABLE_UTILITY_SANDBOX` and `MOZ_DISABLE_GMP_SANDBOX` changed nothing here |

With all three switches set, there were no `sandbox_init` failures and no crashed children.

**Minimal profile.** `prune.sh` removed one rule at a time from `p5.sb`, which is `p4.sb` with one rule per line. It kept a removal only if two runs in a row still produced the baseline md5. The result is `minimal.sb`. Five more runs all matched the baseline, in 2-4 s each.

```
(version 1)
(deny default)
(allow process-fork)
(allow process-exec (subpath "/Applications/Firefox.app"))
(allow file-read* (subpath "/Applications/Firefox.app"))
(allow file-read* file-write* (subpath (param "RUN")))
(allow file-read* (literal (string-append (param "M2") "/page.html")))
(allow file-read* (literal "/"))
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr/lib"))
(allow sysctl-read)
(allow mach-register (global-name-regex #"^org\.mozilla\.machname\."))
(allow mach-lookup (global-name-regex #"^org\.mozilla\.machname\."))
(allow mach-lookup (global-name "com.apple.coreservices.launchservicesd"))
(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))
```

- **`mach-lookup`.** Only `launchservicesd`, `configd`, and Firefox's own `org.mozilla.machname.*` ports, which the parent registers and its children look up. Dropping `launchservicesd` aborts (SIGABRT), and dropping `configd` crashes (SIGSEGV).
  - About 25 other services are looked up and refused with no effect, among them `windowserver.active`, `CARenderServer`, `tccd`, `opendirectoryd.*`, `diagnosticd`, `logd`, `pasteboard.1`, `dock.server` and `SafariLaunchAgent`.
- **`iokit-open`: none.** Firefox asks for `IOSurfaceRootUserClient`, `AGXDeviceUserClient` and `AppleNVMeEANUC`, and gets refused each time. Headless falls back to software rendering, and the PNG is unchanged.
- **Files outside the run dir:** the app bundle, `/System`, `/usr/lib`, and `/` itself (a directory read). The page's Helvetica comes from `/System/Library/Fonts`.
  - Refused with no effect: `/Library/Fonts`, `/usr/share` (ICU, zoneinfo), `/dev/urandom` (Firefox uses `getentropy`), `/dev/null`, `/private/etc/passwd`, `/Library/Preferences/*`, and `file-read-metadata` everywhere else.
- **A failure that looks like success.** Without the `mach-register` rule, children can't check in (`bootstrap_check_in failed`, `Failed to launch tab subprocess`), yet Firefox exits 0 and writes no PNG. The caller has to check that the output exists, not just the exit status.

**`/Users` stays covered.** The profile allows nothing under `/Users` except the run dir and the page.
- Firefox still tries the real `~/Library/Preferences/*.plist`: `.GlobalPreferences`, `org.mozilla.firefox`, `com.apple.universalaccess` and others, under the real home rather than `CFFIXED_USER_HOME`. CFPreferences resolves that path itself. All of these are refused, with no effect on the render.
- It also tries `$(getconf DARWIN_USER_TEMP_DIR)/firefox` under `/private/var/folders/…/T/` despite `TMPDIR`, and is refused there too.
- Nothing was written outside the run dir.

**Other refused operations worth knowing:**
- `signal others [SafariLaunchAgent] signum:15` (from a system framework, inferred)
- `system-socket domain:17` (`AF_ROUTE`)
- `network-outbound /private/var/run/mDNSResponder`, so no DNS
- `file-issue-extension`

**Network.** `page-net.html` loads a 200x100 green PNG from `127.0.0.1:18401` and a blue one from `127.0.0.1:18402`, each served by a plain `python3 -m http.server`. `pngpx.py` counts their pixels in each screenshot:

| Profile | green (18401) | blue (18402) |
|---|---|---|
| unsandboxed | 20000 | 20000 |
| `net.sb`: minimal plus `(allow network-outbound (remote ip "localhost:18401"))` | 20000 | 0, logged as `network-outbound remote:*:18402` |
| `netnone.sb`: minimal, no network rule | 0 | 0 |

The page still renders from `file://` with all network refused. Both cases were run twice, and each gave the same md5 both times.

### What it changes

- **On macOS, `Start` sets `CFFIXED_USER_HOME` to the sandbox home**, next to `HOME`, `TMPDIR` and `XDG_*`. `$HOME` doesn't move where Cocoa looks for `~/Library`. Without this, Firefox 152-157 hangs on the TCC-protected real directory, and later versions write into the real `~/Library`.
  - The real `~/Library/Preferences` is still read through CFPreferences. The profile refuses it, at no cost.
- **trmnl sets three switches on macOS:** `MOZ_DISABLE_CONTENT_SANDBOX`, `MOZ_DISABLE_SOCKET_PROCESS_SANDBOX` and `MOZ_DISABLE_RDD_SANDBOX`. The content switch is required. The other two only stop crashing children.
  - Media in a recipe may start the utility or GMP process. Those switches exist, but this run didn't need them.
- **The `Services` groups start small.** A Firefox group is the `org.mozilla.machname.*` register and lookup, plus `launchservicesd` and `configd`. No `iokit-open` at all.
  - The minimal profile is a floor, not what ships. It refuses `/Library/Fonts`, `/usr/share` and `/dev/*`, which real recipes, other fonts and other runtimes will need. The shipped profile should allow those read-only and keep the services list this short.
- **trmnl checks for the PNG, not just the exit status**, because a sandbox denial can leave Firefox exiting 0 with no output.
- **`NetworkNone` with one allowed loopback port works** for Firefox, and a `file://` page renders with no network at all.
- **Not run:**
  - geckodriver and Marionette under the profile
  - trmnlp's Ruby, Node and other runtimes
  - a page with web fonts or media
  - windowed-mode parity

## M3. LaunchServices under the Firefox profile

Run by the parent session on 2026-11-17, macOS 27.0.1. M2's minimal profile allows `mach-lookup` of `com.apple.coreservices.launchservicesd`, because Firefox aborts without it. design.md and legwork's one-binary.md both promise "no LaunchServices", since LaunchServices starts processes outside the profile. This checks whether that lookup lets a sandboxed process open an app or a URL.

**Setup.** Profiles were built from `spikes/m2/minimal.sb`, plus exec and read of `/usr/bin/open` so there's a client to run. Each test runs `/usr/bin/open -g` on `/System/Applications/Calculator.app` and on `http://127.0.0.1:18777/<beacon>`, with a local `http.server` logging requests. A URL open reaches the default browser (Safari here), which runs outside the profile, so a request in the log means the open escaped. Denials came from `log stream --predicate 'sender == "Sandbox"'`.

| Profile | App open | URL open | Key denial |
|---|---|---|---|
| minimal + `open`, without `launchservicesd` | fails | fails | (not needed) |
| minimal + `open` (Firefox's set) | fails, `kLSNoExecutableErr` | fails, `kLSExecutableIncorrectFormat`; no request logged | `mach-lookup` of `lsd.mapdb`, `lsd.modifydb`, `CoreServices.coreservicesd` |
| plus those services, `file-read-metadata`, `system-info`, DiskArbitration, quarantine-resolver | fails, error -54 | fails, error -54; no request logged | `deny(1) lsopen` |
| plus `(allow lsopen)` | **Calculator launched** | **Safari fetched the beacon** | none |

**What it shows (ran):**
- Seatbelt has a dedicated `lsopen` operation, and it's the real gate. Under `(deny default)` it stays refused even with every LaunchServices Mach service allowed. The open then fails with -54 (`permErr`).
- With `lsopen` allowed, a sandboxed process launches any app and makes the user's browser fetch any URL, which is an egress path past the proxy. So the rule is "never allow `lsopen`", not "never look up `launchservicesd`".

**What it changes:**
- Firefox's `Services` group keeps `launchservicesd`. The library never emits `lsopen`, and a library test asserts that `open` of an app and of a URL both fail under every generated profile.
- The rows in design.md that say "no LaunchServices" now say "never `lsopen`". legwork's one-binary.md Seatbelt section should say the same.
- **Not tested:** other ways to reach `launchservicesd` (raw XPC messages instead of the `LSOpen*` API). Seatbelt checks `lsopen` on the caller's side (inferred from the -54 coming back without `launchservicesd` logging anything), and a hand-written XPC client might skip that check. A review of the Seatbelt phase should look at it.

## Decision raised by M1

Section 5.1 counts "a recipe can reach the server's API" as no boundary. On macOS with `BroadLoopback`, that can't be prevented with Seatbelt as tested. Two ways forward:

1. **Treat it as a reported gap, not the floor.** trmnl's endpoints trust no source address:
   - the admin API takes only a bearer token or a signed-in session cookie (read: `adminapi.go:284`)
   - device calls take the device's `Access-Token` (read: `deviceapi/auth.go`).

   A recipe then gets what any host on the LAN already has. I didn't audit every route to confirm none skips these checks.
2. **No in-place sandbox on macOS until trmnlp takes fixed ports**, with the operator mode or `--no-sandbox` meanwhile.

design.md now takes option 1, in line with principle 1, and moves the trmnlp change up. That's a change to 5.1's floor, so it's flagged for the user.
