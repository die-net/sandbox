# Spikes on design.md's top risks

Run on 2026-11-17 against design.md at edc744f. The spike code is throwaway and uncommitted, under `spikes/`. **Ran** means I ran it and saw the output quoted. **Inferred** means I didn't.

| Spike | Risk | Result |
|---|---|---|
| L1 bubblewrap descriptor passthrough | 1, 2 | All six checks pass on bubblewrap 0.12.0 |
| L2 Firefox headless under legwork's filter | 3 (Linux) | Renders under `strict` and `nested`, pixel-identical to unsandboxed. No pref or trmnlp change needed. |
| M1 Seatbelt per-port deny | 4.3, 9 | Fails. A port deny after a broad `localhost` allow holds for about half of all ports, and `localhost` also matches the host's LAN address. Single-port allows are reliable. |
| M2 Firefox under `sandbox-exec` | 3 (macOS) | Blocked. Headless Firefox hung even with no sandbox, from this session. |

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

A Sonnet subagent ran this one.

- **Setup.** Firefox 152.0.4 from `/Applications/Firefox.app`, with a fresh `-profile` per run and `-no-remote`.
- **Commands.** Results are in `spikes/m2/`.

```
MOZ_HEADLESS=1 MOZ_CRASHREPORTER_DISABLE=1 /Applications/Firefox.app/Contents/MacOS/firefox --headless -no-remote \
  -profile $PWD/base/prof --screenshot $PWD/base/shot.png --window-size=800,480 file://$PWD/page.html
```

**What happened (ran by the subagent):**
- The unsandboxed baseline never produced a screenshot.
  - Six runs hung with the parent's main thread at about 100% CPU.
  - Variants made no difference: `MOZ_DISABLE_CONTENT_SANDBOX`, `MOZ_DISABLE_GPU_SANDBOX` and `MOZ_DISABLE_RDD_SANDBOX` together, `MOZ_WEBRENDER=0`, a software-WebRender `user.js`, and no headless flag at all.
  - Each run printed `sandbox_extension_issue_file_to_process failed for …/plugin-container.app: 1 (Operation not permitted)` and `RenderCompositorSWGL failed mapping default framebuffer`.
- With no working baseline, no profile was built, and nothing was learned about child processes, switches, `mach-lookup` or `iokit-open`.

**Inferred:** the `sandbox_extension_issue` EPERM suggests this agent session's process context can't issue sandbox extensions. It may also be a Firefox 152 bug on macOS 27. I can't tell which.
- **To unblock:** run the baseline once from a normal Terminal in the GUI session. If it works there, rerun M2 from that context.
- **What it changes:** nothing yet. Risk 3 stays open for macOS.

## Decision raised by M1

Section 5.1 counts "a recipe can reach the server's API" as no boundary. On macOS with `BroadLoopback`, that can't be prevented with Seatbelt as tested. Two ways forward:

1. **Treat it as a reported gap, not the floor.** trmnl's endpoints trust no source address:
   - the admin API takes only a bearer token or a signed-in session cookie (read: `adminapi.go:284`)
   - device calls take the device's `Access-Token` (read: `deviceapi/auth.go`).

   A recipe then gets what any host on the LAN already has. I didn't audit every route to confirm none skips these checks.
2. **No in-place sandbox on macOS until trmnlp takes fixed ports**, with the operator mode or `--no-sandbox` meanwhile.

design.md now takes option 1, in line with principle 1, and moves the trmnlp change up. That's a change to 5.1's floor, so it's flagged for the user.
