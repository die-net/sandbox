# Design: a shared sandbox module

Status: proposal. No code yet. Module path assumed `github.com/die-net/sandbox`.

Goal: pull legwork's in-place sandbox (`internal/sandbox`) into a module that legwork and trmnl-byos-go both use, with one interface over two backends: Linux (bubblewrap, namespaces, seccomp) and macOS (Seatbelt).

For trmnl, this is what lets it be one binary plus a few packages from `brew`, `apt` or `dnf`, kept current by the package manager, with no container stack needed. Each build is sandboxed in place, as legwork's [one-binary.md](../../legwork/docs/one-binary.md) does for its children. Project policy (paths, kernel level, egress rules, limits) stays in each project. Operators who'd rather isolate with their own containers or systemd units keep that as a supported mode (section 5), and the library's checks (section 6) tell them what their boundary enforces.

Sources. **Read** means I read the code or doc. **Inferred** means I reasoned it out and haven't run it.

- legwork: I read `docs/sandbox.md` and `docs/one-binary.md`: Goals, Processes, Builds, Code layout, Sandboxes (including Seatbelt, Floor, Root), Egress, Relaxing, Resource limits, Checks, Phases, and the spike's open questions. I read every non-test file in `internal/sandbox`, plus `TestMain` and `TestBridgePeer`, `cmd/legwork-sandbox/main.go` and `internal/cli/sandbox.go`.
- trmnl-byos-go: a Sonnet subagent surveyed the repo. I read `docs/design.md` (lines 34, 68-69, 481-540), `deploy/compose.yaml`, `internal/render/shim.go` lines 170-195, `procgroup_unix.go`, and `cmd/trmnl-render/main.go` lines 100-160 myself.
- Firefox, macOS, package and gem facts: web sources, listed at the end. I ran nothing on macOS.

## 1. Verdict and principles

**Feasible.** The module is a modest extraction from legwork plus the Seatbelt backend legwork has already designed. trmnl moves onto it with a host install on Linux and macOS alike.

Principles, which are the same as legwork's "Relaxing a sandbox" section:

1. **The real alternative is no sandbox.** When a sandbox is cumbersome, people turn it off. So every platform gets the strongest isolation it can give, with no setup beyond installing the packages.
2. **Backends differ, and that's fine.** macOS has no pid namespace, no cgroups and coarser kernel filtering than Linux. It still gets a deny-by-default file and network view, which is most of what protects trmnl's assets. The library reports what each backend gives (`Probe`), and the caller logs it once at startup. Missing pieces are reported, not refused. That covers features outside the kernel filter (memory limits, private loopback, tree kill). The kernel level is the exception: a requested level can be raised but never lowered, and one the host can't meet is an error (4.1).
3. **Zero config.** trmnl finds its tools at startup and works out from where they're installed what the sandbox needs to show (section 3.4). A brew, rbenv or apt user configures nothing.
4. **Refuse only when there's no sandbox at all**, as legwork's floor does. On macOS `sandbox-exec` is always present. On Linux the fix is `apt install bubblewrap`, plus one AppArmor command on Ubuntu, and trmnl's message prints it. `--no-sandbox` stays for development. It never refuses, and it logs what the checks find (section 5).
5. **The operator's own boundary is a sandbox too.** Containers or systemd units set up as section 5 describes do the same job, and the project then runs untrusted code without the library's sandbox. The library's part is to report honestly what that boundary enforces (section 6).

What the library needs, beyond what legwork has:
- `Command`, an entry point a server can call
- `Probe`, which reports what the backend gives
- `Network` (none or host) in the first release, then listeners handed to the parent
- caller file descriptors passed through
- rlimits applied inside the sandbox
- the sandbox's pid exposed
- the Seatbelt backend.

With no image to unpack, the host's root plus covers is the view on both platforms, exactly as in legwork. There's no `Root` field, so the interface is thinner than the earlier draft.

For trmnl, the parent brokers egress: each build gets a proxy listener and no other network. That replaces the proxy container, and it's the one piece trmnl can't do without.

## 2. Generic vs legwork-specific in today's code

| Piece | File | Classification |
|---|---|---|
| Path resolution, link rules, covers, mount-table covers, `/etc` link rebinding, homes from `/etc/passwd` | `spec.go` (all) | Generic (Linux backend) |
| `Spec` fields `Command, Home, Dir, Write, Read, Cover, Kernel` | `spec.go` | Generic and portable. legwork's values all come from config. |
| bwrap discovery with setuid refusal; options on an `--args` fd; `--bind-fd` from `openat2(RESOLVE_NO_SYMLINKS)`; passwd/group via `--ro-bind-data`; scratch tmpfs with `--size`; mount ordering | `sandbox_linux.go` `newLaunch` | Generic (Linux backend) |
| First stage and reaper: private mounts, caps dropped on the locked thread, no_new_privs, re-exec as pid 1, undumpable, TSYNC filter with result check, signal relay, reaping | `sandbox_linux.go` | Generic (Linux backend) |
| Seccomp filter, three levels, per-arch lists | `seccomp_linux.go`, `syscalls_*.go` | Generic (Linux backend) |
| HOME, TMPDIR, XDG_* set to the sandbox's own | `commandEnv` | Generic and portable. Always set by `Start` over `Cmd.Env`, as `commandEnv` does today (read), plus `XDG_RUNTIME_DIR`, which it misses, and on macOS `CFFIXED_USER_HOME`, since Cocoa resolves `~/Library` from that and not from `$HOME` (spikes.md M2). An inherited `HOME` would point into a covered tmpfs. The caller sets anything else on `Cmd.Env` (trmnl's `PATH`, `GEM_HOME`, `GEM_PATH`). |
| `--legwork-sandbox-stage`, `--legwork-sandbox-reaper`, `/dev/legwork-sandbox` | `sandbox_linux.go:28-30` | Rename |
| `--hostname legwork`, fallback account `legwork` | `sandbox_linux.go:357, 547` | `Spec.Hostname` (Linux only); fallback becomes `sandbox` |
| No `--new-session` | `sandbox_linux.go` | Driven by legwork's hub check, but a correct default: the filter refuses `TIOCSTI`. `Cmd` has no session option, and trmnl uses `Setpgid`. |
| `Run`: own stdio, `os.Environ()`, `os.Getwd()`, process-wide `signal.Notify`, `Pdeathsig` on bwrap (read: `sandbox_linux.go:224`) | `Run` | Fine in a dedicated process. Wrong inside a server, where `Pdeathsig` fires when the forking OS thread exits, not the process. Hence `Command` (4.1, 4.4). |
| Reaper starts the command with only fds 0-2 | `reaperStage` | Gap. one-binary's children receive their job on an inherited socketpair. |
| `Run`/`Stage` return `ErrUnsupported` off Linux | `sandbox_other.go` | Replaced by the Seatbelt backend |
| `RegisterFlags` (Go `flag`) | `flags.go` | Generic. legwork's pflag wrapper stays in legwork. |
| `TestBridgePeer` (uses `internal/peer`) | test | Stays in legwork, rewritten against the public `Command` with its own `TestMain` calling `Stage()`. The library keeps a version without `peer`. |
| `cmd/legwork-sandbox` | imports `internal/cli` and pflag | Stays in legwork |
| All other tests | tests | Move. They hold up the findings. |

### Where each sandbox.md guarantee lives after the split

| Guarantee | Library | legwork config/code | macOS, to test before the macOS phase |
|---|---|---|---|
| bwrap from the distro, setuid refused | ✓ | | `/usr/bin/sandbox-exec` by absolute path, never from `PATH` |
| Options on a descriptor, not in pid 1's argv | ✓ | | profile on `/dev/fd/N`, never in argv. Test that it doesn't appear in `ps`. |
| Bind sources by fd with `RESOLVE_NO_SYMLINKS`; a cover that became a link aborts | ✓ | | no fds: Seatbelt matches paths when they're opened. Test a write dir whose component is swapped for a link after the profile is written, and a link inside it pointing out. |
| User/pid/ipc/uts namespaces, uid mapped to itself, `--die-with-parent`, `--as-pid-1` | ✓ | | none. Same-uid processes are visible. Deny `process-info*` and `signal` outside the sandbox, and test `KERN_PROCARGS2` and `kill` on the parent. |
| Read-only root; covers (tmpfs, or `/dev/null` for non-dirs); default covers; people's homes; the account's own home | ✓ | | `file-read*` allow, then cover denies. Test each default cover, including through the `/System/Volumes/Data` firmlink paths (inferred risk: `/Users` is reachable both ways). |
| Legwork's config, state, and other sandboxes' directories covered | | ✓ (`Spec.Cover` from config) | same denies. Test each. |
| Mount-table covers (`.zfs`, other mounts of a covered fs) | ✓ | | no `.zfs`. Other volumes are under `/Volumes`, which is covered. Test an APFS snapshot mount, such as Time Machine's local ones. |
| `/etc` links into covered dirs rebound | ✓ | | `/etc` is itself a link to `/private/etc`. Test reads of `/etc/localtime` and `/etc/hosts`. |
| Path and link rules: no link in home or `write`; a link followed only outside writable dirs; a missing cover inside a writable dir aborts; no mount inside a writable dir; cwd must be shown | ✓ | passes real paths | the same checks in the library before the profile is written. Test that `subpath` on the real path holds. |
| A home per thread; `work` beside the CLI home; `read`/`write` refused if they overlap state | | ✓ | same, in legwork |
| Scratch tmpfs 1 GiB | ✓ default, `ScratchSize` | | none. `TMPDIR` is in `Home`, with no size cap beyond `RLIMIT_FSIZE` per file. Report. |
| One-entry passwd/group | ✓ | | none. Directory Services lists every account through `opendirectoryd`. Report, and test what `getpwnam` needs. |
| First stage: private mounts, caps dropped on the exec'ing thread, no_new_privs, pid 1 re-exec, undumpable | ✓ | | no capabilities to drop. Test that a setuid binary can't escape the profile, such as `sudo` with a cached ticket from the admin's terminal. |
| Filter: allowlist, arg checks, ENOSYS default, foreign ABIs refused, low-32-bit checks, TSYNC result check | ✓ | | none at the syscall level. Seatbelt filters operations. Whether `syscall-unix` rules work under `sandbox-exec` is untested. |
| Kernel level per child | | ✓ (`kernel:`) | one profile for every level, never weaker than asked |
| Caller's session kept, `TIOCSTI`/`TIOCLINUX` refused | ✓ | relies on it | `TIOCSTI` is open, and the admin's ptys share the uid. Deny opening `/dev/ttys*` and `/dev/ptmx` beyond inherited descriptors, and deny `file-ioctl` on ttys where the profile language allows it. Test injecting into another terminal of the same user. |
| Stage runs the caller binary's `init` with `CAP_SYS_ADMIN` (nested userns) | documented | ✓ "no `init`" rule from one-binary's Code layout | n/a: the stage runs outside the profile, as the caller |
| Network namespace, proxy listener handed out | ✓ mechanism (new) | ✓ proxy, allowlist, logging | parent-bound port allowed by number. `BroadLoopback` only by opt-in (4.3). Test that other ports refuse. |
| Bridge check by pid namespace (`--info-fd`), by session on macOS | ✓ exposes the pid, taken only from `--info-fd` (4.4) | ✓ the check | session check through `LOCAL_PEERPID` and `getsid`, legwork's. Test a sandboxed process calling `setsid` and connecting. |
| Root launcher, uid per child, nftables for `direct`, cgroups | ✓ refuses euid 0 and a uid change. The caller must already run as the sandbox's uid, because `Command` resolves paths, opens bind sources, reads homes and writes the passwd entry in the caller. | ✓ the launcher switches uid in its own child before calling the library, as one-binary's Root describes | LaunchDaemon as root, uid switched before the library. Test the euid-0 refusal. |
| Seatbelt profile: deny default, covers as denies after the broad allow, `mcp.sock` by path, proxy port, mach services, never `lsopen` (spikes.md M3) | ✓ (new backend) | ✓ which paths | it is the profile. `mcp.sock` in `Write` needs a `(remote unix-socket (path-literal ...))` connect rule as well as the `subpath` allow, since a file allow doesn't grant a connect. Test that it connects, and that another socket under `Write` doesn't. |
| Startup probe and refusal when there's no sandbox (one-binary "Floor") | ✓ `Probe()`, naming the blocking setting (6.3) | ✓ the refusal, the log, `--no-sandbox` | `sandbox-exec` with a trivial profile |
| Escape tests (one-binary "Checks"), run in CI and in `doctor` | ✓ `Check()`, the generic checks (6.2) | ✓ its `Expect` values, the rerun per relaxation, the rendering | same suite, with macOS rows (6.2) |
| `os.Root` for files in sandbox-writable dirs; `guard` refusing host addresses | | ✓ (not sandbox code) | same |
| Supplementary groups, host secrets readable by mode, snapshot dirs | ✓ generic checks in `Check()` | ✓ `legwork doctor` shows them | the user's groups usually include `staff` and maybe `admin`. Report, and test what `admin` can write, such as `/Library` and `/usr/local`. |

No guarantee is lost. Everything enforced in `internal/sandbox` moves unchanged. The macOS column is the Seatbelt phase's test list. Each item either holds when it runs, or is reported as a known gap.

## 3. trmnl-byos-go as one binary

This section is the in-place mode. Compose stays a supported deployment in operator mode (5.1).

### 3.1 What replaces each piece of the compose split

| Today (read) | One binary, Linux | One binary, macOS |
|---|---|---|
| server | `trmnl-byos serve` under systemd or run directly | `serve` under launchd or run directly |
| proxy (`renderproxy`, TCP forward to the renderer) | `renderproxy` inside `serve`, one listener per build | same |
| renderer (shim, Xvfb, separate uid) | a sandbox per build. The shim becomes a `render-child` subcommand run inside it. Firefox runs headless. | same, via Seatbelt |
| network with no route but the proxy | loopback-only network namespace with the listener inside | profile allows only the build's proxy port and its declared loopback ports |
| dropped capabilities, no-new-privileges | first stage drops caps, no_new_privs, seccomp | deny-default profile, never `lsopen` |
| separate uid hides server files | covers hide the data dir, config, homes | profile denies the same |
| memory cap, no pids cap | cgroup if delegated, else rlimits plus a watchdog (3.5) | rlimits plus a watchdog (3.5) |
| init process, group kill | pid 1 reaps; the whole tree dies with it | process group kill; `setsid` escapes |
| tar over HTTP to the shim | `serve` writes the project into a fresh build dir before start and reads outputs through `os.Root` after `Wait` | same |

### 3.2 What the renderer needs

- **Process tree (read).** `trmnlp build --png ...` (Ruby, third-party) runs Liquid and the recipe's transform (Node, Python, Ruby or PHP). It then drives Firefox through geckodriver over loopback WebDriver, and geckodriver talks to Firefox's Marionette port on loopback. It's all untrusted.
- **Headless (a trmnlp dependency).** Firefox runs `--headless`, so there's no Xvfb, `DISPLAY` or X socket. Firefox honors `MOZ_HEADLESS=1` from its environment, which geckodriver passes on (inferred), so this may need no trmnlp change. If it does, that's a trmnlp change to make. Check that PNGs match windowed output.
- **Selenium Manager (inferred).** trmnlp depends on `selenium-webdriver` (read: gem dependencies), whose Selenium Manager looks for, and may download, a driver and browser into `~/.cache/selenium`. Inside the sandbox `HOME` is the build dir, so it would download on every build through the proxy. trmnl passes the geckodriver and Firefox paths it found at startup, and turns Selenium Manager's downloads off (`SE_OFFLINE`, to verify).
- **Files.**
  - Read-only: the runtimes wherever they're installed (3.4) and fonts.
  - Writable: the build dir, `TMPDIR`, and Firefox's profile under `TMPDIR`.
- **Secrets.** Per-instance `FIELD_*` variables, readable by the payload by design. On Linux the pid namespace stops one build reading another's. On macOS the profile should deny `process-info*` on processes outside the sandbox (inferred, needs a check).
- **Network (read).** Everything goes through `HTTP_PROXY` and `HTTPS_PROXY`, with `NO_PROXY` covering localhost for WebDriver. Node's `fetch` ignores the proxy and fails closed.
- **Resources (read).** About 1 GB peak per build, 7-16 s per build on the measured host.

### 3.3 Install footprint

Everything comes from the platform's package manager and updates with it. The server alone needs nothing but the binary. These packages are only for recipes.

| Need | Debian 13 / Ubuntu 24.04+ | Fedora 44 | macOS (Homebrew) |
|---|---|---|---|
| Sandbox | `bubblewrap`. Ubuntu also needs the AppArmor profile, one root command that trmnl prints, as legwork does. | `bubblewrap` | nothing (`sandbox-exec` ships with macOS) |
| Ruby ≥ 4.0 (trmnl_preview 0.34.1 requires it) | not packaged: Debian and Ubuntu 26.04 ship 3.3. Use ruby-build/rbenv/mise, ideally system-wide to `/usr/local` or `/opt`, plus `build-essential libssl-dev libyaml-dev zlib1g-dev` for Ruby and the native gems (`oj`, `puma`, `nokogiri` when no prebuilt gem fits) | `ruby ruby-devel gcc make redhat-rpm-config` (Fedora 44 ships 4.0) | `ruby` (keg-only, so put it on `PATH`) |
| trmnlp | `gem install trmnl_preview` | same | same |
| Firefox | Debian: `firefox-esr`. Ubuntu: the archive's `firefox` is a snap wrapper, which can't run in the sandbox (`snap-confine` is setuid, and `/run` and `/var` are covered), so use Mozilla's APT repo (`packages.mozilla.org`) | `firefox` | `brew install --cask firefox` |
| geckodriver | not in the archives: the release binary from `github.com/mozilla/geckodriver` into `/usr/local/bin` | reportedly ships with `firefox` (unverified) | `geckodriver` |
| ImageMagick | `imagemagick` | `ImageMagick` | `imagemagick` |
| Transforms | `nodejs python3 php-cli` | `nodejs python3 php-cli` | `node python php` |

On Fedora and macOS that's one package-manager command plus `gem install`. Debian and Ubuntu cost more: Ruby 4 and geckodriver come from outside the archive, and on Ubuntu Firefox does too. `renderer check` (below) gives the exact commands for whatever it finds missing.

**`trmnl-byos renderer check`, which also runs at startup.** It finds `trmnlp`, `ruby`, `firefox`, `geckodriver`, `magick`/`convert`, `node`, `python3` and `php` on `PATH` or where configured, and reports their versions against a supported range. It works out the sandbox's `Read` entries (3.4) and renders a self-test recipe inside the sandbox. A missing transform runtime only disables recipes in that language.

**Render fidelity.** Renders now depend on the host's versions and fonts on both platforms. On macOS, CoreText rasterizes glyphs differently from FreeType (inferred). Ways to limit drift, to weigh and not committed:
- **A supported version range.** Pin `trmnl_preview` to a range (`~> 0.34`) and name Firefox ESR or release majors. `renderer check` warns outside the range. It's cheap, and it's the closest thing to the old image pin.
- **A font check.** A short list of families trmnl expects (Linux via `fc-list`), with the package names to install. Recipes mostly load TRMNL's web fonts through the proxy, so this covers only fallbacks.
- **A render self-test.** A bundled static recipe, rendered at `renderer check` and compared with reference PNGs per palette under a pixel-difference tolerance, with a warning on drift. It also proves the sandbox works. macOS may need its own references.

### 3.4 Runtimes under covered paths

With the host root as the view (read: `spec.go`), anything outside the default covers is visible read-only with no config. Linux covers `/home /root /run /tmp /var /mnt /media /dev/shm /.snapshots /sysroot`. macOS covers `/Users /Volumes /private/var /private/tmp` (per one-binary). Where installs land:

| Install location | Covered? | Handling |
|---|---|---|
| `/usr/lib/ruby`, `/usr/share/gems`, `/usr/local/*`, `/opt/*`, `/usr/lib/firefox*` (Linux) | no | nothing |
| `/opt/homebrew/*`, `/usr/local/*` (Intel), `/Applications/Firefox.app` (macOS) | no | nothing |
| `/var/lib/gems/<ver>` (Debian's `sudo gem install`) | yes, `/var` | `Read` that versioned directory |
| `/var/cache/fontconfig` (Linux) | yes | `Read` it, or every build rebuilds the font cache in its own home |
| `~/.rbenv`, `~/.local/share/mise`, `~/.gem`/`~/.local/share/gem` (user gem installs), `~/.nvm`, `~/.pyenv`, `/home/linuxbrew/.linuxbrew`, `~/Applications/Firefox.app` | yes, a home | `Read` the narrowest directory: the Ruby version's prefix or the gem dir for that version, never the whole `~/.gem` (`~/.gem/credentials` holds the RubyGems API key) |
| `/etc/localtime` linking into `/private/var/db/timezone` (macOS) | the target is | the Seatbelt backend allows `/etc` link targets under covers, as the Linux backend already rebinds them |

How a `Read` entry works (read: `spec.go`):
- It binds a host path back read-only even under a covered path. Inside a covered home it gets its mount point in the cover's tmpfs.
- A link in it is followed only outside directories a sandbox can write.
- A path that doesn't exist is dropped quietly.
- On macOS the same entry becomes a `file-read*` `subpath` allow placed after the cover's deny.

Two practical snags, both handled by `renderer check` and not by the user:
- **Derive, don't configure.** Resolve each tool's real path, and for Ruby read `gem env gempath`. Each result that lies under a covered path becomes a `Read` entry at the narrowest prefix.
- **`HOME` moves.** Inside the sandbox `HOME` is the build dir, so anything that finds itself through `$HOME` breaks: rbenv shims, user gem paths, nvm. Pass absolute paths and set `PATH`, `GEM_HOME` and `GEM_PATH` explicitly from what was resolved outside.

Recommend system-wide installs (`/usr/local`, `/opt`, Homebrew) in the docs, since they need no `Read` at all, but support home installs.

### 3.5 Limits and teardown

Use what the host gives, and log once what's missing.

- **Linux.**
  - With a delegated cgroup (the shipped systemd unit sets `Delegate=yes`; `user@` delegates `memory` and `pids` by default on current distros, inferred):
    - `serve` makes `build-<id>/` with `memory.max` (about 1.5 GB), `memory.swap.max`, `pids.max` (around 1024, since Firefox's threads count) and `memory.oom.group=1`.
    - It starts bubblewrap there with `Cmd.CgroupFD`, which the library turns into `SysProcAttr.UseCgroupFD`. tmpfs pages are charged to it.
    - Afterwards: `cgroup.kill`, then `rmdir`.
  - Without one, rlimits (`CPU`, `NOFILE`, `FSIZE`) and the footprint watchdog below. Don't use `RLIMIT_NPROC`, which counts every task of the uid, or `RLIMIT_AS`, which breaks SpiderMonkey's reservations (inferred).
  - Teardown is complete either way: the sandbox's pid 1 dying kills the whole tree.
- **macOS** (web sources, nothing run).
  - No cgroups, no pid namespace. `RLIMIT_AS` shares its number with `RLIMIT_RSS` in XNU and is reported not to be enforced. `RLIMIT_DATA` rejects values below about 418 GB on Apple Silicon. `RLIMIT_NPROC` counts every process of the uid, the user's apps included. So set `CPU`, `NOFILE` and `FSIZE`, which have standard BSD semantics (inferred).
  - Memory: the watchdog.
  - Teardown: start the build in its own process group and SIGKILL the group. A process that calls `setsid` escapes. It keeps its profile, which names only its own build dir, deleted by then, and its own proxy port, closed by then. So it has no files and no network, and `RLIMIT_CPU` ends it.
- **Footprint watchdog (both, when there's no cgroup).** `serve` polls the build's processes every few hundred ms and kills the build past a threshold. On Linux that's the process group via `/proc/<pid>/status`. On macOS it's `proc_listpgrppids` plus `proc_pid_rusage` `ri_phys_footprint`. It's a soft limit: a fast spike can land between polls, and macOS swaps before it kills. It's still enough to stop a runaway recipe from taking the machine. The library offers `Cmd.Footprint()`, and the threshold is trmnl's.

### 3.6 Firefox under each backend

- **Linux, `strict` (ran: spikes.md L2, Firefox ESR 153 on Debian 13 arm64).**
  - Headless `--screenshot` works under `strict` and `nested`, in about 2 s. The PNG is byte-identical to the unsandboxed render, including inside a loopback-only network namespace.
  - Firefox's own sandbox stays on. Its seccomp filters and file broker (SIGSYS traps) run as they do unsandboxed, and only its user-namespace layer drops out, as bug 1756236 describes. `MOZ_ASSUME_USER_NS=0` silences the probe.
  - What `strict` refuses, all harmless:
    - the `clone(CLONE_NEWUSER)` probe
    - `clone3` (glibc falls back to `clone`)
    - `quotactl`
    - netlink sockets. Firefox still reports `navigator.onLine=true`, so the `network.manage-offline-status` pref isn't needed.
  - `nested` gains trmnl nothing, since a recipe already runs arbitrary code outside any Firefox content process. trmnl uses `strict`.
  - Not run: geckodriver talking to Marionette inside the sandbox. That's TCP on loopback, which `strict` allows (inferred).
- **macOS, Seatbelt (ran: spikes.md M2, Firefox 160 on macOS 27.0.1).**
  - Headless `--screenshot` works under a deny-default profile through `sandbox-exec`, in 2-4 s. The PNG is byte-identical to the unsandboxed render.
  - `CFFIXED_USER_HOME` must point at the sandbox home (4.1). Without it, Firefox 152-157 hangs on the TCC-protected real `~/Library`.
  - A process inside a profile can't apply another one (bug 1417005), so Firefox's children fail `sandbox_init`.
    - The content process then crash-loops with no output.
    - The socket and RDD processes crash, but the render still completes.
    - `MOZ_DISABLE_CONTENT_SANDBOX`, `MOZ_DISABLE_SOCKET_PROCESS_SANDBOX` and `MOZ_DISABLE_RDD_SANDBOX` fix all three. The content switch returns level 0 before the release-build clamp (read: `SandboxSettings.cpp`). The GPU, utility and GMP processes didn't start for a plain page. Media in a recipe may start them.
  - The minimal profile needs:
    - the app bundle, `/System`, `/usr/lib` and `/`
    - `sysctl-read`
    - Mach lookups for `launchservicesd`, `configd` and Firefox's own `org.mozilla.machname.*`, which it registers too. The `launchservicesd` lookup doesn't let it open apps or URLs: Seatbelt's separate `lsopen` operation gates that, and the profile never allows it (spikes.md M3).
    - no `iokit-open`. Headless falls back to software rendering.

    About 25 other services Firefox asks for are refused with no effect. The shipped profile adds read-only fonts, `/usr/share` and `/dev` basics for real recipes, and keeps the services list that short.
  - Without the `mach-register` rule, Firefox exits 0 with no PNG, so trmnl checks that the output exists.
  - The cost compared with Linux: Firefox has no inner layer, so our profile is the only one. Seatbelt filters operations (files, network, Mach services, IOKit), not system calls. For trmnl's assets that changes nothing.
  - Not run: geckodriver and Marionette under the profile, trmnlp's runtimes, web fonts and media.

## 4. Proposed API

One package, `github.com/die-net/sandbox`. Backends: Linux (bubblewrap) and darwin (Seatbelt via `/usr/bin/sandbox-exec`, since legwork builds with `CGO_ENABLED=0`). Other platforms return `ErrUnsupported`. Dependencies stay `x/sys` and `x/net/bpf`, and the module builds and passes its tests with and without CGO.

### 4.1 Types

```go
type Spec struct {
    Command []string
    Home    string       // writable; real path, no links
    Dir     string       // "" means Home
    Write, Read, Cover []string
    Kernel   Kernel      // KernelStrict (default), KernelNested, KernelOpen; raised, never lowered
    Services []Service   // reviewed macOS Mach-service groups, e.g. ServiceFonts; no-op on Linux
    Network  Network     // zero value NetworkNone; NetworkHost must be asked for. In the first release.
    BroadLoopback bool   // macOS only, opt-in: allow all of localhost (4.3); Linux ignores it
    Listen   int         // proxy listeners the parent serves (4.3); added with legwork's phase 4
    Loopback int         // loopback ports the sandbox may bind and dial itself (4.3); same
    Files    []*os.File  // fds 3, 4, ... in the command
    Rlimits  []Rlimit
    Hostname    string   // Linux only
    ScratchSize int64    // Linux only: each private tmpfs; 0 means 1 GiB
}

func Probe() (Report, error) // tries the backend; an error means no sandbox at all
type Report struct {
    Backend         string             // "bubblewrap" or "seatbelt"
    Kernel          map[Kernel]Kernel  // level given per requested one, never lower; a level this host can't meet is absent
    TreeKill        bool               // killing the sandbox kills every descendant
    PrivateLoopback bool               // loopback and abstract sockets private to the sandbox (macOS: true unless BroadLoopback)
    Ignored         []string           // Spec fields this backend ignores, e.g. "Hostname"
    Container       string             // best effort: "docker", "podman", "lxc", "kubernetes", "systemd-unit", ""
    Checks          []Result           // each prerequisite, and what blocks it (6.3)
}

func Stage() (code int, ok bool) // first in main of any binary that starts sandboxes
func Command(ctx context.Context, spec Spec) (*Cmd, error) // ctx cancels: kills the sandbox
type Cmd struct {
    // The only settable parts, checked at Start:
    Stdin     io.Reader
    Stdout    io.Writer
    Stderr    io.Writer
    Env       []string      // nil means empty, never os.Environ(); Start sets HOME, TMPDIR, XDG_* (XDG_RUNTIME_DIR included) and, on macOS, CFFIXED_USER_HOME over it
    WaitDelay time.Duration // as exec.Cmd's
    Setpgid   bool          // new process group (macOS teardown)
    CgroupFD  int           // Linux: start in this cgroup; -1 none
    // unexported: the exec.Cmd, ExtraFiles, SysProcAttr, Path
}
func (c *Cmd) ListenAddrs() []string     // known after Command, so Env can carry HTTP_PROXY
func (c *Cmd) LoopbackPorts() []int      // likewise, for geckodriver and Marionette
func (c *Cmd) Start() error              // resolves paths, opens bind sources, builds --args, then execs
func (c *Cmd) Wait() error
func (c *Cmd) Listeners() []net.Listener // after Start, in order; the caller serves them
func (c *Cmd) Pid() int                  // Linux: host pid of pid 1, from --info-fd only. macOS: the top process
func (c *Cmd) Footprint() (bytes int64, err error) // for a watchdog when there's no cgroup

func Run(ctx context.Context, spec Spec) (int, error) // dedicated-process form, as legwork sandbox uses
func (s *Spec) RegisterFlags(fs *flag.FlagSet)
const SelfPath = ... // this binary as the command names it: /dev/sandbox-stage on Linux, its real path on macOS
```

- **Fields across backends.** Every field is honored or harmlessly ignored on both backends, and ignored fields are listed in `Report`. The caller logs the report once at startup, and the library never logs.
- **Kernel levels.** A level is only ever raised. On macOS every level gets the one profile, which is at least as strict as the request, and `Report.Kernel` shows it. A level the host can't meet is an error from `Command`, and it's missing from `Report.Kernel`, never a silent fall to a weaker level. For example, linux/arm (GOARM=7) has no syscall list. legwork refuses `strict` and `nested` there today (read: `syscalls_linux_other.go`), and the library keeps that.
- **`Env` lives only on `Cmd`**, as on `exec.Cmd`.
  - It starts empty. The caller sets it after reading `ListenAddrs()`, which on macOS isn't known until `Command` has bound the port. `Start` then always sets the sandbox's `HOME`, `TMPDIR` and `XDG_*` over it, including `XDG_RUNTIME_DIR`. legwork's `commandEnv` misses that one, and the host's `/run/user/<uid>` leaked into Firefox (spikes.md L2).
  - On macOS it also sets `CFFIXED_USER_HOME` to the sandbox home. `$HOME` alone doesn't redirect where Cocoa looks for `~/Library` (Application Support, Caches). Without it, Firefox 152-157 hangs on the TCC-protected real `~/Library/Application Support/Firefox`, and later versions write into the real `~/Library` (spikes.md M2). CFPreferences still reads the real `~/Library/Preferences`, and the profile refuses that at no cost.
  - A server that forgets to set it passes on nothing, so none of its tokens leak. `Run`, the standalone form, passes `os.Environ()` explicitly.
  - Rejected: making every listener address known before `Command`. Linux listeners are bound inside the namespace, so the backends would diverge. Also rejected: a `SANDBOX_LISTEN_n` variable for the command to translate, since legwork execs its CLI directly and nothing would translate it.
- **The uid.** `Command` and `Start` run as the sandbox's uid. They resolve paths, open bind sources by fd, read homes and write the passwd entry in the calling process, and switching uid at exec would leave all of that done as root. So `Command` refuses euid 0. There's no `Credential` option at all. legwork's root launcher switches uid in its own child, then calls the library, which matches one-binary's Root.
- **`Cmd` wraps `exec.Cmd` instead of embedding it.** The `--args` body bakes in descriptor numbers, so a caller changing `ExtraFiles`, `SysProcAttr` or `Path` would break the sandbox or drop its parent-death handling. The fields above are trmnl's and legwork's whole need: stdio, `Env`, cancellation through `ctx` plus `WaitDelay`, a process group, and a cgroup. `Start` checks them, then does the path work. Sessions stay unset (2, "No `--new-session`").
- `Services` is the one knob that only means something on one backend. A browser needs Mach services legwork's CLIs don't, so it's a list of library-defined, reviewed groups, not free-form names. Adding a group is a reviewed library change, as sandbox.md requires for a system call.

### 4.2 How `Spec` maps onto each backend

| Field | Linux (bubblewrap) | macOS (Seatbelt, per one-binary) |
|---|---|---|
| `Home`, `Write`, `Read` | binds by fd, link rules | `subpath` allows. Seatbelt checks the real path at access time (inferred). Keep the no-link rule on home and write paths. |
| `Cover` and default covers | tmpfs or `/dev/null` | denies after the broad allow (last match wins) |
| `/etc` link targets under covers | rebound read-only | allowed read-only |
| `Kernel` | strict, nested and open are different filters | all strict |
| Environment | `Start` sets `HOME`, `TMPDIR`, `XDG_*` | the same, plus `CFFIXED_USER_HOME` (4.1) |
| `Services` | ignored | extra `mach-lookup` groups. Firefox's needs only `launchservicesd`, `configd` and its own `org.mozilla.machname.*` register and lookup, with no `iokit-open` (spikes.md M2). |
| `Network: NetworkNone` (zero value) | bubblewrap's `--unshare-net`: a namespace with only loopback, no new code. Abstract sockets become private too. | deny network, except the `Listen`/`Loopback` ports and the unix sockets the `Spec` names. Firefox renders a `file://` page with none, and one allowed port works (spikes.md M2). |
| `Network: NetworkHost` (asked for explicitly) | host network | allow outbound, deny `localhost` |
| `BroadLoopback` (opt-in) | ignored, since loopback is private | allow `localhost:*`, which also reaches the host's LAN address. No reliable per-port deny exists (4.3). |
| `Listen` | bound inside the namespace by the stage, handed to the parent | bound by the parent on `127.0.0.1:0`; the profile allows that port |
| `Loopback` | private loopback; fixed ports returned | allocated by the parent; the profile allows bind and connect on exactly those |
| `Files`, `Rlimits` | through bubblewrap; set by pid 1 | through `sandbox-exec`; set by the stage before it execs |
| Memory, tasks | caller's cgroup, or `Footprint` | `Footprint` |
| Teardown | pid 1 dies, all die | process group; `setsid` escapes |
| `TIOCSTI` | filter refuses | not refusable. The profile denies opening other ttys, and the macOS column of section 2 tests injection. |
| `Hostname`, `ScratchSize` | supported | ignored; `TMPDIR` is in `Home` |

### 4.3 Egress brokered by the parent

Programs read `HTTP_PROXY` as a TCP `host:port`, so the proxy needs a TCP address the sandbox can reach. The interface is the same on both backends: ask for `Listen: 1`, build `HTTP_PROXY` from `ListenAddrs()[0]`, and serve `Listeners()[0]` after `Start`. Each listener belongs to one build, so the proxy knows which policy and log to use without trusting the client. That also gives trmnl the per-recipe egress record its design.md lists as not built.

- **Linux:** the stage binds `127.0.0.1:3128` inside the build's namespace and sends the socket to the parent.
- **macOS:** the parent binds `127.0.0.1:0` and the profile allows that port. Other local processes can connect to it too. They're outside the threat model, and the proxy applies the same public-only rules to them.

`Loopback` is for WebDriver. On Linux any port works, since loopback is private. On macOS a profile that allowed all of `localhost` would expose `serve`'s listeners and other local services. So the parent allocates two ports, and trmnlp starts geckodriver on `LoopbackPorts()[0]` with `--marionette-port LoopbackPorts()[1]`. That's a small trmnlp change, needed on macOS only.

Until trmnlp has that change, the caller can set `Spec.BroadLoopback`, and the profile then allows `localhost:*`.
- It's an explicit opt-in, never automatic. For legwork it would reach `serve`'s listeners and loopback upstreams, past tool policy and the audit log, so legwork never sets it.
- trmnl sets it on macOS until trmnlp takes fixed WebDriver ports, then drops it.

What it opens, measured on macOS 27.0.1 (ran: spikes.md M1):
- **Every TCP listener on any of the host's own addresses.** Seatbelt's `localhost` matched the Mac's LAN address too, not just `127.0.0.1` and `::1`.
- **`serve`'s API included.** Neither earlier mitigation works.
  - A `(deny network-outbound (remote ip "localhost:<port>"))` after the broad allow held for about half of all ports. The set it holds for is the same on every rerun, but no pattern was found, so it can't be relied on.
  - Moving `serve` to its LAN address is undone by the first point.
- **The user's other local services, and other builds' proxy and WebDriver ports** when concurrency is above 1 (trmnl's default is 1, read: `cmd/trmnl-render`).

What stays sound: a profile that allows only named ports (`localhost:<port>`) refused every other port in all 40 ports tested. So `NetworkNone` with the parent's listener and fixed `Loopback` ports works as designed, which makes trmnlp's fixed-port change the real fix.

Decided (2026-11-17): on macOS, `BroadLoopback` is a reported gap, not a refusal, until trmnlp takes fixed ports. The alternatives on a Mac are `--no-sandbox` or a VM, and both are worse, since the file covers still protect the database, secrets and homes.

So reaching `serve` isn't the no-boundary floor. trmnl's endpoints trust no source address: the admin API takes only a bearer token or a signed-in session cookie (read: `adminapi.go:284`), and device calls take the device's `Access-Token` (read: `deviceapi/auth.go`). For `serve`, a recipe gets what any host on the LAN has. I didn't audit every route for a check that's skipped; that audit is a prerequisite for shipping the opt-in.

The gap is wider than `serve`, though. Services bound only to `127.0.0.1` that trust local connections, such as a dev Postgres with `trust` auth or an unauthenticated Redis, are out of the LAN's reach but within a recipe's. trmnl's startup warning while the opt-in is on says that plainly, naming "every local service on this Mac", not just its own API. Its `Check` reports `serve`'s API as reachable (6.2).

The proxy is the caller's: `renderproxy` with the `guard` dialer. legwork's planned proxy has the same shape. A shared egress package is the likely next extraction, separate from this module. `Network` ships in the first release with both values. Its zero value is `NetworkNone`, so adding it later would silently take host network away from every `Spec` written before it, and legwork sets `NetworkHost` at extraction. Only `Listen` and `Loopback`, the listener handoff, wait for legwork's phase 4. Those really are additive: a zero count means no listeners, which is what a `Spec` without them meant anyway.

### 4.4 Re-running its own binary, and passing descriptors

- **Linux.**
  - bubblewrap execs the caller's binary, bound at `/dev/sandbox-stage`, as pid 1. Every binary that starts sandboxes calls `sandbox.Stage()` first in `main`. The stage runs the binary's package `init` code with `CAP_SYS_ADMIN` in a nested userns. one-binary's "no `init` function" rule keeps that acceptable, and trmnl-byos adopts it.
  - A control socketpair, passed through bubblewrap, carries settings in, and listeners and setup errors out. That replaces argv and ends the exit-125 ambiguity. It depends on bubblewrap passing unnamed inherited descriptors through, which spikes.md L1 confirmed on bubblewrap 0.12.0.
  - The socket is only trusted during setup. Pid 1 sends the listeners, stops reading, and closes its end before the command starts, so no untrusted code ever holds it. The parent then ignores anything more that arrives on it.
  - `Pid()` comes only from bubblewrap's `--info-fd` (`child-pid`), never from the control socket. A sandboxed process that could write the socket could otherwise lie about the pid that legwork's bridge check keys on. TestIsolation's descriptor check grows to assert that the command holds neither the control socket nor the info fd.
  - Confirmed on bubblewrap 0.12.0 (ran: spikes.md L1):
    - unnamed fds reach pid 1 at their numbers, and bubblewrap closes the `--args` and `--info-fd` descriptors before the exec
    - `--info-fd`'s `child-pid` is pid 1's host pid
    - the listener handoff under `--unshare-net` works
    - after setup the parent reads EOF on the control socket
    - the command holds only its own fds
    - the lifeline tears everything down on close and on the parent's `SIGKILL`.
  - `Files` are numbered from 3. The stage marks every other inherited fd close-on-exec before starting the command. It never closes fds by number: once Go's runtime is up, a freed number may be its epoll fd, which crashed the spike.
  - **Parent death.** There's no `Pdeathsig` on the server's side, since it fires when the forking OS thread exits, and a Go server's threads come and go.
    - The parent passes the read end of a lifeline pipe and keeps the only write end (close-on-exec).
    - Pid 1 waits on it alongside its children. On EOF, which comes when the server dies however it dies, pid 1 exits, and the namespace's other processes die with it.
    - bubblewrap's `--die-with-parent` kills pid 1 if bubblewrap dies, and bubblewrap exits once pid 1 does. bubblewrap is single-threaded, so its own `PR_SET_PDEATHSIG` doesn't have the thread problem.
    - This is inferred and unbuilt. The alternative is one locked OS thread that does every start for the server's lifetime, which keeps `Pdeathsig` usable.
- **macOS.**
  - The same `Stage()` call runs outside the profile. It sets rlimits and the process group, closes stray descriptors, and starts `/usr/bin/sandbox-exec -f /dev/fd/N -- command`, so the profile isn't in argv.
  - The stage stays alive outside the profile as a small supervisor instead of exec'ing. It holds the lifeline, kills the process group on EOF, and relays the exit status (inferred).
  - The parent binds the listeners, so there's no control socket. `Pid()` is the parent's own child, so it's taken from no message at all.
- **On both,** the command can be the same binary (`[SelfPath, "render-child", ...]`), as one-binary's `turn` and `stdio` children are.

## 5. Isolation modes

| Mode | What isolates untrusted code | Who picks it |
|---|---|---|
| In-place (default) | the library, one sandbox per build or child | anyone running the binary plus host packages |
| Operator | the operator's containers (Compose, Podman) or systemd units | operators who already run containers, or want systemd's controls |
| Both | the library's sandbox inside the operator's boundary | the strongest setup, once the outer runtime allows namespaces (6.3) |
| `--no-sandbox` | nothing | development |

In operator mode the project starts untrusted code without the library's sandbox, because the operator's boundary does that job. The library's part is `Check` against the process as it is (6.1), run by the project at startup and in `doctor`, so the operator sees what the boundary enforces and what it doesn't.

In the in-place, operator and both modes the floor is the same: refuse only when there's no boundary at all. In operator mode, that's when the checks show untrusted code can read the server's secrets, or reach an endpoint that trusts the caller's address instead of a credential. Everything short of that is reported, not refused.

`--no-sandbox` never refuses to start, as in legwork's Floor (one-binary.md:131). It says so in the log. It still runs `Check(ctx, nil, want)` at startup and logs the results, so the operator sees exactly what they gave up.

### 5.1 trmnl in operator mode

Today's `compose.yaml` (read) is the reference setup. It stays supported, not deprecated. "Set up correctly" means:

- **Three processes, split.**
  - The server: the data dir (the DB with device keys and sealed fields), `TRMNL_SECRET_KEY`, and the admin API.
  - The proxy: the render side's only route out, refusing private addresses, never routing packets.
  - The render side (today's `trmnl-render`, a `render` subcommand of the one binary): runs builds.
- **What the render side must not see.**
  - The data volume, `TRMNL_SECRET_KEY` (it opens every sealed field), and any other server environment.
  - The server's processes: same container or same uid means `/proc/<pid>/environ`.
  - Its only secrets are each build's own `FIELD_*`.
- **Its network.** It reaches the proxy and nothing else. That excludes the server's API, host loopback, the LAN and `169.254.169.254`.
- **Its process.** Its own uid, no capabilities, no_new_privs, a memory cap. Compose has all of it today.
- **As systemd units:**
  - Give the render side its own unit, with `DynamicUser=yes`, `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet=`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `MemoryMax=` and `TasksMax=`.
  - Use `IPAddressDeny=any` with `IPAddressAllow=` set to the proxy's address. systemd filters by address, not port. So the server must not listen on the address the proxy uses, which means binding the server to its LAN address rather than `0.0.0.0` (inferred).

What operator mode doesn't give, which `Check` reports:

- **Builds on one render side share a uid.**
  - Concurrent builds can read each other's `FIELD_*` through `/proc/<pid>/environ`.
  - A process a build leaves behind (`setsid` escapes the group kill in `procgroup_unix.go`) sees later builds' variables and files.
  - Fixes, any one of these:
    - concurrency 1 (the default), plus the render side killing every other process in its container after each build. It's alone there with the init, so it can (inferred).
    - the in-place sandbox inside the render container ("both").
    - a container per build, which is heavy.
- **Server and builds in one container, or under one account on the host, with the in-place sandbox off.** That's no boundary. A recipe reads the DB, `TRMNL_SECRET_KEY` from the server's `/proc/<pid>/environ`, and other builds' `FIELD_*`, and calls the admin API on loopback. The render side's checks catch this (the data dir or the server's environment readable, the API reachable), and trmnl refuses unless `--no-sandbox` is given. Under `--no-sandbox` it starts and logs those same failures. A single container is fine with the in-place sandbox on, once the runtime allows it (6.3).

### 5.2 legwork in operator mode

legwork's one-binary.md requires the in-place sandbox and retires the multi-account split, so keeping an operator mode is legwork's call. If it stays, "set up correctly" means:

- **Split:**
  - `serve`, which holds the Slack tokens, upstream credentials, allowlist, transcript, memory, skills, audit log, approvals, `web.sock`, and owns `mcp.sock`
  - turns
  - each stdio server
  - the proxy.
- **A turn must not see:** anything `serve` holds, other threads' scratch dirs or saved sessions, or stdio servers' files. Its network is `mcp.sock` and the proxy.
- **A stdio server must not see:** anything `serve` holds, the CLI's scratch, or another stdio server's files.
- **The gap:** static containers or units give no boundary per thread. Every turn shares a uid, the scratch root and the CLI home, which is today's deployment and what one-binary's "Between threads" fixes. `Check` reports other threads' directories as readable. A container per turn, or "both", closes it.
- **One container with the sandbox off:** the CLI reads the Slack tokens and the DB, and can mark approvals. That's no boundary, and legwork already refuses it.

## 6. Checks: a shared `doctor` core

The library owns the generic checks and one runner. Each project supplies its specifics and renders the results. legwork's `doctor` is designed but not built (read: one-binary "Checks", "Running as a service"), so this changes no code.

### 6.1 API

```go
type Status int
const (
    Pass           Status = iota // the attempt failed, or the property holds
    Fail                         // the attempt worked
    NotEnforceable               // applies, but nothing here can enforce it (memory on macOS)
    Skipped                      // doesn't apply (no proxy given, a Linux-only check on macOS)
)
type Result struct {
    Name   string // stable, e.g. "userns.create", "egress.direct-tcp"
    Status Status
    Detail string // what was tried and what happened, with the fix when there is one
}

type Expect struct {
    Unreadable  []string // paths; also tried through their filesystem's snapshot dirs
    Unwritable  []string
    Unreachable []string // "tcp:127.0.0.1:8080", "udp:host:port", "unix:/path"
    Proxy       string   // host:port the code should use for egress
    Allowed     []string // CONNECT targets the proxy must allow
    Refused     []string // CONNECT targets the proxy must refuse
}

// Check runs the suite in a child and returns one Result per check.
// spec != nil: inside a library sandbox built from spec.
// spec == nil: the child inherits the caller's context as it is, which
// is what an operator's container or unit gives.
func Check(ctx context.Context, spec *Spec, want Expect) ([]Result, error)
```

- **The runner.** The child is `SelfPath` with a check marker that `Stage()` handles, the same way it handles the stage markers. Results come back as JSON lines on an fd. So the only setup is the `Stage()` call every adopter already has.
- **No side effects on the caller.**
  - The namespace, mount and `io_uring` attempts run in that child, or in a child of it.
  - Signals use `kill(pid, 0)`, and tracing uses an `open` of `/proc/<pid>/mem`, which checks attach permission and stops nothing.
  - Writes are `O_CREAT|O_EXCL` of a random name, then `unlink`.
  - Connections are closed at once.
- **What a pass means.** A pass means one attempt failed, not that every path is closed. `Detail` says what was tried.

### 6.2 Generic checks

| Check | Linux | macOS |
|---|---|---|
| no_new_privs, seccomp mode and filter count | `/proc/self/status` | `Skipped` |
| Capabilities: effective, permitted, bounding | `/proc/self/status` | `Skipped` |
| Supplementary groups: none (sandbox.md, The view) | `getgroups` | same |
| Running as uid 0 in the initial user namespace | `/proc/self/uid_map` | `getuid` |
| Create a user namespace; mount a tmpfs; `io_uring_setup`; netfilter `setsockopt` replace; `bpf` | tried | `Skipped` (none exist) |
| Under `kernel: nested`: unmount a cover, remount a read-only bind writable, mount from outside the view | tried, when `spec` says nested | `Skipped` |
| Processes outside our tree: visible, signalable, traceable, environment readable | `/proc`, `kill(pid, 0)`, `/proc/<pid>/{mem,environ}` | `kill(pid, 0)`, `KERN_PROCARGS2` (it returns another same-uid process's environment unless the profile denies `process-info*`, inferred) |
| Well-known host secrets readable: `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, `~/.gem/credentials`, `/etc/shadow` | `open` | same, plus the user's Keychain files |
| Well-known sockets reachable: Docker, Podman, containerd, D-Bus session and system bus, `SSH_AUTH_SOCK`, the systemd user manager, host abstract sockets | `connect` | same, minus abstract sockets |
| Writes outside `Home` and `Write` | each `Read` path and `/`, when `spec` is given | same |
| Anything under a cover readable | one entry per cover, when `spec` is given | same |
| Snapshot dirs: each `Unreadable` path tried through `.zfs/snapshot` at its mount root and through `.snapshots` (sandbox.md, Limits) | tried | `Skipped` |
| Direct egress: TCP to a public address, UDP DNS to a public resolver | tried | tried |
| Metadata services: `169.254.169.254:80`, `[fd00:ec2::254]:80` | tried | tried |
| The LAN: the default gateway on 22, 80, 443 | from `/proc/net/route` | from the routing table |
| Proxy: `Allowed` connect, `Refused` refused | through `Proxy` | same |
| Caller's `Unreadable`, `Unwritable`, `Unreachable` | tried | tried |
| Memory limit; task limit | own cgroup's `memory.max`, `pids.max`, else `RLIMIT_*` | `NotEnforceable` (3.5) |
| Cgroup delegation: can make a child with `memory` and `pids` (what `Delegate=yes` gives) | tried | `Skipped` |

legwork's escape list (one-binary line 284) maps onto these:
- **Generic:**
  - signalling and tracing `serve`
  - UDP and TCP straight to a public address
  - creating a user namespace, mounting a tmpfs, `io_uring_setup`, the iptables `setsockopt`
  - anything else under a covered path
  - writing outside its own dir
  - the nested extras.
- **legwork's `Expect`:**
  - the config, the database, another sandbox's dir and each config-named path (`Unreadable`)
  - sockets other than `mcp.sock`, and `127.0.0.1:9229` (`Unreachable`)
  - the `CONNECT` pair (`Proxy`, `Allowed`, `Refused`).

legwork reruns the suite under each relaxation and decides which checks a relaxation gives up. That's line 209's "every relaxation is visible".

trmnl's `Expect`:
- `Unreadable`: the data dir, the config, other builds' dirs
- `Unreachable`: every address `serve` listens on, plus `tcp:127.0.0.1:<port>` and `tcp:[::1]:<port>` for each of its ports. In-place mode runs this inside a build sandbox at each start. On macOS with `BroadLoopback` on, these fail by design (4.3), and trmnl reports them, not refuses.
- `Proxy`: the build's proxy, with one public host allowed and `10.0.0.1:80` refused.

In operator mode the render side runs `Check(ctx, nil, want)` at startup and on `doctor`, and returns the results to the server through its existing API, so the server can show them.

### 6.3 Why the in-place sandbox can't start

`Probe` tries the backend. On failure it fills `Report.Checks` with the first blocking setting it finds, in this order, and the fix:

| Finding | Detected by | Fix in `Detail` |
|---|---|---|
| bubblewrap missing, setuid, or older than 0.8 | `PATH`, mode bits, `--version` | the distro's package |
| Ubuntu's AppArmor userns restriction | `kernel.apparmor_restrict_unprivileged_userns=1`, and the mount fails in a new userns | an AppArmor profile for this binary's path, which the library generates, plus the one root command to load it (one-binary, Ubuntu) |
| Userns turned off by sysctl | `kernel.unprivileged_userns_clone=0` (older Debian), `user.max_user_namespaces=0` | the sysctl |
| Docker's or Podman's default seccomp profile | `Seccomp: 2`, a container detected, and `unshare(CLONE_NEWUSER)` returns `EPERM`. The moby profile grants these calls only with `CAP_SYS_ADMIN`. That's inferred from legwork's `strict` filter, which starts from moby's list without capabilities and lacks them. | a profile that is the default plus `clone` namespace flags and the calls `nested` adds (read: `nestedSyscalls`: `unshare`, `mount`, `umount2`, `pivot_root`, the new mount API). Never `seccomp=unconfined`. |
| Docker's AppArmor profile | `/proc/self/attr/current` reads `docker-default` | a profile that allows `mount`, or `apparmor=unconfined` for the render container only (inferred) |
| Masked `/proc` | overmounts under `/proc` in `mountinfo`. The kernel refuses a new procfs while the existing one is partly hidden (inferred). | Docker `--security-opt systempaths=unconfined`, Podman `--security-opt unmask=ALL` (inferred) |
| A systemd unit's restrictions | `$INVOCATION_ID` set, own cgroup ends in `.service`, and `unshare` or `mount` refused | relax `RestrictNamespaces=`, and a `SystemCallFilter=` that lacks `@mount`, for this unit only, keeping the rest |
| macOS: already inside a Seatbelt profile | `sandbox-exec` with a trivial profile fails | run outside that profile (another tool's sandbox, an App Sandbox) |

The container fixes relax the outer layer just enough for the inner one, which then applies the stricter filter and the covers to the untrusted code. Container detection is best effort: `/.dockerenv`, `/run/.containerenv`, `KUBERNETES_SERVICE_HOST`, cgroup path patterns, and `systemd-detect-virt -c` when it exists.

### 6.4 What stays in each project

- **legwork:**
  - printing and inspecting service files (`systemctl show` for `Delegate=yes`, `launchctl print`)
  - tunnels
  - npx pinning
  - the Slack notice
  - the relaxation reruns
  - its `Expect`
  - rendering the results.
- **trmnl:**
  - `renderer check`'s tool versions and render self-test
  - its `Expect`
  - showing the results on its status page and in the log.

## 7. Adoption

**legwork** (no behavior change):

1. Seed this repo from legwork's history (`git filter-repo --path internal/sandbox --path docs/sandbox.md`). `cmd/legwork-sandbox` stays in legwork, since it imports `internal/cli` and pflag.
2. Library: rename the markers and constants. Add `Command`, `Probe`, `Check`, the control socket, the lifeline, `Files`, `Rlimits` and `Pid`, and make `Run` a wrapper. Move the tests and the CI job (Ubuntu 24.04, apt bubblewrap, `apparmor_restrict_unprivileged_userns=0`). CI runs with `CGO_ENABLED=0` and `=1`. Tag releases from the first one.
3. Split the docs. The library gets the threat model, mechanism, "Tried and dropped", "Limits", "How it is tested", and the one findings list, kernel and Seatbelt alike. legwork's `sandbox.md` keeps only its policy, and its CLAUDE.md points at the library's findings, so there's never a second copy to drift.
4. legwork imports the module at a pinned, tagged version. That's a deliberate exception to its stdlib-then-`x` dependency rule, so say so where the rule is written.
   - `cli.SandboxSpec` sets `Hostname: "legwork"`, `Dir` from `os.Getwd()` and `Network: NetworkHost`, and legwork sets `Cmd.Env` to the environment `serve` builds for each child (one-binary, Processes). `NetworkHost` keeps today's behavior until phase 4, since the zero value is now `NetworkNone`.
   - `TestBridgePeer` moves onto the public `Command`, with its own `TestMain` that calls `Stage()`.
   - Delete `internal/sandbox`.
5. legwork's phase 4 switches to `NetworkNone` and builds `Listen`. Phase 5 uses `Files`, `Pid` and `Command`. Phase 6 (Seatbelt) is built in the library.

**Both projects** test the `Spec` they actually build, end to end, with `Check(ctx, &spec, want)` in their own tests (a `TestMain` that calls `Stage()`), not only the library's generic suite. `Check` is public for that.

**trmnl-byos-go** (one binary plus host packages):

1. `main` calls `sandbox.Stage()` first. Audit package `init` work. Log `sandbox.Probe()` at startup. Refuse to render only when `Probe` fails, and print the fix. With `--no-sandbox` (development), never refuse. Run `Check(ctx, nil, want)` at startup and log the results instead (section 5).
2. Fold `renderproxy` into `serve` and `trmnl-render` into `render-child`. Drop Xvfb.
3. Add `renderer check` (3.3): find the tools, report versions, derive `Read` entries, run the self-test. It runs at startup and on demand.
4. Per build:
   - `serve` writes the project, then calls `sandbox.Command` with:
     - `Command: [SelfPath, "render-child", ...]`
     - `Home`: the build dir
     - `Read`: derived
     - `Kernel: strict`
     - `Network: NetworkNone` (the zero value), `Listen: 1`, `Loopback: 2`, and `BroadLoopback` on macOS until trmnlp takes fixed WebDriver ports (4.3)
     - `Services: [fonts, ...]`
     - `Rlimits`: `CPU`, `NOFILE`, `FSIZE`
   - On the returned `Cmd` it sets `Env`: `buildEnv` plus `HTTP(S)_PROXY` from `ListenAddrs()`, the resolved `PATH`/`GEM_HOME`/`GEM_PATH`, `MOZ_HEADLESS=1`, `MOZ_CRASHREPORTER_DISABLE=1`, `MOZ_ASSUME_USER_NS=0` on Linux, `MOZ_DISABLE_CONTENT_SANDBOX=1`, `MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1` and `MOZ_DISABLE_RDD_SANDBOX=1` on macOS, and the `FIELD_*` values.
   - It also sets `Stdout`/`Stderr`, `WaitDelay`, and `CgroupFD` when a cgroup is delegated, or `Setpgid` and the watchdog otherwise. Then it serves `renderproxy` on the listener, waits, and reads the outputs through `os.Root`.
5. Ship a systemd unit with `Delegate=yes`, a launchd plist, and install docs per platform (3.3).
6. Keep `compose.yaml` as the operator-mode reference (5.1). Add a `--isolation=operator` flag (name to pick) to the render side. Then it runs `Check(ctx, nil, want)` at startup, reports the results to the server, and refuses only on the no-boundary findings in 5.1.

## 8. Sequencing

Settle the API against both backends now. Build Linux first.

1. **Now:** agree on `Spec`, `Report` and the mapping in 4.2, so macOS lands without breaking changes.
2. **Linux extraction** (mostly moving tested code), plus `Command`, `Probe`, `Network` (`--unshare-net` for none), `Files`, `Rlimits`, `Pid`, `Footprint`, and `Check` with its generic checks (most exist as tests in `internal/sandbox`). legwork switches over.
   - Nothing in this step needs egress under `NetworkNone`. legwork uses `NetworkHost`, `Check(ctx, nil, ...)` has no `Spec`, and a `Check` of a `NetworkNone` spec just expects its egress attempts to fail. trmnl needs `Listen`, which comes in step 3.
   - trmnl can use `Check(ctx, nil, want)` in today's compose render container right away, before it has an in-place sandbox, because the as-is checks need no namespace code.
3. **Listener handoff** (`Listen`, `Loopback`), with legwork's phase 4.
4. **trmnlp's fixed WebDriver ports**, proposed upstream early, since macOS needs it to drop `BroadLoopback`.
5. **trmnl on Linux:** one binary, `renderer check`, headless, cgroup or watchdog. Firefox under `strict` is settled (spikes.md L2).
6. **Seatbelt backend** (legwork's phase 6, built here): profile generation, the stage, `Services` groups, the deny-log runs with both legwork CLIs and with trmnlp, geckodriver and the recipe runtimes (headless Firefox alone is done: spikes.md M2), and a hole-finding review of the profile.
7. **trmnl on macOS.**

Why this order: the Linux backend has a review record and tests behind it, and it's mostly a move. Seatbelt is new code in an undocumented profile language, and its findings will come from running it. trmnl's macOS users can run the server meanwhile.

## 9. Risks and open questions, ranked

1. **The network namespace and listener handoff aren't built** in the library. They're trmnl's one hard prerequisite on Linux. The mechanism works (spikes.md L1), so what's left is library code and its tests.
2. **`BroadLoopback` on macOS opens every TCP listener on the host's own addresses**, `serve`'s included, because a per-port deny is unreliable and `localhost` matches the LAN address (spikes.md M1). It's acceptable only while `serve` trusts no source address. trmnlp's fixed WebDriver ports remove it, so propose that change early.
3. **Seatbelt profiles come from deny logs on one macOS version.** Firefox's minimal set (spikes.md M2) is small, but Apple renames and adds services between releases, and a missing one can fail silently (Firefox exits 0 with no PNG). Still open: trmnlp, geckodriver and the runtimes under the profile, and recipes with media that start the utility or GMP process. `renderer check` should run a known page and compare the PNG on each macOS release.
4. **Install friction that pushes users to `--no-sandbox`.** Ubuntu's AppArmor step; Ruby 4 and geckodriver outside the Debian/Ubuntu archives; the snap Firefox on Ubuntu. `renderer check` should name the exact fix for each, and the docs should lead with the shortest path per platform.
5. **Operator mode set up wrong**, such as the data volume or `TRMNL_SECRET_KEY` on the render side, or a shared container with the sandbox off. The as-is checks catch the common cases. A pass is still only a failed attempt, not proof.
6. **The outer-runtime fixes in 6.3 are partly inferred**: the AppArmor and masked-`/proc` rows, and which `docker`/`podman` options apply. Run bubblewrap in default Docker, rootless Podman and a hardened systemd unit before writing the messages.
7. **A derived `Read` that's too broad** could show a credential (`~/.gem/credentials`, an npm token in `~/.npmrc`). Rule: narrowest versioned prefix only, plus explicit covers for known secret files when a broader directory can't be avoided.
8. **Selenium Manager** downloading drivers or browsers per build if trmnl's paths and `SE_OFFLINE` aren't honored. Check in the first Linux run.
9. **trmnlp changes:** headless, if `MOZ_HEADLESS` isn't enough, and fixed WebDriver ports for macOS (risk 2). Neither blocks. The `--headless` flag worked for `firefox --screenshot` (spikes.md L2). Neither `MOZ_HEADLESS` from the environment nor trmnlp's own WebDriver path was run.
10. **Render drift** across host versions and fonts. Mitigations in 3.3.
11. **Memory without a cgroup** is a polling watchdog: soft, but working.
12. **macOS teardown gap:** an orphaned `setsid` process survives without files or network until `RLIMIT_CPU` ends it. A uid per sandbox (legwork's root launcher) closes it fully.
13. **Stage runs the caller's `init` with `CAP_SYS_ADMIN`** on Linux. Audit trmnl-byos's dependencies.
14. **Fix coordination.** Tag releases, since legwork pins a version as an exception to its stdlib-then-`x` rule. Keep the moby profile pin, the Seatbelt service groups and the findings list in the library only.
15. **Older bubblewrap.** Descriptor passthrough, `--info-fd` and the lifeline were confirmed on 0.12.0 only (spikes.md L1). legwork's floor is 0.8, so CI should run the oldest version it accepts.

Retired by the spikes: Firefox headless under `strict` on Linux (spikes.md L2), headless Firefox under a deny-default Seatbelt profile (M2), and descriptor passthrough on bubblewrap 0.12.0 (L1).

Sources: [Mozilla bug 1756236](https://bugzilla.mozilla.org/show_bug.cgi?id=1756236), [Mozilla bug 1884347](https://bugzilla.mozilla.org/show_bug.cgi?id=1884347), [Mozilla bug 1417005](https://bugzilla.mozilla.org/show_bug.cgi?id=1417005), [SUMO 1451388](https://support.mozilla.com/fa/questions/1451388), [Firefox SandboxInfo.cpp](https://sources.debian.org/src/firefox/148.0-1/security/sandbox/linux/SandboxInfo.cpp), [Firefox SandboxSettings.cpp](https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/sandbox/common/SandboxSettings.cpp), [Mozilla wiki: OS X sandbox rule set](https://wiki.mozilla.org/Sandbox/OS_X_Rule_Set), [Apple forums: RLIMIT_AS](https://developer.apple.com/forums/thread/856401), [Apple forums: RLIMIT_DATA](https://developer.apple.com/forums/thread/702803), [XNU proc_rlimit.c](https://git.saurik.com/apple/xnu.git/blame/refs/heads/master:/tests/proc_rlimit.c), [darwin-kernel on maxproc](https://lists.apple.com/archives/darwin-kernel/2005/Sep/msg00065.html), [trmnl_preview 0.34.1 dependencies](https://rubygems.org/gems/trmnl_preview/versions/0.34.1/dependencies), [Debian ruby versions](https://packages.debian.org/search?keywords=ruby&searchon=names&exact=1&suite=all&section=all), [Ubuntu ruby versions](https://packages.ubuntu.com/search?keywords=ruby&searchon=names&exact=1&suite=all&section=all), [Fedora Ruby 4.0 change](https://fedoraproject.org/wiki/Changes/Ruby_4.0), [Baeldung: installing geckodriver](https://www.baeldung.com/linux/geckodriver-installation).
