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
2. **Backends differ, and that's fine.** macOS has no pid namespace, no cgroups and coarser kernel filtering than Linux. It still gets a deny-by-default file and network view, which is most of what protects trmnl's assets. The library reports what each backend gives (`Probe`), and the caller logs it once at startup. Missing pieces are reported, not refused.
3. **Zero config.** trmnl finds its tools at startup and works out from where they're installed what the sandbox needs to show (section 3.4). A brew, rbenv or apt user configures nothing.
4. **Refuse only when there's no sandbox at all**, as legwork's floor does. On macOS `sandbox-exec` is always present. On Linux the fix is `apt install bubblewrap`, plus one AppArmor command on Ubuntu, and trmnl's message prints it. `--no-sandbox` stays for development. It never refuses, and it logs what the checks find (section 5).
5. **The operator's own boundary is a sandbox too.** Containers or systemd units set up as section 5 describes do the same job, and the project then runs untrusted code without the library's sandbox. The library's part is to report honestly what that boundary enforces (section 6).

What the library needs, beyond what legwork has:
- `Command`, an entry point a server can call
- `Probe`, which reports what the backend gives
- a network namespace with listeners handed to the parent
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
| HOME, TMPDIR, XDG_* set to the sandbox's own | `commandEnv` | Generic and portable. Make these defaults the caller can override. |
| `--legwork-sandbox-stage`, `--legwork-sandbox-reaper`, `/dev/legwork-sandbox` | `sandbox_linux.go:28-30` | Rename |
| `--hostname legwork`, fallback account `legwork` | `sandbox_linux.go:357, 547` | `Spec.Hostname` (Linux only); fallback becomes `sandbox` |
| No `--new-session` | `sandbox_linux.go` | Driven by legwork's hub check, but a correct default: the filter refuses `TIOCSTI`, and a caller that wants a session sets `Setsid`. |
| `Run`: own stdio, `os.Environ()`, `os.Getwd()`, process-wide `signal.Notify`, `Pdeathsig` | `Run` | Fine in a dedicated process. Wrong inside a server. Hence `Command`. |
| Reaper starts the command with only fds 0-2 | `reaperStage` | Gap. one-binary's children receive their job on an inherited socketpair. |
| `Run`/`Stage` return `ErrUnsupported` off Linux | `sandbox_other.go` | Replaced by the Seatbelt backend |
| `RegisterFlags` (Go `flag`) | `flags.go` | Generic. legwork's pflag wrapper stays in legwork. |
| `TestBridgePeer` (uses `internal/peer`) | test | Stays in legwork. The library keeps a version without `peer`. |
| All other tests | tests | Move. They hold up the findings. |

### Where each sandbox.md guarantee lives after the split

| Guarantee | Library | legwork config/code |
|---|---|---|
| bwrap from the distro, setuid refused | ✓ | |
| Options on a descriptor, not in pid 1's argv | ✓ | |
| Bind sources by fd with `RESOLVE_NO_SYMLINKS`; a cover that became a link aborts | ✓ | |
| User/pid/ipc/uts namespaces, uid mapped to itself, `--die-with-parent`, `--as-pid-1` | ✓ | |
| Read-only root; covers (tmpfs, or `/dev/null` for non-dirs); default covers; people's homes; the account's own home | ✓ | |
| Legwork's config, state, and other sandboxes' directories covered | | ✓ (`Spec.Cover` from config) |
| Mount-table covers (`.zfs`, other mounts of a covered fs) | ✓ | |
| `/etc` links into covered dirs rebound | ✓ | |
| Path and link rules: no link in home or `write`; a link followed only outside writable dirs; a missing cover inside a writable dir aborts; no mount inside a writable dir; cwd must be shown | ✓ | passes real paths |
| A home per thread; `work` beside the CLI home; `read`/`write` refused if they overlap state | | ✓ |
| Scratch tmpfs 1 GiB | ✓ default, `ScratchSize` | |
| One-entry passwd/group | ✓ | |
| First stage: private mounts, caps dropped on the exec'ing thread, no_new_privs, pid 1 re-exec, undumpable | ✓ | |
| Filter: allowlist, arg checks, ENOSYS default, foreign ABIs refused, low-32-bit checks, TSYNC result check | ✓ | |
| Kernel level per child | | ✓ (`kernel:`) |
| Caller's session kept, `TIOCSTI`/`TIOCLINUX` refused | ✓ | relies on it |
| Stage runs the caller binary's `init` with `CAP_SYS_ADMIN` (nested userns) | documented | ✓ "no `init`" rule from one-binary's Code layout |
| Network namespace, proxy listener handed out | ✓ mechanism (new) | ✓ proxy, allowlist, logging |
| Bridge check by pid namespace (`--info-fd`), by session on macOS | ✓ exposes the pid (new) | ✓ the check |
| Root launcher, uid per child, nftables for `direct`, cgroups | caller (`Cmd.SysProcAttr`) | ✓ |
| Seatbelt profile: deny default, covers as denies after the broad allow, `mcp.sock` by path, proxy port, mach services, no LaunchServices | ✓ (new backend) | ✓ which paths |
| Startup probe and refusal when there's no sandbox (one-binary "Floor") | ✓ `Probe()`, naming the blocking setting (6.3) | ✓ the refusal, the log, `--no-sandbox` |
| Escape tests (one-binary "Checks"), run in CI and in `doctor` | ✓ `Check()`, the generic checks (6.2) | ✓ its `Expect` values, the rerun per relaxation, the rendering |
| `os.Root` for files in sandbox-writable dirs; `guard` refusing host addresses | | ✓ (not sandbox code) |
| Supplementary groups, host secrets readable by mode, snapshot dirs | ✓ generic checks in `Check()` | ✓ `legwork doctor` shows them |

No guarantee is lost. Everything enforced in `internal/sandbox` moves unchanged.

## 3. trmnl-byos-go as one binary

This section is the in-place mode. Compose stays a supported deployment in operator mode (5.1).

### 3.1 What replaces each piece of the compose split

| Today (read) | One binary, Linux | One binary, macOS |
|---|---|---|
| server | `trmnl-byos serve` under systemd or run directly | `serve` under launchd or run directly |
| proxy (`renderproxy`, TCP forward to the renderer) | `renderproxy` inside `serve`, one listener per build | same |
| renderer (shim, Xvfb, separate uid) | a sandbox per build. The shim becomes a `render-child` subcommand run inside it. Firefox runs headless. | same, via Seatbelt |
| network with no route but the proxy | loopback-only network namespace with the listener inside | profile allows only the build's proxy port and its declared loopback ports |
| dropped capabilities, no-new-privileges | first stage drops caps, no_new_privs, seccomp | deny-default profile, no LaunchServices |
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
    - It starts bubblewrap there with `SysProcAttr.UseCgroupFD`. tmpfs pages are charged to it.
    - Afterwards: `cgroup.kill`, then `rmdir`.
  - Without one, rlimits (`CPU`, `NOFILE`, `FSIZE`) and the footprint watchdog below. Don't use `RLIMIT_NPROC`, which counts every task of the uid, or `RLIMIT_AS`, which breaks SpiderMonkey's reservations (inferred).
  - Teardown is complete either way: the sandbox's pid 1 dying kills the whole tree.
- **macOS** (web sources, nothing run).
  - No cgroups, no pid namespace. `RLIMIT_AS` shares its number with `RLIMIT_RSS` in XNU and is reported not to be enforced. `RLIMIT_DATA` rejects values below about 418 GB on Apple Silicon. `RLIMIT_NPROC` counts every process of the uid, the user's apps included. So set `CPU`, `NOFILE` and `FSIZE`, which have standard BSD semantics (inferred).
  - Memory: the watchdog.
  - Teardown: start the build in its own process group and SIGKILL the group. A process that calls `setsid` escapes. It keeps its profile, which names only its own build dir, deleted by then, and its own proxy port, closed by then. So it has no files and no network, and `RLIMIT_CPU` ends it.
- **Footprint watchdog (both, when there's no cgroup).** `serve` polls the build's processes every few hundred ms and kills the build past a threshold. On Linux that's the process group via `/proc/<pid>/status`. On macOS it's `proc_listpgrppids` plus `proc_pid_rusage` `ri_phys_footprint`. It's a soft limit: a fast spike can land between polls, and macOS swaps before it kills. It's still enough to stop a runaway recipe from taking the machine. The library offers `Cmd.Footprint()`, and the threshold is trmnl's.

### 3.6 Firefox under each backend

- **Linux, `strict`.**
  - Firefox's own sandbox uses seccomp-bpf with a file broker, plus user namespaces and `chroot` when its probe can create them. When the probe fails it keeps seccomp and drops the rest (Mozilla bug 1756236, SUMO 1451388). Flatpak, which is Firefox under bubblewrap with an outer filter that blocks userns, runs that way (bug 1884347). `MOZ_ASSUME_USER_NS=0` skips the probe.
  - Filters stack, and the kernel takes the most restrictive action, so Firefox's `SECCOMP_RET_TRAP` still reaches its broker. It needs `seccomp` and no_new_privs, which `strict` gives (read).
  - `nested` would open user namespaces and mounts to the whole tree. That gains trmnl nothing, since a recipe already runs arbitrary code outside any Firefox content process.
  - Calls `strict` refuses, to confirm with one strace run (inferred): netlink (if Firefox then reports offline, set `network.manage-offline-status=false` through the profile prefs trmnlp hands geckodriver), and `ptrace`/`process_vm_readv` (crash reporter only, so `MOZ_CRASHREPORTER_DISABLE=1`).
- **macOS, Seatbelt.**
  - A process inside a profile can't apply another one, so Firefox's child processes fail when they call `sandbox_init` (bug 1417005). On release builds the pref `security.sandbox.content.level=0` is raised back to 1. But `MOZ_DISABLE_CONTENT_SANDBOX` returns level 0 before that clamp, with no platform guard (read: `SandboxSettings.cpp`). `MOZ_DISABLE_GPU_SANDBOX` is in the same file. The GMP, RDD, socket and utility processes are sandboxed elsewhere, and their switches are unverified. Headless with no media may never start some of them.
  - The cost compared with Linux: Firefox has no inner layer, so our profile is the only one. Seatbelt filters operations (files, network, Mach services, IOKit), not system calls. For trmnl's assets that changes nothing. For defense in depth, the profile should deny `iokit-open` beyond what headless Firefox needs and keep Mach services minimal.
  - The services list comes from the deny log (`log stream --predicate 'sender == "Sandbox"'`) on a real build. Likely: fonts (CoreText), Directory Services, SystemConfiguration (inferred).

## 4. Proposed API

One package, `github.com/die-net/sandbox`. Backends: Linux (bubblewrap) and darwin (Seatbelt via `/usr/bin/sandbox-exec`, since legwork builds with `CGO_ENABLED=0`). Other platforms return `ErrUnsupported`. Dependencies stay `x/sys` and `x/net/bpf`.

### 4.1 Types

```go
type Spec struct {
    Command []string
    Env     []string     // nil: os.Environ(). HOME, TMPDIR, XDG_* default to the sandbox's own where unset
    Home    string       // writable; real path, no links
    Dir     string       // "" means Home
    Write, Read, Cover []string
    Kernel   Kernel      // KernelStrict (default), KernelNested, KernelOpen
    Services []Service   // reviewed macOS Mach-service groups, e.g. ServiceFonts; no-op on Linux
    Network  Network     // NetworkNone (default for trmnl), NetworkHost
    Listen   int         // proxy listeners the parent serves (4.3)
    Loopback int         // loopback ports the sandbox may bind and dial itself (4.3)
    Files    []*os.File  // fds 3, 4, ... in the command
    Rlimits  []Rlimit
    Hostname    string   // Linux only
    ScratchSize int64    // Linux only: each private tmpfs; 0 means 1 GiB
}

func Probe() (Report, error) // tries the backend; an error means no sandbox at all
type Report struct {
    Backend         string             // "bubblewrap" or "seatbelt"
    Kernel          map[Kernel]Kernel  // effective level per requested one (macOS: all strict)
    TreeKill        bool               // killing the sandbox kills every descendant
    PrivateLoopback bool               // loopback and abstract sockets private to the sandbox
    Ignored         []string           // Spec fields this backend ignores, e.g. "Hostname"
    Container       string             // best effort: "docker", "podman", "lxc", "kubernetes", "systemd-unit", ""
    Checks          []Result           // each prerequisite, and what blocks it (6.3)
}

func Stage() (code int, ok bool) // first in main of any binary that starts sandboxes
func Command(ctx context.Context, spec Spec) (*Cmd, error)
type Cmd struct{ *exec.Cmd } // caller may set Stdin/Stdout/Stderr, SysProcAttr, Cancel, append to Env
func (c *Cmd) ListenAddrs() []string     // known after Command, so Env can carry HTTP_PROXY
func (c *Cmd) LoopbackPorts() []int      // likewise, for geckodriver and Marionette
func (c *Cmd) Start() error
func (c *Cmd) Wait() error
func (c *Cmd) Listeners() []net.Listener // after Start, in order; the caller serves them
func (c *Cmd) Pid() int                  // Linux: host pid of pid 1. macOS: the top process
func (c *Cmd) Footprint() (bytes int64, err error) // for a watchdog when there's no cgroup

func Run(ctx context.Context, spec Spec) (int, error) // dedicated-process form, as legwork sandbox uses
func (s *Spec) RegisterFlags(fs *flag.FlagSet)
const SelfPath = ... // this binary as the command names it: /dev/sandbox-stage on Linux, its real path on macOS
```

- Every field is honored or harmlessly ignored on both backends. Ignored fields are listed in `Report`, and a stricter mapping (`nested` to `strict` on macOS) shows in `Report.Kernel`. The caller logs the report once at startup, and the library never logs.
- `Command` returns an `exec.Cmd`, so process groups, sessions, cgroups and cancellation stay with the caller.
- `Services` is the one knob that only means something on one backend. A browser needs Mach services legwork's CLIs don't, so it's a list of library-defined, reviewed groups, not free-form names. Adding a group is a reviewed library change, as sandbox.md requires for a system call.

### 4.2 How `Spec` maps onto each backend

| Field | Linux (bubblewrap) | macOS (Seatbelt, per one-binary) |
|---|---|---|
| `Home`, `Write`, `Read` | binds by fd, link rules | `subpath` allows. Seatbelt checks the real path at access time (inferred). Keep the no-link rule on home and write paths. |
| `Cover` and default covers | tmpfs or `/dev/null` | denies after the broad allow (last match wins) |
| `/etc` link targets under covers | rebound read-only | allowed read-only |
| `Kernel` | strict, nested and open are different filters | all strict |
| `Services` | ignored | extra `mach-lookup` groups |
| `Network: NetworkNone` | network namespace, loopback only | deny network except the ports below |
| `Network: NetworkHost` | host network | allow outbound, deny `localhost` |
| `Listen` | bound inside the namespace by the stage, handed to the parent | bound by the parent on `127.0.0.1:0`; the profile allows that port |
| `Loopback` | private loopback; fixed ports returned | allocated by the parent; the profile allows bind and connect on exactly those |
| `Files`, `Rlimits` | through bubblewrap; set by pid 1 | through `sandbox-exec`; set by the stage before it execs |
| Memory, tasks | caller's cgroup, or `Footprint` | `Footprint` |
| Teardown | pid 1 dies, all die | process group; `setsid` escapes |
| `TIOCSTI` | filter refuses | open (trmnl runs with no terminal; it matters to legwork) |
| `Hostname`, `ScratchSize` | supported | ignored; `TMPDIR` is in `Home` |

### 4.3 Egress brokered by the parent

Programs read `HTTP_PROXY` as a TCP `host:port`, so the proxy needs a TCP address the sandbox can reach. The interface is the same on both backends: ask for `Listen: 1`, build `HTTP_PROXY` from `ListenAddrs()[0]`, and serve `Listeners()[0]` after `Start`. Each listener belongs to one build, so the proxy knows which policy and log to use without trusting the client. That also gives trmnl the per-recipe egress record its design.md lists as not built.

- **Linux:** the stage binds `127.0.0.1:3128` inside the build's namespace and sends the socket to the parent.
- **macOS:** the parent binds `127.0.0.1:0` and the profile allows that port. Other local processes can connect to it too. They're outside the threat model, and the proxy applies the same public-only rules to them.

`Loopback` is for WebDriver. On Linux any port works, since loopback is private. On macOS a profile that allowed all of `localhost` would expose `serve`'s listeners and other local services. So the parent allocates two ports, and trmnlp starts geckodriver on `LoopbackPorts()[0]` with `--marionette-port LoopbackPorts()[1]`. That's a small trmnlp change, needed on macOS only.

Until trmnlp has that change, the profile falls back to allowing `localhost` broadly. That alone would let a recipe reach `serve`'s API on loopback, which 5.1 counts as no boundary. So the fallback uses both options:

- **(a) Deny `serve`'s ports after the broad allow.**
  - The profile writes `(allow network-outbound (remote ip "localhost:*"))`, then one `(deny network-outbound (remote ip "localhost:<port>"))` for each port `serve` listens on. Seatbelt applies the last match, and `serve` knows its ports before any build starts.
  - one-binary.md:81 confirms only that a bare `localhost` deny overrides a plain `(allow network-outbound)`, and that a deny after `(remote ip "*:*")` is ignored. A port deny after a `localhost:*` allow is untried.
  - So it's the default only if the Seatbelt phase shows macOS honors it, for both `127.0.0.1` and `::1`.
- **(b) Nothing of `serve`'s on loopback.**
  - Under the fallback, `serve` binds its HTTP listener to its non-loopback addresses instead of the wildcard, or to a unix socket for local admin, as legwork's `web.sock`. The profile allows only `localhost`, so those addresses are denied by default.
  - It needs no untested Seatbelt form, but it changes where the admin UI is reached, so it's the backstop for when (a) doesn't hold.
- **The check either way.** Each start runs `Check` inside a build sandbox with `serve`'s API addresses in `Unreachable` (6.2). If one is reachable, that's the no-boundary floor: renders refuse, and the message names the fix.

What the fallback still leaves open, reported as `PrivateLoopback: false` with a startup warning:
- the user's other local services on loopback (databases, dev servers, other apps' local APIs)
- with concurrency above 1 (trmnl's default is 1, read: `cmd/trmnl-render`), other builds' proxy and WebDriver ports, since a running profile can't name ports allocated after it.

That's weaker than Linux, but working, in line with principle 1.

The proxy is the caller's: `renderproxy` with the `guard` dialer. legwork's planned proxy has the same shape. A shared egress package is the likely next extraction, separate from this module. `Network`, `Listen` and `Loopback` stay a sketch until the Linux namespace is built. Go fields are additive, so nothing breaks when they're added.

### 4.4 Re-running its own binary, and passing descriptors

- **Linux.**
  - bubblewrap execs the caller's binary, bound at `/dev/sandbox-stage`, as pid 1. Every binary that starts sandboxes calls `sandbox.Stage()` first in `main`. The stage runs the binary's package `init` code with `CAP_SYS_ADMIN` in a nested userns. one-binary's "no `init` function" rule keeps that acceptable, and trmnl-byos adopts it.
  - A control socketpair, passed through bubblewrap, carries settings in, and listeners, the pid and setup errors out. That replaces argv and ends the exit-125 ambiguity. It depends on bubblewrap passing unnamed inherited descriptors through, which I inferred from Flatpak (risk 1).
  - `Files` are numbered from 3, and the stage `close_range`s above them.
- **macOS.** The same `Stage()` call runs outside the profile. It sets rlimits and the process group, closes stray descriptors, and execs `/usr/bin/sandbox-exec -f /dev/fd/N -- command`, so the profile isn't in argv. The parent binds the listeners, so there's no control socket.
- **On both,** the command can be the same binary (`[SelfPath, "render-child", ...]`), as one-binary's `turn` and `stdio` children are.

## 5. Isolation modes

| Mode | What isolates untrusted code | Who picks it |
|---|---|---|
| In-place (default) | the library, one sandbox per build or child | anyone running the binary plus host packages |
| Operator | the operator's containers (Compose, Podman) or systemd units | operators who already run containers, or want systemd's controls |
| Both | the library's sandbox inside the operator's boundary | the strongest setup, once the outer runtime allows namespaces (6.3) |
| `--no-sandbox` | nothing | development |

In operator mode the project starts untrusted code without the library's sandbox, because the operator's boundary does that job. The library's part is `Check` against the process as it is (6.1), run by the project at startup and in `doctor`, so the operator sees what the boundary enforces and what it doesn't.

In the in-place, operator and both modes the floor is the same: refuse only when there's no boundary at all. In operator mode, that's when the checks show untrusted code can read the server's secrets or reach its API. Everything short of that is reported, not refused.

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
- `Unreachable`: every address `serve` listens on, plus `tcp:127.0.0.1:<port>` and `tcp:[::1]:<port>` for each of its ports. In-place mode runs this inside a build sandbox at each start, which is what catches a macOS loopback fallback that doesn't hold (4.3).
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

1. Seed this repo from legwork's history (`git filter-repo --path internal/sandbox --path cmd/legwork-sandbox --path docs/sandbox.md`, 10 commits).
2. Library: rename the markers and constants. Add `Command`, `Probe`, the control socket, `Files`, `Rlimits` and `Pid`, and make `Run` a wrapper. Move the tests and the CI job (Ubuntu 24.04, apt bubblewrap, `apparmor_restrict_unprivileged_userns=0`).
3. Split the docs. The library gets the threat model, mechanism, kernel findings, "Tried and dropped", "Limits", and "How it is tested". legwork's `sandbox.md` keeps its policy and its own findings.
4. legwork imports the module. `cli.SandboxSpec` sets `Hostname: "legwork"` and `Dir` from `os.Getwd()`. `TestBridgePeer` stays. Delete `internal/sandbox`.
5. legwork's phase 4 builds `Network`/`Listen`. Phase 5 uses `Files`, `Pid` and `Command`. Phase 6 (Seatbelt) is built in the library.

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
     - `Network: NetworkNone`, `Listen: 1`, `Loopback: 2`
     - `Services: [fonts, ...]`
     - `Env`: `buildEnv` plus `HTTP(S)_PROXY`, the resolved `PATH`/`GEM_HOME`/`GEM_PATH`, `MOZ_HEADLESS=1`, `MOZ_CRASHREPORTER_DISABLE=1`, `MOZ_ASSUME_USER_NS=0` on Linux, `MOZ_DISABLE_CONTENT_SANDBOX=1` on macOS, and the `FIELD_*` values
     - `Rlimits`: `CPU`, `NOFILE`, `FSIZE`
   - It sets `CgroupFD` when a cgroup is delegated, or `Setpgid` and the watchdog otherwise. Then it serves `renderproxy` on the listener, waits, and reads the outputs through `os.Root`.
5. Ship a systemd unit with `Delegate=yes`, a launchd plist, and install docs per platform (3.3).
6. Keep `compose.yaml` as the operator-mode reference (5.1). Add a `--isolation=operator` flag (name to pick) to the render side. Then it runs `Check(ctx, nil, want)` at startup, reports the results to the server, and refuses only on the no-boundary findings in 5.1.

## 8. Sequencing

Settle the API against both backends now. Build Linux first.

1. **Now:** agree on `Spec`, `Report` and the mapping in 4.2, so macOS lands without breaking changes.
2. **Linux extraction** (mostly moving tested code), plus `Command`, `Probe`, `Files`, `Rlimits`, `Pid`, `Footprint`, and `Check` with its generic checks (most exist as tests in `internal/sandbox`). legwork switches over.
   - trmnl can use `Check(ctx, nil, want)` in today's compose render container right away, before it has an in-place sandbox, because the as-is checks need no namespace code.
3. **Linux network** (`Network`, `Listen`, `Loopback`), with legwork's phase 4.
4. **trmnl on Linux:** one binary, `renderer check`, headless, cgroup or watchdog. One strace comparison run settles Firefox under `strict`.
5. **Seatbelt backend** (legwork's phase 6, built here): profile generation, the stage, `Services` groups, the deny-log runs with both legwork CLIs and trmnl's Firefox, and a hole-finding review of the profile.
6. **trmnl on macOS.**

Why this order: the Linux backend has a review record and tests behind it, and it's mostly a move. Seatbelt is new code in an undocumented profile language, and its findings will come from running it. trmnl's macOS users can run the server meanwhile.

## 9. Risks and open questions, ranked

1. **Descriptor passthrough via bubblewrap** (Linux control socket, listeners, `Files`). Inferred, not checked. Fallback: `--info-fd`/`--sync-fd` plus a socket bound into `/dev`.
2. **The network namespace and listener handoff aren't built.** They're trmnl's one hard prerequisite on Linux.
3. **Firefox under each backend.** Linux: netlink and other refused calls. macOS: the switches for Firefox's non-content processes, and the Mach and IOKit allowances. One strace run and one deny-log run settle them.
4. **Install friction that pushes users to `--no-sandbox`.** Ubuntu's AppArmor step; Ruby 4 and geckodriver outside the Debian/Ubuntu archives; the snap Firefox on Ubuntu. `renderer check` should name the exact fix for each, and the docs should lead with the shortest path per platform.
5. **Operator mode set up wrong**, such as the data volume or `TRMNL_SECRET_KEY` on the render side, or a shared container with the sandbox off. The as-is checks catch the common cases. A pass is still only a failed attempt, not proof.
6. **The outer-runtime fixes in 6.3 are partly inferred**: the AppArmor and masked-`/proc` rows, and which `docker`/`podman` options apply. Run bubblewrap in default Docker, rootless Podman and a hardened systemd unit before writing the messages.
7. **A derived `Read` that's too broad** could show a credential (`~/.gem/credentials`, an npm token in `~/.npmrc`). Rule: narrowest versioned prefix only, plus explicit covers for known secret files when a broader directory can't be avoided.
8. **Selenium Manager** downloading drivers or browsers per build if trmnl's paths and `SE_OFFLINE` aren't honored. Check in the first Linux run.
9. **trmnlp changes:** headless, if `MOZ_HEADLESS` isn't enough, and the WebDriver ports on macOS. Headless doesn't block, since the env var covers it. Ports don't block either, but the fallback (4.3) is weaker. It rests on a port deny after a broad `localhost` allow, which is untried, with `serve` moved off loopback as the backstop. It also leaves the user's other local services reachable. The startup check guards `serve`'s API.
10. **Render drift** across host versions and fonts. Mitigations in 3.3.
11. **Memory without a cgroup** is a polling watchdog: soft, but working.
12. **macOS teardown gap:** an orphaned `setsid` process survives without files or network until `RLIMIT_CPU` ends it. A uid per sandbox (legwork's root launcher) closes it fully.
13. **Stage runs the caller's `init` with `CAP_SYS_ADMIN`** on Linux. Audit trmnl-byos's dependencies.
14. **Fix coordination.** Tag releases, and keep the moby profile pin and the Seatbelt service groups in one place.

Sources: [Mozilla bug 1756236](https://bugzilla.mozilla.org/show_bug.cgi?id=1756236), [Mozilla bug 1884347](https://bugzilla.mozilla.org/show_bug.cgi?id=1884347), [Mozilla bug 1417005](https://bugzilla.mozilla.org/show_bug.cgi?id=1417005), [SUMO 1451388](https://support.mozilla.com/fa/questions/1451388), [Firefox SandboxInfo.cpp](https://sources.debian.org/src/firefox/148.0-1/security/sandbox/linux/SandboxInfo.cpp), [Firefox SandboxSettings.cpp](https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/sandbox/common/SandboxSettings.cpp), [Mozilla wiki: OS X sandbox rule set](https://wiki.mozilla.org/Sandbox/OS_X_Rule_Set), [Apple forums: RLIMIT_AS](https://developer.apple.com/forums/thread/856401), [Apple forums: RLIMIT_DATA](https://developer.apple.com/forums/thread/702803), [XNU proc_rlimit.c](https://git.saurik.com/apple/xnu.git/blame/refs/heads/master:/tests/proc_rlimit.c), [darwin-kernel on maxproc](https://lists.apple.com/archives/darwin-kernel/2005/Sep/msg00065.html), [trmnl_preview 0.34.1 dependencies](https://rubygems.org/gems/trmnl_preview/versions/0.34.1/dependencies), [Debian ruby versions](https://packages.debian.org/search?keywords=ruby&searchon=names&exact=1&suite=all&section=all), [Ubuntu ruby versions](https://packages.ubuntu.com/search?keywords=ruby&searchon=names&exact=1&suite=all&section=all), [Fedora Ruby 4.0 change](https://fedoraproject.org/wiki/Changes/Ruby_4.0), [Baeldung: installing geckodriver](https://www.baeldung.com/linux/geckodriver-installation).
