# Using the library

How a program adopts the sandbox. The [README](../README.md) has a first example. [security-model.md](security-model.md) says what the sandbox guarantees, and the Go doc comments on `Spec` and `Cmd` are the field reference.

## Stage and re-exec

Both backends start this binary again to run the first stage, which sets the sandbox up before anything untrusted runs. So every program that starts sandboxes calls `sandbox.Stage` first in `main`, before flag parsing and before it starts anything else:

```go
if code, ok := sandbox.Stage(); ok {
	os.Exit(code)
}
```

`Stage` returns `ok` when this run is a stage (or a `Check` child), and `code` is the exit status to use. Otherwise it returns at once.

- **Linux.** bubblewrap runs the caller's binary, bound read-only at `/dev/sandbox-stage`, as pid 1 inside the sandbox. The stage runs the binary's package `init` code with `CAP_SYS_ADMIN` in a nested user namespace, so keep `init` functions out of the program and audit its dependencies ([open issues](security-model.md#open-issues)).
- **macOS.** The stage runs outside the profile, as the caller, and supervises `sandbox-exec`.
- **Test binaries.** A package's tests that start sandboxes need a `TestMain` that calls `Stage`.
- **The command can be the same binary.** `Spec.Command = []string{sandbox.SelfPath, "child-mode", ...}` runs this binary again inside the sandbox. `SelfPath` is `/dev/sandbox-stage` on Linux and the binary's real path on macOS, and every profile lets the command read and run exactly that file. The program calls `Stage` first in `main` there too, then handles its own mode.

## Starting a sandbox

`Command` returns a `*Cmd`. Set its fields, then `Start` and `Wait`, as with `os/exec`:

- **`Env`** is the command's whole environment. It starts empty, never the caller's. `Start` sets `HOME`, `TMPDIR` and `XDG_*` (`XDG_RUNTIME_DIR` included) to the sandbox's own over it, and on macOS `CFFIXED_USER_HOME` too. Set `Env` after reading `ListenAddrs`, which on macOS isn't known until `Command` has bound the port. A bare program name in `Spec.Command` is looked up on the `PATH` in `Env`, with no default, so with an empty `Env` a name like `sh` isn't found on either platform. `TestAPIStartErrors` checks it on Linux. Name the program by its full path, as the README example does, or set `PATH` in `Env`.
- **`Stdin`, `Stdout`, `Stderr`** are as on `os/exec`. An `*os.File` reaches the command as that descriptor, with the caveat under [Passing descriptors](#passing-descriptors).
- **`WaitDelay`** is as on `os/exec`. Set it where a process that holds the output open must not block `Wait`.
- **`ctx`** ending kills the sandbox. Cancelling it gives the command no chance to save state ([Limits](security-model.md#limits)).
- **`Run`** is the form for a process that does nothing else. It uses the caller's own streams, environment and working directory, relays `SIGTERM` and `SIGHUP`, and returns the exit status, or 128 plus the signal. It can't serve listeners.
- **`Home`** must be a real path with no link in it, and must exist. `t.TempDir()` and `os.MkdirTemp` lead through links on macOS (`/var` is a link), so resolve them with `filepath.EvalSymlinks` first.
- **Root.** `Command` refuses to run as root, and there's no way to ask for another account. A program that runs as root switches to the sandbox's uid first, in its own child, before it calls the library. The library resolves paths and writes the passwd entry in the calling process, so a uid change at exec would leave all of that done as root. On macOS `Command` also refuses a process whose real uid isn't its effective uid, such as one that dropped privileges with `seteuid` only: the command inherits both ids, and the teardown lists the sandbox's processes by effective uid. On Linux bubblewrap refuses that itself (`setuid use of bubblewrap is not supported`, seen with 0.12.0).
- **A `Cmd` is for one use.**
- **Homes.** No `Cover` may lie inside a `Home`, so each sandbox that must be kept apart from another gets a `Home` of its own.

## Spec fields on each backend

Every field is honored or harmlessly ignored on both backends. `Probe` lists the ignored ones in `Report.Ignored` and the refused ones in `Report.Unsupported`.

| Field | Linux | macOS |
|---|---|---|
| `Home`, `Write`, `Read` | Bound by descriptor, with the link rules. | `subpath` allows. Seatbelt checks the real path at open time. The same no-link rule on `Home` and `Write`. |
| `Cover` and the default covers | An empty tmpfs, or `/dev/null` for anything but a directory. | Denies after the broad allow (the last match wins). |
| `/etc` links that lead under a cover | Rebound read-only. | Rebound read-only. |
| `Kernel` | `strict`, `nested` and `open` are different filters. | All get the one profile, which is at least as strict as the request. |
| Environment | `HOME`, `TMPDIR` and `XDG_*` set by `Start`. | The same, plus `CFFIXED_USER_HOME`. |
| `Services` | Ignored. | Extra `mach-lookup` groups. |
| `Network: NetworkNone` | A network namespace with only a private loopback. | Deny network, except the `Listen` and `Loopback` ports and the unix sockets the `Spec` names. |
| `Network: NetworkHost` | The host's network. | Allow TCP and UDP out and name lookups, deny `localhost:*`. |
| `BroadLoopback` | Ignored, since loopback is private. | Opt-in: allow `localhost:*` to bind, accept and dial, TCP and UDP. |
| `Listen` | Bound inside the namespace by the stage, handed to the caller. | Bound by the caller on `127.0.0.1:0`, and the profile allows that port. |
| `Loopback` | Fixed ports in a private loopback. | Free ports chosen by the caller. Not private. |
| `Files`, `Rlimits` | Through bubblewrap, set by pid 1. | Through `sandbox-exec`, set by the stage before it execs. |
| Memory and tasks | `CgroupFD`, or `Footprint`. | `Footprint`. |
| `Hostname`, `ScratchSize` | Supported. | Ignored. `TMPDIR` is in `Home`. |
| `OwnSession` | bubblewrap's `--new-session`: pid 1, which `Pid` names, leads the session. The caller keeps the terminal's foreground. | The caller starts the stage with `setsid`, so the stage, which `Pid` names, leads the session. |

`OwnSession` is for a caller that tells sandboxes apart by a peer's session, as a bridge can on macOS, which has no pid namespace: the peer's session is `Pid`, unless the peer called `setsid`, and a session the caller can't place should be refused. It costs the command its controlling terminal. A terminal on `Stdin` still reads and writes, but `/dev/tty` doesn't open, and a Ctrl-C at the terminal goes to the caller.

A `Kernel` level is only ever raised. A level the host can't meet is an error from `Command`, never a silent fall to a weaker one. For example, 32-bit arm has no system call list, so `strict` and `nested` are refused there.

`Cmd` wraps an `exec.Cmd` instead of embedding one. The options the backend is given name descriptor numbers, so a caller that changed `ExtraFiles`, `SysProcAttr` or `Path` would break the sandbox or drop its parent-death handling. The fields it exposes are the whole need: standard streams, `Env`, cancellation through `ctx` plus `WaitDelay`, and a cgroup.

## Passing descriptors

An `*os.File` in `Spec.Files` reaches the command as descriptor 3, 4 and so on. The caller keeps them open and can close them after `Start`. Only descriptors 0 to 2 and the `Files` are open in the command. Everything else the stage inherited is marked close-on-exec. A stage that can't mark them starts nothing, and `Start` returns its error.

A descriptor grants whatever its object's owner and mode let the sandbox's uid do, whatever mode the caller opened it in and whatever the sandbox covers. On Linux the command can reopen a file through `/proc/self/fd/N` with more access: a read-only file under a covered directory can be rewritten, and an append-only log can be truncated. So where a limit matters, pass a pipe or a socket. A socket can't be reopened, and a pipe reopens only as another end of the same pipe. `Stdin`, `Stdout` and `Stderr` that are any other `io.Reader` or `io.Writer` are copied through a pipe, which has the same property.

On macOS a reopen through `/dev/fd/N` is checked by path, so it's refused under a cover, though a write to a descriptor opened for writing is allowed.

## Egress through Files and Listen

The default network is none. A command that needs to reach something gets it through the caller, which holds the policy.

**Listeners.** Programs read `HTTP_PROXY` as a TCP `host:port`, so the proxy needs an address the sandbox can reach. Ask for `Listen: 1`, build `HTTP_PROXY` and `HTTPS_PROXY` from `ListenAddrs()[0]`, and serve `Listeners()[0]` after `Start`:

- **Linux:** the stage binds `127.0.0.1:3128` (then 3129 and up) inside the sandbox's network namespace and sends the socket to the caller.
- **macOS:** the caller binds `127.0.0.1:0` in `Command`, and the profile lets the command connect to that port number.

Each listener belongs to one sandbox, so the proxy knows which policy and log to apply without trusting what the client says. The proxy itself is the caller's. It should refuse the host's own interface addresses as well as the private ranges, or a command reaches whatever the host serves on its public address ([findings](#files-a-caller-handles-for-a-run)). On macOS other local processes can connect to a `Listen` port too, so the proxy applies its rules to them as to anyone. Node's `fetch` ignores the proxy variables and fails closed.

**Loopback ports.** For a command that serves itself, such as a browser and its driver, ask for `Loopback: n` and read `LoopbackPorts()`.

- **Linux:** the ports are fixed (4444 and up) and private to the sandbox.
- **macOS:** they're chosen free, they're **not private**, and they're reachable on the LAN address ([macos.md](macos.md#the-network)). Another process could also take one between `Start` freeing it and the command binding it. The command must bind `127.0.0.1` explicitly. If a LAN peer reaching it isn't acceptable, don't use `Loopback`: bind a listener on `127.0.0.1` yourself and pass it in `Files`. That listener is on `127.0.0.1` only.

**Files.** A socket or a pipe in `Spec.Files` is a channel the command can't widen. That suits a job description in, a result out, or a connected socket to one fixed peer.

**`NetworkHost`** shares the host's network, with its loopback and abstract sockets, and has to be asked for. It can't be combined with `Listen` or `Loopback`. On macOS it allows TCP and UDP out and name lookups, and denies `localhost:*`. Under `NetworkHost` on Linux, the command reaches the caller's own loopback listeners and abstract sockets.

## Probe and Check

A program that sandboxes should tell its operator what the sandbox gives and what it can't. `Probe` and `Check` are for that, in a startup log or a `doctor` command. The library never logs.

### Probe

`Probe` tries the backend for real and returns a `Report`:

- `Backend` is `bubblewrap` or `seatbelt`.
- `Kernel` maps each level asked for to the level given, never a lower one. A level the host can't meet is absent.
- `TreeKill`, `PrivateLoopback`, `Unsupported` and `Ignored` say what the backend does and doesn't do.
- `Container` is the container the process runs in, best effort: `docker`, `podman`, `lxc`, `kubernetes`, `systemd-unit`, or empty.
- `Checks` has one finding per prerequisite, ending at the first that blocks the sandbox, with the fix in `Detail`.

An error means no sandbox can start, and `Report.Checks` says why. Refuse to run untrusted code only then. Log the report once, and print the first failed finding's `Detail`, which holds the fix.

On macOS, `Checks` also lists each gap as `NotEnforceable`.

### Check

```go
func Check(ctx context.Context, spec *Spec, want Expect) ([]Result, error)
```

`Check` runs the escape attempts in a child of the program, so the program must call `Stage` first. A `Result` has a stable `Name` such as `userns.create`, a `Status` and a `Detail` that says what was tried and what happened.

| Status | Meaning |
|---|---|
| `Pass` | The attempt failed, or the property holds. |
| `Fail` | The attempt worked. |
| `NotEnforceable` | It applies, but nothing on this platform can enforce it, such as memory on macOS. |
| `Skipped` | It doesn't apply, or there was nothing to try. |

- **`spec != nil`:** the child runs inside a sandbox built from `spec`. Call it with the `Spec` a program really builds, in its own tests, not only the library's. `spec.Command` is ignored. The `covers` results judge each covered directory by the `Spec` as the sandbox prepares it, not as given: it also has the covers for the homes and the mount table, and the files that links in `/etc` lead to under a cover (Ubuntu's `/etc/resolv.conf` leads into `/run`), with the empty directories they are mounted in. Any other entry in a cover fails.
- **`spec == nil`:** the child inherits the caller's context as it is. That's what an operator's container or systemd unit gives, so an operator who isolates untrusted code with their own boundary can see what it enforces.

`Expect` adds the program's own claims: `Unreadable` and `Unwritable` paths (each `Unreadable` path is also tried through its filesystem's snapshot directories), `Unreachable` endpoints as `tcp:127.0.0.1:8080`, `udp:host:port` or `unix:/path`, and a `Proxy` with `Allowed` and `Refused` CONNECT targets.

The generic suite tries, on both platforms: running as uid 0, supplementary groups, other processes (visible, signalable, traceable, environment readable), well-known secrets (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, `~/.gem/credentials`, `/etc/shadow`, and on macOS the Keychain files), well-known sockets (Docker, Podman, containerd, D-Bus, `SSH_AUTH_SOCK`, the systemd user manager), writes outside `Home` and `Write`, anything under a cover, direct TCP and UDP to a public address, the cloud metadata addresses, and the default gateway.

On Linux it also tries a user namespace, a tmpfs mount, `io_uring_setup`, the iptables `setsockopt` and `bpf`. It reads the capability, `no_new_privs` and seccomp state and the memory and task limits, checks whether it can make a cgroup with `memory` and `pids` (what `Delegate=yes` gives), and under `nested` it tries to undo the view. [linux.md](linux.md#probe-and-check) and [macos.md](macos.md#probe-and-check) say what differs.

A pass means one attempt failed, not that every path is closed. The checks have no side effects on the caller: signals use `kill(pid, 0)`, tracing opens `/proc/<pid>/mem` and stops nothing, writes create a file of a random name and remove it, and connections close at once.

### Why the sandbox can't start

`Probe` finds the first blocking setting, in this order, and gives the fix:

| Finding | How it's detected | Fix |
|---|---|---|
| bubblewrap missing, setuid, or older than 0.8 | `PATH`, mode bits, `--version` | The distribution's package. |
| Ubuntu's AppArmor restriction on user namespaces | `kernel.apparmor_restrict_unprivileged_userns=1`, and the trial sandbox fails | An AppArmor profile for this binary's path with a `userns` rule, which `Probe` prints, plus the commands to load it. A child profile for bubblewrap doesn't work ([linux.md](linux.md#probe-and-check)). |
| User namespaces turned off | `kernel.unprivileged_userns_clone=0` (older Debian) or `user.max_user_namespaces=0` | The sysctl. |
| Docker's or Podman's default seccomp profile | `Seccomp: 2`, a container detected, and `unshare(CLONE_NEWUSER)` returns `EPERM`. The default profile grants those calls only with `CAP_SYS_ADMIN`. | A seccomp profile that is the runtime's default plus `clone` with the namespace flags, `unshare`, `mount`, `umount2`, `pivot_root` and the new mount API. Never `seccomp=unconfined`. |
| Docker's AppArmor profile | `/proc/self/attr/current` reads `docker-default` | A profile that allows `mount`, or `--security-opt apparmor=unconfined` for this container only. |
| Masked `/proc` | Overmounts under `/proc` in the mount table. The kernel refuses a new procfs while the existing one is partly hidden. | Docker `--security-opt systempaths=unconfined`, or Podman `--security-opt unmask=ALL`. |
| A hardened systemd unit | `$INVOCATION_ID` set, the cgroup ends in `.service`, and namespaces or mounts are refused | Relax `RestrictNamespaces=`, and a `SystemCallFilter=` that lacks `@mount`, for this unit only. |
| macOS: already inside a Seatbelt profile | `sandbox-exec` with a trivial profile fails | Run outside that profile: another tool's sandbox or an App Sandbox. |

In a container, the fix relaxes the outer layer just enough for the inner one, which then applies the stricter filter and the covers to the untrusted code. This is why the sandbox can't start inside default Docker, rootless Podman or a hardened unit: all three refuse the namespace and mount calls that bubblewrap makes. The AppArmor row was verified on Ubuntu 24.04. The masked-`/proc` row and the Docker and Podman options were inferred, not run.

Container detection is best effort: `/.dockerenv`, `/run/.containerenv`, `KUBERNETES_SERVICE_HOST`, cgroup path patterns, and `systemd-detect-virt -c` when it exists.

`scripts/apparmor.sh` loads the profile for this package's own test binary. A program that adopts the library uses the profile `Probe` prints for its own path.

## Tools installed under covered paths

With the host's root as the view, anything outside the default covers is visible read-only with no setup. Linux covers `/home /root /run /tmp /var /mnt /media /dev/shm /.snapshots /sysroot`. macOS covers `/Users /Volumes /private/var /private/tmp`. So a tool installed in a system location needs nothing, and one installed under a covered path needs a `Read` entry:

| Install location | Covered? | What to do |
|---|---|---|
| `/usr/lib/...`, `/usr/share/...`, `/usr/local/*`, `/opt/*` | no | Nothing. |
| `/opt/homebrew/*`, `/usr/local/*` (Intel), `/Applications/...` on macOS | no | Nothing. |
| `/var/lib/gems/<version>` (Debian's `sudo gem install`), `/var/cache/fontconfig` | yes, `/var` | `Read` that directory. Without the fontconfig cache, every sandbox rebuilds it in its own home. |
| `~/.rbenv`, `~/.local/share/mise`, `~/.gem`, `~/.nvm`, `~/.pyenv`, `/home/linuxbrew/.linuxbrew`, `~/Applications/...` | yes, a home | `Read` the narrowest directory: the Ruby version's prefix or the gem directory for that version, never the whole `~/.gem`. |

**Never read a whole directory that holds credentials.** `~/.gem/credentials` holds the RubyGems API key, and `~/.npmrc` can hold an npm token. If a broader directory can't be avoided, add a `Cover` for the secret file inside it.

How a `Read` entry works:

- It shows a host path again, read-only, even under a covered path. On Linux it binds the path back, and inside a covered home it gets its mount point in the cover's tmpfs. On macOS it becomes a `file-read*` allow placed after the cover's deny.
- A link in it is followed only outside directories a sandbox can write.
- A path that doesn't exist is dropped quietly.
- A `Read` entry can't make a path writable. Use `Write` for that.

Derive entries, don't ask the operator for them. Resolve each tool's real path (`exec.LookPath`, then `filepath.EvalSymlinks`), and for a language runtime ask it where its libraries are (for Ruby, `gem env gempath`). Each result that lies under a covered path becomes a `Read` entry at the narrowest prefix.

**`HOME` moves.** Inside the sandbox `HOME` is the sandbox's home, not the caller's. Anything that finds itself through `$HOME` breaks: `rbenv` shims, user gem paths, `nvm`, a package manager that looks in `~/.cache`. Pass absolute paths, and set `PATH` and the runtime's own variables (`GEM_HOME`, `GEM_PATH`, `NODE_PATH` and so on) explicitly in `Env`, from what was resolved outside. A tool that caches under `$HOME` caches in the sandbox's home, so each run starts cold.

Prefer system-wide installs (`/usr/local`, `/opt`, Homebrew) in an adopter's docs, since they need no `Read` at all, and support home installs on top.

## Limits

Use what the host gives, and log once what's missing.

### Linux

**With a delegated cgroup.** A systemd unit with `Delegate=yes` owns its cgroup subtree. A user session's `user@.service` delegates `memory` and `pids` by default on current distributions (inferred). The recipe:

1. Make a child directory for the sandbox, such as `build-<id>`.
2. Write `memory.max`, `memory.swap.max`, `pids.max` and `memory.oom.group` (set to 1, so the kernel kills the group together). Leave room in `pids.max` for threads: a browser's threads count.
3. Open the directory and set `Cmd.CgroupFD` to its descriptor. The library turns it into `SysProcAttr.UseCgroupFD`, so bubblewrap starts in the cgroup. tmpfs pages are charged to it, and `memfd` and anonymous shared memory are bounded by it, which nothing else bounds.
4. After `Wait`, write 1 to `cgroup.kill`, then `rmdir` the directory.

The kernel also needs write access to the common ancestor's `cgroup.procs` to start a process in a cgroup. `TestAPICgroupFD` skips on a login session that doesn't delegate that, and `Check` has a cgroup delegation row.

**Without one.** Use `Rlimits` (`CPU`, `NOFILE`, `FSIZE`) and the `Footprint` watchdog below. Don't use `ResourceProcesses`, which counts every task of the uid, or `ResourceAddressSpace`, which breaks runtimes that reserve address space up front (a JavaScript engine's reservations, for one; inferred).

**Teardown** is complete either way: the sandbox's pid 1 dying kills the whole tree.

### macOS

- Set `CPU`, `NOFILE` and `FSIZE`, which have standard BSD semantics. `CPU` is a `SIGXCPU` that a program can ignore, and the hard limit doesn't kill a program that ignores it.
- `ResourceAddressSpace` is refused, since nothing enforces it.
- `ResourceProcesses` counts every process of the uid, the user's apps included, so don't use it.
- Memory is the `Footprint` watchdog.

### Footprint watchdog

`Cmd.Footprint` returns the memory of every process in the sandbox, on both platforms. Poll it every few hundred milliseconds, and kill the sandbox (cancel its context) past a threshold the caller picks:

```go
for range time.Tick(300 * time.Millisecond) {
	n, err := cmd.Footprint()
	if err != nil || n > limit {
		cancel()
		return
	}
}
```

- **Linux:** the sum of resident sets of the bubblewrap process's descendants, through `/proc/<pid>/statm`. A page that processes share is counted for each.
- **macOS:** `ri_phys_footprint` over every process under the sandbox's profile, wherever it has gone, plus the command's group and descendants.
- **It's a soft limit.** A fast spike can land between polls, and macOS swaps before it kills. It's still enough to stop a runaway from taking the machine.
- An error from `Footprint` means the sandbox is gone or wasn't started, so stop polling.

## What to do on ErrSurvivors

On macOS, teardown ends every process it can find under the sandbox's profile. A fork bomb, or a chain of processes that fork faster than the scan, can keep ahead of it. Teardown gives up on that after about a second, once the number of processes it finds has stopped falling, and `Wait` returns the error at once. Other processes of the same account that start and exit thousands of times a second with the CPUs busy can keep the scan from settling too, with nothing left running ([macos.md](macos.md#process-churn)). Teardown keeps trying for five seconds then, which was enough for every load measured, so the error is returned for a clean host only under a heavier one. When no scan could prove the sandbox empty in the time allowed, `Wait` and `Run` return an error that matches `sandbox.ErrSurvivors` with `errors.Is`. It wraps the command's own result, so `errors.As(err, &exitErr)` still finds the `*exec.ExitError`, and `Run` still returns the exit status. Linux never returns it.

```go
if errors.Is(err, sandbox.ErrSurvivors) {
	// Treat the host as dirty.
}
```

No method lists the survivors, so treat the host as dirty:

- **A survivor keeps what the profile gave it:** the home, the `Write` paths, the network the `Spec` allows, and the command's output. It can also read the arguments and environment of every other process of the account, as the command could.
- **Don't trust what it wrote.** A survivor can keep writing to the home and the `Write` paths after `Wait` returns.
- **Don't start a later sandbox that must be kept apart** from this one while a survivor may still be running, since it can read that sandbox's environment (the same `KERN_PROCARGS2` gap as above).
- **Set `WaitDelay`** if `Wait` itself must not block on a survivor that holds the output open.
- **Limit how long a sandbox can run.** A fork bomb only outruns the scan until it stops on its own, so a `Footprint` or wall-clock limit that cancels the context shortens it.

## Firefox

Headless Firefox runs under both backends and renders a page byte-identical to an unsandboxed render. What each needs:

### Linux

- **`Kernel: strict`** is enough. It rendered the same under `strict` and `nested`, so `nested` gains a page-rendering caller nothing.
- Headless `--screenshot` takes about 2 seconds. The PNG is byte-identical to the unsandboxed render, including inside a loopback-only network namespace.
- Firefox's own sandbox stays on. Its seccomp filters and file broker run as they do unsandboxed. Only its user-namespace layer drops out, as Mozilla bug 1756236 describes. Set `MOZ_ASSUME_USER_NS=0` to silence the probe, and `MOZ_CRASHREPORTER_DISABLE=1` is harmless.
- What `strict` refuses is harmless: the `clone(CLONE_NEWUSER)` probe, `clone3` (glibc falls back to `clone`), `quotactl`, and netlink sockets. Firefox still reports `navigator.onLine` true.
- `Start` sets `XDG_RUNTIME_DIR` to a directory of the sandbox's own. The host's `/run/user/<uid>` reached Firefox before, and dconf failed to create its directory under the read-only cover.
- A snap-packaged Firefox can't run: `snap-confine` is setuid, and `/run` and `/var` are covered. Use the distribution's own package or Mozilla's.
- Not run: geckodriver and Marionette inside the sandbox. That's TCP on loopback, which `strict` allows (inferred).

### macOS

- Use `Services: []sandbox.Service{sandbox.ServiceFirefox}` and no network. A render takes 2 to 3 seconds, and `TestFirefoxScreenshot` compares it byte for byte with an unsandboxed one.
- Set `MOZ_DISABLE_CONTENT_SANDBOX=1`, `MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1` and `MOZ_DISABLE_RDD_SANDBOX=1`. Firefox's own processes can't apply a profile of their own inside ours. Without the content switch the content process crash-loops with no output. The other two only stop crashing children.
- `Start` sets `CFFIXED_USER_HOME` to the sandbox's home. Without it, Firefox 152 to 157 hangs on the TCC-protected real `~/Library`, and later versions write into it.
- **Check that the PNG exists, not only the exit status.** A denial, such as a missing `mach-register` rule, can leave Firefox exiting 0 with no output.
- An image from the `Listen` port loads, and one from a port the sandbox wasn't given doesn't (`TestFirefoxNetwork`).
- There's no inner sandbox layer, so the Seatbelt profile is the only one. Seatbelt filters operations, not system calls.
- Firefox makes `Library/Application Support` in the home with an ACL that denies deletion. A caller that removes the home runs `chmod -RN` on it first.
- The group's `org.mozilla.machname.*` names are shared with the user's own Firefox and with other sandboxes given the group. Run untrusting Firefox sandboxes one at a time.
- Media in a page may start the GPU, utility or GMP processes, which didn't start for a plain page. Their `MOZ_DISABLE_*` switches exist and weren't needed.
- Not run: geckodriver and Marionette under the profile, web fonts and media, and windowed-mode parity.

[macos.md](macos.md#m2-headless-firefox-under-sandbox-exec) lists what the experiment measured.

## Files a caller handles for a run

The program that adopts the library handles files and addresses around each run, and gets some of them wrong in the same ways. These were found in the project the library came from. They aren't sandbox bugs, and the sandbox can't stop them:

- **A bridge sent any file a placeholder named.** An absolute path outside the scratch directory went to a tool, past a CLI confined by `--restricted`. Send only files in the scratch directory, through `os.Root`.
- **A runner's writes followed links.** `os.WriteFile` followed a link the CLI left in its scratch directory, which could have carried the next run's prompt into another thread's directory. Write through `os.Root`.
- **A model's URL reached the host's own services.** A client that refused addresses that aren't public still reached whatever the host served on its own public address. It must refuse the host's interface addresses too.
- **A root launcher followed links.** A compromised server could plant links for a root launcher's `chown` or binds to follow, which would be root on the host. A launcher works beneath a descriptor for the state directory with `openat2`, without following links.
- **One shared home carries trust forward.** A run could change what every later run trusts, such as its credentials file. Give each thread, or each party that must be kept apart, a home of its own.
- **A shell tool's commands could write the files the next run's CLI loads.** Give the commands a `work` directory beside those files.
- **A uid fixed per thread can't last.** Threads have no limit and a range does. A uid belongs to one running child.
- **`NetworkHost` reaches loopback**, where the caller's own listeners are, past its tool policy and audit log. The default is `NetworkNone` for this reason. Keeping parties apart under `NetworkHost` leaves loopback and abstract sockets shared between them.
- **A proxy the sandbox reaches must refuse the host's own public address.**
- **A router's public address** that forwards back to the host isn't refused by a client that only refuses the host's interface addresses.
