# Sandbox

This module (`github.com/die-net/sandbox`) runs a command in a sandbox, in place, without root. On Linux it uses bubblewrap, a seccomp filter and namespaces. On macOS it uses a Seatbelt profile that `/usr/bin/sandbox-exec` applies, with no VM. It was extracted from the legwork project, whose sandbox it began as, and [design.md](design.md) says how it is meant to be used by the projects that adopt it.

This doc says how the sandbox holds, every way past it that has been found and what stops each one now, what was tried and dropped, and what it does not do. Anyone changing the sandbox should read the findings first: each is an attack that worked once.

## What it protects

The command, everything it runs, and every server it starts are untrusted. They run as the caller's own uid, so without a sandbox they could read and change anything the caller can. A sandbox keeps the caller's data confidential: its config, database, and credentials, other sandboxes' files, and people's homes. It also keeps the sandbox from reaching the caller's processes.

A uid boundary gives some things for free that a sandbox has to give instead. File modes and the kernel's rules on signals and tracing are two. The biggest is that the uid is the credential every local service checks through `SO_PEERCRED`, such as the account's systemd user manager, ssh-agent, and gpg-agent, which accept any process of the account. So a sandbox must not reach their sockets at all. The same goes for the kernel's per-uid state: the caller's session keyring, and the process group the caller's own processes share.

It makes no claim to hide the host or its owner from what runs inside. A sandbox can read what any account on the host can, sees the machine id, and under `NetworkHost` its traffic leaves from the host's addresses. Secrets of the host's own that file modes leave readable are the operator's to fix, and `Check` warns about the usual ones, as under [Limits](#limits).

## How it works on Linux

### bubblewrap

bubblewrap builds the sandbox. It is the setup Flatpak runs every app through, so a reviewer can rely on its record and read only what this package hands it, where a builder of our own would have to be reviewed whole. The package needs 0.8.0 or later, from the distribution, and refuses a setuid copy, since bubblewrap's serious past flaws were in its setuid mode. It has been tested on 0.12.0.

`Command` works out the view and `Start` hands bubblewrap every option on a descriptor with `--args`, so pid 1's command line, which any process inside can read, does not list them. Each bind source is opened by the caller's process and passed as a descriptor with `--bind-fd` or `--ro-bind-fd`, and the account's `passwd` and `group` entries with `--ro-bind-data`. bubblewrap makes new user, mount, pid, IPC, and UTS namespaces, and a network namespace unless `NetworkHost` is asked for. It maps the account's uid and gid to the same ids inside, and closes every descriptor it was handed before it starts the command.

`Command` refuses to run as root. It opens paths and writes the sandbox's `passwd` in the calling process, so a caller that runs as root must switch to the sandbox's uid first.

Three options are left out on purpose. There is no `--new-session`, so the command stays in its caller's session, which a caller may check a bridge by, and the filter refuses `TIOCSTI` instead. There is no `--die-with-parent`, as [the lifeline](#the-lifeline) explains. And there is no `--seccomp`, since the filter refuses calls the first stage makes.

### The view

bubblewrap makes these mounts parent first, so a path bound back under a cover gets its mount point in the cover:

- the host's root, bound recursively and read-only;
- an empty tmpfs over each covered directory, made read-only once the binds inside it are in place, and `/dev/null` over any other covered path, such as a file or a socket, which nothing can read from or connect to;
- the sandbox's own home and `Write` paths, read-write;
- its `Read` paths, and the regular files that links in the host's `/etc` lead to under a default cover, such as Ubuntu's `/etc/resolv.conf`, read-only;
- a fresh `/proc`, and bubblewrap's own `/dev` with a new `devpts` instance, made read-only once `/dev/shm` and the stage's binary are mounted in it;
- a writable tmpfs for each of `/tmp`, `/var/tmp`, and `/dev/shm`, each holding at most `Spec.ScratchSize` bytes, 1 GiB by default, set with bubblewrap's `--size`;
- a `passwd` and `group` with one entry for the sandbox's uid and gid, whose home is its own directory;
- this binary, read-only at `/dev/sandbox-stage`, for the first stage.

Every tmpfs the sandbox can write has a size. The device nodes in `/dev` still work: `null`, `zero`, `full`, `random`, `urandom`, `tty`, `ptmx` with `/dev/pts`, and the `/dev/fd` and `/dev/std*` links. Memory that is not a file is outside the limit. `memfd_create` and anonymous shared memory count against no tmpfs, so only a cgroup's `memory.max` bounds them. A caller that needs that limit delegates a cgroup and passes it as `Cmd.CgroupFD`.

The covered paths are:

- every path the caller names in `Spec.Cover`;
- people's homes: the account's own, each home in `/etc/passwd` that its account owns, and the whole directory where two or more such homes sit side by side, which also hides homes that `/etc/passwd` does not list;
- `/home`, `/root`, `/run`, `/tmp`, `/var`, `/mnt`, `/media`, `/dev/shm`, snapper's `/.snapshots`, and an ostree host's `/sysroot`;
- from the host's mount table, every ZFS dataset's `.zfs` directory, and any other mount of a filesystem that shows a covered path somewhere else, such as a bind mount.

A cover inside another is left out when nothing bound between them would show it, and so is a cover at the same path as a bind, which shows that path whole.

The root is bound whole, rather than a list of what programs need, because a list is what breaks npx, uvx, and toolchains under `/opt`, `/usr/local`, or `/nix`. That is safe because file modes still apply inside, and the sandbox's uid owns nothing outside its own directories and the covered ones. It holds only while the account has no supplementary groups, since an unprivileged user namespace keeps them, and `Check` warns about any.

### Paths and links

A sandbox's home and `Write` paths are untrusted: an earlier run, or another sandbox that shares the directory, may have changed what is in them. So `Command` and `Start` resolve every path themselves before bubblewrap starts:

- A home or `Write` path must have no link in it at all, since a sandbox that can write a directory on the way could have planted it. That refuses a link the operator made too, such as an ostree host's `/home`, so the caller has to pass the real path, and must not resolve the path itself either.
- Any other path is followed through a link only where the link lies outside every directory the sandbox can write.
- The working directory is resolved the same way, and must be the home, a `Write` or `Read` path, or a path no cover hides, so a sandbox never starts in an empty cover.
- A covered path inside a writable directory that has gone missing stops the sandbox from starting, since a sandbox could have moved it away to uncover what it hid.
- No mount may lie inside the home or a `Write` path at all, so every mount point is inside a tmpfs bubblewrap made or a read-only host path, never content a sandbox wrote.
- Each bind source is opened with `openat2` and `RESOLVE_NO_SYMLINKS` and passed as a descriptor, and a cover that has become a link since it was resolved stops the sandbox, so nothing swapped in between the check and the mount can redirect it.

### The first stage

bubblewrap does not start the command itself. With `--as-pid-1`, it starts this binary again inside as pid 1, holding `CAP_SYS_ADMIN` and `CAP_SETPCAP` from `--cap-add`, and that first stage runs before anything untrusted does. Every program that starts sandboxes calls `Stage` first in `main`, which finds it. The stage:

1. Copies the view into a mount namespace of its own and makes every mount in it private. bubblewrap leaves the view a slave of the host's mounts, so a mount made on the host later would appear inside. Run unprivileged, bubblewrap puts pid 1 in a user namespace nested inside the one that owns the view's mounts, so its capabilities cannot change the view.
2. Joins a new, anonymous session keyring, so the sandbox does not share the caller's.
3. Drops every capability, its bounding set included, and sets `no_new_privs`. Both belong to a thread, so it does this on the one thread it has locked, the one that execs next. It also asks to die with bubblewrap's outer process.
4. Execs itself again, since `unshare` moves only the calling thread, which leaves the whole of pid 1 in the new namespace and no process inside in bubblewrap's. The new image starts with that one thread's empty sets, so no thread of pid 1 holds a capability, nor does the command, even as uid 0 inside. This second run, the reaper, makes itself undumpable, so the command cannot open its memory, descriptors, or root through `/proc`.
5. Reads its settings from the control socket, binds the `Listen` listeners, sets the `Rlimits` (pid 1 holds them too), marks every inherited descriptor but the command's own close-on-exec, and installs the seccomp filter on all its threads.
6. Sends the caller the listeners, or its setup error, on the control socket, and closes the socket.
7. Starts the command. It then passes on to it any SIGTERM or SIGHUP it gets, reaps orphans, and exits with the command's status, which ends everything left inside.

The stage holds `CAP_SYS_ADMIN` in its nested user namespace while the binary starts, so whatever runs before `Stage`, such as its libraries' `init` functions, runs with it. That is the adopting program's own code and what it links, not anything the sandbox runs, so such programs keep `init` functions out of it.

### The control socket

A `SOCK_SEQPACKET` socketpair, passed through bubblewrap, carries the stage's settings in (the kernel level, the listener count, the file count, and the limits) and its one reply out, with the listeners as descriptors. The command line used to carry them, which left pid 1's argv naming them and made an exit status the only way to report an error.

The socket is trusted only during setup. Pid 1 sends its reply, stops reading, and closes its end before the command starts, so no untrusted code ever holds it. The caller ignores anything that arrives on it afterwards, and takes the sandbox's pid from `--info-fd` and nowhere else, since a process that could write the socket could lie about it.

### The lifeline

The caller passes pid 1 the read end of a pipe and keeps the only write end, close-on-exec. Pid 1 reads it from its first moment. When it reaches EOF, which is when the caller closes it or dies, however it dies, pid 1 exits and the namespace's other processes die with it.

`--die-with-parent` is not used, and neither is `Pdeathsig` on the caller's side. Both fire when the OS thread that started the process exits, not when the process does, and a Go server's threads come and go. A locked goroutine that called `Start` and returned killed its sandbox. The first stage sets `PR_SET_PDEATHSIG` on itself instead, whose parent is bubblewrap's outer process, a single-threaded program. Without it a bubblewrap killed alone would leave pid 1 and the command holding the caller's output pipes, and `Wait`, which closes the lifeline, would never get past copying them.

### The process group and the terminal

`Start` always starts bubblewrap in a process group of its own, and keeps the caller's session. The filter allows `kill`, `tgkill`, `pidfd_send_signal`, and `setpriority`, and the kernel lets a process signal or renice a group in another pid namespace when the uid matches. A sandbox that shared its caller's group could end the caller and its siblings with `kill(0, sig)`, or slow them with `setpriority(PRIO_PGRP, 0, n)`. In a group of its own, `kill(0)` and `kill(-1)` reach only the sandbox.

A background group is stopped when it reads the terminal. So when `Stdin` is a terminal whose foreground group is the caller's, which is what `Run` passes, the sandbox's group takes the foreground. `Wait` gives it back to the caller's group, if the sandbox still holds it, with `SIGTTOU` blocked on the calling thread, since setting the foreground from the background would otherwise stop the caller. A Ctrl-C then goes to the sandbox's group and not the caller's. For `Run` that is enough: bubblewrap ends, and pid 1 follows it.

### The network

`NetworkNone`, the default, gives the sandbox a network namespace with only a loopback, which is private to it. That also makes the host's abstract sockets unreachable. A caller that wants the command to reach something sets `Listen` and the stage binds that many TCP listeners on `127.0.0.1` in the namespace, from port 3128, and sends them to the caller to serve. `Loopback` reserves ports from 4444 for a command that serves itself, such as a browser and its driver. `NetworkHost` shares the host's network, with its loopback and abstract sockets, and has to be asked for. It cannot be combined with `Listen` or `Loopback`.

### The filter

The filter is an allowlist from the system calls Docker's default profile allows without a capability, as Go constants from `x/sys/unix` for amd64 and arm64. It refuses the rest with `ENOSYS`, so a call added in a later kernel stays refused until it is reviewed, and a program falls back as it would on an older kernel. It leaves out io_uring, `bpf`, `perf_event_open`, `userfaultfd`, the key calls, module and `kexec` calls, `ptrace`, the mount calls, `unshare`, and `setns`. Of what it allows, it checks the arguments of:

- `clone`, which may not make namespaces. `clone3` passes its flags in memory, where the filter cannot read them, so it is refused, and libc falls back to `clone`.
- `socket`, which only makes Unix sockets and stream and datagram IP sockets of TCP, UDP, and ping. Another family gets `EAFNOSUPPORT` and another type `ESOCKTNOSUPPORT`, so a program that probes falls back. Raw and packet sockets get `EPERM`.
- `socketpair`, which only makes Unix pairs.
- `ioctl`, which may not use `TIOCSTI` or `TIOCLINUX`, either of which could type a command into the terminal of whoever started the sandbox.
- `setsockopt` and `getsockopt`, which may not use the legacy netfilter options that replace and read iptables, arptables, ebtables, ip6tables, ipset, and IPVS state.
- `personality`, which takes only the values Docker allows.

A call through another ABI, such as 32-bit x86 or x32, gets `ENOSYS`. The filter checks only the low 32 bits of each argument, since the kernel reads only those, so a caller cannot pass a check by setting a high bit. Argument checks come before the plain list, so the kernel caches the result for every call on it. A call took about 7 ns longer under the filter on the spike's host.

The `Kernel` setting relaxes it:

- `strict`, the default, is the filter above.
- `nested` also allows user namespaces, the mount calls, and `chroot`, for software that runs a sandbox of its own, such as Chromium or bubblewrap. The kernel locks the mounts it copies into a namespace the code makes, so it cannot unmount a cover, make a read-only bind writable, or bind the root elsewhere without its covers. It can map its own uid and mount a tmpfs of its own, which those sandboxes need, and filesystems an unprivileged user namespace may mount, such as overlayfs and FUSE, which puts their code within its reach. The netfilter options stay refused.
- `open` gives up the allowlist, and keeps refusing other ABIs and the terminal ioctls. On an architecture with no list, such as 32-bit arm, it has no filter at all. It allows the key calls, which is why the stage gives the sandbox a session keyring of its own at every level.

A level is only raised, never lowered. `Command` refuses one the host cannot give, and `Probe` shows which it can.

### Descriptors handed in

`Spec.Files` and the command's `Stdin`, `Stdout`, and `Stderr` become descriptors in the command. Only descriptors 0 to 2 and the `Files` are open in it, at fixed numbers. The stage marks every other descriptor close-on-exec rather than closing it by number, since once Go's runtime is up a number may be one of its own, such as its epoll descriptor.

A descriptor is more than the access it was opened with. It grants whatever the underlying object's owner and mode let the sandbox's uid do, whatever mode the caller opened it in and whatever the sandbox covers, because `/proc/self/fd/N` reopens it. That is how Unix descriptors work, and nothing here prevents it. A caller that needs a limit passes a pipe or a socket. A socket cannot be reopened, and a pipe reopens only as another end of the same pipe. [The findings](#descriptors-handed-in-reach-more-than-they-were-opened-for) show it.

### Probe and Check

`Probe` tries the backend and returns a `Report`: which backend, which kernel levels it can give, whether killing the sandbox kills every process in it, whether loopback is private, and what the host's container is. When no sandbox can start, `Report.Checks` ends at the first prerequisite that blocks it, with the fix. Those are bubblewrap missing, setuid or too old, Ubuntu's AppArmor restriction on user namespaces, a sysctl that turns them off, Docker's and Podman's default profiles, a masked `/proc`, and a systemd unit's restrictions. The AppArmor fix is a profile for this one binary's path, which the package generates. It grants user namespaces to that binary and what it starts, and to no other program. It does not use a child profile for bubblewrap: the kernel ignores exec rules in an unconfined-mode profile, so bubblewrap would stay in the parent's label and be refused. Without the profile on Ubuntu 24.04, `Probe` names it, but `Start` fails with bubblewrap's own message, such as `loopback: Failed RTM_NEWADDR: Operation not permitted`, because the kernel lets bubblewrap make a user namespace and takes its capabilities away.

`Check` runs the escape attempts of the generic suite in a child of this binary, inside a sandbox built from a `Spec` or, with none, in the caller's own context, which is what an operator's container or unit gives. The child is started with a marker that `Stage` handles, and gets its settings on a descriptor, not in argv. Each attempt returns a pass when it failed. The suite tries to make a user namespace, mount a tmpfs, call `io_uring_setup`, replace an iptables table, load a BPF program, signal and trace and read the environment of processes outside, read well-known secrets and reach well-known sockets, write outside the home, read under each cover, reach the network directly, and make a cgroup. It also reports capabilities, `no_new_privs`, the seccomp mode, and supplementary groups, and it takes a caller's own `Unreadable`, `Unwritable`, and `Unreachable` lists. A pass means one attempt failed, not that every path is closed.

## How it works on macOS

macOS has no namespaces, no seccomp and no cgroups, so the backend is a different shape, and it gives less. It gives a deny-by-default view of files, the network and Mach services, and a teardown that ends every process under the profile with the command. It does not give a pid namespace (so the caller's environment is readable), a system call filter, a private loopback or a memory limit, and the sections below say what that costs. [Limits](#limits) lists each.

### Seatbelt and sandbox-exec

The package writes a Seatbelt profile from the `Spec` and runs the command under `/usr/bin/sandbox-exec`, by that absolute path and never one found on `PATH`. There is no cgo: the profile language is Apple's, but `sandbox-exec` is the one program that applies it without linking `libsandbox`, and the module builds with `CGO_ENABLED=0`. Seatbelt is the engine App Sandbox and Firefox's own content sandboxes use. It is deprecated, and undocumented but for what Apple's own profiles in `/System/Library/Sandbox/Profiles` show, so every rule here came from running something and reading the deny log (`log stream --predicate 'sender == "Sandbox"'`).

A process that is already inside a profile cannot apply another. `Probe` tries a trivial profile and says so, and a Firefox started under one cannot start its own child processes' sandboxes, which is why [Firefox](#firefox) needs three environment switches.

### The profile

Seatbelt takes the last rule that matches, so the profile is written in the order of the view: `(deny default)`, the base rules, the host's files readable, a deny for each cover, an allow for each `Read` path, the home and `Write` paths readable and writable, then the network and Mach services. File rules are sorted by depth, shallowest first, with a cover before an allow at the same path, so the nearest rule above a path decides, as the nearest mount does on Linux. A `Read` path inside a cover inside a `Read` path works, and a cover at a `Read` path's own path shows it.

The base rules are `process-fork`; `process-exec*` of anything the profile lets the command read, which includes `#!` interpreters; `sysctl-read`; `signal` and `process-info*` to the sandbox's own processes (`(target same-sandbox)`) and no others; and writes to `/dev/null` and `/dev/zero`. All of `/dev` is denied but `null`, `zero`, `random`, `urandom` and `/dev/fd/N`, so a command reaches a terminal, a console, a serial port, packet capture or a disk only as a descriptor it was given. A list of what to deny had missed `/dev/console` and `/dev/cu.*`. `dtracehelper`, which every process tries to open, is denied too, and Firefox renders without it. Last, the home and each `Write` path get a deny of unlink and create at their own path, so the sandbox cannot remove, rename or replace its own root ([findings](#a-sandbox-could-replace-its-own-home-with-a-link)). The profile never allows `lsopen`, which would let the command open any app or URL through LaunchServices, outside the profile. It never allows a Mach service outside a requested group, `iokit-open`, or `file-write*` outside the home and the `Write` paths.

The covered paths are:

- every path the caller names in `Spec.Cover`;
- `/Users`, which holds people's homes and the account's own;
- `/Volumes`, where other volumes and APFS snapshots mount;
- `/private/var`, which holds the per-user temporary and cache directories, the sockets of system services, and the state of the system's databases, and `/private/tmp`.

`/var` and `/tmp` are links to those, and `/System/Volumes/Data` is the data volume under another name: `/Users` is the same directory as `/System/Volumes/Data/Users`. Seatbelt resolves links and firmlinks before it matches a rule, so a rule for the real path holds however the command names it, and every one of those names is covered. The rule has to be for the usual name, though: it matches `/Users`, and a rule written for `/System/Volumes/Data/Users` matches nothing. A `Cover` named that way once covered nothing, silently. `prepare` now maps a name through the data volume that a firmlink also gives (the list is `/usr/share/firmlinks`) to the usual one, in `Read`, `Cover` and `Dir`, and refuses it in `Home` and `Write`, where a link is refused anyway, with the name to use. A path that exists only on the data volume has no other name and is kept. A path on a case-insensitive volume matches whatever case it is written in, so no path needs its case normalized.

Two paths under `/private/var` are shown to every sandbox, since nothing runs without them and neither holds anything private. `/bin/sh` is a stub that reads `/private/var/select/sh` to find its shell, and `/etc/localtime` leads into `/private/var/db/timezone`. Other links in `/etc` that lead into a covered path are rebound read-only, as on Linux (`linkedFiles` runs here too): the resolver's file and the timezone file are shown, and hold nothing private.

`Read`, `Write`, `Home`, `Dir` and `Cover` go through the same resolution as on Linux, in the shared `prepare`, so the same layouts are refused. There are no bind mounts, so the rule that no mount may lie inside a writable directory is kept for another reason: a cover inside the home is a path-based deny, and a sandbox that can rename a directory it can write could move the covered one away and uncover what it hid.

A path goes into the profile only as a `subpath` or `literal` filter, never a regular expression, with a backslash and a double quote escaped. One with a control character, or bytes that are not UTF-8, is refused by `Start`, since nothing here can say what the parser makes of it.

### Paths and links

Seatbelt checks the path a file has when it is opened, not one opened earlier, so there is nothing to open by descriptor and nothing for a swap between the check and the use to redirect. A `Write` directory that another process replaces with a link after the profile is written gives the sandbox nothing: its path leads somewhere the rule does not name. A link the sandbox plants in its home leads out of the rule that allows the home, so nothing is read or written through it. The sandbox cannot swap its own root either: the profile denies unlink and create at the literal path of the home and of each `Write` path, so `rmdir` and `rename` of it, and a link made in its place, fail. Without that, the sandbox could remove its home and put a link to the caller's private directory there, and the caller, which reads and cleans up by that name, would follow it. A home or `Write` path with a link in it is still refused, for the reason it is on Linux: the next run would be pointed at what the link leads to, and a caller must name the real path (`t.TempDir()` leads through `/var`).

### The stage

`Start` runs this binary again, as the stage, with `Stage` finding it first in `main`, outside the profile and as the caller. It cannot exec `sandbox-exec` and be done, since macOS has no `Pdeathsig` and nothing else ends a command when its caller dies. The stage:

1. Takes its settings, the profile and the limits, from a pipe, and sets the limits on itself, so it holds them as pid 1 does on Linux.
2. Marks every inherited descriptor but the command's close-on-exec, from `/dev/fd`, and never closes one by number.
3. Starts `sandbox-exec -f /dev/fd/N -- command` in a process group of its own, with the profile on a pipe, so no command line names it, and the caller's `Files` at 3 and up. The command's group is the caller's session and not the caller's group, so `kill(0)` and `kill(-1)` from inside reach only the sandbox.
4. Sends the caller one reply, the command's group or the setup error, and closes that pipe, so `Start` returns once the command has been started.
5. Relays `SIGTERM`, `SIGHUP` and `SIGINT` to the command, and waits for it.
6. Ends the command's group, and then every process under the sandbox's profile, with `SIGKILL`, until none is left, when the command exits, and exits with its status, or 128 plus the signal.

The lifeline is a pipe the caller holds the write end of, as on Linux. The stage reads it from its first moment, and when it reaches EOF, which is when the caller closes it or dies, however it dies, the stage ends the sandbox and exits. If the stage itself is killed it cannot, so `Wait` watches for that and ends the sandbox as soon as the stage is gone, since a process it left behind could hold the command's output open and keep `Wait` from returning. `Cmd.Pid` is the stage's pid, this process's own child, and `Footprint` finds the command's group through the stage's reply.

#### Finding the sandbox's processes

The command's process group is not the sandbox. A command can leave it with `setpgid`, with a shell's job control (`set -m`), or by joining its parent's group, which is the stage's and so the caller's, and a process whose parent has died is no one's descendant. Each of those used to outlive the teardown and drop out of `Footprint`. The sandbox's processes are found by the profile instead. Every profile carries a pair of random Mach service names, one it allows a lookup of and one it denies. The stage, and `Footprint` in the caller, both outside the profile, ask the kernel for each pid, with `sandbox_check(pid, "mach-lookup", SANDBOX_FILTER_GLOBAL_NAME, name)`, and a process is the sandbox's when the first is allowed and the second denied. A process with no sandbox allows both. A process under another profile has other names: a deny-default profile denies both, and an allow-default one allows both. Another sandbox of this package has names of its own. So only a process under this sandbox's own profile gives that pair of answers, and it cannot change them, since a process inside a profile cannot apply another. `TestMarkerNamesOnlyItsSandbox` checks it against each of those kinds of process.

`sandbox_check` is a libSystem function, and the module builds with `CGO_ENABLED=0`. It is reached as `golang.org/x/sys/unix` reaches its libc calls: a dynamic import, an assembly trampoline (`member_darwin.s`), and `syscall.syscall9`, which the Go runtime exports. The function is variadic, and Apple's arm64 convention passes variadic arguments on the stack, so the name is given both where amd64 reads it (the fourth register) and where arm64 does (the first stack slot, the ninth argument of `syscall9`). It has been run on arm64 and on amd64 under Rosetta 2 (the test table has both). A path would be the more usual filter, but a name that does not exist gives "denied" for every process, and a Mach name needs no file.

The teardown scans `kern.proc.all` and signals each match the moment it is found, not after the scan, and repeats until five scans in a row find none, or five seconds pass. A first version listed every match and signaled afterwards, and a single process that forked, exited and made a session again every millisecond outran it: each generation had exited by the time it was signaled, and its successor was not yet in the list. A scan of 700 processes took 10 ms then, and with only this account's processes asked, about a third of that. `TestEscapeReforkingProcessEnds` runs that chain, one live process at a time, which stops by itself after 10 seconds so that a teardown that fails leaves nothing running; the teardown ends it in under a second. A fork bomb, or enough of these, can still keep ahead of the scan until it stops on its own, and nothing bounds it, since `RLIMIT_NPROC` counts the whole uid and does not limit a chain with one live process. When the last scan could not confirm the sandbox empty, `Wait` and `Run` return an error that matches the exported `ErrSurvivors` with `errors.Is` (and wraps the command's own result, so `errors.As` still finds its `*exec.ExitError`, and `Run` still returns the status). Linux never returns it, since the sandbox's pid namespace dies with its pid 1. `TestAPIErrSurvivors` checks both. No method lists the survivors, so a caller that sees it should treat the host as dirty. A survivor keeps what the profile gave it: the home, the `Write` paths, the network the `Spec` allows, and the command's output, which keeps `Wait` itself from returning unless `WaitDelay` is set. The caller does the last scan, after the stage is gone, and kills by the profile's marker only: the command's process group is a pid that the kernel may give to someone else once the group is empty, and a late `Wait` once could have signaled it. `Footprint` counts a member of the group only if the stage is among its ancestors, for the same reason.

The command holds descriptors 0 to 2 and its `Files`, and one more: the read end of the pipe that held its profile, which `sandbox-exec` has read to the end and which holds nothing. It cannot be closed from outside, since `sandbox-exec` execs the command with it open. A wrapper to close it was not worth a second exec inside the profile. `TestEscapeProfileNotInArgv` checks that it is at end of file and that no command line holds the profile or a covered path.

When `Stdin` is a terminal that the caller is the foreground of, the stage starts the command with the foreground, and gives it back, with `SIGTTOU` ignored for the call, when the command ends, as `Wait` does on Linux. `ctx` ending closes the lifeline, and a stage that has not gone five seconds later is killed. A `SIGTERM` or `SIGHUP` to a process in `Run` closes it too, so it ends the sandbox, as on Linux.

### The network

`NetworkNone` allows no network operation at all, except what the `Spec` names, which are single-port allows, since a port deny after a broad allow does not hold ([findings](#a-localhost-deny-held-only-in-one-form)):

- `Listen`: `Command` binds that many listeners on `127.0.0.1:0` and `ListenAddrs` returns them, so `Env` can carry `HTTP_PROXY`. The profile lets the command connect to those port numbers, over TCP, on any address the host has. The caller serves them. Other local processes can connect to them too, and a proxy applies its rules to them as to anyone.
- `Loopback`: `Command` reserves free ports, and `LoopbackPorts` returns them. `Start` frees them and the profile lets the command bind, accept on and dial exactly those, over TCP and no other protocol. Another process could take one between `Start` freeing it and the command binding it. There is no way to hold a port for a process that binds it later. **It is not a private loopback.** A profile names a host only as `*` or `localhost`, and `localhost` is every address the host has, so the command can bind a Loopback port on the LAN address or the wildcard, and under `NetworkNone` any host that can reach any address of this Mac, such as a peer on the LAN, over a VPN or on a routable IPv6 address, reaches it by connecting there. Only this Mac dialing its own LAN address was seen, and no second machine was tried. Seatbelt checks the remote address when a connection is made and not when it is accepted, so the peers cannot be limited to this host either: a `network-inbound` deny of every remote but `localhost`, written after the allow, let a local connection through, and the same allow with a remote filter made `listen` itself fail. Any local process reaches these ports too. A command that serves must bind `127.0.0.1` explicitly, and a caller that cannot accept those hosts being able to reach it should not give a command a `Loopback` port. A command that can take an inherited socket needs none: a listener the caller binds on `127.0.0.1` and passes in `Spec.Files` is on `127.0.0.1` only, since the command's own binds of that port elsewhere are refused (`TestEscapeInheritedListenerIsLoopbackOnly`). `TestGapLoopbackBindsLANAddress` shows it, and fails when it stops being so.
- A `Write` path that is a socket gets a connect rule for that path, since a file allow does not grant a connect. Another socket in a `Write` directory, in the home, or anywhere else does not connect, and the command cannot bind one of its own. Linux allows both, and a command that serves a unix socket for itself fails here.

`NetworkHost` allows TCP and UDP out, and the one unix socket name lookups go through, `/private/var/run/mDNSResponder`, with the Mach services a lookup needs, and then denies `localhost:*`. In a profile `localhost` is every address the host has, so this refuses the host's LAN address and the caller's own listeners on it too, which is better than the design counted on. `BroadLoopback` is the opt-in gap: it allows `localhost:*` to bind, accept and dial, TCP and UDP, so the command reaches every listener on any address the host has, `serve`'s included, and the user's other local services, and it can bind any port on any address, which lets it squat a port a local client expects, or serve the LAN. `Probe` reports `PrivateLoopback` as false.

### The environment, the home and temporary files

`Start` sets `HOME`, `TMPDIR`, `XDG_RUNTIME_DIR` and `XDG_*` over `Cmd.Env`, as on Linux, and `CFFIXED_USER_HOME` to the home, since Cocoa finds `~/Library` by that and not by `$HOME`. `TMPDIR` and `XDG_RUNTIME_DIR` are a directory named `tmp` in the home, which `Start` makes with mode 0700. There is no private `/tmp`, so a program that hard-codes `/tmp` is refused, and the directory has no size cap beyond `RLIMIT_FSIZE` per file, and stays until the caller removes the home. `ScratchSize` and `Hostname` are ignored.

### Services

A `Service` is a reviewed group of Mach services to allow lookups of. There are two, each with the evidence it came from:

- `ServiceFirefox`: `mach-register` and `mach-lookup` of `org.mozilla.machname.*`, which Firefox's processes register and look each other up by, and the lookups of `launchservicesd` and `configd`, which it aborts or crashes without. [spikes.md](spikes.md) M2 found them. The `launchservicesd` lookup does not let the command open anything, since `lsopen` is a different operation, which M3 found. The `org.mozilla.machname.` names are one namespace for the whole user session, shared with the user's own Firefox and with every other sandbox given this group, so two sandboxes can find each other's services and pass ports, and one can register a name before the other. Firefox 160.0.1 builds the name from a compiled-in format (`org.mozilla.machname.%d`, as `strings` on its `XUL` shows) and has no setting that was found for a prefix per instance, so the group cannot be narrowed to one sandbox's own processes. Run Firefox sandboxes one at a time, and not beside another program that registers such names, if the sandboxes do not trust each other.
- `ServiceDirectory`: the `opendirectoryd.libinfo` lookup, which `getpwuid` and `getpwnam` use. Without it they find nothing, since the sandbox has no passwd entry of its own, and `id -un` prints only the number. With it the command can look up, and list, every account on the host.

The design's example, a fonts group, is not defined: Firefox renders text from `/System/Library/Fonts` with file reads alone. `Command` refuses a name it does not know.

### Limits on macOS

`Rlimits` are set by the stage. Only `CPU`, `FSIZE`, `CORE` and `NOFILE` do what they say, and a CPU limit is a `SIGXCPU` that a program can ignore, which ends it only if it does not ([findings](#rlimit_cpu-is-not-a-kill)). `RLIMIT_AS` is the same number as `RLIMIT_RSS` on macOS and nothing enforces it, so `Command` refuses `ResourceAddressSpace`, and `Probe` lists it in `Unsupported`. `RLIMIT_NPROC` counts every process of the uid, the caller's own included. A limit of none is the most this process may set: `RLIM_INFINITY` is 2^63-1 there, an unprivileged process cannot raise a hard limit, and an open-file limit above `kern.maxfilesperproc` is refused outright.

`Cmd.Footprint` is the memory watchdog: the sum of `ri_phys_footprint`, which macOS itself charges a process and which counts compressed and swapped pages that a resident size leaves out, over every process that runs under the sandbox's profile, wherever it has gone (see [finding the sandbox's processes](#finding-the-sandboxs-processes)), and also the command's process group and every descendant of its members, which covers the moment before `sandbox-exec` has applied the profile. An error that says no process is left means the command and all it started have ended. It is read through `proc_info` directly, since the package builds without cgo. It is the sum at one moment, a process that is gone before it is read is left out, and macOS swaps before it kills, so it is a soft limit for a caller to poll. Linux has `Footprint` too, as the sum of resident sets of the bubblewrap process's descendants, for a host with no delegated cgroup.

### Probe and Check

`Probe` applies a trivial profile with `sandbox-exec`. It reports `seatbelt`, every `Kernel` level as `strict` (there is one profile, which is at least as strict as any request), `TreeKill` true, `PrivateLoopback` false, `Ignored` `Hostname` and `ScratchSize`, `Unsupported` the address-space limit, and `Container` as `app-sandbox` or `launchd-job` where it can tell. Its `Checks` end with a `NotEnforceable` finding for each gap: no pid namespace, the caller's environment readable, Loopback and Listen ports on every address, `BroadLoopback`, `F_SETOWN` signals, files of the account outside the covers, no system call filter, no limits, no scratch size. When the trial fails, because the process is already inside a deny-default profile, `probe.seatbelt` fails with the fix. A profile that allows everything does not stop a second from being applied, so only a restrictive one is detected.

`Check` runs the generic suite on macOS. The Linux-only checks are skipped. Processes outside are listed through `kern.proc.all`, and tried with `kill(pid, 0)` and with `KERN_PROCARGS2`, which returns another process's environment when it has one, except for Apple's own binaries, whose environment it leaves out. The account's own processes are tried first, since only a profile stops those: the others refuse by uid. A sandbox gives the check child its own `HOME` and an empty environment, so what it would build from them, the user's `~/.ssh` or the socket in `SSH_AUTH_SOCK`, names nothing of the caller's. `Check` therefore works those out in the caller, and sends the child the secrets and sockets that exist, and the directories outside the sandbox's own that this account can write (`access(2)`, so nothing is created to find them). `secrets.readable`, `sockets.reachable` and `writes.outside` try those, and are skipped, with the reason, where nothing exists to try, not passed. `TestCheckCatchesEscapesDarwin` makes each fail by a hole in the `Spec`, or with no sandbox, or in the check directly. `proc.trace` is skipped: `task_for_pid` needs a signed binary or root, and `ptrace` would stop its target. `proc.visible` and `proc.environ` fail inside a sandbox, and are the gaps below. The well-known sockets include Docker Desktop's, Colima's, OrbStack's and Podman's.

### Firefox

Headless Firefox runs under the generated profile with `Services: [ServiceFirefox]` and no network, in 2 to 3 seconds, and the PNG is byte-identical to an unsandboxed render (docs/spikes.md M2 and `TestFirefoxScreenshot`). The caller sets `MOZ_DISABLE_CONTENT_SANDBOX`, `MOZ_DISABLE_SOCKET_PROCESS_SANDBOX` and `MOZ_DISABLE_RDD_SANDBOX`, because Firefox's own processes cannot apply a profile of their own inside ours, and checks that the PNG exists and not only the exit status, since a denial can leave Firefox exiting 0 with none. An image from the `Listen` port loads, and one from a port the sandbox was not given does not (`TestFirefoxNetwork`). Firefox makes `Library/Application Support` in the home with an ACL that denies deletion, so a caller that removes the home runs `chmod -RN` on it first.

## Findings

Reviews by Fable, each given only the design and the code, and re-checks of their fixes, found these. Most were confirmed on a Proxmox VE container on ZFS with a 7.0 kernel, and the later ones in a Debian 13 VM on arm64 with a 6.12 kernel. Each says how the attack worked, what stops it now, and the test that checks it.

### Covered files reached another way

- **Landlock alone reached the account's own services.** Before ABI 9, Landlock does not check `connect()` on a socket file, so a sandbox reached the account's systemd user manager and read a covered file out through `systemd-run --user`. ptys, SysV IPC, and other processes' command lines leaked the same way. Landlock is gone, as under [Tried and dropped](#tried-and-dropped), the namespaces are the floor, and `/run` is covered. `TestIsolation` connects to a socket file outside.
- **Landlock alone granted every pty read-write.** A sandbox could write to an admin's terminal on the same account. bubblewrap's `/dev` has a new `devpts` instance.
- **ZFS snapshots showed covered files.** Every snapshot of a dataset is under its `.zfs`, at paths no cover names, even with `snapdir=hidden`, and file modes do not help when the sandbox's uid owns the files. A sandbox read a covered home's `.bash_history` through `/.zfs/snapshot`. Covers now come from the mount table too. `TestMountCovers` checks them on a fake mount table, and the fix was checked by hand on the ZFS host, since the VM has none.
- **A host mount made after start appeared inside.** bubblewrap leaves the view a slave of the host's mounts, so a later bind of a covered path showed inside a running sandbox. The first stage gives it private mounts of its own. `TestLateMounts` binds a covered directory on a fake host once the sandbox has started.
- **pid 1's root showed the host's later mounts.** When only the first stage moved to private mounts, bubblewrap's own reaper stayed in the old namespace, and the command read a later mount through `/proc/1/root`. The stage is pid 1 now, undumpable, with no process left in the old namespace. `TestLateMounts` also reads through `/proc/1/root`, and fails without `--as-pid-1`.
- **A cover on a socket was skipped.** Covers handled only directories and regular files, so a covered listening socket stayed reachable. Anything but a directory now gets `/dev/null`. `TestIsolation` covers a listening socket and expects `ECONNREFUSED`.

### Paths and links

- **A planted link pointed the next sandbox at the caller's state.** `prepare` followed links outside the sandbox, so a run replaced a directory in its home with a link to the state directory, and the next run had the state bound read-write. Links in writable directories are now refused, as under [Paths and links](#paths-and-links). `TestResolve`, `TestPrepare`, and `TestRefusedLayouts` plant them.
- **A covered path moved away was uncovered.** A missing cover was skipped, and a sandbox can rename a directory it can write. A missing cover inside a writable directory now stops the sandbox. `TestRefusedLayouts` moves one.
- **A cover inside the home never took effect.** Pruning dropped it as inside `/home`, and the home's bind went on top of it, so another sandbox's saved sessions were readable. Covers are now pruned by the nearest mount above them, and no cover may lie inside the home at all, so each sandbox that must be kept apart gets a home of its own. `TestCovers` and `TestRefusedLayouts` check both.
- **A home that was also covered became read-only.** The account's own home and the homes `/etc/passwd` gives it are covered, so a deployment whose sandbox home is one of them, outside every default cover, had the cover and the home's bind at one path. bubblewrap remounts a cover read-only once the binds are in, and the remount took the bind on top, so the home could not be written. The same happened with a path given both as a cover and as a `Write` path. A cover at a bind's path is now left out. `TestCovers` checks it, and `TestHomeCovered` writes in such a home.
- **bubblewrap follows a link while it makes a mount point.** Before 0.12.0, setup can follow a symlink in a mount destination's parent and create files on the host as the account (CVE-2026-87766, GHSA-pxhw-h44j-8pfx). Debian 12 will not fix it, and Ubuntu 24.04 rolled its fix back. No mount may lie inside a directory a sandbox can write. `TestPrepare` refuses such layouts.
- **A link where a tool's directory should be.** A run's CLI could write the scratch directory that held its shell commands' `work` directory, so a link planted there would have made the next shell sandbox's home the CLI's home. A home or `Write` path may have no link in it. `TestPrepare` refuses a home through a link.

### Processes and the kernel

- **pid 1 showed every cover.** The spike's own builder ran its stages with the caller's arguments, so `/proc/1/cmdline` named every covered path, token files included. bubblewrap now reads them from a descriptor, and the stages' settings travel on the control socket. `TestIsolation` checks pid 1's command line, environment, and descriptors, and `TestEscapeOptionsNotInArgv` checks the options.
- **The capability drop covered one thread.** pid 1 dropped its capabilities and set `no_new_privs` after its second exec, on a goroutine not locked to a thread. Both are per thread, and bubblewrap raises `--cap-add` as ambient capabilities, so every other thread of pid 1 kept `CAP_SYS_ADMIN` and `CAP_SETPCAP`, and the command could be forked from one of them and keep them as ambient ones. The first stage now drops them on its locked thread before it execs, so the new image starts with none. `TestIsolation` reads every set from the status of each thread of the command and of pid 1.
- **A thread that could not take the filter went unnoticed.** With TSYNC, the kernel reports a thread it cannot move to the new filter by returning that thread's id with no error, and installs the filter on no thread at all. pid 1 checked only for an error, so it would have started the command with no filter. Any result but 0 now stops the sandbox. `TestSeccompUnsyncedThread` gives one thread a filter of its own first.
- **`nested` reached iptables' table code.** Code under `nested` that made its own user and network namespace held `CAP_NET_ADMIN` there, and `IPT_SO_SET_REPLACE` reached the code behind CVE-2021-22555, answering `EINVAL` where it should have been refused. The filter refuses the netfilter options. `TestSeccompFilter` checks them, and `TestNestedMounts` tries it from such a namespace.
- **`open` left `TIOCSTI` open.** With `--new-session` dropped, a command under `open` could type into its caller's terminal on a kernel before 6.2. `open` keeps the terminal checks. `TestSeccompFilter` and `TestKernelLevels` check `TIOCSTI` at every level.
- **Every IP protocol and socket-pair family was open.** The filter checked only the socket family, so SCTP, DCCP, L2TP, MPTCP, and SMC were reachable, and a socket pair in any family loaded and ran that family's code. `TestSeccompFilter` checks the protocols and pairs.
- **Protocol 0 picked SCTP.** Protocol 0 means whichever protocol registered the type first, so an IP sequenced-packet socket was SCTP with the module loaded. Only stream and datagram IP sockets are allowed. `TestSeccompFilter` checks `SOCK_SEQPACKET` and `SOCK_DCCP`.
- **Temporary space had no limit.** A tmpfs is as large as the host's memory allows, 47 GB on the spike's host, so a sandbox could fill memory through `/tmp`, `/var/tmp`, or `/dev/shm`. That is a denial of service, not a leak. Each now holds at most 1 GiB, or `Spec.ScratchSize`, with bubblewrap's `--size`, from 0.7.0. `TestEscapeScratch` checks each size from inside, and a write past it stops at the limit.
- **A parent's thread exit killed its sandbox.** bubblewrap's `--die-with-parent` is `PR_SET_PDEATHSIG` on bubblewrap, so it fires when the Go thread that started it exits. A locked goroutine that called `Start` and returned killed the sandbox. The lifeline replaces it, as [above](#the-lifeline). `TestAPIStartThreadExits`, `TestEscapeParentKilled`, and `TestCommandParentKilled` check it.

### Found by the security review of the Linux backend

A review of the finished backend by Fable 5.2 found four issues and no full escape. These are what it found and what fixed each.

#### A sandbox could signal and renice its caller through the shared process group

- **How it worked.** `Start` put bubblewrap in the caller's own process group unless the caller asked for another. The filter allows `kill`, `tgkill`, `pidfd_send_signal`, and `setpriority`, and a same-uid process may use them across a pid namespace on a group it can name. `kill(0, SIGUSR1)` from inside ended the caller, `kill -TERM 0` ended a sibling of the caller, and `setpriority(PRIO_PGRP, 0, n)` reniced the caller's group.
- **What stops it.** Bubblewrap now always starts in a process group of its own, in the caller's session, so `kill(0)` and `kill(-1)` from inside reach only the sandbox. The `Setpgid` field of `Cmd` is gone, since it no longer means anything. When `Stdin` is a terminal the caller is the foreground of, the sandbox's group takes the foreground and `Wait` gives it back, because a background group stops on `SIGTTIN`.
- **The tests.** `TestEscapeSignalsStayInside` runs `kill(0)`, `kill(-1)`, and `setpriority` from inside, with a canary process in the caller's group, and asserts the canary and the caller are untouched. `TestEscapeTerminalForeground` runs a shell that reads a pty, which stops without the foreground, and checks the caller has the foreground again after `Wait`. `TestEscapeSessionKept` and `TestAPIProcessGroup` check every process is in one group that is not the caller's, and in the caller's session.

#### `/dev` was a writable tmpfs with no size

- **How it worked.** bubblewrap's `--dev /dev` makes a tmpfs with no size, and it was left writable. A sandbox with `ScratchSize` at 16 MiB wrote 64 MiB into `/dev`, past the limit, and so could fill the host's memory.
- **What stops it.** `/dev` is remounted read-only after everything mounted under it. That leaves `/dev/shm`, which is its own sized tmpfs, as the one place to write, and the device nodes, which are binds of the host's and work as before.
- **What it does not stop.** `memfd_create` and anonymous shared memory are not files on any tmpfs, so `ScratchSize` does not bound them. Only a delegated cgroup's `memory.max` does, as under [Limits](#limits).
- **The test.** `TestEscapeDevReadOnly` creates files, directories, and links in `/dev` and gets `EROFS`, walks the mount table and checks that every writable tmpfs the sandbox made reports a size no larger than `ScratchSize`, and checks the devices, a new pty, `/dev/fd`, and `/dev/shm`.

#### Descriptors handed in reach more than they were opened for

- **How it worked.** A file in `Spec.Files` that was under a covered directory and opened read-only was reopened write-only through `/proc/self/fd/3` and overwritten. A standard output opened append-only was truncated the same way. Opening through `/proc/self/fd` checks the file's owner and mode, not the mode the descriptor has, and not the covers.
- **What stops it.** Nothing, and nothing can: it is how Unix descriptors work. It is documented on `Spec.Files`, `Cmd.Stdin`, `Cmd.Stdout`, and `Cmd.Stderr`. A caller that wants a limit passes a pipe or a socket.
- **The test.** `TestEscapeReopenDescriptor` documents it: a file opened read-only is reopened and rewritten, a socket cannot be reopened (`ENXIO`), and a pipe reopens only as another end of the same pipe, where what the sandbox writes comes out of the pipe the caller holds and nothing else. It fails if the behavior changes, so the docs get changed with it.

#### The caller's session keyring was readable under `open`

- **How it worked.** The sandbox inherited the caller's session keyring. `strict` and `nested` refuse `keyctl`, but `open` allows it, and the kernel's check on a key looks at the uid, which the sandbox keeps. A `keyctl` search and read inside returned a key the caller had added, such as a Kerberos ticket.
- **What stops it.** The first stage joins a new, anonymous session keyring (`KEYCTL_JOIN_SESSION_KEYRING` with no name) on its locked thread, before the filter and at every level, so the reaper and the command inherit it. A kernel with no key support, or a host filter that refuses `keyctl` with `EPERM`, as Docker's does, has nothing to join, and the same filter refuses it to the command.
- **The test.** `TestEscapeSessionKeyring` puts a key in a session keyring and the user keyring of a process of its own, runs a sandbox from it under `open`, and searches every keyring the sandbox has, and the caller's by id, for the key.

### Found while building the macOS backend

These were found by running things under profiles, since the macOS design rested on inferences. Each says what was expected, what happened, and the test.

#### `(deny default)` does not deny process-info

- **How it worked.** `proc_pidinfo` and `proc_pid_rusage` of any process of the uid succeeded under a deny-default profile with no `process-info` rule, and under `(allow process-info* (target self))`, which looks as if it should restrict them. The design counted on the default deny.
- **What stops it.** The profile denies `process-info*` by name, then allows it for `(target same-sandbox)`. With that, the sandbox's own processes can be asked about, and no one else.
- **The test.** `TestEscapeProcessInfo`, and `TestEscapeSignalsStayInside`, which also tries `proc_pid_rusage`. A mutation that removes the deny fails both.

#### A profile cannot stop another process's environment being read

- **How it worked.** `sysctl(KERN_PROCARGS2)` returns the environment of any same-uid process that is not one of Apple's. It still did under `(deny process-info*)`, under `(deny sysctl-read (sysctl-name "kern.procargs2"))`, and under `(deny sysctl-read)` on an allow-default base. The design expected `process-info*` to stop it.
- **What stops it.** Nothing. It is a gap: a `FIELD_*` variable in one build's environment is readable by another build's code while both run. Concurrency 1 and ending the other builds' processes between builds are the caller's mitigations, as in design.md 5.1.
- **It includes the caller's own environment.** The stage's parent is the caller, so a command reads the environment the caller was started with, whatever `Cmd.Env` holds. `Env` controls only what the command is given, and design.md 4.1 once said a server that sets none leaks none of its tokens, which is not so on macOS. A caller must hold no secret in its environment there: read it, then re-exec with a scrubbed one, or take it from a file or a descriptor. The same goes for every other process of the account, the user's shells, editors and agents among them, and for every process's arguments, which are readable the same way.
- **The test.** `TestGapProcessEnvironment` reads it inside a sandbox, then shows that the profile that denies both rules does not stop it, and fails when that changes. `TestGapCallerEnvironmentReadable` reads a caller's token through a sandbox given an empty `Env`. `Check` reports `proc.environ` as failed.

#### A localhost deny held in only one form

- **How it worked.** In a minimal profile, after an allow written `(remote ip "*:*")`, `(deny network-outbound (remote ip "localhost:*"))` denied nothing, as the per-port denies of spikes.md M1 did not hold (rechecked on 27.2.0). After `(remote tcp "*:*")` and `(remote udp "*:*")`, the same deny held for 127.0.0.1, `::1` and the host's LAN address, over every one of 40 ports tried. A deny written with `(local ip ...)` refused everything. In the full generated profile, the `ip` form held as well, so which shapes of profile work is not something to predict from one that does.
- **What stops it.** `NetworkHost` is written in the tcp and udp form that held in every shape tried, and `TestProfileNetwork` checks the form as text. `TestEscapeNetworkHost` checks the behavior, and fails if the deny is removed. `localhost` in a profile is every address the host has, so the host's own listeners on its LAN address are refused too.
- **The test.** `TestEscapeNetworkHost`, which also checks that a name resolves and a TLS connection verifies. Re-run it when macOS is updated.

#### `RLIMIT_CPU` is not a kill

- **How it worked.** The design counted on `RLIMIT_CPU` to end a process that escaped the teardown. On macOS 27.0.1 and 27.2.0 a soft limit sends `SIGXCPU`, and the hard limit sent no `SIGKILL` to a Go program or a Python one that ignored `SIGXCPU`, which ran on for a hundred seconds past a limit of 2.
- **What stops it.** Nothing. A shell dies of `SIGXCPU`, as `TestAPIRlimits` checks. A process that ignores it is not limited.
- **The test.** `TestEscapeSetsidDiesWithTeardown` starts a process that leaves the process group, under a CPU limit, and shows it ended with the sandbox, which the CPU limit does not do.

#### A process could leave the process group, and outlive teardown and `Footprint`

- **How it worked.** Teardown ended the command's process group and `Footprint` summed it and its descendants, and the docs said only a `setsid` in a child escaped. A review found much more. The command could `setpgid` itself into its parent's group, which is the stage's, so the caller's, and `Footprint` then said "no process of the sandbox is left" while it ran, and closing the lifeline ended nothing. `/bin/sh -c 'set -m; sleep 600 & exit 0'` left `sleep` running in a group of its own with no `setsid`, and since it held the sandbox's output pipe, `Wait` blocked for over two minutes on a writer that was not a file. What an escapee kept was also more than the docs said: under `NetworkHost` all outbound network, in every mode write access to the home and `Write` paths and a unix socket in `Write`, and `KERN_PROCARGS2` of every later build. Nothing listed the escapees, so "ending the other builds' processes between builds" was not something a caller could do, and a `Footprint` watchdog bounded only code that stayed put.
- **What stops it.** The stage and `Footprint` find the sandbox's processes by the profile's marker, a pair of random Mach names that `sandbox_check` answers differently for this profile than for any other ([finding the sandbox's processes](#finding-the-sandboxs-processes)). Teardown ends every match until a scan finds none, and `Footprint` sums them. `Wait` ends them as soon as it sees the stage is gone, so an escapee that holds the output open does not block it.
- **The tests.** `TestEscapeSetpgidAndJobControl` (job control, a `setpgid` child and a `setsid` child, each holding the output of a writer that is not a file), `TestEscapeFootprintCountsEscapees` (the same, and the command joining the caller's group, each counted by `Footprint` and ended with the sandbox), `TestEscapeStageKilledEscapeeHoldsOutput`, `TestEscapeParentKilledEndsEscapees`, `TestEscapeSetsidDiesWithTeardown`, and `TestMarkerNamesOnlyItsSandbox`. Each fails with the marker taken out of the teardown and `Footprint`: the waits time out, and the command in the caller's group is not counted.
- **What is left.** A fork bomb can outpace the scan and nothing bounds it, though a single process that re-forks every millisecond is ended (`TestEscapeReforkingProcessEnds`), and `Wait` returns an error when it could not confirm the sandbox empty (`TestTeardownReportsWhatItCouldNotConfirm`). `TestGapSetsidConnect` still connects from a child in a session of its own to a unix socket in `Write`, and checks that its session is neither the command's nor the caller's, so a bridge check that keys on the session sees a session it cannot place.

#### A sandbox could replace its own home with a link

- **How it worked.** `(allow file-read* file-write* process-exec* (subpath HOME))` matches HOME itself, so the sandbox could `rmdir` its home and `ln -s` a directory of the caller's in its place. The caller reads results from the home, writes inputs and cleans up by name, so it then read a file from its own private directory (`os.OpenRoot(home)` followed it too, since the root was what was swapped). The same worked for a `Write` directory, and a `Write` socket was removed and replaced with a directory. On Linux a bind mount point cannot be removed from inside, so this was macOS only.
- **What stops it.** After the allows, the profile denies `file-write-unlink` and `file-write-create` at the literal path of the home and of each `Write` path, which stops `rmdir`, a rename of it, a rename over it and a link in its place. The sandbox still writes everything inside. Each way was tried under each name a root has: its own, upper case, the other Unicode normalization, through `/System/Volumes/Data` and `/.vol/<dev>/<inode>`, with a trailing slash and through `x/..`, with `rmdir`, `unlink`, `rename` away and over (a directory, file or link), `renamex_np` with `RENAME_SWAP`, `symlink`, and for a `Write` path that is a file or a socket as well as a directory (`TestEscapeRootsEveryName`). What the deny does not stop, and a caller must allow for: the sandbox can change a root's mode, flags and extended attributes (`chmod 0`, `chflags uchg`, `setxattr`), so Home may be unreadable or immutable after a run and `os.RemoveAll` fails until the caller clears `uchg`, and it can make a FIFO (`mkfifo`) in Home, so a caller that opens a result by name can block on one, which `os.Root` does not prevent. Open results with `O_NONBLOCK`, or check the mode with `Lstat` first (`TestGapRootModeAndFifo`).
- **The test.** `TestEscapeRootsCannotBeSwapped`, which fails with those denies removed. `TestEscapeSwappedAfterStart` is the host doing the swap, which Seatbelt already handled.

#### A Cover named through the data volume covered nothing

- **How it worked.** Seatbelt matches the usual name of a firmlinked path, so `(deny ... (subpath "/System/Volumes/Data/private/var/x"))` never matched, and a `Cover` written that way left the files readable with no error. A `Read` or `Write` path named that way failed closed, which is why only the deny was a hole.
- **What stops it.** `canonicalName` maps such a name to the usual one in `prepare`'s resolution, so `Cover` and `Read` mean what they say, and `Home` and `Write` are refused with the name to use. A path that exists only on the data volume is kept.
- **The test.** `TestEscapeFirmlinkNames` tries each pair of spellings of a `Read` and a `Cover`, including the review's (a `Read` by the usual name and a `Cover` by the other), and `TestCanonicalName` the mapping.

#### `F_SETOWN` with `O_ASYNC` signals a process outside

- **How it worked.** `fcntl(fd, F_SETOWN, pid)` and `O_ASYNC` on a socketpair make the kernel send `SIGIO` and `SIGURG` to `pid` when the descriptor is ready. The kernel does not ask Seatbelt's signal hook, so the denial of `signal` outside the sandbox does not cover them. A negative owner would name a process group.
- **What stops it.** Nothing; it is a gap. Both signals are ignored by default and by Go, so only a program that handles them is affected. `(deny system-fcntl (fcntl-command F_SETOWN))` was the idea in the review and was not tried.
- **The test.** `TestGapSetOwnSignalsOutside` sends `SIGIO` to a canary the test started, and fails when it stops arriving.

#### The caller's secrets and sockets were never tried by `Check`

- **How it worked.** `writes.outside` tried `/`, which is the sealed system volume and refuses without any sandbox, `secrets.readable` and `sockets.reachable` built their paths from `$HOME`, which `Start` had set to the sandbox's home, and from `SSH_AUTH_SOCK`, which is empty there, and `proc.signal` tried the parent and the lowest pids, which are root's. All four passed without trying anything of the user's.
- **What stops it.** `Check` works out the targets in the caller and sends them in its payload: the secrets and sockets that exist, and directories the account can write outside the sandbox's own. A row with nothing to try is skipped, with the reason. `proc.signal` tries the account's own processes before the others.
- **The test.** `TestCheckCatchesEscapesDarwin` makes each row fail, and `TestCheckSandboxDarwin` shows each passing with a count of what it tried.

#### Opening a terminal, packet capture or a disk

- **How it worked.** `file-read*` of `/` shows `/dev/ttys*`, `/dev/ptmx`, `/dev/bpf*` and the disks. The account is usually in `access_bpf`, and its own terminals share its uid, so a sandbox could read keystrokes and type output into another terminal, or sniff.
- **What stops it.** The profile denies all of `/dev` but `null`, `zero`, `random`, `urandom` and `/dev/fd/N`, so a terminal reaches the command only as a descriptor it was handed, and `TIOCSTI` on that one is refused. A first version denied those four families by name, and missed `/dev/console` (`crw--w--w-`, owned by the login user) and `/dev/cu.*` and `/dev/uart.*` (`rw-rw-rw-`), whose stat worked, and so, by their permissions, probably their open. Nothing opened one, since opening a serial port can toggle a line on attached hardware.
- **The test.** `TestEscapeTerminals` opens each device for reading and for writing. `TestEscapeDevices` stats every entry of `/dev` and shows each refused but the allowed ones, which it uses, and `TestFirefoxScreenshot` still renders. It has a control for `TIOCSTI`, which the kernel on 27.x refuses outside a sandbox too, so there the check is only the profile's refusal to open another terminal.

#### A setuid program does not run

- A setuid program cannot be run inside a profile, so `sudo`, `ps` and `su` fail. It is why the checks that would use `ps` are done in Go, and why `sudo` with a cached ticket cannot be used to leave the profile. `TestEscapeSetuid`.

#### `/bin/sh` needs a path under a cover

- `/bin/sh` reads `/private/var/select/sh`, which the default cover of `/private/var` hid, so no script ran. The profile shows `/private/var/select` and `/private/var/db/timezone` (for `/etc/localtime`) and nothing else under it. `TestEscapeViewShowsHost`.

#### TLS needed a Mach service from 27.2

- curl under `NetworkHost` verified certificates on 27.0.1 and failed with `unable to get local issuer certificate` on 27.2.0, because it looked up `com.apple.TrustEvaluationAgent`. `NetworkHost` allows that lookup. It is the kind of service list that changes between releases, which design.md section 9, risk 3, names. `TestEscapeNetworkHost`.

#### A descriptor's reopen is checked by path

- On Linux a read-only file under a cover can be reopened for writing through `/proc/self/fd`. On macOS `/dev/fd/N` is the file's path, and the profile checks it, so the reopen is refused under a cover, though a write to a descriptor opened for writing is allowed. `TestEscapeDescriptorsHandedIn`.

#### Launching apps and URLs

- **What was checked.** `open` of an app and of a URL, `open -a`, and `osascript` telling Calculator to launch, all fail under every `Services` group, even the one that allows the lookup of `launchservicesd`, and no app starts and the default browser fetches nothing. `TestEscapeLaunchServices` snapshots the Calculator processes by executable path before, looks after each attempt, and ends any it did not find. A raw XPC client that connects to `launchservicesd` directly gets a connection with the group and `Connection invalid` without it, and nothing opens (`TestEscapeLaunchServicesRawXPC`).
- **What was not.** Our message is rejected by `launchservicesd` outside the sandbox as well, since the real request is private to LaunchServices, and the library's calls to it do not go through any public `xpc_connection_create*` function, so interposing could not capture one to replay. The `lsopen` denial is logged against the calling process, which suggests the check is on the caller's side. Whether `launchservicesd` checks it on the server side is untested, and a review should look at it.
- **A false alarm.** An earlier run of this test reported "an app was launched: 2 processes of Calculator, was 0", and the profile-in-argv test saw profile text in `ps`. Both were the suite's own checks matching command lines of other programs: the Calculator count matched any command line that named `Calculator.app`, including a hand-run `lsopen` experiment that did launch it, and the argv check looked at every process on the machine, where other tools run `sandbox-exec -p` with a profile. The tests now count executables by path, snapshot before, and look only at the sandbox's own process tree.

### Files a caller handles for a run

These were found in legwork's own code, before the extraction, and are history here. They are the adopting program's to get right, and are kept because the same shapes recur:

- **A bridge sent any file a placeholder named.** An absolute path outside the scratch directory went to a tool, past a CLI confined by `--restricted`. The bridge sends only files in the scratch directory, through `os.Root`.
- **A runner's writes followed links.** `os.WriteFile` followed a link the CLI left in its scratch directory, which could have carried the next run's prompt into another thread's directory. Write through `os.Root`.
- **A model's URL reached the host's own services.** A client that refused addresses that are not public still reached whatever the host served on its own public address. It must refuse the host's interface addresses too.

### Found in the plans that adopt it

These came from reviewing legwork's plan for adopting the sandbox, which was changed to meet them:

- A compromised server could plant links for a root launcher's chown or binds to follow, which would be root on the host. A launcher works beneath a descriptor for the state directory with `openat2`, without following links.
- bubblewrap run as root maps the sandbox to host uid 0. A launcher switches to the child's uid before it runs bubblewrap, so it needs user namespaces as much as any other way of running. `Command` refuses to run as root for the same reason.
- A uid fixed per thread cannot last, since threads have no limit and a range does. A uid belongs to one running child.
- `NetworkHost` without root reaches loopback, where the server's own listeners are, past its tool policy and audit log. The default is `NetworkNone` for this reason.
- A proxy that the sandbox reaches must refuse the host's own public address.
- On macOS, `open` allowed any service but the keychain, and LaunchServices starts processes outside the profile. No list of services to refuse could be complete, so `open` on macOS is the same as `strict`.
- One shared home lets a run change what every later run trusts, such as its credentials file. Each thread gets a home of its own.
- A shell tool's commands could write the files the next run's CLI loads. They get a `work` directory beside those files.
- Keeping threads apart under `NetworkHost` leaves loopback and abstract sockets shared between them.

## Tried and dropped

- **Landlock alone.** Before ABI 9 it does not check socket files, so it does not keep a sandbox off the account's own services, and it leaves ptys, SysV IPC, and other processes' command lines open too.
- **Landlock inside the namespaces.** Its file rules come from the same paths as the mounts, so they shared the mounts' mistakes: both planted-link findings got through it. Its ptrace and signal scopes repeat the pid namespace, and its abstract-socket scope and port rule repeat the network namespace. Under `nested` it refused what the mount locks already refuse, and stopped Chromium's and bubblewrap's sandboxes from starting, since it refuses mounts and writes to `/proc/<pid>/uid_map`. Its one real job, keeping a sandbox off the host's abstract sockets, ended when the network namespace came. Taking it out also took out a walk of the host's root on every start, a workaround so renames between directories work, refused terminal ioctls on device files, and a dependency from outside the standard library and `golang.org/x`. The filter still allows the Landlock calls, so a program inside can use Landlock on itself, as Cursor's sandbox does.
- **A namespace builder of our own.** The spike built the namespaces and the view itself with Go's `SysProcAttr`, a staging root, and `pivot_root`, and it worked, but its whole setup would have to be reviewed, where bubblewrap's has a long record. It had already needed a fix that bubblewrap does not: Go's ambient setup leaves capabilities in the inheritable set, which a file's inheritable capabilities combine with outside the bounding set.
- **bubblewrap's `--seccomp`.** The filter refuses the calls the first stage makes, so the stage installs it after them.
- **bubblewrap's `--new-session`.** It would guard against `TIOCSTI`, but a new session fails a caller's check that a bridge is in the session of the command's starter. A process group of its own does the job a session would for signals. The filter refuses `TIOCSTI` instead.
- **bubblewrap's `--die-with-parent` and `Pdeathsig`.** Both fire on the exit of the thread that started the process. The lifeline replaces them, as [above](#the-lifeline).
- **bubblewrap's `--cap-add` to change the view or the network.** Unprivileged bubblewrap runs the command in a user namespace nested inside the one that owns the view's mounts and the network namespace, so the capabilities are real but do not reach either. That is why the first stage makes a mount namespace of its own, and why adding routes would need a network namespace of its own too.
- **The first stage making only itself private.** `unshare` moves one thread, and bubblewrap's own reaper stays behind, so other processes inside still see the host's later mounts through `/proc/<pid>/root`. The stage execs itself and is pid 1.
- **Letting the caller pick the process group.** A `Setpgid` field on `Cmd` made the shared group the default. Every sandbox gets its own now, and the field is gone.
- **Reading the pid from the control socket.** A sandbox that could write to it could lie. The pid comes from `--info-fd`.
- **Closing inherited descriptors by number.** Once Go's runtime is up, a freed number may be its epoll descriptor, which crashed the spike. The stage marks them close-on-exec.
- **Covering the machine id.** The sandbox makes no claim to hide the host, and addresses and much else identify it anyway.
- **elastic/go-seccomp-bpf.** It cannot make `ENOSYS` the default or answer `EAFNOSUPPORT`, so the filter is written with `x/net/bpf` instead.

macOS:

- **`sandbox_init` through cgo or `dlopen`.** It would apply the profile in the stage, with no `sandbox-exec`, no pipe and no leftover descriptor. It breaks `CGO_ENABLED=0` builds, which legwork's are, and a profile applied to a Go runtime that then execs is a larger change than a program that only execs.
- **A shell wrapper to close the profile's descriptor.** One more exec inside the profile, for a pipe that is at end of file.
- **`(deny network-outbound (remote ip "localhost:P"))` after a broad allow.** It held for about half of all ports, as spikes.md M1 found. `localhost:*` after a tcp and udp allow holds, and a profile that allows only named ports always did.
- **Denying `kern.procargs2` by name, or `process-info*`.** Neither stops `KERN_PROCARGS2`.
- **Denying signals to others by name.** `(target same-sandbox)` allows exactly the sandbox's own, which a list of what to refuse could not do.
- **Normalizing the case of paths.** Seatbelt matches case-insensitively on a case-insensitive volume, so there is nothing to normalize.
- **Writing each rule under both names of a firmlinked path.** Seatbelt matches the usual name, so a rule for the other matches nothing and a second rule is dead weight. `prepare` maps a name through `/System/Volumes/Data` to the usual one instead ([findings](#a-cover-named-through-the-data-volume-covered-nothing)).
- **`RLIMIT_AS`.** Not enforced. It is refused rather than set.

## Limits

- **Abstract sockets and loopback under `NetworkHost`.** With the host's network, a sandbox reaches every abstract socket and loopback listener on the host, which have no permission check. `NetworkNone` gives it a private loopback, and `TestEscapeLoopbackIsPrivate` checks that.
- **Memory that is not a file.** `ScratchSize` bounds the sandbox's tmpfs, which are the only ones it can write. It does not bound `memfd_create` or anonymous shared memory, which belong to no tmpfs, nor ordinary process memory. Only a delegated cgroup's `memory.max` does, by `Cmd.CgroupFD`. `Rlimits` bound each process, not the sandbox.
- **Descriptors the caller hands in.** A descriptor grants what the object's owner and mode allow, whatever the open mode and the covers, as under [Descriptors handed in](#descriptors-handed-in). Pass a pipe or a socket where that matters.
- **The mount table.** `/proc/self/mountinfo` shows where each cover and bind is, so a cover hides what is under a path, not that the path exists. A caller that covers its config and state by directory shows those directories' names, not the files in them.
- **What the mount table cannot show.** A btrfs snapshot directory other than `/.snapshots`, or a home neither `/etc/passwd` nor a prefix of two homes reveals, has to be covered by name. `Check` can try a path through `.zfs/snapshot` and `.snapshots`, which finds the ones that are reachable.
- **Links the operator made.** A home or `Write` path through any link is refused, so on an ostree host the caller passes `/var/home/...`, not `/home/...`.
- **Stopping a sandbox.** Cancelling `ctx`, or a SIGTERM or SIGHUP to a process that is in `Run`, reaches only bubblewrap's outer process, which does not pass signals on, so it ends, and pid 1 dies with it and kills everything inside with SIGKILL. The command gets no chance to save its state. Pid 1 does pass SIGTERM and SIGHUP on to the command, so a caller could send them to the pid from `Pid` for a clean stop, but no test does that yet.
- **pid reuse before kernel 6.5.** Without `SO_PEERPIDFD`, a check that looks a socket's peer up in `/proc` by pid, to see whether it is in the sandbox's pid namespace, could judge a process that took that pid in between.
- **A router's address.** A client that refuses the host's interface addresses does not refuse a router's public address that forwards back to the host.
- **Other architectures.** With no system call list, only `Kernel: open` starts, with no filter and so no `TIOCSTI` refusal. `Command` refuses the other levels before it starts bubblewrap.
- **The account's groups and the host's file modes.** Both are the operator's to get right. `Check` warns when the account has supplementary groups, and when it can read any of a short list of files no service account should: `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers` and `/etc/sudoers.d`, the SSH host keys, `/etc/ssl/private`, `/etc/wireguard`, NetworkManager's `system-connections`, netplan's files, PPP's and IPsec's secrets, `/etc/krb5.keytab`, certbot's `live` and `archive`, `/etc/mysql/debian.cnf`, and the admin kubeconfigs of Kubernetes and k3s. A secret an admin puts in a world-readable file, such as a password in `/etc/fstab`, is past what a list can find.
- **Pseudoterminals.** The sandbox's own `devpts` lets it open ptys, which the kernel's own limit bounds, not the sandbox's.

On macOS:

- **No pid namespace.** The sandbox sees every process of the uid, and reads the arguments and the environment of the ones that are not Apple's (`KERN_PROCARGS2`). It cannot signal them, renice them, or ask about them with `process-info`, except that `fcntl(F_SETOWN)` with `O_ASYNC` makes the kernel send them `SIGIO` and `SIGURG`, which are ignored by default.
- **The caller's environment is readable.** The caller is a process of the uid, so the command reads its environment, whatever `Cmd.Env` holds. A caller must hold no secret in its environment on macOS: read it and re-exec scrubbed, or take it from a file. The same goes for its arguments, and for every other process of the account (shells, editors, agents).
- **Teardown finds the sandbox's processes by the profile.** A process that leaves the command's group, by `setpgid`, a shell's job control or `setsid`, or whose parent died, is found by the marker in the profile and ended with the sandbox, and counted by `Footprint`. A fork bomb can keep ahead of the teardown's scan until it stops on its own, and nothing bounds it (`RLIMIT_NPROC` counts the whole uid, and does not limit a chain of single processes); `Wait` then returns an error saying it could not confirm the sandbox empty, and `Probe` lists it. `RLIMIT_CPU` does not end a process. If the stage is itself killed with `SIGKILL`, `Wait` ends the sandbox.
- **`Loopback` and `Listen` ports are on every address.** A profile names a host only as `*` or `localhost`, which is every address the host has, so the command can bind a Loopback port on the LAN address or the wildcard and, under `NetworkNone`, any host that can reach any address of this Mac (the LAN, a VPN, a routable IPv6 address) and connects there reaches it, as any local process can. Nothing in a profile limits the peers. Only this Mac dialing its own LAN address was seen: no second machine was tried. A command that serves should bind `127.0.0.1`, and `PrivateLoopback` is false. For a command that takes an inherited socket there is no gap: a listener the caller binds on `127.0.0.1` and passes in `Spec.Files` serves with no `Loopback` port, and the command's own binds of that port on the LAN address and the wildcard are refused (`TestEscapeInheritedListenerIsLoopbackOnly`).
- **`BroadLoopback`.** Bind, accept and dial on any port of every address the host has, TCP and UDP. Without it, only the ports `Listen` and `Loopback` name, over TCP.
- **Files of the account outside the covers are readable.** The sandbox reads with the caller's uid and groups, so a file the account owns outside the four default covers is readable whatever its mode: `/opt/homebrew/var` and `etc` (service configs and database directories, even a mode-0700 Postgres data directory), `/usr/local` on an Intel Mac, and user-owned directories under `/Library/Application Support`. "A sandbox can read what any account on the host can" understates it. The default covers stay as they are, since nothing under those paths is clearly secret on every host. A caller that has such data names it in `Spec.Cover`.
- **`ServiceFirefox`'s Mach names are shared.** `org.mozilla.machname.*` is shared with the user's own Firefox and with every other sandbox given the group ([Services](#services)).
- **No system call filter.** Seatbelt filters operations, so every `Kernel` level gets the one profile, and a `Kernel` of `nested` or `open` gets no more.
- **Memory and processes.** `RLIMIT_AS` is not enforced, `RLIMIT_NPROC` counts the whole uid, and `RLIMIT_CPU` is only a signal. `Footprint` is a poll.
- **Temporary files.** `TMPDIR` is in the home, with no size cap beyond `RLIMIT_FSIZE` per file, and stays until the caller removes the home. A program that hard-codes `/tmp` is refused.
- **Unix sockets.** The command cannot bind one of its own or connect to any but the `Write` sockets, and no device but `null`, `zero`, `random`, `urandom` and `/dev/fd/N` can be opened.
- **Directory Services.** Without `ServiceDirectory`, `getpwuid` finds nothing. With it, the command can list every account.
- **One descriptor more.** The command holds the pipe that held its profile, at end of file.
- **Version dependence.** The Mach service lists and the form of a rule that held come from running macOS 27.0.1 and 27.2.0. Apple adds and renames services between releases, and a missing one can fail silently. Run the tests, and a render, on each new release.
- **`lsopen` on the server side** is untested ([findings](#launching-apps-and-urls)).
- **Descriptors the caller hands in** grant what the object does, as on Linux. A file reopened through `/dev/fd` is checked by its path, which is stricter.

## How it is tested

The tests run real sandboxes on Linux, as the account's own uid, which takes bubblewrap's unprivileged path as a deployment does. Running them as root of a user namespace had hidden that bubblewrap's capabilities do not reach the view. Some build a fake host first, in a user and mount namespace of their own: homes under `/srv`, a `passwd` that lists them, links in `/etc`, a stand-in for a caller's state, and a listening socket. The test binary is also the code that runs inside the sandbox, as its own first stage and as a checker the tests name.

`scripts/linux-test.sh` builds the test binary, copies it to a machine, and runs it there in a directory of its own (never `/tmp` itself, which the sandbox covers). It vets linux/amd64, arm64 and arm. Extra arguments go to the test binary. These targets have been run, each with `CGO_ENABLED=0` and with cgo on (`CGO=1`, which builds on the target, since the host has no C cross-compiler):

| Target | How | Pass | Skip | Fail |
|---|---|---|---|---|
| Debian 13, arm64, kernel 6.12, bubblewrap 0.12.0, Lima VM `sbx-dev` | default (rerun after the macOS review fixes) | 293 | 5 | 0 |
| Debian 13, x86_64, Proxmox kernel 7.0.14, LXC container, bubblewrap 0.12.0 | `SBX_SSH=user@host` (rerun after the macOS review fixes) | 293 | 5 | 0 |
| Ubuntu 24.04.5, arm64, kernel 6.8, bubblewrap 0.9.0 from apt, AppArmor restriction on, Lima VM (made with `limactl create --name=sbx-ubuntu --cpus=4 --memory=4 --set '.mounts=[]' template:ubuntu-24.04`, plus `bubblewrap` and `gcc`, and Go copied in for cgo) | `SBX_VM=sbx-ubuntu SBX_APPARMOR=1` (rerun after the macOS review fixes) | 293 | 5 | 0 |

The counts include subtests, and are the same with and without cgo. `SBX_APPARMOR=1` loads the profile for the test binary with `scripts/apparmor.sh` and removes it after. Without it, the same Ubuntu run fails 159 of the tests that start a sandbox, in 11 seconds and with no hang, and `TestProbeVM` shows the diagnostic. `SBX_LOCAL=1` runs on the machine the script is on, which is how CI runs it.

The skips are the same on every target except where noted. `TestWriteApparmorProfile` is the helper that `scripts/apparmor.sh` calls, and skips unless asked. `TestAPIRlimits` skips where the host's hard core limit is unlimited, so no higher one can be asked for. `TestAPICgroupFD` skips where the login session has no delegated cgroup to start in. The `.zfs` case of `TestEscapeMountTableCovers` skips where there is no ZFS dataset (`TestMountCovers` checks the rule on a fake mount table). Two differ by target. The foreign-ABI case of `TestEscapeSeccomp` skips on arm64, since a Go test there cannot call another ABI (`TestSeccompFilter` checks the architecture test offline), and runs on amd64. `TestEscapeSessionKeyring` skips on the LXC host, whose seccomp profile makes the key calls fail with `ENOSYS`.

The LXC host differs from a VM in ways that changed three tests, which now allow for it. Its seccomp profile is inherited by every process, so `TestCheckVM` no longer requires `proc.seccomp` to fail without a sandbox. Its Yama `ptrace_scope` is 1, so `proc.trace` passes without a sandbox. Its `nsswitch.conf` lists `systemd`, so with cgo `user.Lookup` finds `root` and `nobody` even though the sandbox's `/etc/passwd` does not (`TestEscapePasswd` still requires the exact file). `TestCheckArgvHoldsNoSettings` also flagged the check child's own namespace attempts, `--sandbox-check noop` and `mount`, which a fast sampler sees. It now accepts those two fixed modes. The arm64 VM's slower sampler had been missing them.

On Ubuntu 24.04 the tests run as the account's uid under a profile for the test binary. The suite passes on apt's bubblewrap 0.9.0, so the 0.8 floor is tested at 0.9, and the symlink flaw fixed in 0.12.0 stays open there as noted above.

### macOS

The tests start real sandboxes with `/usr/bin/sandbox-exec` as the account's own uid, and need no setup. `go test` and `go test -race` run the whole suite on the machine, and CI runs both on `macos-latest`. A tree that holds the test binary, `/bin/sh`, and, for two tests, `/Applications/Firefox.app` and a C compiler is all they need, and those tests skip without them. Every path a test gives a `Spec` is a real one, since `t.TempDir()` leads through `/var`.

| Target | How | Pass | Subtests | Skip | Fail |
|---|---|---|---|---|---|
| macOS 27.2.1, arm64, Apple silicon, Go 1.27 | `go test` | 131 | 91 | 1 | 0 |
| the same | `go test -race` (about 6.5 minutes, since each sandbox starts a race-built binary) | 131 | 91 | 1 | 0 |
| macOS 27.2.1, amd64 under Rosetta 2 on the same Mac, Go 1.27, cross-built with `GOARCH=amd64` | `go test` (`CGO_ENABLED=0`; about 1 minute) | 130 | 91 | 2 | 0 |
| the same | `go test -race` (`CGO_ENABLED=1`, about 6.5 minutes) | 130 | 91 | 2 | 0 |

The counts are top-level tests and their subtests, and the arm64 skip is `TestWriteApparmorProfile`, the Linux AppArmor helper. Under Rosetta, `TestEscapeLaunchServicesRawXPC` also skips: the Command Line Tools' `cc` shim is arm64 only and cannot start under `arch -x86_64`, so the test cannot build its C client there. It runs on arm64. The suite found macOS 27.0.1 and 27.2.0 differ: curl needed one more Mach service on 27.2.0.

- **API tests** (`api_guarantee_darwin_test.go`) try every public contract: what `Command` refuses, what `Start` does and undoes on failure, each `Spec` and `Cmd` field, `Run`, `Footprint`, limits, listeners and concurrent sandboxes.
- **Escape tests** (`escape_guarantee_darwin_test.go`) take each cell of the macOS column of design.md's table and run code inside a sandbox that tries to get past it. Each says which row it checks. A guarantee that cannot be given has a `TestGap...` that shows the gap and fails when it closes. `escape_review_darwin_test.go` holds the tests for the review's findings and its re-review's: the ways out of teardown and `Footprint`, a process that re-forks every millisecond, the marker and the refusal of a second profile it rests on, a reused group number, a sandbox replacing its own root, firmlink names, the device list, `F_SETOWN`, Loopback ports on every address, the caller's environment, and one sandbox signaling another. `profile_darwin_test.go` checks the generated profile as text, `probe_darwin_test.go` and `check_sandbox_darwin_test.go` check `Probe` and `Check`, and `firefox_darwin_test.go` renders a page with headless Firefox under the generated profile.
- **Mutations.** Each check that guards a rule was checked to fail with the rule taken out: the foreground of the terminal, the quoting of paths, the `process-info` deny, the group kill when the command exits, the group kill when the stage is killed, the lifeline, the terminal deny, the `localhost` deny of `NetworkHost`, the covers, the signal target, the loopback port rule and the readable `SelfPath`. They run on a copy of the tree, never in place, and a mutation that allows signals is run with probes that signal nothing (`kill` with 0, a harmless signal for the broadcasts), since a profile that fails open would otherwise signal the caller's own processes. The test for the localhost deny does not detect the form of the allow before it: see the finding above. The checks for the review's findings were mutated the same way: the teardown without the marker (every wait in `TestEscapeSetpgidAndJobControl` times out, and the command that joined the caller's group is not counted), the profile without the denies at each root, with the old `/dev` regular expression, with `ip` for `tcp` on the Loopback rules (UDP then binds), and `canonicalName` as the identity (a `Cover` by the data volume's name then leaves the secret readable). The `/dev` mutation is a reason `TestEscapeDevices` only stats: an earlier version opened every device with the old profile and hung on one.

Two groups of tests carry the guarantees:

- **API tests** (`api_guarantee_linux_test.go`) try every public contract: what `Command` refuses, what `Start` does and undoes on failure, each `Spec` and `Cmd` field, `Run`, and concurrent sandboxes.
- **Escape tests** (`escape_guarantee_linux_test.go`, and `hardening_linux_test.go` for the review's findings) take each Linux guarantee in design.md's table and run code inside a sandbox that tries to get past it. Each test says which row it checks. `TestEscapeChecksCatchEscapes` runs the checks against sandboxes that have the hole, to see that they fail.

Each check that guards a finding was checked to fail with the fix taken out: the covers, the filter, the first stage's private mounts, `--as-pid-1`, the cover of other file types, the mount order, the netfilter rule, and the four from the latest review (the sandbox's process group and foreground, the read-only `/dev`, and the session keyring; the descriptor test documents a behavior and fails if it changes). The ZFS fix was checked by hand on the ZFS host, as [spikes.md](spikes.md) records.
