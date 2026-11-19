# Sandbox

This module (`github.com/die-net/sandbox`) runs a command in a sandbox, in place, without root. On Linux it uses bubblewrap, a seccomp filter and namespaces. A macOS backend with Seatbelt is planned. It was extracted from the legwork project, whose sandbox it began as, and [design.md](design.md) says how it is meant to be used by the projects that adopt it.

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

`Probe` tries the backend and returns a `Report`: which backend, which kernel levels it can give, whether killing the sandbox kills every process in it, whether loopback is private, and what the host's container is. When no sandbox can start, `Report.Checks` ends at the first prerequisite that blocks it, with the fix. Those are bubblewrap missing, setuid or too old, Ubuntu's AppArmor restriction on user namespaces, a sysctl that turns them off, Docker's and Podman's default profiles, a masked `/proc`, and a systemd unit's restrictions. The AppArmor fix is a profile for this one binary's path, which the package generates.

`Check` runs the escape attempts of the generic suite in a child of this binary, inside a sandbox built from a `Spec` or, with none, in the caller's own context, which is what an operator's container or unit gives. The child is started with a marker that `Stage` handles, and gets its settings on a descriptor, not in argv. Each attempt returns a pass when it failed. The suite tries to make a user namespace, mount a tmpfs, call `io_uring_setup`, replace an iptables table, load a BPF program, signal and trace and read the environment of processes outside, read well-known secrets and reach well-known sockets, write outside the home, read under each cover, reach the network directly, and make a cgroup. It also reports capabilities, `no_new_privs`, the seccomp mode, and supplementary groups, and it takes a caller's own `Unreadable`, `Unwritable`, and `Unreachable` lists. A pass means one attempt failed, not that every path is closed.

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

## How it is tested

The tests run real sandboxes on Linux, as the account's own uid, which takes bubblewrap's unprivileged path as a deployment does. Running them as root of a user namespace had hidden that bubblewrap's capabilities do not reach the view. Some build a fake host first, in a user and mount namespace of their own: homes under `/srv`, a `passwd` that lists them, links in `/etc`, a stand-in for a caller's state, and a listening socket. The test binary is also the code that runs inside the sandbox, as its own first stage and as a checker the tests name.

`scripts/linux-test.sh` cross-compiles them, vets amd64, and runs them in a Lima VM (`sbx-dev`: Debian 13 on arm64, a 6.12 kernel, bubblewrap 0.12.0). About 290 tests and subtests pass. Four skip: `TestAPIRlimits`, where the host's hard core limit is unlimited and no higher one can be asked for, `TestAPICgroupFD`, where the VM session has no delegated cgroup to start in, the foreign-ABI case of `TestEscapeSeccomp`, since a Go test on arm64 cannot call another ABI (`TestSeccompFilter` checks the architecture test offline), and the `.zfs` case, since the VM has no ZFS dataset (`TestMountCovers` checks the rule on a fake mount table).

Two groups of tests carry the guarantees:

- **API tests** (`api_guarantee_linux_test.go`) try every public contract: what `Command` refuses, what `Start` does and undoes on failure, each `Spec` and `Cmd` field, `Run`, and concurrent sandboxes.
- **Escape tests** (`escape_guarantee_linux_test.go`, and `hardening_linux_test.go` for the review's findings) take each Linux guarantee in design.md's table and run code inside a sandbox that tries to get past it. Each test says which row it checks. `TestEscapeChecksCatchEscapes` runs the checks against sandboxes that have the hole, to see that they fail.

Each check that guards a finding was checked to fail with the fix taken out: the covers, the filter, the first stage's private mounts, `--as-pid-1`, the cover of other file types, the mount order, the netfilter rule, and the four from the latest review (the sandbox's process group and foreground, the read-only `/dev`, and the session keyring; the descriptor test documents a behavior and fails if it changes). The ZFS fix was checked by hand on the ZFS host, as [spikes.md](spikes.md) records.
