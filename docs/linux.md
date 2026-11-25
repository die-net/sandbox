# The Linux backend

How the sandbox is built on Linux, and what was tried and dropped. [security-model.md](security-model.md) says what it guarantees and [findings.md](findings.md) says what each part of it fixed.

## bubblewrap

bubblewrap builds the sandbox. It's the setup Flatpak runs every app through, so a reviewer can rely on its record and read only what this package hands it, where a builder of our own would have to be reviewed whole.

- The package needs bubblewrap 0.8.0 or later, from the distribution. The suite passes on 0.12.0, 0.9.0 and 0.8.0.
- It refuses a setuid copy, since bubblewrap's serious past flaws were in its setuid mode.
- `Command` works out the view. `Start` hands bubblewrap every option on a descriptor with `--args`, so pid 1's command line, which any process inside can read, doesn't list them.
- Each bind source is opened by the caller's process and passed as a descriptor with `--bind-fd` or `--ro-bind-fd`. The account's `passwd` and `group` entries go in with `--ro-bind-data`.
- bubblewrap makes new user, mount, pid, IPC and UTS namespaces, and a network namespace unless `NetworkHost` is asked for. It maps the account's uid and gid to the same ids inside, and closes every descriptor it was handed before it starts the command.
- The command follows `--` in bubblewrap's own argv. Putting it inside the `--args` body gives a usage error.

`Command` refuses to run as root. It opens paths and writes the sandbox's `passwd` in the calling process, so a caller that runs as root must switch to the sandbox's uid first.

Two options are left out on purpose, and one is off by default:

- **`--new-session`**, unless `Spec.OwnSession` is set. By default the command stays in its caller's session, which a caller may check a bridge by, and the filter refuses `TIOCSTI` instead. With it, bubblewrap calls `setsid` in pid 1, which `--as-pid-1` makes the first stage, so `Pid` leads the session and every process the command starts is in it (`TestEscapeOwnSession`, on bubblewrap 0.8.0, 0.9.0 and 0.12.0). pid 1 isn't a process group leader, since bubblewrap has a group of its own, so `setsid` can't fail there.
- **`--die-with-parent`.** See [the lifeline](#the-lifeline).
- **`--seccomp`.** The filter refuses calls the first stage makes, so the stage installs it after them.

### Descriptor passthrough

Spike L1 checked that bubblewrap passes unnamed inherited descriptors through to pid 1, which the control socket, the lifeline and `Spec.Files` all rest on. It ran on bubblewrap 0.12.0 on Debian 13, with a throwaway program that played the parent, the stage and the command. All of this held:

- Unnamed descriptors reach pid 1 at their numbers. bubblewrap consumes and closes the `--args` and `--info-fd` descriptors before the exec, so neither reaches pid 1.
- `--info-fd` gives `{"child-pid": N}`, and `N` is pid 1's host pid (`NSpid: N 1`).
- A listener bound inside `--unshare-net` and sent out over a `SOCK_SEQPACKET` socket with `SCM_RIGHTS` reaches the parent, which can accept on it and talk to the command.
- After pid 1 closes its end, the parent reads EOF on the control socket, so bubblewrap's monitor process holds no copy of it.
- The command holds only its own descriptors: no control socket, no lifeline, no info descriptor.
- Closing the lifeline's write end ends pid 1, bubblewrap and the command. So does `kill -9` of the parent, with no `Pdeathsig` anywhere.
- Inside `--unshare-all` the only interface is `lo`. TCP to a public address and to the gateways, and UDP, all fail with `network is unreachable`.

One caveat came out of it. The spike closed descriptors 3 and 4 in pid 1 "to be safe", and by then those numbers were Go's own epoll descriptor, so the runtime crashed with `epollwait on fd 4 failed with 9`. The stage must never close a descriptor by number once Go is running. It marks the inherited ones close-on-exec.

## The view

bubblewrap makes these mounts parent first, so a path bound back under a cover gets its mount point in the cover:

- The host's root, bound recursively and read-only.
- An empty tmpfs over each covered directory, made read-only once the binds inside it are in place. `/dev/null` goes over any other covered path, such as a file or a socket, which nothing can read from or connect to.
- The sandbox's own home and `Write` paths, read-write.
- Its `Read` paths, and the regular files that links in the host's `/etc` lead to under a default cover (such as Ubuntu's `/etc/resolv.conf`), read-only.
- A fresh `/proc`, and bubblewrap's own `/dev` with a new `devpts` instance, made read-only once `/dev/shm` and the stage's binary are mounted in it.
- A writable tmpfs for each of `/tmp`, `/var/tmp` and `/dev/shm`, each holding at most `Spec.ScratchSize` bytes (1 GiB by default), set with bubblewrap's `--size`.
- A `passwd` and `group` with one entry for the sandbox's uid and gid, whose home is its own directory.
- This binary, read-only at `/dev/sandbox-stage`, for the first stage.

Every tmpfs the sandbox can write has a size. The device nodes in `/dev` still work: `null`, `zero`, `full`, `random`, `urandom`, `tty`, `ptmx` with `/dev/pts`, and the `/dev/fd` and `/dev/std*` links.

Memory that isn't a file is outside the limit. `memfd_create` and anonymous shared memory count against no tmpfs, so only a cgroup's `memory.max` bounds them. A caller that needs that limit delegates a cgroup and passes it as `Cmd.CgroupFD` ([usage.md](usage.md#limits)).

The covered paths are:

- Every path the caller names in `Spec.Cover`.
- People's homes: the account's own, each home in `/etc/passwd` that its account owns, and the whole directory where two or more such homes sit side by side, which also hides homes that `/etc/passwd` doesn't list.
- `/home`, `/root`, `/run`, `/tmp`, `/var`, `/mnt`, `/media`, `/dev/shm`, snapper's `/.snapshots`, and an ostree host's `/sysroot`.
- From the host's mount table, every ZFS dataset's `.zfs` directory, and any other mount of a filesystem that shows a covered path somewhere else, such as a bind mount.

A cover inside another is left out when nothing bound between them would show it. A cover at the same path as a bind is left out too, since the bind shows that path whole.

The root is bound whole, rather than a list of what programs need, because a list is what breaks `npx`, `uvx` and toolchains under `/opt`, `/usr/local` or `/nix`. That's safe because file modes still apply inside, and the sandbox's uid owns nothing outside its own directories and the covered ones. It holds only while the account has no supplementary groups, since an unprivileged user namespace keeps them. `Check` warns about any.

## Paths and links

A sandbox's home and `Write` paths are untrusted: an earlier run, or another sandbox that shares the directory, may have changed what is in them. So `Command` and `Start` resolve every path themselves before bubblewrap starts:

- A home or `Write` path must have no link in it at all, since a sandbox that can write a directory on the way could have planted it. That refuses a link the operator made too, such as an ostree host's `/home`. The caller has to pass the real path, and must not resolve the path itself either.
- Any other path is followed through a link only where the link lies outside every directory the sandbox can write.
- The working directory is resolved the same way. It must be the home, a `Write` or `Read` path, or a path no cover hides, so a sandbox never starts in an empty cover.
- A covered path inside a writable directory that has gone missing stops the sandbox from starting, since a sandbox could have moved it away to uncover what it hid.
- No mount may lie inside the home or a `Write` path at all, and the home may not lie inside a `Write` path, since a sandbox that can rename a directory above it can put a link or a new tree there. So every mount point is inside a tmpfs bubblewrap made or a read-only host path, never content a sandbox wrote.
- Each bind source is opened with `openat2` and `RESOLVE_NO_SYMLINKS` and passed as a descriptor. A cover that has become a link since it was resolved stops the sandbox, so nothing swapped in between the check and the mount can redirect it.

## The first stage

bubblewrap doesn't start the command itself. With `--as-pid-1`, it starts this binary again inside as pid 1, holding `CAP_SYS_ADMIN` and `CAP_SETPCAP` from `--cap-add`. That first stage runs before anything untrusted does. Every program that starts sandboxes calls `Stage` first in `main`, which finds it. The stage:

1. Copies the view into a mount namespace of its own and makes every mount in it private. bubblewrap leaves the view a slave of the host's mounts, so a mount made on the host later would appear inside. Run unprivileged, bubblewrap puts pid 1 in a user namespace nested inside the one that owns the view's mounts, so its capabilities can't change the view.
2. Joins a new, anonymous session keyring, so the sandbox doesn't share the caller's.
3. Drops every capability, its bounding set included, and sets `no_new_privs`. Both belong to a thread, so it does this on the one thread it has locked, the one that execs next. It also asks to die with bubblewrap's outer process.
4. Execs itself again. `unshare` moves only the calling thread, which leaves the whole of pid 1 in the new namespace and no process inside in bubblewrap's. The new image starts with that one thread's empty sets, so no thread of pid 1 holds a capability, and neither does the command, even as uid 0 inside. This second run, the reaper, makes itself undumpable, so the command can't open its memory, descriptors or root through `/proc`.
5. Reads its settings from the control socket, binds the `Listen` listeners, sets the `Rlimits` (pid 1 holds them too), marks every inherited descriptor but the command's own close-on-exec (with `close_range`, or from `/proc/self/fd` before Linux 5.11, and if neither works it starts nothing and replies with the error), and installs the seccomp filter on all its threads.
6. Sends the caller the listeners, or its setup error, on the control socket, and closes the socket.
7. Starts the command. It then passes any `SIGTERM` or `SIGHUP` it gets on to the command, reaps orphans, and exits with the command's status, which ends everything left inside.

The stage holds `CAP_SYS_ADMIN` in its nested user namespace while the binary starts. So whatever runs before `Stage`, such as its libraries' `init` functions, runs with it. That is the adopting program's own code and what it links, not anything the sandbox runs, so such programs keep `init` functions out of it ([open issues](security-model.md#open-issues)).

## The control socket

A `SOCK_SEQPACKET` socketpair, passed through bubblewrap, carries the stage's settings in (the kernel level, the listener count, the file count and the limits) and its one reply out, with the listeners as descriptors. The command line used to carry them, which left pid 1's argv naming them and made an exit status the only way to report an error.

The socket is trusted only during setup. Pid 1 sends its reply, stops reading and closes its end before the command starts, so no untrusted code ever holds it. The caller ignores anything that arrives on it afterwards. It takes the sandbox's pid from `--info-fd` and nowhere else, since a process that could write the socket could lie about it.

## The lifeline

The caller passes pid 1 the read end of a pipe and keeps the only write end, close-on-exec. Pid 1 reads it from its first moment. When it reaches EOF, which is when the caller closes it or dies, however it dies, pid 1 exits and the namespace's other processes die with it. A caller that dies during setup leaves no command running either, since the closed write end reads as EOF whenever it's first read. A caller that dies after bubblewrap makes pid 1 but before it reads `--info-fd` only costs bubblewrap a `SIGPIPE`, and pid 1 reads EOF anyway.

`--die-with-parent` isn't used, and neither is `Pdeathsig` on the caller's side. Both fire when the OS thread that started the process exits, not when the process does, and a Go server's threads come and go. A locked goroutine that called `Start` and returned killed its sandbox.

The first stage sets `PR_SET_PDEATHSIG` on itself instead, whose parent is bubblewrap's outer process, a single-threaded program. Without it, a bubblewrap killed alone would leave pid 1 and the command holding the caller's output pipes, and `Wait`, which closes the lifeline, would never get past copying them.

## The process group and the terminal

`Start` always starts bubblewrap in a process group of its own, and keeps the caller's session unless `OwnSession` moves pid 1 to one of its own. The filter allows `kill`, `tgkill`, `pidfd_send_signal` and `setpriority`, and the kernel lets a process signal or renice a group in another pid namespace when the uid matches. A sandbox that shared its caller's group could end the caller and its siblings with `kill(0, sig)`, or slow them with `setpriority(PRIO_PGRP, 0, n)`. In a group of its own, `kill(0)` and `kill(-1)` reach only the sandbox.

A background group is stopped when it reads the terminal. So when `Stdin` is a terminal whose foreground group is the caller's, which is what `Run` passes, the sandbox's group takes the foreground. `Wait` gives it back to the caller's group, if the sandbox still holds it, with `SIGTTOU` blocked on the calling thread, since setting the foreground from the background would otherwise stop the caller. A Ctrl-C then goes to the sandbox's group and not the caller's. For `Run` that is enough: bubblewrap ends, and pid 1 follows it.

With `OwnSession`, `Start` doesn't hand the foreground over. The sandbox's session has no controlling terminal, so job control doesn't stop its reads (`tty_check_change` in `drivers/tty/tty_jobctrl.c` checks only a process's own controlling terminal), and no group in it could hold the terminal's foreground. bubblewrap's group would hold only bubblewrap's outer process, and a Ctrl-C there would end the sandbox while the caller kept running. The caller keeps the foreground, and a Ctrl-C goes to it (`TestOwnSessionTerminal`).

## The network

`NetworkNone`, the default, gives the sandbox a network namespace with only a loopback, which is private to it. That also makes the host's abstract sockets unreachable.

- **`Listen`.** The stage binds that many TCP listeners on `127.0.0.1` in the namespace, from port 3128, and sends them to the caller to serve.
- **`Loopback`.** Reserves ports from 4444 for a command that serves itself, such as a browser and its driver.
- **`NetworkHost`.** Shares the host's network, with its loopback and abstract sockets. It has to be asked for, and can't be combined with `Listen` or `Loopback`.

## The filter

The filter is an allowlist from the system calls Docker's default profile allows without a capability, as Go constants from `x/sys/unix` for amd64 and arm64. It refuses the rest with `ENOSYS`, so a call added in a later kernel stays refused until it is reviewed, and a program falls back as it would on an older kernel. It leaves out io_uring, `bpf`, `perf_event_open`, `userfaultfd`, the key calls, module and `kexec` calls, `ptrace`, the mount calls, `unshare` and `setns`.

Of what it allows, it checks the arguments of:

- **`clone`**, which may not make namespaces. `clone3` passes its flags in memory, where the filter can't read them, so it is refused, and libc falls back to `clone`.
- **`socket`**, which only makes Unix sockets and stream and datagram IP sockets of TCP, UDP and ping. Another family gets `EAFNOSUPPORT` and another type `ESOCKTNOSUPPORT`, so a program that probes falls back. Raw and packet sockets get `EPERM`.
- **`socketpair`**, which only makes Unix pairs.
- **`ioctl`**, which may not use `TIOCSTI` or `TIOCLINUX`, either of which could type a command into the terminal of whoever started the sandbox.
- **`setsockopt` and `getsockopt`**, which may not use the legacy netfilter options that replace and read iptables, arptables, ebtables, ip6tables, ipset and IPVS state.
- **`personality`**, which takes only the values Docker allows.

A call through another ABI, such as 32-bit x86 or x32, gets `ENOSYS`. The filter checks only the low 32 bits of each argument, since the kernel reads only those, so a caller can't pass a check by setting a high bit. Argument checks come before the plain list, so the kernel caches the result for every call on it. A call took about 7 ns longer under the filter on the spike's host.

The `Kernel` setting relaxes it:

- **`strict`**, the default, is the filter above.
- **`nested`** also allows user namespaces, the mount calls and `chroot`, for software that runs a sandbox of its own, such as Chromium or bubblewrap. The kernel locks the mounts it copies into a namespace the code makes, so it can't unmount a cover, make a read-only bind writable, or bind the root elsewhere without its covers. It can map its own uid and mount a tmpfs of its own, which those sandboxes need, and filesystems an unprivileged user namespace may mount, such as overlayfs and FUSE, which puts their code within its reach. The netfilter options stay refused.
- **`open`** gives up the allowlist, and keeps refusing other ABIs and the terminal ioctls. On an architecture with no list, such as 32-bit arm, it has no filter at all. It allows the key calls, which is why the stage gives the sandbox a session keyring of its own at every level.

A level is only raised, never lowered. `Command` refuses one the host can't give, and `Probe` shows which it can.

## Descriptors handed in

`Spec.Files` and the command's `Stdin`, `Stdout` and `Stderr` become descriptors in the command. Only descriptors 0 to 2 and the `Files` are open in it, at fixed numbers. The stage marks every other descriptor close-on-exec rather than closing it by number, since once Go's runtime is up a number may be one of its own, such as its epoll descriptor.

A descriptor is more than the access it was opened with. It grants whatever the underlying object's owner and mode let the sandbox's uid do, whatever mode the caller opened it in and whatever the sandbox covers, because `/proc/self/fd/N` reopens it. That is how Unix descriptors work, and nothing here prevents it. A caller that needs a limit passes a pipe or a socket. A socket can't be reopened, and a pipe reopens only as another end of the same pipe. [The finding](findings.md#descriptors-handed-in-reach-more-than-they-were-opened-for) shows it.

## Probe and Check

`Probe` tries the backend and returns a `Report`: which backend, which kernel levels it can give, whether killing the sandbox kills every process in it, whether loopback is private, and what the host's container is. When no sandbox can start, `Report.Checks` ends at the first prerequisite that blocks it, with the fix. They are checked in this order:

1. bubblewrap missing, setuid or older than 0.8.
2. Ubuntu's AppArmor restriction on user namespaces.
3. A sysctl that turns user namespaces off.
4. Docker's or Podman's default seccomp profile.
5. Docker's AppArmor profile.
6. A masked `/proc`.
7. A systemd unit's restrictions.

[usage.md](usage.md#probe-and-check) says how a program uses them.

The AppArmor fix is a profile for this one binary's path, which the package generates. It grants user namespaces to that binary and what it starts, and to no other program. It doesn't use a child profile for bubblewrap: the kernel ignores exec rules in an unconfined-mode profile, so bubblewrap would stay in the parent's label and be refused. Without the profile on Ubuntu 24.04, `Probe` names it, but `Start` fails with bubblewrap's own message, such as `loopback: Failed RTM_NEWADDR: Operation not permitted`, because the kernel lets bubblewrap make a user namespace and takes its capabilities away.

`Check` runs the escape attempts of the generic suite in a child of this binary, inside a sandbox built from a `Spec` or, with none, in the caller's own context, which is what an operator's container or unit gives. The child is started with a marker that `Stage` handles, and gets its settings on a descriptor, not in argv. Each attempt returns a pass when it failed. The suite tries to:

- make a user namespace, mount a tmpfs, call `io_uring_setup`, replace an iptables table, load a BPF program and make a cgroup;
- signal, trace and read the environment of processes outside;
- read well-known secrets and reach well-known sockets;
- write outside the home, read under each cover and reach the network directly.

It also reports capabilities, `no_new_privs`, the seccomp mode and supplementary groups, and it takes a caller's own `Unreadable`, `Unwritable` and `Unreachable` lists. A pass means one attempt failed, not that every path is closed.

## Tried and dropped

- **Landlock alone.** Before ABI 9 it doesn't check socket files, so it doesn't keep a sandbox off the account's own services, and it leaves ptys, SysV IPC and other processes' command lines open too.
- **Landlock inside the namespaces.** Its file rules come from the same paths as the mounts, so they shared the mounts' mistakes: both planted-link findings got through it. Its ptrace and signal scopes repeat the pid namespace, and its abstract-socket scope and port rule repeat the network namespace. Under `nested` it refused what the mount locks already refuse, and stopped Chromium's and bubblewrap's sandboxes from starting, since it refuses mounts and writes to `/proc/<pid>/uid_map`. Its one real job, keeping a sandbox off the host's abstract sockets, ended when the network namespace came. Taking it out also took out a walk of the host's root on every start (a workaround so renames between directories work), refused terminal ioctls on device files, and a dependency from outside the standard library and `golang.org/x`. The filter still allows the Landlock calls, so a program inside can use Landlock on itself, as Cursor's sandbox does.
- **A namespace builder of our own.** The spike built the namespaces and the view itself with Go's `SysProcAttr`, a staging root and `pivot_root`. It worked, but its whole setup would have to be reviewed, where bubblewrap's has a long record. It had already needed a fix that bubblewrap doesn't: Go's ambient setup leaves capabilities in the inheritable set, which a file's inheritable capabilities combine with outside the bounding set.
- **bubblewrap's `--seccomp`.** The filter refuses the calls the first stage makes, so the stage installs it after them.
- **bubblewrap's `--new-session` by default.** It would guard against `TIOCSTI`, but a new session fails a caller's check that a bridge is in the session of the command's starter. A process group of its own does the job a session would for signals. The filter refuses `TIOCSTI` instead. `Spec.OwnSession` turns it on for a caller that checks by the sandbox's own session instead.
- **bubblewrap's `--die-with-parent` and `Pdeathsig`.** Both fire on the exit of the thread that started the process. The lifeline replaces them ([the lifeline](#the-lifeline)).
- **bubblewrap's `--cap-add` to change the view or the network.** Unprivileged bubblewrap runs the command in a user namespace nested inside the one that owns the view's mounts and the network namespace. So the capabilities are real but don't reach either. That's why the first stage makes a mount namespace of its own, and why adding routes would need a network namespace of its own too.
- **The first stage making only itself private.** `unshare` moves one thread, and bubblewrap's own reaper stays behind, so other processes inside still see the host's later mounts through `/proc/<pid>/root`. The stage execs itself and is pid 1.
- **Letting the caller pick the process group.** A `Setpgid` field on `Cmd` made the shared group the default. Every sandbox gets its own now, and the field is gone.
- **Reading the pid from the control socket.** A sandbox that could write to it could lie. The pid comes from `--info-fd`.
- **Closing inherited descriptors by number.** Once Go's runtime is up, a freed number may be its epoll descriptor, which crashed the spike. The stage marks them close-on-exec.
- **Covering the machine id.** The sandbox makes no claim to hide the host, and addresses and much else identify it anyway.
- **elastic/go-seccomp-bpf.** It can't make `ENOSYS` the default or answer `EAFNOSUPPORT`, so the filter is written with `x/net/bpf` instead.
