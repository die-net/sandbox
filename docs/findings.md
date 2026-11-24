# Findings

Read this before changing the sandbox. Each of these is an attack that worked once.

Reviews by Fable, each given only the design and the code, and re-checks of their fixes, found these. Most were confirmed on a Proxmox VE container on ZFS with a 7.0 kernel. The later ones were confirmed in a Debian 13 VM on arm64 with a 6.12 kernel. The macOS findings came from running things under profiles on macOS 27.0.1 and 27.2.0, since the macOS design rested on inferences.

Each finding says how it worked, what stops it now, and the test that checks it. [security-model.md](security-model.md) has the guarantees, and [linux.md](linux.md) and [macos.md](macos.md) have the mechanisms.

- [Covered files reached another way](#covered-files-reached-another-way)
- [Paths and links](#paths-and-links)
- [Processes and the kernel](#processes-and-the-kernel)
- [Found by the security review of the Linux backend](#found-by-the-security-review-of-the-linux-backend)
- [Found while building the macOS backend](#found-while-building-the-macos-backend)
- [Found by the review of the macOS teardown proof](#found-by-the-review-of-the-macos-teardown-proof)
- [Found in the code and plans of the projects that adopt it](#found-in-the-code-and-plans-of-the-projects-that-adopt-it)

## Covered files reached another way

### Landlock alone reached the account's own services

- **How it worked.** Before ABI 9, Landlock doesn't check `connect()` on a socket file. A sandbox reached the account's systemd user manager and read a covered file out through `systemd-run --user`. ptys, SysV IPC and other processes' command lines leaked the same way.
- **What stops it.** Landlock is gone ([linux.md](linux.md#tried-and-dropped)), the namespaces are the floor, and `/run` is covered.
- **Test.** `TestIsolation` connects to a socket file outside.

### Landlock alone granted every pty read-write

- **How it worked.** A sandbox could write to an admin's terminal on the same account.
- **What stops it.** bubblewrap's `/dev` has a new `devpts` instance.
- **Test.** No test of its own. `TestEscapeDevReadOnly` checks that a new pty works in the sandbox's `/dev`, and `TestEscapeSeccomp` checks the terminal ioctls.

### ZFS snapshots showed covered files

- **How it worked.** Every snapshot of a dataset is under its `.zfs`, at paths no cover names, even with `snapdir=hidden`. File modes don't help when the sandbox's uid owns the files. A sandbox read a covered home's `.bash_history` through `/.zfs/snapshot`.
- **What stops it.** Covers now come from the mount table too: every ZFS dataset's `.zfs` directory, and any other mount of a filesystem that shows a covered path.
- **Test.** `TestMountCovers` checks them on a fake mount table, and `TestEscapeMountTableCovers` runs a real one (its `.zfs` case skips where there's no ZFS). The fix was checked by hand on the ZFS host, since the VM has none.

### A host mount made after start appeared inside

- **How it worked.** bubblewrap leaves the view a slave of the host's mounts, so a later bind of a covered path showed inside a running sandbox.
- **What stops it.** The first stage gives it private mounts of its own.
- **Test.** `TestLateMounts` binds a covered directory on a fake host once the sandbox has started.

### pid 1's root showed the host's later mounts

- **How it worked.** When only the first stage moved to private mounts, bubblewrap's own reaper stayed in the old namespace, and the command read a later mount through `/proc/1/root`.
- **What stops it.** The stage is pid 1 now (`--as-pid-1`), undumpable, with no process left in the old namespace.
- **Test.** `TestLateMounts` also reads through `/proc/1/root`, and fails without `--as-pid-1`.

### A cover on a socket was skipped

- **How it worked.** Covers handled only directories and regular files, so a covered listening socket stayed reachable.
- **What stops it.** Anything but a directory now gets `/dev/null`.
- **Test.** `TestIsolation` covers a listening socket and expects `ECONNREFUSED`.

## Paths and links

### A planted link pointed the next sandbox at the caller's state

- **How it worked.** `prepare` followed links outside the sandbox, so a run replaced a directory in its home with a link to the state directory, and the next run had the state bound read-write.
- **What stops it.** Links in writable directories are now refused ([linux.md](linux.md#paths-and-links)).
- **Test.** `TestResolve`, `TestPrepare` and `TestRefusedLayouts` plant them.

### A covered path moved away was uncovered

- **How it worked.** A missing cover was skipped, and a sandbox can rename a directory it can write.
- **What stops it.** A missing cover inside a writable directory now stops the sandbox.
- **Test.** `TestRefusedLayouts` moves one.

### A cover inside the home never took effect

- **How it worked.** Pruning dropped it as inside `/home`, and the home's bind went on top of it, so another sandbox's saved sessions were readable.
- **What stops it.** Covers are now pruned by the nearest mount above them, and no cover may lie inside the home at all. So each sandbox that must be kept apart gets a home of its own.
- **Test.** `TestCovers` and `TestRefusedLayouts` check both.

### A home that was also covered became read-only

- **How it worked.** The account's own home and the homes `/etc/passwd` gives it are covered. A deployment whose sandbox home was one of them, outside every default cover, had the cover and the home's bind at one path. bubblewrap remounts a cover read-only once the binds are in, and the remount took the bind on top, so the home couldn't be written. The same happened with a path given both as a cover and as a `Write` path.
- **What stops it.** A cover at a bind's path is now left out.
- **Test.** `TestCovers` checks it, and `TestHomeCovered` writes in such a home.

### bubblewrap follows a link while it makes a mount point

- **How it worked.** Before 0.12.0, setup can follow a symlink in a mount destination's parent and create files on the host as the account (CVE-2026-87766, GHSA-pxhw-h44j-8pfx). Debian 12 won't fix it, and Ubuntu 24.04 rolled its fix back.
- **What stops it.** No mount may lie inside a directory a sandbox can write, so there's no parent a sandbox could have planted a link in.
- **Test.** `TestPrepare` refuses such layouts.

### A link where a tool's directory should be

- **How it worked.** A run's CLI could write the scratch directory that held its shell commands' `work` directory, so a link planted there would have made the next shell sandbox's home the CLI's home.
- **What stops it.** A home or `Write` path may have no link in it.
- **Test.** `TestPrepare` refuses a home through a link.

## Processes and the kernel

### pid 1 showed every cover

- **How it worked.** The spike's own builder ran its stages with the caller's arguments, so `/proc/1/cmdline` named every covered path, token files included.
- **What stops it.** bubblewrap now reads its options from a descriptor, and the stages' settings travel on the control socket.
- **Test.** `TestIsolation` checks pid 1's command line, environment and descriptors, and `TestEscapeOptionsNotInArgv` checks the options.

### The capability drop covered one thread

- **How it worked.** pid 1 dropped its capabilities and set `no_new_privs` after its second exec, on a goroutine not locked to a thread. Both are per thread, and bubblewrap raises `--cap-add` as ambient capabilities. So every other thread of pid 1 kept `CAP_SYS_ADMIN` and `CAP_SETPCAP`, and the command could be forked from one of them and keep them as ambient ones.
- **What stops it.** The first stage drops them on its locked thread before it execs, so the new image starts with none.
- **Test.** `TestIsolation` reads every set from the status of each thread of the command and of pid 1.

### A thread that couldn't take the filter went unnoticed

- **How it worked.** With `TSYNC`, the kernel reports a thread it can't move to the new filter by returning that thread's id with no error, and installs the filter on no thread at all. pid 1 checked only for an error, so it would have started the command with no filter.
- **What stops it.** Any result but 0 now stops the sandbox.
- **Test.** `TestSeccompUnsyncedThread` gives one thread a filter of its own first.

### `nested` reached iptables' table code

- **How it worked.** Code under `nested` that made its own user and network namespace held `CAP_NET_ADMIN` there, and `IPT_SO_SET_REPLACE` reached the code behind CVE-2021-22555, answering `EINVAL` where it should have been refused.
- **What stops it.** The filter refuses the netfilter options.
- **Test.** `TestSeccompFilter` checks them, and `TestNestedMounts` tries it from such a namespace.

### `open` left `TIOCSTI` open

- **How it worked.** With `--new-session` dropped, a command under `open` could type into its caller's terminal on a kernel before 6.2.
- **What stops it.** `open` keeps the terminal checks.
- **Test.** `TestSeccompFilter` and `TestKernelLevels` check `TIOCSTI` at every level.

### Every IP protocol and socket-pair family was open

- **How it worked.** The filter checked only the socket family, so SCTP, DCCP, L2TP, MPTCP and SMC were reachable, and a socket pair in any family loaded and ran that family's code.
- **What stops it.** The filter checks the protocol, and allows only Unix socket pairs.
- **Test.** `TestSeccompFilter` checks the protocols and pairs.

### Protocol 0 picked SCTP

- **How it worked.** Protocol 0 means whichever protocol registered the type first, so an IP sequenced-packet socket was SCTP with the module loaded.
- **What stops it.** Only stream and datagram IP sockets are allowed.
- **Test.** `TestSeccompFilter` checks `SOCK_SEQPACKET` and `SOCK_DCCP`.

### Temporary space had no limit

- **How it worked.** A tmpfs is as large as the host's memory allows, 47 GB on the spike's host, so a sandbox could fill memory through `/tmp`, `/var/tmp` or `/dev/shm`. That's a denial of service, not a leak.
- **What stops it.** Each holds at most 1 GiB, or `Spec.ScratchSize`, with bubblewrap's `--size` (from 0.7.0).
- **Test.** `TestEscapeScratch` checks each size from inside, and a write past it stops at the limit.

### A parent's thread exit killed its sandbox

- **How it worked.** bubblewrap's `--die-with-parent` is `PR_SET_PDEATHSIG` on bubblewrap, so it fires when the Go thread that started it exits. A locked goroutine that called `Start` and returned killed the sandbox.
- **What stops it.** The lifeline replaces it ([linux.md](linux.md#the-lifeline)).
- **Test.** `TestAPIStartThreadExits`, `TestEscapeParentKilled` and `TestCommandParentKilled`.

## Found by the security review of the Linux backend

A review of the finished backend by Fable 5.2 found four issues and no full escape.

### A sandbox could signal and renice its caller through the shared process group

- **How it worked.** `Start` put bubblewrap in the caller's own process group unless the caller asked for another. The filter allows `kill`, `tgkill`, `pidfd_send_signal` and `setpriority`, and a same-uid process may use them across a pid namespace on a group it can name. `kill(0, SIGUSR1)` from inside ended the caller, `kill -TERM 0` ended a sibling of the caller, and `setpriority(PRIO_PGRP, 0, n)` reniced the caller's group.
- **What stops it.** bubblewrap now always starts in a process group of its own, in the caller's session, so `kill(0)` and `kill(-1)` from inside reach only the sandbox. The `Setpgid` field of `Cmd` is gone, since it no longer means anything. When `Stdin` is a terminal the caller is the foreground of, the sandbox's group takes the foreground and `Wait` gives it back, because a background group stops on `SIGTTIN`.
- **Test.** `TestEscapeSignalsStayInside` runs `kill(0)`, `kill(-1)` and `setpriority` from inside, with a canary process in the caller's group, and asserts the canary and the caller are untouched. `TestEscapeTerminalForeground` runs a shell that reads a pty, which stops without the foreground, and checks the caller has the foreground again after `Wait`. `TestEscapeSessionKept` and `TestAPIProcessGroup` check every process is in one group that isn't the caller's, and in the caller's session.

### `/dev` was a writable tmpfs with no size

- **How it worked.** bubblewrap's `--dev /dev` makes a tmpfs with no size, and it was left writable. A sandbox with `ScratchSize` at 16 MiB wrote 64 MiB into `/dev`, past the limit, and so could fill the host's memory.
- **What stops it.** `/dev` is remounted read-only after everything mounted under it. That leaves `/dev/shm`, which is its own sized tmpfs, as the one place to write, and the device nodes, which are binds of the host's and work as before. It doesn't stop `memfd_create` and anonymous shared memory, which aren't files on any tmpfs: only a delegated cgroup's `memory.max` does ([usage.md](usage.md#limits)).
- **Test.** `TestEscapeDevReadOnly` creates files, directories and links in `/dev` and gets `EROFS`, walks the mount table and checks that every writable tmpfs the sandbox made reports a size no larger than `ScratchSize`, and checks the devices, a new pty, `/dev/fd` and `/dev/shm`.

### Descriptors handed in reach more than they were opened for

- **How it worked.** A file in `Spec.Files` that was under a covered directory and opened read-only was reopened write-only through `/proc/self/fd/3` and overwritten. A standard output opened append-only was truncated the same way. Opening through `/proc/self/fd` checks the file's owner and mode, not the mode the descriptor has, and not the covers.
- **What stops it.** Nothing, and nothing can: it's how Unix descriptors work. It's documented on `Spec.Files`, `Cmd.Stdin`, `Cmd.Stdout` and `Cmd.Stderr`. A caller that wants a limit passes a pipe or a socket.
- **Test.** `TestEscapeReopenDescriptor` documents it: a file opened read-only is reopened and rewritten, a socket can't be reopened (`ENXIO`), and a pipe reopens only as another end of the same pipe, where what the sandbox writes comes out of the pipe the caller holds and nothing else. It fails if the behavior changes, so the docs get changed with it.

### The caller's session keyring was readable under `open`

- **How it worked.** The sandbox inherited the caller's session keyring. `strict` and `nested` refuse `keyctl`, but `open` allows it, and the kernel's check on a key looks at the uid, which the sandbox keeps. A `keyctl` search and read inside returned a key the caller had added, such as a Kerberos ticket.
- **What stops it.** The first stage joins a new, anonymous session keyring (`KEYCTL_JOIN_SESSION_KEYRING` with no name) on its locked thread, before the filter and at every level, so the reaper and the command inherit it. A kernel with no key support, or a host filter that refuses `keyctl` with `EPERM`, as Docker's does, has nothing to join, and the same filter refuses it to the command.
- **Test.** `TestEscapeSessionKeyring` puts a key in a session keyring and the user keyring of a process of its own, runs a sandbox from it under `open`, and searches every keyring the sandbox has, and the caller's by id, for the key.

## Found while building the macOS backend

### `(deny default)` doesn't deny process-info

- **How it worked.** `proc_pidinfo` and `proc_pid_rusage` of any process of the uid succeeded under a deny-default profile with no `process-info` rule, and under `(allow process-info* (target self))`, which looks as if it should restrict them. The design counted on the default deny.
- **What stops it.** The profile denies `process-info*` by name, then allows it for `(target same-sandbox)`. With that, the sandbox's own processes can be asked about, and no one else.
- **Test.** `TestEscapeProcessInfo`, and `TestEscapeSignalsStayInside`, which also tries `proc_pid_rusage`. A mutation that removes the deny fails both.

### A profile can't stop another process's environment being read

- **How it worked.** `sysctl(KERN_PROCARGS2)` returns the environment of any same-uid process that isn't one of Apple's. It still did under `(deny process-info*)`, under `(deny sysctl-read (sysctl-name "kern.procargs2"))`, and under `(deny sysctl-read)` on an allow-default base. The design expected `process-info*` to stop it.
- **What stops it.** Nothing. It's a gap: an environment variable in one sandbox's caller is readable by another sandbox's code while both run. A caller that must keep two sandboxes' environments apart runs one at a time and ends the first's processes before it starts the next.
- **It includes the caller's own environment.** The stage's parent is the caller, so a command reads the environment the caller was started with, whatever `Cmd.Env` holds. `Env` controls only what the command is given. An earlier draft said a server that sets none leaks none of its tokens, which isn't so on macOS. A caller must hold no secret in its environment there: read it, then re-exec with a scrubbed one, or take it from a file or a descriptor. The same goes for every other process of the account (the user's shells, editors and agents among them) and for every process's arguments, which are readable the same way.
- **Test.** `TestGapProcessEnvironment` reads it inside a sandbox, then shows that the profile that denies both rules doesn't stop it, and fails when that changes. `TestGapCallerEnvironmentReadable` reads a caller's token through a sandbox given an empty `Env`. `Check` reports `proc.environ` as failed.

### A localhost deny held in only one form

- **How it worked.** In a minimal profile, after an allow written `(remote ip "*:*")`, `(deny network-outbound (remote ip "localhost:*"))` denied nothing, as the per-port denies of the early experiment didn't hold either ([macos.md](macos.md#m1-seatbelts-per-port-deny), rechecked on 27.2.0). After `(remote tcp "*:*")` and `(remote udp "*:*")`, the same deny held for 127.0.0.1, `::1` and the host's LAN address, over every one of 40 ports tried. A deny written with `(local ip ...)` refused everything. In the full generated profile the `ip` form held as well, so which shapes of profile work isn't something to predict from one that does.
- **What stops it.** `NetworkHost` is written in the tcp and udp form that held in every shape tried, and `TestProfileNetwork` checks the form as text. `localhost` in a profile is every address the host has, so the host's own listeners on its LAN address are refused too.
- **Test.** `TestEscapeNetworkHost` checks the behavior, fails if the deny is removed, and checks that a name resolves and a TLS connection verifies. Re-run it when macOS is updated.

### `RLIMIT_CPU` is not a kill

- **How it worked.** The design counted on `RLIMIT_CPU` to end a process that escaped the teardown. On macOS 27.0.1 and 27.2.0 a soft limit sends `SIGXCPU`, and the hard limit sent no `SIGKILL` to a Go program or a Python one that ignored `SIGXCPU`, which ran on for a hundred seconds past a limit of 2.
- **What stops it.** Nothing. A shell dies of `SIGXCPU`, as `TestAPIRlimits` checks. A process that ignores it isn't limited.
- **Test.** `TestEscapeSetsidDiesWithTeardown` starts a process that leaves the process group, under a CPU limit, and shows it ended with the sandbox, which the CPU limit doesn't do.

### A process could leave the process group, and outlive teardown and `Footprint`

- **How it worked.** Teardown ended the command's process group and `Footprint` summed it and its descendants, and the docs said only a `setsid` in a child escaped. A review found much more.
  - The command could `setpgid` itself into its parent's group, which is the stage's, so the caller's. `Footprint` then said "no process of the sandbox is left" while it ran, and closing the lifeline ended nothing.
  - `/bin/sh -c 'set -m; sleep 600 & exit 0'` left `sleep` running in a group of its own with no `setsid`. It held the sandbox's output pipe, so `Wait` blocked for over two minutes on a writer that wasn't a file.
  - What an escapee kept was also more than the docs said: under `NetworkHost` all outbound network, in every mode write access to the home and `Write` paths and a unix socket in `Write`, and `KERN_PROCARGS2` of every later sandbox.
  - Nothing listed the escapees, so ending them between sandboxes wasn't something a caller could do, and a `Footprint` watchdog bounded only code that stayed put.
- **What stops it.** The stage and `Footprint` find the sandbox's processes by the profile's marker, a pair of random Mach names that `sandbox_check` answers differently for this profile than for any other ([macos.md](macos.md#finding-the-sandboxs-processes)). Teardown ends every match until a scan finds none, and `Footprint` sums them. `Wait` ends them as soon as it sees the stage is gone, so an escapee that holds the output open doesn't block it.
- **Test.** `TestEscapeSetpgidAndJobControl` (job control, a `setpgid` child and a `setsid` child, each holding the output of a writer that isn't a file), `TestEscapeFootprintCountsEscapees` (the same, and the command joining the caller's group, each counted by `Footprint` and ended with the sandbox), `TestEscapeStageKilledEscapeeHoldsOutput`, `TestEscapeParentKilledEndsEscapees`, `TestEscapeSetsidDiesWithTeardown` and `TestMarkerNamesOnlyItsSandbox`. Each fails with the marker taken out of the teardown and `Footprint`: the waits time out, and the command in the caller's group isn't counted.
- **What's left.** A fork bomb can outpace the scan and nothing bounds it, though a single process that re-forks every millisecond is ended (`TestEscapeReforkingProcessEnds`). `Wait` returns an error when it couldn't confirm the sandbox empty (`TestTeardownReportsWhatItCouldNotConfirm`). `TestGapSetsidConnect` still connects from a child in a session of its own to a unix socket in `Write`, and checks that its session is neither the command's nor the caller's, so a bridge check that keys on the session sees a session it can't place.

### A sandbox could replace its own home with a link

- **How it worked.** `(allow file-read* file-write* process-exec* (subpath HOME))` matches HOME itself, so the sandbox could `rmdir` its home and `ln -s` a directory of the caller's in its place. The caller reads results from the home, writes inputs and cleans up by name, so it then read a file from its own private directory (`os.OpenRoot(home)` followed it too, since the root was what was swapped). The same worked for a `Write` directory, and a `Write` socket was removed and replaced with a directory. On Linux a bind mount point can't be removed from inside, so this was macOS only.
- **What stops it.** After the allows, the profile denies `file-write-unlink`, `file-write-create` and `file-link` at the literal path of the home and of each `Write` path. That stops `rmdir`, a rename of it, a rename over it, a link in its place, and a hard link of it elsewhere ([below](#a-write-file-could-be-hard-linked-into-the-home-on-macos-15-and-26)). The sandbox still writes everything inside.
  - Each way was tried under each name a root has: its own, upper case, the other Unicode normalization, through `/System/Volumes/Data` and `/.vol/<dev>/<inode>`, with a trailing slash and through `x/..`.
  - The operations were `rmdir`, `unlink`, `rename` away and over (a directory, file or link), `renamex_np` with `RENAME_SWAP`, and `symlink`, for a `Write` path that is a file or a socket as well as a directory.
  - What the deny doesn't stop, and a caller must allow for: the sandbox can change a root's mode, flags and extended attributes (`chmod 0`, `chflags uchg`, `setxattr`), so `Home` may be unreadable or immutable after a run and `os.RemoveAll` fails until the caller clears `uchg`. It can also make a FIFO (`mkfifo`) in `Home`, so a caller that opens a result by name can block on one, which `os.Root` doesn't prevent. Open results with `O_NONBLOCK`, or check the mode with `Lstat` first.
- **Test.** `TestEscapeRootsCannotBeSwapped` fails with those denies removed. `TestEscapeRootsEveryName` tries every name and operation above. `TestGapRootModeAndFifo` shows what isn't stopped. `TestEscapeSwappedAfterStart` is the host doing the swap, which Seatbelt already handled.

### A `Write` file could be hard-linked into the home on macOS 15 and 26

- **How it worked.** `link(2)` of a `Write` file into the home worked on macOS 26.7.2 and 15.8.2, which GitHub's runners found the first time CI ran there. The link gives the caller's file a second name inside the home, where the rules that pin the root's own name don't apply. A caller that later writes, truncates or changes the mode of files in the home changes its own file. Every run before had been on macOS 27, which refuses the link by itself.
- **Why 27 differs.** The kernel refuses a hard link whose source has a write operation denied that the target allows, and logs it as `forbidden-link-priv<op>`. On 27 that covers `file-write-create`, which the root's deny names. On 15 and 26 it covers `file-write*`, `-data`, `-mode`, `-flags` and `-xattr`, but not `file-write-create` or `file-write-unlink`, the only two the root's deny named. A probe of each operation on the three releases showed this.
- **What stops it.** The root's deny also names `file-link`, an operation Seatbelt checks for the source and the target of `link(2)` on all three releases.
- **Test.** `TestEscapeRootsEveryName` tries the link, and failed on 26 before the fix. On 27 it passes either way, so `TestRootLinkRefusedByFileLink` keeps only the `file-link` part of each root's deny and checks the link is still refused, with a control that the link works without it. It fails with `file-link` taken out of the rule.

### A cover named through the data volume covered nothing

- **How it worked.** Seatbelt matches the usual name of a firmlinked path, so `(deny ... (subpath "/System/Volumes/Data/private/var/x"))` never matched, and a `Cover` written that way left the files readable with no error. A `Read` or `Write` path named that way failed closed, which is why only the deny was a hole.
- **What stops it.** `canonicalName` maps such a name to the usual one in `prepare`'s resolution, so `Cover` and `Read` mean what they say, and `Home` and `Write` are refused with the name to use. A path that exists only on the data volume is kept.
- **Test.** `TestEscapeFirmlinkNames` tries each pair of spellings of a `Read` and a `Cover`, including the review's (a `Read` by the usual name and a `Cover` by the other), and `TestCanonicalName` the mapping.

### `F_SETOWN` with `O_ASYNC` signals a process outside

- **How it worked.** `fcntl(fd, F_SETOWN, pid)` and `O_ASYNC` on a socketpair make the kernel send `SIGIO` and `SIGURG` to `pid` when the descriptor is ready. The kernel doesn't ask Seatbelt's signal hook, so the denial of `signal` outside the sandbox doesn't cover them. A negative owner would name a process group.
- **What stops it.** Nothing. It's a gap. Both signals are ignored by default and by Go, so only a program that handles them is affected. `(deny system-fcntl (fcntl-command F_SETOWN))` was the idea in the review and wasn't tried.
- **Test.** `TestGapSetOwnSignalsOutside` sends `SIGIO` to a canary the test started, and fails when it stops arriving.

### The caller's secrets and sockets were never tried by `Check`

- **How it worked.** `writes.outside` tried `/`, which is the sealed system volume and refuses without any sandbox. `secrets.readable` and `sockets.reachable` built their paths from `$HOME`, which `Start` had set to the sandbox's home, and from `SSH_AUTH_SOCK`, which is empty there. `proc.signal` tried the parent and the lowest pids, which are root's. All four passed without trying anything of the user's.
- **What stops it.** `Check` works out the targets in the caller and sends them in its payload: the secrets and sockets that exist, and directories the account can write outside the sandbox's own. A row with nothing to try is skipped, with the reason. `proc.signal` tries the account's own processes before the others.
- **Test.** `TestCheckCatchesEscapesDarwin` makes each row fail, and `TestCheckSandboxDarwin` shows each passing with a count of what it tried.

### Opening a terminal, packet capture or a disk

- **How it worked.** `file-read*` of `/` shows `/dev/ttys*`, `/dev/ptmx`, `/dev/bpf*` and the disks. The account is usually in `access_bpf`, and its own terminals share its uid, so a sandbox could read keystrokes and type output into another terminal, or sniff.
- **What stops it.** The profile denies all of `/dev` but `null`, `zero`, `random`, `urandom` and `/dev/fd/N`, so a terminal reaches the command only as a descriptor it was handed, and `TIOCSTI` on that one is refused. A first version denied those four families by name, and missed `/dev/console` (`crw--w--w-`, owned by the login user) and `/dev/cu.*` and `/dev/uart.*` (`rw-rw-rw-`), whose stat worked, and so, by their permissions, probably their open. Nothing opened one, since opening a serial port can toggle a line on attached hardware.
- **Test.** `TestEscapeTerminals` opens each device for reading and for writing. `TestEscapeDevices` stats every entry of `/dev` and shows each refused but the allowed ones, which it uses, and `TestFirefoxScreenshot` still renders. It has a control for `TIOCSTI`, which the kernel on 27.x refuses outside a sandbox too, so there the check is only the profile's refusal to open another terminal.

### A setuid program doesn't run

- **How it worked.** Not an attack: a setuid program can't be run inside a profile, so `sudo`, `ps` and `su` fail. It's why the checks that would use `ps` are done in Go, and why `sudo` with a cached ticket can't be used to leave the profile.
- **What stops it.** The profile.
- **Test.** `TestEscapeSetuid`.

### `/bin/sh` needs a path under a cover

- **How it worked.** `/bin/sh` reads `/private/var/select/sh`, which the default cover of `/private/var` hid, so no script ran.
- **What stops it.** The profile shows `/private/var/select` and `/private/var/db/timezone` (for `/etc/localtime`) and nothing else under `/private/var`.
- **Test.** `TestEscapeViewShowsHost`.

### TLS needed a Mach service from 27.2

- **How it worked.** curl under `NetworkHost` verified certificates on 27.0.1 and failed with `unable to get local issuer certificate` on 27.2.0, because it looked up `com.apple.TrustEvaluationAgent`. It's the kind of service list that changes between releases ([open issues](security-model.md#open-issues)).
- **What stops it.** `NetworkHost` allows that lookup.
- **Test.** `TestEscapeNetworkHost`.

### A descriptor's reopen is checked by path

- **How it worked.** On Linux a read-only file under a cover can be reopened for writing through `/proc/self/fd`. On macOS `/dev/fd/N` is the file's path, and the profile checks it.
- **What stops it.** The reopen is refused under a cover, though a write to a descriptor opened for writing is allowed.
- **Test.** `TestEscapeDescriptorsHandedIn`.

### Launching apps and URLs

- **How it worked.** Not an escape: this is what was checked. `open` of an app and of a URL, `open -a`, and `osascript` telling Calculator to launch all fail under every `Services` group, even the one that allows the lookup of `launchservicesd`. No app starts and the default browser fetches nothing. A raw XPC client that connects to `launchservicesd` directly gets a connection with the group and `Connection invalid` without it, and nothing opens.
- **What stops it.** The profile never allows `lsopen` ([macos.md](macos.md#m3-launchservices-and-lsopen)).
- **What wasn't checked.** The message the XPC client sends is rejected by `launchservicesd` outside the sandbox as well, since the real request is private to LaunchServices. The library's calls to it don't go through any public `xpc_connection_create*` function, so interposing couldn't capture one to replay. The `lsopen` denial is logged against the calling process, which suggests the check is on the caller's side. Whether `launchservicesd` checks it on the server side is untested, and a review should look at it.
- **Test.** `TestEscapeLaunchServices` snapshots the Calculator processes by executable path before, looks after each attempt, and ends any it didn't find. `TestEscapeLaunchServicesRawXPC` is the raw client.
- **A false alarm.** An earlier run of this test reported "an app was launched: 2 processes of Calculator, was 0", and the profile-in-argv test saw profile text in `ps`. Both were the suite's own checks matching command lines of other programs. The Calculator count matched any command line that named `Calculator.app`, including a hand-run `lsopen` experiment that did launch it. The argv check looked at every process on the machine, where other tools run `sandbox-exec -p` with a profile. The tests now count executables by path, snapshot before, and look only at the sandbox's own process tree.

## Found by the review of the macOS teardown proof

A Fable review of the proof-based teardown, reading the code against XNU's source.

### The scan excused the command itself as a dying child of the stage

- **How it worked.** A scan excused a zombie, or a process that is exiting, when its parent was a process the scan had found not to be a member: a non-member can't have a member for a child, since `fork` gives a child its parent's profile. One member breaks that. `sandbox-exec` applies the profile to itself and becomes the command, so the command is a member whose parent, the stage, is under none. The command could leave the stage's group and wait for the teardown, then fork a child after the scan took its list of pids and exit before the scan read its pid. The scan read a zombie or an exiting process whose parent was cleared, excused it, and was clean with the child running under the profile. `Wait` then returned nil. The child isn't in the list, so only a scan that found nothing else wrong could miss it, and the command could time it: its list is taken about a millisecond after the first signal to its group.
- **What stops it.** A scan never excuses a pid that may be the `sandbox-exec` of this sandbox (`mayApply`) by its parent. It counts as unknown until a later scan finds it a zombie with the same start time. Where the caller doesn't know the pid (`abortStart`), no dying child is excused by its parent. That costs one more scan, since the next scan has seen it.
- **Test.** `TestScanDyingCommandIsNotExcusedByItsParent` runs the cases with a fake system. `TestEscapeCommandForksAndExitsAfterTheList` runs a real sandbox whose command forks and exits after the list is taken, with the stage stopped so that it can't end the child, and checks that the scan isn't clean. Both fail with the `mayApply` test taken out of the scan. The scan's read of the command is the one thing in the second that isn't the kernel's: the window in which a real zombie shows is too short to hit, so the test answers as the kernel does for a process that is exiting.

### Teardown listed processes by effective uid, and `Command` checked only that one

- **How it worked.** `proc_listpids(PROC_UID_ONLY)` compares the credential's effective uid (`kauth_cred_getuid`, in `bsd/kern/proc_info.c`). A caller whose real uid differs from its effective uid, such as a daemon that dropped privileges with `seteuid` only, gave the command both ids. If the command set its effective uid to the real one, it left the list, and every scan could be clean with it alive. Whether Seatbelt stops that call wasn't tried. A real uid of root would also have let the command become root again, which the check for euid 0 didn't see.
- **What stops it.** On macOS `Command` and `Run` refuse a process whose real uid differs from its effective uid, and the one with euid 0 as before. On Linux, bubblewrap refuses it: it exits with `setuid use of bubblewrap is not supported` (tried with 0.12.0 under `setpriv --ruid=0 --euid=502`), so `Start` fails. `Command` there has no check of its own.
- **Test.** `TestEscapeRefusesEuid0` and `TestAPICommandErrors` drive the ids through `commandAs`, since the suite can't be root or setuid. Both fail with the check taken out.

### A `Home` inside a `Write` path could be replaced from above

- **How it worked.** `prepare` refused a `Write` path inside the home and a cover, read or write path inside either, but not the home inside a `Write` path. With `Write: /w` and `Home: /w/a/home`, the macOS profile denies unlink and create at `/w/a/home` only, so the sandbox could rename `/w/a` and put a link or a new tree at `/w/a`. The caller reads and cleans up by the home's name, and followed it. That is [a sandbox replacing its own home](#a-sandbox-could-replace-its-own-home-with-a-link), one level up. A `Home` directly in a `Write` path (`/w/home`) was pinned. On Linux the same layout mounts the home inside content a sandbox wrote. This was in the first version, and the review of the proof found it.
- **What stops it.** `prepare` refuses a `Home` that lies inside a `Write` path, on both platforms.
- **Test.** `TestPrepare` (the case "a home inside a write path") and `TestEscapeStartRefusesLayouts`. Both fail with the home taken out of the paths the nesting check looks at.

### An exiting process was settled by an earlier scan, though a spawn can still add a child

- **How it worked.** The scan took a process that an earlier scan had found exiting, and not yet a zombie, as settled: it had begun to exit before this snapshot, and the docs said `fork1` ends a child whose parent has begun to exit. The check is in `fork()` in `bsd/kern/kern_fork.c`, after `fork1` has made the child, and `posix_spawn` in `bsd/kern/kern_exec.c`, which calls `fork1` itself, has none (read in xnu-12377.121.6). A thread of an exiting member that was inside `posix_spawn` could add a child after the snapshot, which isn't in the list, while the scan said the process was settled. It needs a thread to stay in the kernel across the wait between two scans, which is 1 to 25 ms, so this was not shown to work. A process is past that only when it is a zombie: `proc_exit`, which sets `SZOMB`, is called by the last thread to terminate (`bsd/kern/kern_exit.c`).
- **What stops it.** A scan remembers only zombies. A process that is exiting and not yet a zombie is unknown in every scan that finds it so, unless its parent is cleared. A member stuck in exit now holds the teardown, which fails closed and returns `ErrSurvivors`.
- **Test.** `TestScanExitingPidIsNeverSettledUntilAZombie`, `TestScanDyingChildOfAClearedParent` and `TestScanDyingCommandIsNotExcusedByItsParent` fail if an exiting process is remembered. No test makes a real thread sit inside `posix_spawn` while its process exits.

### A scan remembered the stage's child before it execed `sandbox-exec`

- **How it worked.** A scan remembers a pid it found not to be a member, with its start time, and a later scan doesn't ask about it again. The one process that can become a member is the `sandbox-exec` that applies the profile, so a pid that may be it was never remembered. It was checked only by its name, though, and the stage's child has the stage's name until it execs `sandbox-exec`. Where the caller has no pid for the one it started (`abortStart`), every process counts as one that may be it, and such a pid was remembered once it was found free under another name. If the stage was killed between its child's `dup2` of the status pipe and the `execve`, and the first scan wasn't clean for another reason, the next scan took the child as cleared by its start time alone. It then execed `sandbox-exec` and ran the command with nothing watching it. Found by reading, and not run: the window is a few microseconds inside the child's fork and exec.
- **What stops it.** With no pid for its `sandbox-exec`, a scan remembers no pid it found free. The next scan looks again, and finds the command a member. That costs the failure path a second look at each process of the account on every scan.
- **Not stopped.** A first scan that is clean ends the teardown, and it is clean if it finds that child free under the stage's name, so a stage killed in that window can still leave the command running. The child can't be told from an ordinary process of the account before it execs, and nothing under the profile starts it.
- **Test.** `TestScanWithNoExecPidLooksAgainAtWhatItFoundFree` fails if the pid is remembered.

## Found in the code and plans of the projects that adopt it

These came from the code and plans of the project the library was extracted from, which changed to meet them. Most are for the adopting program to get right, not the sandbox, and are listed in [usage.md](usage.md#files-a-caller-handles-for-a-run). Two are about the library itself.

### bubblewrap as root maps the sandbox to host uid 0

- **How it worked.** bubblewrap run as root maps the sandbox to host uid 0. A launcher that ran it as root gave the command root's identity in the user namespace.
- **What stops it.** A launcher switches to the child's uid before it runs bubblewrap, so it needs user namespaces as much as any other way of running. `Command` refuses to run as root for the same reason.
- **Test.** `TestEscapeRefusesEuid0` and `TestCommandRefusesRoot`.

### macOS `open` allowed any service but the keychain

- **How it worked.** An early plan for the macOS `open` kernel level allowed any Mach service but the keychain. LaunchServices starts processes outside the profile, and no list of services to refuse could be complete.
- **What stops it.** On macOS `open` is the same as `strict`: every level gets the one profile.
- **Test.** `TestEscapeKernelLevels`.
