# Sandbox

`legwork sandbox`, and `legwork-sandbox`, which is the same thing built on its own, run a command in a sandbox. The code is `internal/sandbox`. [one-binary.md](one-binary.md) plans how Legwork will use it: for each turn's CLI and each stdio MCP server, first inside today's multi-account deployment and then in place of its accounts.

This doc says how the sandbox holds, every way past it that has been found and what stops each one now, what was tried and dropped, and what it does not do. Anyone changing the sandbox should read the findings first: each is an attack that worked once.

## What it protects

The CLI, everything the model has it run, and every stdio MCP server are untrusted, as [architecture.md](architecture.md#threat-model) explains. Once Legwork runs as one account, they share a uid with `serve`, which holds the Slack tokens, upstream credentials, and the database. A sandbox keeps Legwork's data confidential: its config, database, and credentials, other sandboxes' files, and people's homes.

A uid boundary gave some things for free that a sandbox has to give instead. File modes and the kernel's rules on signals and tracing are two. The biggest is that the uid is the credential every local service checks through `SO_PEERCRED`, such as the account's systemd user manager, ssh-agent, and gpg-agent, which accept any process of the account. So a sandbox must not reach their sockets at all.

It makes no claim to hide the host or its owner from what runs inside. A sandbox can read what any account on the host can, sees the machine id and network addresses, and its traffic leaves from the host's addresses. Secrets of the host's own that file modes leave readable are the operator's to fix, and `legwork doctor` will warn about the usual ones, as under [Limits](#limits).

## How it works on Linux

### bubblewrap

bubblewrap builds the sandbox. It is the setup Flatpak runs every app through, so a reviewer can rely on its record and read only what Legwork hands it, where a builder of Legwork's own would have to be reviewed whole. Legwork needs 0.8.0 or later, from the distribution, and refuses a setuid copy, since bubblewrap's serious past flaws were in its setuid mode. Ubuntu 24.04's 0.9.0 runs the tests in CI, and 0.12.0 on the spike's host.

`legwork sandbox` works out the view and hands bubblewrap every option on a descriptor with `--args`, so pid 1's command line, which any process inside can read, does not list them. Each bind source is opened by `legwork sandbox` and passed as a descriptor with `--bind-fd` or `--ro-bind-fd`, and the account's `passwd` and `group` entries with `--ro-bind-data`. bubblewrap makes new user, mount, pid, IPC, and UTS namespaces, maps the account's uid and gid to the same ids inside, and closes every descriptor it was handed before it starts the command. It is given `--die-with-parent`, so killing `legwork sandbox` kills everything inside, and not `--new-session`, so the command stays in its caller's session, which the hub's check on `mcp.sock` needs.

There is no network namespace yet. It comes with the egress proxy, as [one-binary.md](one-binary.md#egress) plans, and until then a sandbox shares the host's network.

### The view

bubblewrap makes these mounts parent first, so a path bound back under a cover gets its mount point in the cover:

- the host's root, bound recursively and read-only;
- an empty tmpfs over each covered directory, made read-only once the binds inside it are in place, and `/dev/null` over any other covered path, such as a file or a socket, which nothing can read from or connect to;
- the sandbox's own home and `write` paths, read-write;
- its `read` paths, and the regular files that links in the host's `/etc` lead to under a default cover, such as Ubuntu's `/etc/resolv.conf`, read-only;
- a fresh `/proc`, bubblewrap's own `/dev` with a new `devpts` instance, and a writable tmpfs `/tmp`, `/var/tmp`, and `/dev/shm` of its own, each holding at most 1 GiB, set with bubblewrap's `--size`;
- a `passwd` and `group` with one entry for the sandbox's uid and gid, whose home is its own directory;
- `legwork` itself, read-only at `/dev/legwork-sandbox`, for the first stage.

The covered paths are:

- every path the caller names, which for Legwork is every path its config names other than the sandbox's own;
- people's homes: the account's own, each home in `/etc/passwd` that its account owns, and the whole directory where two or more such homes sit side by side, which also hides homes that `/etc/passwd` does not list;
- `/home`, `/root`, `/run`, `/tmp`, `/var`, `/mnt`, `/media`, `/dev/shm`, snapper's `/.snapshots`, and an ostree host's `/sysroot`;
- from the host's mount table, every ZFS dataset's `.zfs` directory, and any other mount of a filesystem that shows a covered path somewhere else, such as a bind mount.

A cover inside another is left out when nothing bound between them would show it, and so is a cover at the same path as a bind, which shows that path whole.

The root is bound whole, rather than a list of what programs need, because a list is what breaks npx, uvx, and toolchains under `/opt`, `/usr/local`, or `/nix`. That is safe because file modes still apply inside, and the sandbox's uid owns nothing outside its own directories and the covered ones. It holds only while the account has no supplementary groups, since an unprivileged user namespace keeps them, and `legwork doctor` will warn about any.

### Paths and links

A sandbox's home and `write` paths are untrusted: an earlier run, or another sandbox that shares the directory, may have changed what is in them. So `legwork sandbox` resolves every path itself before bubblewrap starts:

- A home or `write` path must have no link in it at all, since a sandbox that can write a directory on the way could have planted it. That refuses a link the operator made too, such as an ostree host's `/home`, so the caller has to pass the real path, and must not resolve the path itself either.
- Any other path is followed through a link only where the link lies outside every directory the sandbox can write.
- A covered path inside a writable directory that has gone missing stops the sandbox from starting, since a sandbox could have moved it away to uncover what it hid.
- No mount may lie inside the home or a `write` path at all, so every mount point is inside a tmpfs bubblewrap made or a read-only host path, never content a sandbox wrote.
- Each bind source is opened with `openat2` and `RESOLVE_NO_SYMLINKS` and passed as a descriptor, and a cover that has become a link since it was resolved stops the sandbox, so nothing swapped in between the check and the mount can redirect it.

### The first stage

bubblewrap does not start the command itself. With `--as-pid-1`, it starts `legwork` again inside as pid 1, holding `CAP_SYS_ADMIN` and `CAP_SETPCAP` from `--cap-add`, and that first stage runs before anything untrusted does:

1. bubblewrap leaves the view a slave of the host's mounts, so a mount made on the host later would appear inside. Run unprivileged, bubblewrap puts pid 1 in a user namespace nested inside the one that owns the view's mounts, so its capabilities cannot change the view. The stage copies the view into a mount namespace of its own and makes every mount in it private.
2. It drops every capability, its bounding set included, and sets `no_new_privs`. Both belong to a thread, so it does this on the one thread it has locked, the one that execs next.
3. `unshare` moves only the calling thread, so the stage execs itself again, which leaves the whole of pid 1 in the new namespace and no process inside in bubblewrap's. The new image starts with that one thread's empty sets, so no thread of pid 1 holds a capability, nor does the command, even as uid 0 inside. pid 1 makes itself undumpable, so the command cannot open its memory, descriptors, or root through `/proc`.
4. It installs the seccomp filter on all its threads and starts the command. It then relays signals to it, reaps orphans, and exits with its status, which ends everything left inside.

The stage holds `CAP_SYS_ADMIN` in its nested user namespace while the binary starts, so whatever runs before `Stage`, such as its libraries' `init` functions, runs with it. That is Legwork's own code and what it links, not anything the sandbox runs, and `legwork-sandbox` links less of it.

### The filter

The filter is an allowlist from the system calls Docker's default profile allows without a capability, as Go constants from `x/sys/unix` for amd64 and arm64. It refuses the rest with `ENOSYS`, so a call added in a later kernel stays refused until it is reviewed, and a program falls back as it would on an older kernel. It leaves out io_uring, `bpf`, `perf_event_open`, `userfaultfd`, the key calls, module and `kexec` calls, `ptrace`, the mount calls, `unshare`, and `setns`. Of what it allows, it checks the arguments of:

- `clone`, which may not make namespaces. `clone3` passes its flags in memory, where the filter cannot read them, so it is refused, and libc falls back to `clone`.
- `socket`, which only makes Unix sockets and stream and datagram IP sockets of TCP, UDP, and ping. Another family gets `EAFNOSUPPORT` and another type `ESOCKTNOSUPPORT`, so a program that probes falls back. Raw and packet sockets get `EPERM`.
- `socketpair`, which only makes Unix pairs.
- `ioctl`, which may not use `TIOCSTI` or `TIOCLINUX`, either of which could type a command into the terminal of whoever started the sandbox.
- `setsockopt` and `getsockopt`, which may not use the legacy netfilter options that replace and read iptables, arptables, ebtables, ip6tables, ipset, and IPVS state.
- `personality`, which takes only the values Docker allows.

A call through another ABI, such as 32-bit x86 or x32, gets `ENOSYS`. The filter checks only the low 32 bits of each argument, since the kernel reads only those, so a caller cannot pass a check by setting a high bit. Argument checks come before the plain list, so the kernel caches the result for every call on it. A call took about 7 ns longer under the filter on the spike's host.

The `kernel` setting relaxes it:

- `strict`, the default, is the filter above.
- `nested` also allows user namespaces, the mount calls, and `chroot`, for software that runs a sandbox of its own, such as Chromium or bubblewrap. The kernel locks the mounts it copies into a namespace the code makes, so it cannot unmount a cover, make a read-only bind writable, or bind the root elsewhere without its covers. It can map its own uid and mount a tmpfs of its own, which those sandboxes need, and filesystems an unprivileged user namespace may mount, such as overlayfs and FUSE, which puts their code within its reach. The netfilter options stay refused.
- `open` gives up the allowlist, and keeps refusing other ABIs and the terminal ioctls. On an architecture with no list, such as 32-bit arm, it has no filter at all.

## Findings

Two reviews by Fable, each given only the design and the code, and re-checks of their fixes, found these. Most were confirmed on a Proxmox VE container on ZFS with a 7.0 kernel. Each says how the attack worked, what stops it now, and the test that checks it.

### Covered files reached another way

- **Landlock alone reached the account's own services.** Before ABI 9, Landlock does not check `connect()` on a socket file, so a sandbox reached the account's systemd user manager and read a covered file out through `systemd-run --user`. ptys, SysV IPC, and other processes' command lines leaked the same way. Landlock is gone, as under [Tried and dropped](#tried-and-dropped), the namespaces are the floor, and `/run` is covered. `TestIsolation` connects to a socket file outside.
- **Landlock alone granted every pty read-write.** A sandbox could write to an admin's terminal on the same account. bubblewrap's `/dev` has a new `devpts` instance.
- **ZFS snapshots showed covered files.** Every snapshot of a dataset is under its `.zfs`, at paths no cover names, even with `snapdir=hidden`, and file modes do not help when the sandbox's uid owns the files. A sandbox read a covered home's `.bash_history` through `/.zfs/snapshot`. Covers now come from the mount table too. `TestMountCovers` checks them on a fake mount table, and the fix was checked by hand on the ZFS host, since CI has none.
- **A host mount made after start appeared inside.** bubblewrap leaves the view a slave of the host's mounts, so a later bind of a covered path showed inside a running sandbox. The first stage gives it private mounts of its own. `TestLateMounts` binds a covered directory on a fake host once the sandbox has started.
- **pid 1's root showed the host's later mounts.** When only the first stage moved to private mounts, bubblewrap's own reaper stayed in the old namespace, and the command read a later mount through `/proc/1/root`. The stage is pid 1 now, undumpable, with no process left in the old namespace. `TestLateMounts` also reads through `/proc/1/root`, and fails without `--as-pid-1`.
- **A cover on a socket was skipped.** Covers handled only directories and regular files, so a covered listening socket stayed reachable. Anything but a directory now gets `/dev/null`. `TestIsolation` covers a listening socket and expects `ECONNREFUSED`.

### Paths and links

- **A planted link pointed the next sandbox at Legwork's state.** `prepare` followed links outside the sandbox, so a turn replaced a directory in its home with a link to the state directory, and the next turn had the state bound read-write. Links in writable directories are now refused, as under [Paths and links](#paths-and-links). `TestResolve`, `TestPrepare`, and `TestRefusedLayouts` plant them.
- **A covered path moved away was uncovered.** A missing cover was skipped, and a sandbox can rename a directory it can write. A missing cover inside a writable directory now stops the sandbox. `TestRefusedLayouts` moves one.
- **A cover inside the home never took effect.** Pruning dropped it as inside `/home`, and the home's bind went on top of it, so every thread's saved sessions were readable. Covers are now pruned by the nearest mount above them, and no cover may lie inside the home at all, so each thread will get a home of its own. `TestCovers` and `TestRefusedLayouts` check both.
- **A home that was also covered became read-only.** The account's own home and the homes `/etc/passwd` gives it are covered, so a deployment whose sandbox home is one of them, outside every default cover, had the cover and the home's bind at one path. bubblewrap remounts a cover read-only once the binds are in, and the remount took the bind on top, so the home could not be written. The same happened with a path given both as a cover and as a `write` path. A cover at a bind's path is now left out. `TestCovers` checks it, and `TestHomeCovered` writes in such a home.
- **bubblewrap follows a link while it makes a mount point.** Before 0.12.0, setup can follow a symlink in a mount destination's parent and create files on the host as the account (CVE-2026-87766, GHSA-pxhw-h44j-8pfx). Debian 12 will not fix it, and Ubuntu 24.04 rolled its fix back. No mount may lie inside a directory a sandbox can write. `TestPrepare` refuses such layouts.
- **A link where the shell tool's directory should be.** A turn's CLI can write the scratch directory that holds its shell commands' `work` directory, so a link planted there would have made the next shell sandbox's home the CLI's home. A home or `write` path may have no link in it. `TestPrepare` refuses a home through a link.

### Processes and the kernel

- **pid 1 showed every cover.** The spike's own builder ran its stages with the caller's arguments, so `/proc/1/cmdline` named every covered path, token files included. bubblewrap now reads them from a descriptor. `TestIsolation` checks pid 1's command line, environment, and descriptors.
- **The capability drop covered one thread.** pid 1 dropped its capabilities and set `no_new_privs` after its second exec, on a goroutine not locked to a thread. Both are per thread, and bubblewrap raises `--cap-add` as ambient capabilities, so every other thread of pid 1 kept `CAP_SYS_ADMIN` and `CAP_SETPCAP`, and the command could be forked from one of them and keep them as ambient ones. The first stage now drops them on its locked thread before it execs, so the new image starts with none. `TestIsolation` reads every set from the status of each thread of the command and of pid 1.
- **A thread that could not take the filter went unnoticed.** With TSYNC, the kernel reports a thread it cannot move to the new filter by returning that thread's id with no error, and installs the filter on no thread at all. pid 1 checked only for an error, so it would have started the command with no filter. Any result but 0 now stops the sandbox. `TestSeccompUnsyncedThread` gives one thread a filter of its own first.
- **`nested` reached iptables' table code.** Code under `nested` that made its own user and network namespace held `CAP_NET_ADMIN` there, and `IPT_SO_SET_REPLACE` reached the code behind CVE-2021-22555, answering `EINVAL` where it should have been refused. The filter refuses the netfilter options. `TestSeccompFilter` checks them, and `TestNestedMounts` tries it from such a namespace.
- **`open` left `TIOCSTI` open.** With `--new-session` dropped, a command under `open` could type into its caller's terminal on a kernel before 6.2. `open` keeps the terminal checks. `TestSeccompFilter` and `TestKernelLevels` check `TIOCSTI` at every level.
- **Every IP protocol and socket-pair family was open.** The filter checked only the socket family, so SCTP, DCCP, L2TP, MPTCP, and SMC were reachable, and a socket pair in any family loaded and ran that family's code. `TestSeccompFilter` checks the protocols and pairs.
- **Protocol 0 picked SCTP.** Protocol 0 means whichever protocol registered the type first, so an IP sequenced-packet socket was SCTP with the module loaded. Only stream and datagram IP sockets are allowed. `TestSeccompFilter` checks `SOCK_SEQPACKET` and `SOCK_DCCP`.

- **Temporary space had no limit.** A tmpfs is as large as the host's memory allows, 47 GB on the spike's host, so a sandbox could fill memory through `/tmp`, `/var/tmp`, or `/dev/shm`. That is a denial of service, not a leak. Each now holds at most 1 GiB, with bubblewrap's `--size`, from 0.7.0. `TestIsolation` checks each size from inside, and a write past it stops at the limit.

### Files Legwork handles for a turn

- **The bridge sent any file a placeholder named.** An absolute path outside the scratch directory went to a tool, past a CLI confined by `--restricted`. The bridge sends only files in the scratch directory, through `os.Root`. `TestPlaceholderFileRefusedByTheBridge` tries an absolute path, `..`, and a link.
- **The runner's writes followed links.** `os.WriteFile` followed a link the CLI left in its scratch directory, which could have carried the next turn's prompt into another thread's directory. The runner writes through `os.Root`. `TestInstructionsStayInScratch` plants one.
- **A model's URL reached the host's own services.** `guard.Client` refused addresses that are not public, but the host's own public address is public, and reached whatever it serves on every address. It refuses the host's interface addresses too. `TestHostAddress` checks them.

### In the design, not yet built

These were found in [one-binary.md](one-binary.md)'s plan, which was changed to meet them:

- A compromised `serve` could plant links for the root launcher's chown or binds to follow, which would be root on the host. The launcher works beneath a descriptor for the state directory with `openat2`, without following links.
- bubblewrap run as root maps the sandbox to host uid 0. The launcher switches to the child's uid before it runs bubblewrap, so it needs user namespaces as much as any other way of running.
- A uid fixed per thread cannot last, since threads have no limit and a range does. A uid belongs to one running child.
- `network: direct` without root reaches loopback, where `serve`'s listeners and loopback upstreams are, past tool policy and the audit log. It needs root, whose nftables rule refuses loopback, private addresses, and the host's own.
- The planned proxy would have let a sandbox reach the host's own public address. It refuses it.
- On macOS, `open` allowed any service but the keychain, and LaunchServices starts processes outside the profile. No list of services to refuse could be complete, so `open` on macOS is the same as `strict`.
- One CLI home shared by every thread lets a turn change what every later turn trusts, such as its credentials file. Each thread gets a home of its own.
- The `shell` tool's commands could write the files the next turn's CLI loads. They get a `work` directory beside those files.
- Keeping threads apart before the network namespace leaves loopback and abstract sockets shared between threads, which the plan says.

## Tried and dropped

- **Landlock alone.** Before ABI 9 it does not check socket files, so it does not keep a sandbox off the account's own services, and it leaves ptys, SysV IPC, and other processes' command lines open too.
- **Landlock inside the namespaces.** Its file rules come from the same paths as the mounts, so they shared the mounts' mistakes: both planted-link findings got through it. Its ptrace and signal scopes repeat the pid namespace, and its abstract-socket scope and port rule repeat the network namespace. Under `nested` it refused what the mount locks already refuse, and stopped Chromium's and bubblewrap's sandboxes from starting, since it refuses mounts and writes to `/proc/<pid>/uid_map`. Its one real job, keeping a sandbox off the host's abstract sockets, ends when the network namespace comes. Taking it out also took out a walk of the host's root on every start, a workaround so renames between directories work, refused terminal ioctls on device files, and a dependency from outside the standard library and `golang.org/x`. The filter still allows the Landlock calls, so a program inside can use Landlock on itself, as Cursor's sandbox does.
- **A namespace builder of Legwork's own.** The spike built the namespaces and the view itself with Go's `SysProcAttr`, a staging root, and `pivot_root`, and it worked, but its whole setup would have to be reviewed, where bubblewrap's has a long record. It had already needed a fix that bubblewrap does not: Go's ambient setup leaves capabilities in the inheritable set, which a file's inheritable capabilities combine with outside the bounding set.
- **bubblewrap's `--seccomp`.** The filter refuses the calls the first stage makes, so the stage installs it after them.
- **bubblewrap's `--new-session`.** It would guard against `TIOCSTI`, but a new session fails the hub's check that a bridge is in its turn's session. The filter refuses `TIOCSTI` instead.
- **bubblewrap's `--cap-add` to change the view or the network.** Unprivileged bubblewrap runs the command in a user namespace nested inside the one that owns the view's mounts and the network namespace, so the capabilities are real but do not reach either. That is why the first stage makes a mount namespace of its own, and why adding routes would need a network namespace of its own too.
- **The first stage making only itself private.** `unshare` moves one thread, and bubblewrap's own reaper stays behind, so other processes inside still see the host's later mounts through `/proc/<pid>/root`. The stage execs itself and is pid 1.
- **Covering the machine id.** The sandbox makes no claim to hide the host, and addresses and much else identify it anyway.
- **elastic/go-seccomp-bpf.** It cannot make `ENOSYS` the default or answer `EAFNOSUPPORT`, so the filter is written with `x/net/bpf` instead.

## Limits

- **Abstract sockets and loopback.** Until a sandbox has a network namespace, it reaches every abstract socket and loopback listener on the host, which have no permission check, and under `network: direct` it always will. `TestIsolation` expects an abstract socket outside to be reachable, so the test changes when that does.
- **The mount table.** `/proc/self/mountinfo` shows where each cover and bind is, so a cover hides what is under a path, not that the path exists. Legwork covers its config and state by directory, so the table names those directories, not the files in them.
- **What the mount table cannot show.** A btrfs snapshot directory other than `/.snapshots`, or a home neither `/etc/passwd` nor a prefix of two homes reveals, has to be covered by name. `legwork doctor` will warn when Legwork's state is on a filesystem with snapshots.
- **Links the operator made.** A home or `write` path through any link is refused, so on an ostree host the caller passes `/var/home/...`, not `/home/...`.
- **pid reuse before kernel 6.5.** Without `SO_PEERPIDFD`, the planned pid-namespace check on `mcp.sock` looks the peer up in `/proc` by pid, so a process that takes that pid in between would be judged instead.
- **A router's address.** `guard.Client` refuses the host's interface addresses, not a router's public address that forwards back to the host.
- **Other architectures.** With no system call list, only `kernel: open` starts, with no filter and so no `TIOCSTI` refusal. `legwork sandbox` refuses the other levels before it starts bubblewrap.
- **The account's groups and the host's file modes.** Both are the operator's to get right. `legwork doctor` will warn when the account has supplementary groups, and when it can read any of a short list of files no service account should: `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers` and `/etc/sudoers.d`, the SSH host keys, `/etc/ssl/private`, `/etc/wireguard`, NetworkManager's `system-connections`, netplan's files, PPP's and IPsec's secrets, `/etc/krb5.keytab`, certbot's `live` and `archive`, `/etc/mysql/debian.cnf`, and the admin kubeconfigs of Kubernetes and k3s. A secret an admin puts in a world-readable file, such as a password in `/etc/fstab`, is past what a list can find.

## How it is tested

The tests in `internal/sandbox` run real sandboxes on Linux, as the account's own uid, which takes bubblewrap's unprivileged path as a deployment does. Running them as root of a user namespace had hidden that bubblewrap's capabilities do not reach the view. Some build a fake host first, in a user and mount namespace of their own: homes under `/srv`, a `passwd` that lists them, links in `/etc`, a stand-in for Legwork's state, and a listening socket. CI runs them on Ubuntu 24.04 with its bubblewrap 0.9.0, with `kernel.apparmor_restrict_unprivileged_userns` off, and they ran on the spike's host with 0.12.0.

Each check that guards a finding was checked to fail with the fix taken out: the covers, the filter, the first stage's private mounts, `--as-pid-1`, the cover of other file types, the mount order, and the netfilter rule. The ZFS fix, real Claude turns, and the servers in use were checked by hand on the spike's host, as [one-binary.md](one-binary.md#what-the-spike-found) records.
