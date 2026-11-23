# The macOS backend

How the sandbox is built on macOS, what the early experiments measured, and what was tried and dropped. [security-model.md](security-model.md) says what it guarantees and [findings.md](findings.md) says what each part of it fixed.

macOS has no namespaces, no seccomp and no cgroups, so this backend is a different shape and gives less. It gives a deny-by-default view of files, the network and Mach services, and a teardown that ends every process under the profile with the command. It doesn't give a pid namespace (so the caller's environment is readable), a system call filter, a private loopback or a memory limit. [Limits](security-model.md#on-macos) lists each.

## Seatbelt and sandbox-exec

The package writes a Seatbelt profile from the `Spec` and runs the command under `/usr/bin/sandbox-exec`, by that absolute path and never one found on `PATH`. There's no cgo. The profile language is Apple's, but `sandbox-exec` is the one program that applies it without linking `libsandbox`, so the module builds with `CGO_ENABLED=0`.

Seatbelt is the engine App Sandbox and Firefox's own content sandboxes use. It's deprecated, and undocumented but for what Apple's own profiles in `/System/Library/Sandbox/Profiles` show. So every rule here came from running something and reading the deny log:

```
log stream --predicate 'sender == "Sandbox"'
```

A process that is already inside a profile can't apply another. `Probe` tries a trivial profile and says so. A Firefox started under one can't start its own child processes' sandboxes, which is why [Firefox](usage.md#firefox) needs three environment switches.

## The profile

Seatbelt takes the last rule that matches, so the profile is written in the order of the view:

1. `(deny default)`.
2. The base rules.
3. The host's files readable.
4. A deny for each cover.
5. An allow for each `Read` path.
6. The home and `Write` paths readable and writable.
7. The network and Mach services.

File rules are sorted by depth, shallowest first, with a cover before an allow at the same path. So the nearest rule above a path decides, as the nearest mount does on Linux. A `Read` path inside a cover inside a `Read` path works, and a cover at a `Read` path's own path shows it.

The base rules are:

- `process-fork`.
- `process-exec*` of anything the profile lets the command read, which includes `#!` interpreters.
- `sysctl-read`.
- `signal` and `process-info*` to the sandbox's own processes, `(target same-sandbox)`, and no others.
- Writes to `/dev/null` and `/dev/zero`.

All of `/dev` is denied but `null`, `zero`, `random`, `urandom` and `/dev/fd/N`, so a command reaches a terminal, a console, a serial port, packet capture or a disk only as a descriptor it was given. A list of what to deny had missed `/dev/console` and `/dev/cu.*`. `dtracehelper`, which every process tries to open, is denied too, and Firefox renders without it.

Last, the home and each `Write` path get a deny of unlink and create at their own path, so the sandbox can't remove, rename or replace its own root ([findings](findings.md#a-sandbox-could-replace-its-own-home-with-a-link)).

The profile never allows `lsopen`, which would let the command open any app or URL through LaunchServices, outside the profile. It never allows a Mach service outside a requested group, `iokit-open`, or `file-write*` outside the home and the `Write` paths.

### Covers

The covered paths are:

- Every path the caller names in `Spec.Cover`.
- `/Users`, which holds people's homes and the account's own.
- `/Volumes`, where other volumes and APFS snapshots mount.
- `/private/var`, which holds the per-user temporary and cache directories, the sockets of system services and the state of the system's databases, and `/private/tmp`.

`/var` and `/tmp` are links to those, and `/System/Volumes/Data` is the data volume under another name: `/Users` is the same directory as `/System/Volumes/Data/Users`. Seatbelt resolves links and firmlinks before it matches a rule, so a rule for the real path holds however the command names it, and every one of those names is covered.

The rule has to be for the usual name, though. It matches `/Users`, and a rule written for `/System/Volumes/Data/Users` matches nothing. A `Cover` named that way once covered nothing, silently. `prepare` now maps a name through the data volume that a firmlink also gives (the list is `/usr/share/firmlinks`) to the usual one, in `Read`, `Cover` and `Dir`. It refuses the name in `Home` and `Write`, where a link is refused anyway, and gives the name to use. A path that exists only on the data volume has no other name and is kept. A path on a case-insensitive volume matches whatever case it is written in, so no path needs its case normalized.

Two paths under `/private/var` are shown to every sandbox, since nothing runs without them and neither holds anything private:

- `/bin/sh` is a stub that reads `/private/var/select/sh` to find its shell.
- `/etc/localtime` leads into `/private/var/db/timezone`.

Other links in `/etc` that lead into a covered path are rebound read-only, as on Linux (`linkedFiles` runs here too). The resolver's file and the timezone file are shown, and hold nothing private.

### Paths and quoting

`Read`, `Write`, `Home`, `Dir` and `Cover` go through the same resolution as on Linux, in the shared `prepare`, so the same layouts are refused. There are no bind mounts, so the rule that no mount may lie inside a writable directory is kept for another reason. A cover inside the home is a path-based deny, and a sandbox that can rename a directory it can write could move the covered one away and uncover what it hid.

A path goes into the profile only as a `subpath` or `literal` filter, never a regular expression, with a backslash and a double quote escaped. One with a control character, or bytes that aren't UTF-8, is refused by `Start`, since nothing here can say what the parser makes of it.

Seatbelt checks the path a file has when it is opened, not one opened earlier. So there's nothing to open by descriptor and nothing for a swap between the check and the use to redirect:

- A `Write` directory that another process replaces with a link after the profile is written gives the sandbox nothing, since its path leads somewhere the rule doesn't name.
- A link the sandbox plants in its home leads out of the rule that allows the home, so nothing is read or written through it.
- The sandbox can't swap its own root. The profile denies unlink and create at the literal path of the home and of each `Write` path, so `rmdir`, a rename of it and a link made in its place fail. Without that, the sandbox could remove its home and put a link to the caller's private directory there, and the caller, which reads and cleans up by that name, would follow it.
- A home or `Write` path with a link in it is still refused, for the reason it is on Linux: the next run would be pointed at what the link leads to. A caller must name the real path (`t.TempDir()` leads through `/var`).

## The stage

`Start` runs this binary again, as the stage, with `Stage` finding it first in `main`, outside the profile and as the caller. It can't exec `sandbox-exec` and be done, since macOS has no `Pdeathsig` and nothing else ends a command when its caller dies. The stage:

1. Takes its settings, the profile and the limits, from a pipe, and sets the limits on itself, so it holds them as pid 1 does on Linux.
2. Marks every inherited descriptor but the command's close-on-exec, from `/dev/fd`, and never closes one by number.
3. Starts `sandbox-exec -f /dev/fd/N -- command` in a process group of its own, with the profile on a pipe, so no command line names it, and the caller's `Files` at 3 and up. The command's group is in the caller's session and isn't the caller's group, so `kill(0)` and `kill(-1)` from inside reach only the sandbox.
4. Sends the caller a reply, the command's group or the setup error, so `Start` returns once the command has been started. Each message on the pipe says its kind (`reply` or `done`), and a reader refuses the wrong one: a lifeline that closes during `Start` can make the stage's last message the first the caller reads (`TestStageMessagesRefuseTheWrongKind`).
5. Relays `SIGTERM`, `SIGHUP` and `SIGINT` to the command, and waits for it.
6. When the command exits, ends the command's group and then every process under the sandbox's profile with `SIGKILL`, until none is left. Then it exits with the command's status, or 128 plus the signal.

The lifeline is a pipe the caller holds the write end of, as on Linux. The stage reads it from its first moment. When it reaches EOF, which is when the caller closes it or dies, however it dies, the stage ends the sandbox and exits.

If the stage itself is killed it can't end anything, so `Wait` watches for that and ends the sandbox as soon as the stage is gone. A process the stage left behind could hold the command's output open and keep `Wait` from returning.

`Cmd.Pid` is the stage's pid, this process's own child. `Footprint` finds the command's group through the stage's reply.

When `Stdin` is a terminal that the caller is the foreground of, the stage starts the command with the foreground, and gives it back when the command ends, with `SIGTTOU` ignored for the call, as `Wait` does on Linux. `ctx` ending closes the lifeline, and a stage that hasn't gone five seconds later is killed. A `SIGTERM` or `SIGHUP` to a process in `Run` closes it too, so it ends the sandbox, as on Linux.

The command holds descriptors 0 to 2 and its `Files`, and one more: the read end of the pipe that held its profile. `sandbox-exec` has read it to the end, and it holds nothing. It can't be closed from outside, since `sandbox-exec` execs the command with it open, and a wrapper to close it wasn't worth a second exec inside the profile. `TestEscapeProfileNotInArgv` checks that it is at end of file and that no command line holds the profile or a covered path.

The profile is one form after `(version 1)`, `(begin ...)`, and its marker rules come first. If the stage is killed while `sandbox-exec` is still reading the profile from the pipe, `sandbox-exec` sees a prefix. It runs the command under a prefix that ends between two rules, with the rules after it missing, which can be every deny that follows an allow. A prefix of a profile in one form is a syntax error, and `sandbox-exec` exits 65 without running the command. `TestProfileCutShortDoesNotRun` feeds it every prefix of a real profile. Taking a file for the profile, in place of the pipe, would leave the profile readable by the command through its open descriptor, which the pipe at end of file avoids.

### Finding the sandbox's processes

The command's process group isn't the sandbox. A command can leave it with `setpgid`, with a shell's job control (`set -m`), or by joining its parent's group, which is the stage's and so the caller's. A process whose parent has died is no one's descendant. Each of those used to outlive the teardown and drop out of `Footprint`.

The sandbox's processes are found by the profile instead:

- Every profile carries a pair of random Mach service names: one it allows a lookup of, and one it denies.
- The stage, and `Footprint` in the caller, both outside the profile, ask the kernel about each pid with `sandbox_check(pid, "mach-lookup", SANDBOX_FILTER_GLOBAL_NAME, name)`. A process is the sandbox's when the second is denied and then the first allowed, asked in that order. `sandbox-exec` applies a profile to itself in place, so a process can be unsandboxed at one call and under another sandbox's deny-default profile at the next. Asked allowed-then-denied, that process looked like a member, and any teardown killed it. That was the `TestAPIConcurrent` flake: a sandbox started while another's scan ran came back with status 137. Out first means that process answers "allowed" at the first call. A process can't leave or change a profile, so "denied, then allowed" can't come from a change between the calls. `TestMemberNeverMatchesAProcessApplyingAProfile` hammers `sandbox-exec` starts with `member`; it finds a false match in about a third of them with the other order.
- `sandbox_check` answers 1, as for a denial, for a pid the kernel no longer finds: one that has gone, a zombie, and a process that has begun to exit. So after two denials, `member` asks `sandbox_check(pid, "no-such-operation", NO_REPORT)`, which answers -1 (EINVAL) for a pid the kernel finds, sandboxed or not, and 1 for one it doesn't, and counts the answer as unknown in that case. These answers were measured, as Sandbox.kext isn't public.
- A process with no sandbox allows both. A process under another profile has other names: a deny-default profile denies both, and an allow-default one allows both. Another sandbox of this package has names of its own.
- So only a process under this sandbox's own profile gives that pair of answers, and it can't change them, since a process inside a profile can't apply another.

`TestMarkerNamesOnlyItsSandbox` checks it against each of those kinds of process. The first idea, a path, failed: a path that doesn't exist reads as denied for every process, and a Mach name needs no file.

`sandbox_check` is a libSystem function, and the module builds with `CGO_ENABLED=0`. It's reached as `golang.org/x/sys/unix` reaches its libc calls: a dynamic import, an assembly trampoline (`member_darwin.s`) and `syscall.syscall9`, which the Go runtime exports. The function is variadic, and Apple's arm64 convention passes variadic arguments on the stack. So the name is given both where amd64 reads it (the fourth register) and where arm64 does (the first stack slot, the ninth argument of `syscall9`). It has been run on arm64 and on amd64 under Rosetta 2.

### Teardown

The stage ends the command's process group, then scans until a scan proves that nothing runs under the profile, or until it has reason to stop (below). `Wait` skips its own scan when the stage says it did, and returns `ErrSurvivors` without one when the stage says it gave up on members. The scan code is `scan_darwin.go`, and the two `proc_info` calls it makes are `procinfo_darwin.go`.

#### What a scan proves

The earlier teardown listed processes with `sysctl kern.proc.all`, signaled each match as it found it, and stopped after five scans in a row found none. Five empty scans made a miss unlikely and didn't rule it out. In XNU, `kern.proc.all` is `sysctl_prochandle` in `bsd/kern/kern_sysctl.c`, which calls `proc_iterate` in `bsd/kern/kern_proc.c`. `proc_iterate` copies the pids under `proc_list_lock`, skips every process whose `p_stat` is `SIDL` (it is still being made by `fork`), and fills in each pid after it has dropped the lock, leaving out any that has gone by then. A sandbox process that forks and exits inside that window makes the scan look empty while its child lives.

A scan now starts from `proc_listpids(PROC_UID_ONLY, euid)`, which `proc_info_internal` reaches in `bsd/kern/proc_info.c` as `proc_listpids`. It copies every matching pid out of `allproc` and then `zombproc` inside one hold of `proc_list_lock`. It skips only exec shadow processes (`P_REF_SHADOW`), and `bsd/kern/kern_exec.c` swaps the shadow and the real process of a pid inside one hold of that lock, so every pid is listed once. Zombies are in it. A process that `fork` is still making isn't: `forkproc` puts it in the pid hash, but `pinsertchild` adds it to `allproc` only after `fork_create_child` has copied the address space, and `proc_pidinfo` can't reference it until then (`P_REF_NEW`). The proof doesn't need it. Such a child exists only because its parent is inside `fork`, so the parent is alive and in the list, and if the child will be the sandbox's, so is the parent: the scan kills it, or finds it exiting or gone, and isn't clean. `fork1` ends the child if the parent has begun to exit. Every process of the uid that is on those lists at that moment is in the list, and none that forks later is. If every pid in the list is then shown not to be under the profile, nothing under the profile existed at that moment, and nothing can start under it again. A process only gets the profile from a parent that has it, or from `sandbox-exec` applying it to itself, which the table below covers.

The list is only pids, so each pid is checked, in this order, and a pid the scan can't account for makes the scan unclean:

| What the scan finds for a pid | Result |
|---|---|
| An earlier scan of this teardown found it not to be the sandbox's, and `proc_pidinfo` shows the same start time | Safe, and not asked again. A process can't become a member (below), so what it does since doesn't matter: it can exit, turn zombie or hang in exit. |
| `sandbox_check` says it is the sandbox's | `SIGKILL` it now. The scan isn't clean. |
| `proc_pidinfo(PROC_PIDTBSDINFO)` fails, as with `ESRCH` | Unknown. The process may have been the sandbox's, with children the list didn't hold, or the number may now be another process's. |
| Its `pbi_status` is `SIDL` | Unknown. `proc_pidinfo` can see one only for the few instructions between `pinsertchild` and `p_stat = SRUN`, so this is belt and braces. |
| `PROC_FLAG_INEXIT` is set in `pbi_flags` and it isn't a zombie (a zombie keeps the flag) | Unknown. `proc_exit` sets `P_LEXIT` first. From then until the process is a zombie, `proc_pidinfo` still returns it alive with its old start time, and `sandbox_check` answers 1, so a member that was exiting looked like a non-member, and it may have forked a child after the snapshot. A run of 4000 `/usr/bin/true` children of a sandboxed shell had 16841 such checks. |
| Its start time (`pbi_start_tvsec`, `pbi_start_tvusec`) is at or after T, the time noted just before the list | Unknown. The pid may be a reuse, so the check may have been about another process. A process that started before T and is still there is the one that was listed: `forkproc` in `bsd/kern/kern_fork.c` skips a pid that is in the pid hash, which holds zombies too, so a number isn't given to a second process while the first is listed. |
| `sandbox_check` failed, or answered 1 for a pid the kernel doesn't find | Unknown. |
| It is under no profile (the lookup of the name the profile denies was allowed), its name (`pbi_comm`) is `sandbox-exec`, and it is the pid of the `sandbox-exec` that the stage or `Start` started | Unknown. `sandbox-exec` applies the profile to itself and then runs the command, so before that it is unsandboxed, and afterwards it is the sandbox. Only a stage killed in the few milliseconds before that leaves one. A second check after the name is read catches one that applied the profile and started the command in between, which changes its name. A process in another sandbox, or any other pid, doesn't count. Only `Start`'s failure path, which doesn't have the pid, takes any unsandboxed process of that name, and its result isn't reported, so a stray one there costs that path up to a second. |
| It is a zombie (`pbi_status` `SZOMB`), or exiting and not yet a zombie, and the previous scan did not see it so with the same start time | Unknown unless its parent is cleared (next row). It may have been the sandbox's, alive at this snapshot, with children. |
| It is a zombie or exiting, and the previous scan saw it so with the same start time | Safe. It was dead or dying before this snapshot, so it can't fork (`fork1` ends a child whose parent has begun to exit), and the children it had made are in this snapshot and are checked themselves. This is what stops a process stuck in exit from holding every scan. |
| It is a zombie or exiting, new to the scan, and its parent (`pbi_ppid`) is a process that this scan found not to be the sandbox's and that started no later than it | Safe. `fork` gives a child its parent's profile, and a non-member can't become one. The parent is listed too: it was alive at the snapshot, since it is alive when the child's parent is read, and a number taken by a later process belongs to one that started after T, which can't be the parent of a child that started before. `proc_exit` in `bsd/kern/kern_exit.c` gives the children of an exiting parent to launchd (pid 1, never a cleared parent), and `ptrace(PT_ATTACH)` in `bsd/kern/mach_process.c` makes the debugger the target's parent until it detaches (`p_oppid`). So a member could look like a non-member's child only if a process outside any sandbox, started by the account's owner, attached a debugger to it, and the check that the parent started no later than the child rules out a debugger younger than what it attaches to. |
| Anything else | Not the sandbox's, and remembered with its start time. |

The `sandbox_check` comes before the `proc_pidinfo`, so that the start time read afterwards shows which process the check was about.

The zombie rule, which the exiting rule shares, comes from `proc_pidinfo` in `bsd/kern/proc_info.c`. For `PROC_PIDTBSDINFO` it calls `proc_find`, and only if the call's `arg` is non-zero and that fails, `proc_find_zombref`, which finds a process that `proc_list_exited` says has exited and not been reaped. `proc_pidbsdinfo` then reports `p_stat`, which is `SZOMB`, and the start time. So the scan passes `arg` 1. Without the rule, one zombie that nothing reaps would make every scan unknown and end in `ErrSurvivors`. With it, the first scan after the zombie appears costs one more, and `TestTeardownLingeringZombie` runs that. A process in between, which `proc_find` can no longer reference and `proc_find_zombref` doesn't yet find, is `ESRCH` and so unknown, and the next scan sees it as a zombie.

`proc_listpids` returns at most `nprocs + 20` pids and at most what the buffer holds, and a list that fills either is asked for again, so a scan never works from a list that was cut short.

A scan costs about 2 ms with 400 processes on the account, and a `/usr/bin/true` sandbox needs one. The old teardown scanned five times in the stage and five in the caller. A scan after the first costs less, since a process it already found not to be the sandbox's is only stat'ed.

#### The order of checks

After the list, the scan checks the pids that no earlier scan of the teardown cleared, and then reads the start time of the ones that did. Each new pid is a process that may have been a member and may vanish before it is read, and what makes it vanish is the time from the list to the read, so those go first. The cleared ones still need their start time: a pid is the same process only if its start time is, and a number that was cleared may now belong to a process that was forked from a member. So the scan can't trust the number alone, and `TestScanDoesNotTrustARememberedNumberAlone` kills a member that took one. With the same start time the process is the one that was cleared, and a process can't become a member, so nothing more is asked of it.

#### How a teardown spends its time

The first scan runs at once, so a `/usr/bin/true` sandbox costs one scan and no wait. After an unclean scan the teardown waits 1 ms, then twice as long each time up to 25 ms, and never past its deadline (`backoffStart` and `backoffMax`). A scan that follows straight after the last takes the processors from what the scan is waiting for: the processes it signaled finishing their exit, the parents that reap zombies, and the account's own churn. The waits are injected through the `prober` like the clock, so the tests of the schedule run in no time.

The teardown also ends early, and it is the cause of the unclean scans that decides. A scan that signaled a member counts. If `giveUpScans` scans (10) have found members, something is forking against the teardown, and it gives up with `endMembers`, in about 130 ms, instead of using its whole budget (`TestRunGivesUpOnMembersThatKeepTurningUp`). Scans that found no member and only pids they couldn't account for, such as vanished pids, new zombies, exiting processes and failed checks, are noise, and it keeps trying for the whole budget of five seconds (`TestRunKeepsTryingThroughNoise`). A program that shuts down normally has its members signaled in the first scan (or killed with the command's group before it), a second scan for what they forked as they died, and a third for the children of those at most (`TestRunDoesNotGiveUpOnANormalShutdown`). Eight chains of processes that fork and exit at once, each leaving a session of its own, end in 3 to 5 scans, with the stage and no caller scan, and `Wait` returns nil (`TestTeardownDoesNotGiveUpOnShortChains`); so 10 is twice what that took. A real chain could not be made to defeat the teardown on this machine, and no test makes a fork bomb. The tests that give up take the stage's `kill` away, with `SANDBOX_TEST_STAGE_NO_KILL` in the command's environment, so the member, which is out of the command's group, is found again at every scan (`TestTeardownGivesUpOnMembersItCannotEnd`), and in the caller with a hook in the test process (`TestWaitGivesUpOnMembersItCannotEnd`).

The stage says how it ended in `stageDone`: `empty`, or `members` when it gave up on them, and neither when it ran out of its budget on noise or when it was killed. `Wait` returns `ErrSurvivors` at once when the stage says `members`, since another budget of scans would go the same way and the stage had all of the first. When the stage says neither, `Wait` scans for itself, with the same rules. `Wait` can still never return nil unless a scan proved the sandbox empty, its own or the stage's: the report can only make it return the error sooner, and the stage is as trusted as for `empty`.

#### Process churn

A pid that vanishes or is new between the list and the read makes a scan unclean, whoever's it is, so other processes of the account that start and exit fast enough keep scans from being clean. A pid that has gone can't be accounted for: the scan doesn't know what it was. The scan takes more of them in its stride than it did: it remembers what it cleared, it excuses a zombie or exiting process by its parent, it remembers one that is stuck in exit, it checks new pids first, and it waits between scans. What is left is the processes that exit before the scan reads them.

`SANDBOX_CHURN=1 go test -run TestChurnCleanScanRate` measures it with fork loops (`perl` forking one child at a time that exits at once), on a quiet 10-core Mac. It scans for 2 seconds, waiting between unclean scans as a teardown does, and then makes 20 teardowns with a 200 ms budget (`SANDBOX_CHURN_BUDGET_MS`, `SANDBOX_CHURN_LOOPS` and `SANDBOX_CHURN_BACKOFF` change them). Clean scans, and teardowns of 20 that gave up, by the tree:

| Fork loops | Forks per second | Before: no waits, remembered pids first | Waits only | Waits and new pids first (now) |
|---|---|---|---|---|
| 1 | 1,200 to 1,300 | 82%, 82%, none gave up | 64%, none | 76%, 76%, none |
| 2 | 2,500 | 71%, 70%, none | | 69%, 69%, none |
| 4 | about 4,500 | 47%, 47%, none | 26%, 57%, 34%; 1, 1, none | 64%, 66%, none |
| 8 | 6,100 to 6,800 | 37%, 34%, none | 2%, 18%, 3%; 11, 5, 13 | 49%, 49%, none |
| 16 | 6,700 to 6,900 | 31%, 30%, none | 4%; 12 | 45%, 43%; 1, 2 |

"Before" is the tree as it was before the waits, which already had the memory of cleared pids and the parent rule. Without any of those, the first review's tree had 0% at 16 loops and gave up in 18 or 19 of 20. The percentages are per scan, and scans with waits come less often, so they say how likely a scan is to be clean, not how long a teardown takes. The teardowns say that: with the waits and the new order, a teardown averaged 1.3 scans at 1 loop and 4.3 at 16, and the worst took 3 ms and 200 ms. Waits alone did harm, and I don't know why; the guess is that with scans further apart more of the remembered pids have changed between them, so the order of checks matters more. Without the waits the new order made no difference (36% and 34% at 8 and 16 loops).

With a budget of 5 seconds, the teardowns that the scans of the table stand for don't give up: at 8, 16 and 24 loops (7,200 forks per second) 20 of 20 each finished, in 3, 4 and 5 scans on average, and the worst took 90, 180 and 295 ms. The budget is about 17 times the worst teardown, so it stays at 5 seconds. A normal command that leaves two orphans behind took 26 ms from `Start` to `Wait` on an idle machine (p50, 1 scan), 32 ms with 4 loops, and 62 ms with 16 (p90 115 ms, 3.4 scans on average), with no `ErrSurvivors`; with no waits the same runs were 24, 32 and 67 ms. The waits were picked by trying 0, 1 to 25, 0.5 to 10, 2 to 50 and 5 to 100 ms: bigger waits gave up more at 16 loops (3 of 20 at 2 to 50, and 2 at 5 to 100, with a 200 ms budget) and cost latency, and 0.5 to 10 was no better than 1 to 25.

This is a limit of the design, not of these fixes: at about 7,000 forks a second with the CPUs saturated, more than half of the scans are still not clean. A teardown settles in a few scans anyway, but a longer load, or a heavier one, could run out its budget for a clean host. It takes a process that forks that fast, so it also takes the CPUs; the cost is that one sandbox can slow the teardown of another and, at the extreme, turn a `Wait` into `ErrSurvivors`. [security-model.md](security-model.md) lists it.

#### The stage tells the caller

The stage keeps its status pipe open after its first reply. After its teardown and before it exits it sends one more message, `stageDone`: whether the last scan proved the sandbox empty, and how many scans it made. `Wait` reads it after the stage has exited, and takes it only if it says it is the `done` message. If it says the sandbox is empty, `Wait` doesn't scan, since nothing can ever start under the profile again. If it says it gave up on members, `Wait` returns `ErrSurvivors` without scanning. A stage that was killed, or that ran out of time on noise, sends nothing or says neither, and `Wait` runs the same scan itself, until a scan proves it, it gives up on members, or five seconds pass. The pipe is read with a one-second deadline, so something else holding its write end can't stall `Wait`. `watchStage` is as it was: it starts that scan as soon as it sees the stage is gone, since a survivor may hold the command's output open.

The caller trusts the stage's word. The stage runs outside the profile, and the sandbox can't signal it, since the profile allows signals only within the sandbox. Nothing in the sandbox is given the status pipe either: the stage marks every descriptor it doesn't pass on close-on-exec before it starts the command. So the command can neither make the stage report falsely nor stop it from reporting, short of ending the stage, and a stage that has ended sends nothing.

`Footprint` still lists with `kern.proc.all`. It needs each process's parent and group for the descendants, a sum that leaves out a process that is gone before it is read is what it promises, and it isn't proving anything. Using the atomic list would add pids without parents.

#### What's left

A first version of the old teardown listed every match and signaled afterwards. A single process that forked, exited and made a session again every millisecond outran it: each generation had exited by the time it was signaled, and its successor wasn't yet in the list. `TestEscapeReforkingProcessEnds` runs that chain, one live process at a time. It stops by itself after 10 seconds so that a teardown that fails leaves nothing running, and the teardown ends it in under a second.

A fork bomb, or enough of these, can still keep ahead of the scan until it stops on its own, and nothing bounds it: every scan then has a member to kill, so none is clean. The teardown stops after 10 such scans, about 130 ms, and `Wait` returns the error at once. `RLIMIT_NPROC` counts the whole uid and doesn't limit a chain with one live process. When no scan proved the sandbox empty in the time allowed, `Wait` and `Run` return an error that matches the exported `ErrSurvivors` with `errors.Is`. It wraps the command's own result, so `errors.As` still finds its `*exec.ExitError`, and `Run` still returns the status. Linux never returns it, since the sandbox's pid namespace dies with its pid 1. `TestAPIErrSurvivors` checks both. [usage.md](usage.md#what-to-do-on-errsurvivors) says what a caller does.

A survivor keeps what the profile gave it: the home, the `Write` paths, the network the `Spec` allows, and the command's output, which keeps `Wait` itself from returning unless `WaitDelay` is set.

The caller's own scan kills by the profile's marker only. The command's process group is a pid that the kernel may give to someone else once the group is empty, and a late `Wait` once could have signaled it. `Footprint` counts a member of the group only if the stage is among its ancestors, for the same reason.

## The network

`NetworkNone` allows no network operation at all, except what the `Spec` names. Those are single-port allows, since a port deny after a broad allow doesn't hold ([measurements](#measurements-from-the-early-experiments)):

- **`Listen`.** `Command` binds that many listeners on `127.0.0.1:0` and `ListenAddrs` returns them, so `Env` can carry `HTTP_PROXY`. The profile lets the command connect to those port numbers, over TCP, on any address the host has. The caller serves them. Other local processes can connect to them too, and a proxy applies its rules to them as to anyone.
- **`Loopback`.** `Command` reserves free ports, and `LoopbackPorts` returns them. `Start` frees them, and the profile lets the command bind, accept on and dial exactly those, over TCP and no other protocol. Another process could take one between `Start` freeing it and the command binding it. There's no way to hold a port for a process that binds it later.
- **A `Write` path that is a socket** gets a connect rule for that path, since a file allow doesn't grant a connect. Another socket in a `Write` directory, in the home or anywhere else doesn't connect, and the command can't bind one of its own. Linux allows both, so a command that serves a unix socket for itself fails here.

**`Loopback` isn't a private loopback.** A profile names a host only as `*` or `localhost`, and `localhost` is every address the host has. So the command can bind a `Loopback` port on the LAN address or the wildcard. Under `NetworkNone`, any host that can reach any address of this Mac (a peer on the LAN, over a VPN, or on a routable IPv6 address) can connect there. Only this Mac dialing its own LAN address was seen, and no second machine was tried.

Seatbelt checks the remote address when a connection is made and not when it is accepted, so the peers can't be limited to this host either:

- A `network-inbound` deny of every remote but `localhost`, written after the allow, let a local connection through.
- The same allow with a remote filter made `listen` itself fail.

Any local process reaches these ports too. A command that serves must bind `127.0.0.1` explicitly, and a caller that can't accept those hosts being able to reach it should not give a command a `Loopback` port. A command that can take an inherited socket needs none: a listener the caller binds on `127.0.0.1` and passes in `Spec.Files` is on `127.0.0.1` only, since the command's own binds of that port elsewhere are refused (`TestEscapeInheritedListenerIsLoopbackOnly`). `TestGapLoopbackBindsLANAddress` shows the gap, and fails when it stops being so. The rules are TCP only, so a UDP socket on those ports is refused (`TestEscapeLoopbackPortsAllAddresses`).

**`NetworkHost`** allows TCP and UDP out, and the one unix socket that name lookups go through, `/private/var/run/mDNSResponder`, with the Mach services a lookup needs. Then it denies `localhost:*`. In a profile `localhost` is every address the host has, so this refuses the host's LAN address and the caller's own listeners on it too, which is stricter than planned.

**`BroadLoopback`** is the opt-in gap. It allows `localhost:*` to bind, accept and dial, TCP and UDP. The command then reaches every listener on any address the host has, including the caller's own and the user's other local services. It can also bind any port on any address, which lets it squat a port a local client expects, or serve the LAN. Services bound only to `127.0.0.1` that trust local connections, such as a development database with `trust` authentication or an unauthenticated Redis, are out of the LAN's reach but within the command's. `Probe` reports `PrivateLoopback` as false.

## The environment, the home and temporary files

`Start` sets `HOME`, `TMPDIR`, `XDG_RUNTIME_DIR` and `XDG_*` over `Cmd.Env`, as on Linux. It also sets `CFFIXED_USER_HOME` to the home, since Cocoa finds `~/Library` by that and not by `$HOME`.

`TMPDIR` and `XDG_RUNTIME_DIR` are a directory named `tmp` in the home, which `Start` makes with mode 0700. There's no private `/tmp`, so a program that hard-codes `/tmp` is refused. The directory has no size cap beyond `RLIMIT_FSIZE` per file, and stays until the caller removes the home. `ScratchSize` and `Hostname` are ignored.

## Services

A `Service` is a reviewed group of Mach services to allow lookups of. There are two, each with the evidence it came from:

- **`ServiceFirefox`:** `mach-register` and `mach-lookup` of `org.mozilla.machname.*`, which Firefox's processes register and look each other up by. Also the lookups of `launchservicesd` and `configd`, which it aborts or crashes without. The `launchservicesd` lookup doesn't let the command open anything, since `lsopen` is a different operation ([below](#m3-launchservices-and-lsopen)).
- **`ServiceDirectory`:** the `opendirectoryd.libinfo` lookup, which `getpwuid` and `getpwnam` use. Without it they find nothing, since the sandbox has no passwd entry of its own, and `id -un` prints only the number. With it the command can look up, and list, every account on the host.

The `org.mozilla.machname.` names are one namespace for the whole user session, shared with the user's own Firefox and with every other sandbox given this group. So two sandboxes can find each other's services and pass ports, and one can register a name before the other. Firefox 160.0.1 builds the name from a compiled-in format (`org.mozilla.machname.%d`, as `strings` on its `XUL` shows) and has no setting that was found for a prefix per instance. So the group can't be narrowed to one sandbox's own processes. If the sandboxes don't trust each other, run Firefox sandboxes one at a time, and not beside another program that registers such names.

A fonts group isn't defined: Firefox renders text from `/System/Library/Fonts` with file reads alone, and a group needs evidence. `Command` refuses a name it doesn't know.

## Limits

`Rlimits` are set by the stage. Only `CPU`, `FSIZE`, `CORE` and `NOFILE` do what they say:

- A CPU limit is a `SIGXCPU` that a program can ignore, which ends it only if it doesn't ([findings](findings.md#rlimit_cpu-is-not-a-kill)).
- `RLIMIT_AS` is the same number as `RLIMIT_RSS` on macOS and nothing enforces it. `Command` refuses `ResourceAddressSpace`, and `Probe` lists it in `Unsupported`.
- `RLIMIT_NPROC` counts every process of the uid, the caller's own included.
- A limit of none is the most this process may set. `RLIM_INFINITY` is 2^63-1 there, an unprivileged process can't raise a hard limit, and an open-file limit above `kern.maxfilesperproc` is refused outright.

`Cmd.Footprint` is the memory watchdog. It sums `ri_phys_footprint`, which macOS itself charges a process and which counts compressed and swapped pages that a resident size leaves out. It sums over every process that runs under the sandbox's profile, wherever it has gone ([finding the sandbox's processes](#finding-the-sandboxs-processes)), and also the command's process group and every descendant of its members, which covers the moment before `sandbox-exec` has applied the profile.

An error that says no process is left means the command and all it started have ended. It's read through `proc_info` directly, since the package builds without cgo. It's the sum at one moment, a process that is gone before it is read is left out, and macOS swaps before it kills. So it's a soft limit for a caller to poll. Linux has `Footprint` too, as the sum of resident sets of the bubblewrap process's descendants, for a host with no delegated cgroup.

## Differences from Linux in the API

- **`Pid`** is the stage's pid, this process's own child. On Linux it's pid 1's host pid, from `--info-fd`.
- **No control socket.** The parent binds the listeners, so settings, the reply and the lifeline are pipes.
- **`Command` binds the `Listen` listeners and reserves the `Loopback` ports**, since `ListenAddrs` and `LoopbackPorts` are known before `Start`. `Start` frees the reserved ports just before the command can bind them. A `Cmd` that is never started gives its sockets back when its context ends.
- **`SelfPath`** is a variable, the binary's real path, and every profile lets the command read and run exactly that file. On Linux it's the constant `/dev/sandbox-stage`.
- **`Service`** names only two groups, and `Command` refuses any other.
- **`Kernel`.** Every level gets the one profile, which is at least as strict as the request.
- **`argv[0]`** of the command is the `PATH`-resolved path, since `sandbox-exec` takes the program and not a name for it.
- **The command can't call `setsid`** (it leads its group), but its children can, and it can leave the group with `setpgid`. Neither matters to teardown now.
- **Unix sockets.** The command can't bind one anywhere, which Linux allows.
- **Firefox's `Library/Application Support`** in the home is made with an ACL that denies deletion, so a caller that removes the home runs `chmod -RN` on it first.

## Probe and Check

`Probe` applies a trivial profile with `sandbox-exec`. It reports:

- backend `seatbelt`;
- every `Kernel` level as `strict` (there's one profile, which is at least as strict as any request);
- `TreeKill` true and `PrivateLoopback` false;
- `Ignored`: `Hostname` and `ScratchSize`, and `Unsupported`: the address-space limit;
- `Container` as `app-sandbox` or `launchd-job` where it can tell.

Its `Checks` end with a `NotEnforceable` finding for each gap: no pid namespace, the caller's environment readable, Loopback and Listen ports on every address, `BroadLoopback`, `F_SETOWN` signals, files of the account outside the covers, no system call filter, no limits, and no scratch size. When the trial fails because the process is already inside a deny-default profile, `probe.seatbelt` fails with the fix. A profile that allows everything doesn't stop a second from being applied, so only a restrictive one is detected.

`Check` runs the generic suite on macOS. The Linux-only checks are skipped.

- Processes outside are listed through `kern.proc.all`, and tried with `kill(pid, 0)` and with `KERN_PROCARGS2`. That returns another process's environment when it has one, except for Apple's own binaries. The account's own processes are tried first, since only a profile stops those: the others refuse by uid.
- A sandbox gives the check child its own `HOME` and an empty environment, so what it would build from them, the user's `~/.ssh` or the socket in `SSH_AUTH_SOCK`, names nothing of the caller's. `Check` therefore works those out in the caller. It sends the child the secrets and sockets that exist, and the directories outside the sandbox's own that this account can write (`access(2)`, so nothing is created to find them).
- `secrets.readable`, `sockets.reachable` and `writes.outside` try those. They're skipped, with the reason, where nothing exists to try, not passed. `TestCheckCatchesEscapesDarwin` makes each fail by a hole in the `Spec`, or with no sandbox, or in the check directly.
- `proc.trace` is skipped: `task_for_pid` needs a signed binary or root, and `ptrace` would stop its target.
- `proc.visible` and `proc.environ` fail inside a sandbox. They are the gaps in [Limits](security-model.md#on-macos).
- The well-known sockets include Docker Desktop's, Colima's, OrbStack's and Podman's.

## Measurements from the early experiments

Three experiments on macOS 27.0.1 (Apple silicon) settled the design. Their code was throwaway, and what they measured is kept here.

### M1: Seatbelt's per-port deny

The question was whether a profile could allow `localhost` broadly and deny single ports. It can't.

- **A port deny after a broad allow is unreliable.** With `(allow network-outbound (remote ip "localhost:*"))` and then a deny of one port, the deny held for 16 of 36 ports in 18070 to 18105. It worked for 18081, 8080, 3128, 9229, 18256 and 18400 over both `127.0.0.1` and `::1`, and was ignored for 18080, 18082, 18084 and 18100.
- **The pattern is stable and has no known cause.** It was the same on every rerun and with a `(deny default)` base. It changes with the filter's form: `(remote tcp ...)` gives a different but equally mixed pattern. `(require-all (remote ip "localhost:*") (require-not (remote ip "localhost:P")))` denied nothing at all. The rule order was the same in every case, so "last match wins" doesn't hold for port filters under a wildcard.
- **`localhost` means the host's own addresses, not loopback only.** Under the broad allow, a connection to the Mac's LAN address succeeded. `127.0.0.2`, which isn't configured, was refused. So moving a server off loopback onto its LAN address doesn't take it out of reach.
- **Single-port allows are reliable.** With a profile allowing only `localhost:P`, all 40 ports tested were reachable themselves and refused every other port. Both address families were checked, and the host's LAN address on that port was also allowed, which matches the point above. `(deny network-outbound)` alone refused everything, LAN address included.

So `NetworkNone` with single-port allows holds. A later finding showed one form of broad-then-deny does work, and it's the one `NetworkHost` uses ([findings](findings.md#a-localhost-deny-held-in-only-one-form)).

### M2: headless Firefox under sandbox-exec

Firefox 160 renders a page under a deny-default profile, byte-identical to an unsandboxed render. [usage.md](usage.md#firefox) says how to run it. What the experiment measured:

- **The first attempt hung with no sandbox at all.** `~/Library/Application Support/Firefox` is protected by TCC on macOS 27, and reading it without Full Disk Access fails with `EPERM`. Firefox 152 reads it even when `-profile` points elsewhere, and spins when it can't (fixed upstream in Firefox 158). The fix is `CFFIXED_USER_HOME` pointed at an empty directory, which is why `Start` sets it.
- **The `sandbox_extension_issue_file_to_process … Operation not permitted` line is noise.** It prints on every run, including the ones that work.
- **Child processes fail `sandbox_init`.** All of them run the same `plugin-container` binary, and a process already inside a profile can't apply another (`forbidden-sandbox-reinit` in the log):

  | Child | Unswitched | Switch that fixes it |
  |---|---|---|
  | content (tab) | crash loop: 523 `sandbox_init` failures in 25 s, no screenshot | `MOZ_DISABLE_CONTENT_SANDBOX=1` |
  | socket | fails init; the render still completes | `MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1` |
  | RDD | fails init; the render still completes | `MOZ_DISABLE_RDD_SANDBOX=1` |
  | GPU, utility, GMP | never started for this page | their switches changed nothing here |

- **The minimal profile** was found by widening a deny-default profile only from the deny log, then removing one rule at a time. It needs: the app bundle, `/System`, `/usr/lib` and `/` itself (a directory read); `sysctl-read`; and Mach lookups of `launchservicesd`, `configd` and `org.mozilla.machname.*`, which Firefox also registers. Dropping `launchservicesd` aborts it (`SIGABRT`) and dropping `configd` crashes it (`SIGSEGV`).
- **About 25 other Mach services are looked up and refused with no effect**, among them `windowserver.active`, `CARenderServer`, `tccd`, `opendirectoryd.*`, `diagnosticd`, `logd`, `pasteboard.1` and `dock.server`.
- **`iokit-open` isn't needed.** Firefox asks for `IOSurfaceRootUserClient`, `AGXDeviceUserClient` and `AppleNVMeEANUC` and is refused each time. Headless falls back to software rendering, and the PNG is unchanged.
- **Refused with no effect:** `/Library/Fonts`, `/usr/share` (ICU, zoneinfo), `/dev/urandom` (Firefox uses `getentropy`), `/dev/null`, `/private/etc/passwd`, `/Library/Preferences/*`, and `file-read-metadata` almost everywhere else. The page's Helvetica comes from `/System/Library/Fonts`.
- **`/Users` stays covered.** Firefox still tries the real `~/Library/Preferences/*.plist` through CFPreferences, which resolves that path itself, and `$(getconf DARWIN_USER_TEMP_DIR)/firefox`, despite `TMPDIR`. All are refused with no effect on the render. Nothing was written outside the run directory.
- **Other refused operations:** `signal` to another process from a system framework, `system-socket domain:17` (`AF_ROUTE`), `network-outbound /private/var/run/mDNSResponder` (so no DNS under `NetworkNone`), and `file-issue-extension`.
- **A failure that looks like success.** Without the `mach-register` rule, children can't check in (`bootstrap_check_in failed`), yet Firefox exits 0 and writes no PNG. The caller has to check that the output exists.
- **Network.** A page that loads a green image from one loopback port and a blue one from another got the green one only when the profile allowed that one port. With no network rule it got neither, and a `file://` page still rendered.
- **Not run:** geckodriver and Marionette under the profile, trmnlp's runtimes, web fonts and media, and windowed-mode parity.

### M3: LaunchServices and lsopen

Firefox needs a lookup of `launchservicesd`. The question was whether that lets a sandboxed process open an app or a URL, which would start a process outside the profile. It doesn't. The test ran `open -g` on an app and on a URL, with a local server logging requests, since a URL open reaches the default browser outside the profile:

| Profile | App open | URL open | Key denial |
|---|---|---|---|
| Firefox's set plus `open`, without `launchservicesd` | fails | fails | not needed |
| plus `launchservicesd` (Firefox's set) | fails, `kLSNoExecutableErr` | fails, no request logged | lookups of `lsd.mapdb`, `lsd.modifydb`, `coreservicesd` |
| plus those services and the file and system rules they asked for | fails, error -54 | fails, error -54, no request logged | `deny(1) lsopen` |
| plus `(allow lsopen)` | **Calculator launched** | **Safari fetched the beacon** | none |

Seatbelt has a dedicated `lsopen` operation, and it's the real gate. Under `(deny default)` it stays refused even with every LaunchServices Mach service allowed, and the open fails with -54 (`permErr`). With `lsopen` allowed, a sandboxed process launches any app and makes the user's browser fetch any URL, which is an egress path.

So the rule is **never allow `lsopen`**, not "never look up `launchservicesd`". The library never emits it, and `TestEscapeLaunchServices` asserts that `open` of an app and of a URL both fail under every `Services` group. What isn't tested: whether `launchservicesd` checks `lsopen` on the server side ([findings](findings.md#launching-apps-and-urls)).

## Tried and dropped

- **`sandbox_init` through cgo or `dlopen`.** It would apply the profile in the stage, with no `sandbox-exec`, no pipe and no leftover descriptor. It breaks `CGO_ENABLED=0` builds, and a profile applied to a Go runtime that then execs is a larger change than a program that only execs.
- **A shell wrapper to close the profile's descriptor.** One more exec inside the profile, for a pipe that is at end of file.
- **`(deny network-outbound (remote ip "localhost:P"))` after a broad allow.** It held for about half of all ports (M1). `localhost:*` after a tcp and udp allow holds, and a profile that allows only named ports always did.
- **Denying `kern.procargs2` by name, or `process-info*`.** Neither stops `KERN_PROCARGS2`.
- **Denying signals to others by name.** `(target same-sandbox)` allows exactly the sandbox's own, which a list of what to refuse couldn't do.
- **Normalizing the case of paths.** Seatbelt matches case-insensitively on a case-insensitive volume, so there's nothing to normalize.
- **Writing each rule under both names of a firmlinked path.** Seatbelt matches the usual name, so a rule for the other matches nothing and a second rule is dead weight. `prepare` maps a name through `/System/Volumes/Data` to the usual one instead ([findings](findings.md#a-cover-named-through-the-data-volume-covered-nothing)).
- **`RLIMIT_AS`.** Not enforced. It's refused rather than set.
- **A path as the teardown's marker.** A path that doesn't exist reads as denied for every process. A Mach name needs no file.
- **Ending only the command's process group.** A command can leave it ([findings](findings.md#a-process-could-leave-the-process-group-and-outlive-teardown-and-footprint)).
