# Testing

How the sandbox is tested, where the tests have run, and how to run them. The test names in [security-model.md](security-model.md) and [findings.md](findings.md) are in `*_test.go` files in the repository root.

## Test layers

The tests run real sandboxes, as the account's own uid. On Linux that takes bubblewrap's unprivileged path as a deployment does. Running them as root of a user namespace had hidden that bubblewrap's capabilities don't reach the view.

1. **Unit tests** need no sandbox. They check path resolution, covers and links (`spec_test.go`), the seccomp filter offline (`seccomp_linux_test.go`), the generated Seatbelt profile as text (`profile_darwin_test.go`), flags, `Probe`'s diagnosis (`probe_test.go`) and the `Check` machinery.
2. **Core tests** start sandboxes and check the basics: `Command`, `Start`, the lifeline, listeners, the kernel levels, the mount layouts, and `TestIsolation`, which runs the generic escape attempts that need no proxy.
3. **API tests** (`api_guarantee_*_test.go`) try every public contract: what `Command` refuses, what `Start` does and undoes on failure, each `Spec` and `Cmd` field, `Run`, limits, listeners, `Footprint` and concurrent sandboxes.
4. **Escape tests** take each guarantee in [security-model.md](security-model.md) and run code inside a sandbox that tries to get past it, and the test asserts it fails. Each cites the row it checks as `Row: ...`, by the first words of the guarantee. A guarantee a platform can't give has a `TestGap...` test that shows the gap and fails when it closes, so the docs get changed with it.
   - Linux: `escape_guarantee_linux_test.go`, and `hardening_linux_test.go` for the review's findings. `TestEscapeChecksCatchEscapes` runs the checks against sandboxes that have the hole, to see that they fail.
   - macOS: `escape_guarantee_darwin_test.go`, and `escape_review_darwin_test.go` for the review's findings and its re-review's: the ways out of teardown and `Footprint`, a process that re-forks every millisecond, the marker and the refusal of a second profile it rests on, a reused group number, a sandbox replacing its own root, firmlink names, the device list, `F_SETOWN`, Loopback ports on every address, the caller's environment, and one sandbox signaling another.
5. **`Probe` and `Check` tests** (`probe_*_test.go`, `check_*_test.go`) check the diagnosis and the checks, and that each check fails when the guarantee is broken, so none passes whatever happens.
6. **Firefox tests** (`firefox_darwin_test.go`) render a page with headless Firefox under the generated profile and check a network allow and a refusal. They skip where Firefox or a C compiler isn't there.
7. **Mutation checks**, by hand. See [below](#mutation-checks).

The test binary is also the code that runs inside the sandbox, as its own first stage and as a checker the tests name. A `TestMain` calls `Stage`.

### Linux fixtures

Some tests build a fake host first, in a user and mount namespace of their own: homes under `/srv`, a `passwd` that lists them, links in `/etc`, a stand-in for a caller's state, and a listening socket. That lets them test layouts a real host rarely has, such as a second user's home or a ZFS mount table.

### macOS fixtures

The tests start real sandboxes with `/usr/bin/sandbox-exec`, as the account's own uid, and need no setup. A tree that holds the test binary, `/bin/sh` and, for two tests, `/Applications/Firefox.app` and a C compiler is all they need. Those tests skip without them. Every path a test gives a `Spec` is a real one, since `t.TempDir()` leads through `/var`.

## Where the tests have run

The counts include subtests, and are the same with and without cgo. They are the last recorded runs. Only the macOS top-level count (132 tests: 131 passing and 1 skipped) was rechecked when these docs were written, with `go test -list`.

### Linux

| Target | How | Pass | Skip | Fail |
|---|---|---|---|---|
| Debian 13, arm64, kernel 6.12, bubblewrap 0.12.0, Lima VM `sbx-dev` | default | 293 | 5 | 0 |
| Debian 13, x86_64, Proxmox kernel 7.0.14, LXC container, bubblewrap 0.12.0 | `SBX_SSH=user@host` | 293 | 5 | 0 |
| Ubuntu 24.04.5, arm64, kernel 6.8, bubblewrap 0.9.0 from apt, AppArmor restriction on, Lima VM `sbx-ubuntu` | `SBX_VM=sbx-ubuntu SBX_APPARMOR=1` | 293 | 5 | 0 |

Each was run with `CGO_ENABLED=0` and with cgo on (`CGO=1`, which builds on the target, since the host has no C cross-compiler). Each was rerun after the macOS review fixes.

Without `SBX_APPARMOR=1`, the same Ubuntu run fails 159 of the tests that start a sandbox, in 11 seconds and with no hang, and `TestProbeVM` shows the diagnostic. On Ubuntu 24.04 the tests run as the account's uid under a profile for the test binary. The suite passes on apt's bubblewrap 0.9.0, so the 0.8 floor is tested at 0.9, and the symlink flaw fixed in 0.12.0 stays open there as [security-model.md](security-model.md#open-issues) notes.

**The skips** are the same on every target except where noted:

- `TestWriteApparmorProfile` is the helper that `scripts/apparmor.sh` calls, and skips unless asked.
- `TestAPIRlimits` skips where the host's hard core limit is unlimited, so no higher one can be asked for.
- `TestAPICgroupFD` skips where the login session has no delegated cgroup to start in.
- The `.zfs` case of `TestEscapeMountTableCovers` skips where there's no ZFS dataset (`TestMountCovers` checks the rule on a fake mount table).
- Two differ by target. The foreign-ABI case of `TestEscapeSeccomp` skips on arm64, since a Go test there can't call another ABI (`TestSeccompFilter` checks the architecture test offline), and runs on amd64. `TestEscapeSessionKeyring` skips on the LXC host, whose seccomp profile makes the key calls fail with `ENOSYS`.

**The LXC host differs from a VM** in ways that changed four tests, which now allow for it:

- Its seccomp profile is inherited by every process, so `TestCheckVM` no longer requires `proc.seccomp` to fail without a sandbox.
- Its Yama `ptrace_scope` is 1, so `proc.trace` passes without a sandbox.
- Its `nsswitch.conf` lists `systemd`, so with cgo `user.Lookup` finds `root` and `nobody` even though the sandbox's `/etc/passwd` doesn't (`TestEscapePasswd` still requires the exact file).
- `TestCheckArgvHoldsNoSettings` also flagged the check child's own namespace attempts, `--sandbox-check noop` and `mount`, which a fast sampler sees. It now accepts those two fixed modes. The arm64 VM's slower sampler had been missing them.

### macOS

| Target | How | Pass | Subtests | Skip | Fail |
|---|---|---|---|---|---|
| macOS 27.2.1, arm64, Apple silicon, Go 1.27 | `go test` | 131 | 91 | 1 | 0 |
| the same | `go test -race` (about 6.5 minutes, since each sandbox starts a race-built binary) | 131 | 91 | 1 | 0 |
| macOS 27.2.1, amd64 under Rosetta 2 on the same Mac, Go 1.27, cross-built with `GOARCH=amd64` | `go test` (`CGO_ENABLED=0`, about 1 minute) | 130 | 91 | 2 | 0 |
| the same | `go test -race` (`CGO_ENABLED=1`, about 6.5 minutes) | 130 | 91 | 2 | 0 |

The counts are top-level tests and their subtests. The arm64 skip is `TestWriteApparmorProfile`, the Linux AppArmor helper. Under Rosetta, `TestEscapeLaunchServicesRawXPC` also skips: the Command Line Tools' `cc` shim is arm64 only and can't start under `arch -x86_64`, so the test can't build its C client there. It runs on arm64.

The suite found that macOS 27.0.1 and 27.2.0 differ: curl needed one more Mach service on 27.2.0 ([findings.md](findings.md#tls-needed-a-mach-service-from-272)).

### CI

`.github/workflows/test.yml` runs on every push and pull request. It has not run yet, since this repository has no GitHub remote.

- **Vet:** `go vet` for linux amd64, arm64 and arm, with `CGO_ENABLED=0`.
- **Linux:** the tests on `ubuntu-24.04` with apt's bubblewrap, with cgo off and on. The runner keeps `kernel.apparmor_restrict_unprivileged_userns` at 1 and loads the test binary's profile, so CI exercises the fix users get (`SBX_LOCAL=1 SBX_APPARMOR=1`).
- **macOS:** `go build`, `go vet` for arm64 and amd64, and `go test` on `macos-latest`, with cgo off and on, and `go test -race` on the cgo leg.

### What the tests can't cover

- The refusal of euid 0 is driven through a variable on macOS (`TestEscapeRefusesEuid0`), not by a real root.
- An APFS snapshot mount needs root, so the `/Volumes` cover isn't tried against one.
- A replay of a real `launchservicesd` open request wasn't possible. `TestEscapeLaunchServicesRawXPC` shows the lookup and that nothing opens from the test's own message, and not that the server checks `lsopen`.
- `syscall-unix` rules in a Seatbelt profile weren't tried, since nothing here claims a system call filter on macOS.
- A second machine reaching a macOS `Loopback` port wasn't tried. The test connects from the host to its own LAN address.
- The lowest bubblewrap version, 0.8, has no run.

## Running the tests

### On macOS

```bash
go test ./...
go test -race ./...
```

`go test -race` is slow, since every sandbox starts a race-built binary. Read [the host-safety rules](#host-safety-on-macos) before changing or adding a darwin test.

### On Linux

`scripts/linux-test.sh` builds the test binary, copies it to a machine and runs it there in a directory of its own, never `/tmp` itself, which the sandbox covers. It vets linux/amd64, arm64 and arm. Extra arguments go to the test binary:

```bash
scripts/linux-test.sh -test.run TestIsolation -test.v
```

Targets:

| Variable | Target |
|---|---|
| none | The `sbx-dev` Lima VM (Debian 13, arm64, bubblewrap from apt). |
| `SBX_VM=name` | Another Lima VM, such as `sbx-ubuntu`. |
| `SBX_SSH=user@host` | A machine reached by passwordless ssh. Its architecture comes from `uname -m`. |
| `SBX_LOCAL=1` | This machine, which must be Linux. CI uses it. |
| `CGO=1` | Build with cgo. The default is `CGO_ENABLED=0`, as releases are. Cgo needs a C compiler for the target, so the script copies the sources to the target and builds there. The target needs `go` (on `PATH`, `/usr/local/go/bin`, or `/usr/local/bin`) and `gcc`. |
| `SBX_APPARMOR=1` | Load the AppArmor profile for the test binary before the tests and remove it after, with `scripts/apparmor.sh`. Ubuntu 24.04 needs it. Without it the tests fail there, which is the library's behavior. |

### The Ubuntu VM

`sbx-ubuntu` is a Lima VM with Ubuntu 24.04. Make it with:

```bash
limactl create --name=sbx-ubuntu --cpus=4 --memory=4 --set '.mounts=[]' template:ubuntu-24.04
```

Then start it, install `bubblewrap` and `gcc` with apt, and copy Go in for cgo builds. Run the tests with:

```bash
SBX_VM=sbx-ubuntu SBX_APPARMOR=1 scripts/linux-test.sh
```

## Host safety on macOS

The darwin tests run code that tries to escape a sandbox, on the developer's own machine, as their uid. If a profile fails open, the code that escapes it can reach everything the user owns. This has happened: a broadcast `kill(-1, SIGUSR1)`, meant to check that signals stay inside, ended the user's desktop session three times when the profile let it through.

So these rules hold for every darwin test:

- **No signal but 0 or `SIGWINCH` to a process the test didn't start.** Signal 0 reports the check without delivering anything. `SIGWINCH` is ignored by default. Processes a test ends are found by the sandbox's own marker, which names only processes under that sandbox's profile.
- **No app launches.** A test may try `open` or LaunchServices from inside a sandbox, and asserts that nothing started. It counts executables by path before and after. It never allows `lsopen` to see what happens: the one experiment that did launch Calculator was run by hand.
- **No changes to settings, launchd, TCC or the keychain.** A test may try to read these from inside a sandbox, and only checks that the attempt failed.
- **Write only to temp directories the test made.**
- **Mutation checks only on a copy of the tree**, never in place. A mutation that allows signals is run with probes that signal nothing (`kill` with 0, or a harmless signal for the broadcasts), since a profile that fails open would otherwise signal the caller's own processes.

**Where the tests don't follow the write rule.** `escWritesDenied` (used by `TestEscapeWriteOutside` and `TestEscapeAdminGroupWrites`) tries, from inside a sandbox, to create a file named `.esc-write` in system directories and in the user's own home and working directory, such as `/usr/local`, `/Library` and `/Applications`. A working profile refuses it. If a profile failed open, the file would be created and then removed. That is a write outside a temp directory the test made, so it is an exception to the rule above, and a change to those tests would have to decide whether to keep it.

## Mutation checks

A check is only worth its passes if it fails when the guarantee is taken away. Each check that guards a finding was run with the fix removed, on a copy of the tree, and seen to fail.

- **Linux:** the covers, the filter, the first stage's private mounts, `--as-pid-1`, the cover of other file types, the mount order, the netfilter rule, and the four from the latest review: the sandbox's process group and foreground, the read-only `/dev` and the session keyring. The descriptor test documents a behavior and fails if it changes. The ZFS fix was checked by hand on the ZFS host.
- **macOS:** the foreground of the terminal, the quoting of paths, the `process-info` deny, the group kill when the command exits, the group kill when the stage is killed, the lifeline, the terminal deny, the `localhost` deny of `NetworkHost`, the covers, the signal target, the loopback port rule and the readable `SelfPath`.
- **macOS teardown proof:** a vanished pid counted as clean (`TestScanVanishedPidForcesAnotherScan`, `TestScanBudget` and `TestTeardownReportsWhatItCouldNotConfirm` fail), and a new zombie counted as safe (`TestScanZombies` and `TestTeardownLingeringZombie` fail).
- **macOS teardown proof, review findings:** each is a mutation that a test catches. A scan that ignores an exiting process (`TestScanExitingPidForcesAnotherScan`), `statPid` without the exit flag (`TestProcStatOfReadsTheFlagsAndTheName`), `member` that never asks the kernel whether it finds the pid (`TestMemberNeverClearsAnExitingChild`, `TestMemberOfGonePids`), and all three together (`TestRealScanIsNeverCleanWhileAChainLives`); the old In-then-Out order of checks (`TestMemberNeverMatchesAProcessApplyingAProfile`); no rule for an unsandboxed `sandbox-exec` (`TestScanSandboxExecThatHasNotAppliedItsProfile`, `TestRealScanIsNotCleanWhileSandboxExecWaitsForItsProfile`); a message kind that isn't checked (`TestStageMessagesRefuseTheWrongKind`); a list compared with the first size only (`TestListPidsAsksAgainWhenTheListMayBeCut`); a profile that isn't one form, or has its marker last (`TestProfileCutShortDoesNotRun`); a stage that always reports empty or a caller that ignores the report (`TestTeardownStageThatCannotProveLeavesItToTheCaller`); and a missing report counted as empty (`TestWaitScansWhenTheStageWasKilledAndNothingHoldsTheOutput`).
- **macOS teardown proof, second review:** a `sandbox-exec` name rule that ignores whether the process is under a profile (`TestScanSandboxExecThatCannotBeTheOne`, `TestSandboxExecInAnotherSandboxDoesNotStallTeardown`), that ignores the pid the stage started, or has no second look after the name is read (`TestScanProcessThatAppliedTheProfileBetweenTheCheckAndTheRead`); exiting processes not remembered between scans (`TestScanExitingPidSeenBeforeIsSettled`); cleared pids not remembered, remembered without their start time, or a member or a pending `sandbox-exec` remembered (`TestScanRemembersWhatItCleared`, `TestScanDoesNotRememberWhatMayStillBeAMember`); a dying child excused with no cleared parent, a parent younger than the child, or launchd as the parent (`TestScanDyingChildOfAClearedParent`, `TestRealScanExcusesAZombieOfANonMember`); a marker that a later rule allows (`TestMarkerSurvivesEveryServiceAndOption`); and a profile cut that exits 71 where only the version alone should (`TestProfileCutShortDoesNotRun`). `SANDBOX_CHURN=1 go test -run TestChurnCleanScanRate` measures the clean-scan rate under process churn ([macos.md](macos.md#process-churn)).
- **macOS teardown, waits and giving up:** no wait between scans, a wait before the first scan, one with no cap or past the deadline (`TestRunBackoff`, `TestRunDoesNotWaitBeforeTheFirstScanOrAfterTheLast`, `TestRunWaitStopsAtTheDeadline`); a teardown that never gives up on members, gives up at the first, or counts noise (`TestRunGivesUpOnMembersThatKeepTurningUp`, `TestRunDoesNotGiveUpOnANormalShutdown`, `TestRunKeepsTryingThroughNoise`, `TestTeardownDoesNotGiveUpOnShortChains`); a `Wait` that ignores the stage's report that it gave up, returns nil on it, or a stage that doesn't send it or reports empty (`TestTeardownGivesUpOnMembersItCannotEnd`, `TestWaitGivesUpOnMembersItCannotEnd`); remembered pids checked before new ones, or trusted by number alone (`TestScanChecksNewPidsBeforeRememberedOnes`, `TestScanDoesNotTrustARememberedNumberAlone`). `SANDBOX_CHURN=1 go test -run 'TestChurn'` also measures a normal command's teardown latency under churn.
- **macOS review findings:** the teardown without the marker (every wait in `TestEscapeSetpgidAndJobControl` times out, and the command that joined the caller's group isn't counted), the profile without the denies at each root, with the old `/dev` regular expression, with `ip` for `tcp` on the Loopback rules (UDP then binds), and `canonicalName` as the identity (a `Cover` by the data volume's name then leaves the secret readable).
- **Not detected:** the test for the `localhost` deny doesn't detect the form of the allow before it ([findings.md](findings.md#a-localhost-deny-held-in-only-one-form)). The `/dev` mutation is why `TestEscapeDevices` only stats entries: an earlier version opened every device with the old profile and hung on one.
