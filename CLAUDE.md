# sandbox

`github.com/die-net/sandbox` is a Go library that runs a command in a sandbox built on demand: bubblewrap, namespaces and a seccomp filter on Linux, and a generated Seatbelt profile under `/usr/bin/sandbox-exec` on macOS. The command, everything it runs and every server it starts are untrusted. The docs are in `docs/`:

- `security-model.md` is the threat model and every guarantee, with its mechanism and the test that tries to break it.
- `linux.md` and `macos.md` are how each backend works.
- `findings.md` is every way past the sandbox found so far, with what stops it and the test that checks it. Read it before changing the sandbox.
- `usage.md` is for callers, and `testing.md` covers the tests, where they ran, and how to run them safely.

Read the sections a change touches before making it. A change to behavior a doc describes updates that doc in the same PR. A change to a guarantee updates its row in `security-model.md` and the table in `README.md`. A change to the public API updates `usage.md`, and its doc comment.

## Checks

- macOS: `go test ./...` and `go test -race ./...`.
- Linux: `scripts/linux-test.sh`, which runs the suite on a Linux machine as `docs/testing.md` describes. CI runs it on Ubuntu 24.04 and 26.04, and the suite on macOS, without cgo and with cgo under the race detector.
- Vet every platform the code builds for: `GOOS=linux` with `GOARCH` amd64, arm64 and arm, `GOOS=darwin` with arm64 and amd64, and `GOOS=windows GOARCH=amd64`, each with `CGO_ENABLED=0`.
- Lint: `golangci-lint run` with each `GOOS` above (linux, darwin and windows). It is clean before work is done, including issues you did not cause.

## Host safety

The darwin tests run escape attempts on the developer's own machine, as their uid. A profile that fails open lets that code reach everything the user owns. A broadcast `kill(-1, SIGUSR1)` that got through once ended the user's desktop session. Every darwin test, experiment and review follows these rules, which `docs/testing.md` explains:

- No signal but 0 or `SIGWINCH` to a process the test didn't start. A test finds the processes it ends by the sandbox's marker, never by name or by a broadcast.
- No app launches. No changes to settings, launchd, TCC or the keychain. A test may try these from inside a sandbox, and checks only that the attempt failed.
- Write only to temp directories the test made.
- Mutation checks run only on a copy of the tree, never in the checkout. A mutation that may let signals through uses probes that signal nothing.
- No fork bombs. A test of re-forking processes is bounded, and ends only what it started.
- Run long suites in the foreground with a timeout. After a darwin run, check that no `sandbox.test`, `sandbox-stage` or `sandbox-exec` process is left.

## Test dependencies

Tests must run, and check what they claim, on a minimal host with no network.

- No network beyond the host. A test that needs an outside peer opens its own listener on loopback or on the host's own non-loopback address. No test names a public address, host name or DNS server.
- Only programs a minimal host has. On Linux that's a Debian or Ubuntu minimal install plus bubblewrap. On macOS it's a clean install with no Xcode or Command Line Tools. That means `/bin/sh`, the base system's own tools, and the test binary's own child modes. No compiler, no Perl, Python or other scripting runtime, no app installed separately, and nothing the OS has deprecated or plans to drop, such as macOS's bundled Perl or Linux's net-tools.
- A test that skips without the network or such a program doesn't count as checking anything. Replace the dependency rather than skip.
- A test takes about a second or less when it passes in a normal `go test ./...` run, alongside the rest of the suite. It arranges the case it checks instead of repeating until the case happens, and it waits for events instead of sleeping a fixed time.

## Guarantees

- Every guarantee in `security-model.md` has an escape test that runs code in a real sandbox and asserts the attempt fails. It cites the row it checks as `Row: ...`. A guarantee a platform can't give has a `TestGap...` test that shows the gap and fails when it closes.
- A check is worth only its failures. A test that guards a guarantee or a finding was seen to fail with the fix removed, on a copy of the tree, and `docs/testing.md` lists the mutation.
- A new way past the sandbox goes into `findings.md`, with what stops it and the test that checks it, in the same PR as the fix.
- Fail closed. When a backend can't enforce what a `Spec` asks for, `Command` returns an error, never a weaker sandbox. `Probe` reports what the host's backend enforces.
- Deny by default. A new `Spec` field or `Service` grants nothing unless set, and its zero value is the safe one.
- Nothing about the sandbox's settings goes on a command line, where every process of the uid can read it (`TestEscapeOptionsNotInArgv`, `TestEscapeProfileNotInArgv`). The command's environment is only `Cmd.Env` and what `Start` sets, never the caller's.
- A descriptor reaches the command only when the caller hands it in. Every other descriptor is close-on-exec.
- `Start` undoes everything it did when it fails part way. On macOS, `Wait` never returns nil unless a teardown scan proved no process is left under the profile. A teardown that can't prove it returns `ErrSurvivors`.
- The library is pure Go on every platform. It builds and works with `CGO_ENABLED=0`, and calls libc on macOS through assembly trampolines and `syscall`'s linknamed `syscall9`, never cgo. A platform with no backend gets `errors.ErrUnsupported` from the `_other.go` stubs.

## Go

- Wrap errors with a short lowercase context: `fmt.Errorf("start bubblewrap: %w", err)`.- The library never logs. It returns errors, and `Probe` and `Check` report what they find.
- Tests use the standard `testing` package, not testify. Several cases go in a table: `for _, tc := range []struct{...}{...}`.
- Every exported identifier has a doc comment. A field whose meaning or zero value is not obvious has one too. Comments say what a thing is for and why, in full sentences.
- Test-only helpers, flags, and hooks live in `_test.go` files, not in production code. An environment variable a test reads is read in `TestMain` or the test, never by the library.
- A rename or move updates every caller. No wrapper, alias, or shim is kept for the old name.
- A new dependency comes from the standard library first, then `golang.org/x`, before anything else.

## Efficiency

- Starting a sandbox costs about 6 ms on Linux and 19 ms on macOS, and `README.md` says so. A change on the start or teardown path measures it before and after (`SANDBOX_OVERHEAD=200 go test -run TestOverheadTrue -v` on macOS) and updates the README if it moves.
- Don't move or copy data that isn't needed. A command's streams go through as descriptors or pipes, never read into memory to hand on.
- Don't do the same work twice. Hoist what doesn't change out of loops, and batch system calls rather than making one per item where the kernel offers a batch.
- Know how cost grows with input. No loop, or call inside a loop, makes cost quadratic or worse in something the command controls, such as how many processes it starts or files it makes.
- Measure before claiming a speedup, and don't trade clarity for a gain nobody measured.

## Failure modes

For every entry point a change adds or touches, such as `Command`, `Start`, `Wait`, the stage, `Probe` or `Check`, work out what happens in each case below, and handle it on purpose:

- The command is hostile. It forks, leaves its process group, calls `setsid`, closes or holds its streams, ignores signals, or races the teardown.
- The caller's context is canceled, the caller exits or is killed, or the stage is killed with `SIGKILL`.
- `Start` fails part way: a missing binary, an unreadable path, a full disk, a descriptor limit.
- Several sandboxes start, run and end at once in one process, and one sandbox's processes must never be mistaken for another's.
- The host lacks a feature: an older kernel or bubblewrap, AppArmor's user-namespace restriction, a new macOS release, or a profile the kernel refuses.
- The machine is loaded: other processes of the uid fork and exit heavily, or the CPUs are saturated.

A behavior change comes with a test that exercises the failure mode, not only the success path.

## Fixes

- Fix the general cause, in the backend or the shared helper, rather than special-casing the one input that broke.
- An `if`, flag, retry, or fallback added only to make one failure go away is not a fix. Find why it fails and fix that. If the root fix is out of reach, say so in the PR rather than patching around it.
- A failing check is never made to pass by weakening it: no new `t.Skip`, deleted or loosened assertion, raised timeout or threshold, `t.Log` in place of `t.Fatal`, `_ =` on an error, or `//nolint`, unless the owner agreed to that specific change.
- A new `Spec` field, option, or exported name is added only when no existing one can carry it. Prefer deleting or generalizing code to adding it.

## Writing

- A commit subject is one imperative sentence about the change in behavior, ending with a period, for example "End every process under the profile at teardown, not only the command's group." Do not use Conventional Commits prefixes.
- Docs, comments, and messages people see use short, plain sentences.
- A claim about kernel or OS behavior names its source: the XNU or Linux file and function, or the test that shows it.
