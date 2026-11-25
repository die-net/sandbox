# sandbox

`github.com/die-net/sandbox` lets a Go program run a command with only the access it needs, instead of everything its user can reach. It builds a sandbox on demand for each command, in about 6 ms on Linux and 19 ms on macOS, with no root, no VM and no container runtime.

## Why

The Unix user model gives every program you run all of your access. That includes your SSH keys, cloud credentials, browser cookies, source trees, and the right to push code as you. This mostly worked when the code came from trusted sources and you typed the commands yourself.

That's no longer the whole picture:

- **Supply chain attacks** put hostile code inside dependencies you'd otherwise trust.
- **Tools like `npx` and `uvx`** make it routine to run code straight off the internet.
- **Coding agents** run commands for you. They do well most of the time, but they sometimes make mistakes.

Each of these is a good case for least privilege. Tools to sandbox semi-trusted code exist, especially on Linux, but they're often cumbersome. Some need setup that fits an OS package better than a program. Others want everything to run under `docker compose` or similar.

This library makes least privilege cheap enough to use by default. It's for Go programs that run bundled third-party software, or that need to limit what an agent can touch. The program describes what a command may read, write and reach in a `Spec`, and gets a sandbox with exactly that.

## How

On Linux it uses bubblewrap, namespaces and a seccomp filter. On macOS it uses a generated Seatbelt profile that `/usr/bin/sandbox-exec` applies. Both give the command a read-only view of the host, with your config, state and people's homes hidden, and only its own directories writable. The network is off unless you turn it on.

What you get:

- **Nothing to set up.** There's no daemon, no image and no root. Your program re-executes itself as the sandbox's first stage. Linux needs only the distribution's bubblewrap package, and macOS needs nothing.
- **Deny by default.** The command gets no network, no local service sockets and no write access outside its own directories unless you grant them in the `Spec`.
- **You hand it what it needs.** Pass a listener or a descriptor instead of opening the network. A build that needs one proxy gets that proxy and nothing else.
- **Tested by trying to escape.** Each guarantee below has a test that runs code inside a real sandbox and tries to get past it. Each known gap has a test that fails when the gap closes.
- **It tells you what you're getting.** `Probe` reports what this host's backend enforces and names the fix when it can't start. `Check` runs the escape attempts on the host, for a `doctor` command.

It began as the sandbox in the legwork project.

## Example

A program that starts sandboxes calls `Stage` first in `main`. Then `Command`, `Start` and `Wait`, as with `os/exec`:

```go
func main() {
	if code, ok := sandbox.Stage(); ok {
		os.Exit(code)
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (err error) {
	dir, err := os.MkdirTemp("", "sandbox-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	home, err := filepath.EvalSymlinks(dir) // Home may not contain a link.
	if err != nil {
		return err
	}
	cmd, err := sandbox.Command(context.Background(), sandbox.Spec{
		Command: []string{"/bin/sh", "-c", "echo hello from $HOME"},
		Home:    home,
	})
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}
```

[example_test.go](example_test.go) holds the same code, so `go vet` checks it compiles. [docs/usage.md](docs/usage.md) covers the rest of the API.

## What it guarantees

The command, everything it runs and every server it starts are untrusted. This is what holds on each platform. [docs/security-model.md](docs/security-model.md) gives the mechanism for each row and the test that tries to break it.

| | Linux | macOS |
|---|---|---|
| Files | The host's files are read-only. Your config, state, people's homes, `/run`, `/tmp` and `/var` are covered. Only the sandbox's home and `Write` paths are writable. | The same, through a deny-by-default profile. Covers: `/Users`, `/Volumes`, `/private/var`, `/private/tmp`. Files of your account outside them are readable, so name them in `Cover`. |
| Other processes | A pid namespace. The command can't see, signal, trace or read the environment of anything outside. | It can see every process of your uid and read their arguments and environment, yours included. It can't signal them. |
| Signals | The sandbox has a process group of its own. `kill(0)` and `kill(-1)` reach only the sandbox. | The same, with one gap: `fcntl(F_SETOWN)` can send `SIGIO` and `SIGURG` outside. |
| Network | None by default, with a private loopback. `Listen` hands the caller listeners to serve. `NetworkHost` is opt-in. | None by default. `Listen` and `Loopback` ports are single-port allows. `NetworkHost` is opt-in. |
| Local services (ssh-agent, Docker and similar sockets) | Not reachable: the sockets' directories are covered, and the network namespace hides the host's abstract sockets. `NetworkHost` shares them. | Not reachable: unix sockets are refused except `Write` paths, and Mach lookups only for services you ask for. |
| Session keyring or keychain | A new anonymous session keyring. | The login keychain file is covered, and `securityd` is refused. |
| Terminal | `TIOCSTI` and `TIOCLINUX` are refused. The sandbox gets its own `devpts`. | Terminals and consoles open only as descriptors handed in. |
| Limits | `Rlimits`, a cgroup through `CgroupFD`, sized tmpfs, and a `Footprint` poll. | `CPU` (a signal only), `FSIZE`, `CORE`, `NOFILE` and processes (counted per uid), and a `Footprint` poll. |
| Teardown | Pid 1 dies, and every process in the namespace dies with it. | The stage ends every process under the profile. A fork bomb can outrun it, and `Wait` then returns `ErrSurvivors`. |

## Known gaps

On macOS:

- **No pid namespace.** The command reads the arguments and environment of your other processes, and of the caller. A caller must hold no secret in its environment.
- **Loopback ports are reachable from the LAN.** A profile can't name `127.0.0.1`, only `localhost`, which is every address the host has. A `Loopback` port can be reached on the LAN address. A listener you bind on `127.0.0.1` and pass in `Spec.Files` doesn't have this gap.
- **`RLIMIT_AS` isn't enforced.** `Command` refuses `ResourceAddressSpace`.
- **A fork bomb can outrun teardown.** `Wait` and `Run` then return an error that matches `ErrSurvivors`, and the caller should treat the host as dirty.

On both: a file descriptor you hand in grants whatever its object allows, whatever mode you opened it in. Pass a pipe or a socket where that matters. [docs/security-model.md](docs/security-model.md#limits) lists the rest.

## Requirements

- **Go** 1.26 or later.
- **Linux:** bubblewrap 0.8 or later from your distribution, not setuid. The suite passes on 0.12.0 and 0.9.0.
- **Ubuntu 24.04 and later** restrict unprivileged user namespaces, so the binary needs an AppArmor profile. `Probe` prints one for the binary's own path, and the commands to load it. It picks the profile by what the host loads: Ubuntu 26.04's profile for bubblewrap needs a different one ([docs/linux.md](docs/linux.md#probe-and-check)). [scripts/apparmor.sh](scripts/apparmor.sh) does the same for this package's test binary.
- **macOS:** `/usr/bin/sandbox-exec`, which ships with the system. It must not already be inside a Seatbelt profile.
- **Elsewhere:** `Command` and `Run` return `errors.ErrUnsupported`.

## Status

Both backends are built and tested, on Linux (amd64 and arm64, Debian 13 and Ubuntu 24.04 and 26.04) and on macOS 15, 26 and 27 (arm64, and amd64 under Rosetta 2 on 27). Each has had a security review by a model, and [docs/findings.md](docs/findings.md) lists what they found. No release has been tagged. The Seatbelt rules come from running macOS 27.0.1 and 27.2.0. CI runs the suite on macOS 15 and 26, which needed one more rule. Rerun the tests on each new release.

## Documentation

- [docs/usage.md](docs/usage.md): adopting the library. `Stage`, egress, `Probe` and `Check`, tools under covered paths, limits, `ErrSurvivors`, Firefox.
- [docs/security-model.md](docs/security-model.md): the threat model, every guarantee with its test, the limits and the open issues.
- [docs/linux.md](docs/linux.md) and [docs/macos.md](docs/macos.md): how each backend works.
- [docs/findings.md](docs/findings.md): every way past the sandbox that has been found. Read it before changing the sandbox.
- [docs/testing.md](docs/testing.md): the tests, the platforms they ran on, and how to run them safely.

## AI Disclosure

Though the design, architecture, some of the code, reviews, and testing were
done by a human, most of the code was written by Opus 5.5 and Sonnet 5.5, with
security reviews by Fable 5.2.

## License

Copyright 2026 Aaron Hopkins and contributors. All rights reserved.

Licensed under the [Apache License, Version 2.0](LICENSE).
