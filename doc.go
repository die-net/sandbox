// Package sandbox runs a command in a sandbox that shows it the host's files
// read-only, with the paths that hold the caller's data, people's homes, and
// other services' state covered by empty directories, and only its own
// directories writable. docs/security-model.md says what it guarantees and
// what it doesn't, and docs/findings.md lists every way past it found so far,
// with what stops it and the test that checks it.
//
// On Linux, bubblewrap builds the sandbox from new namespaces without root,
// from options this package works out and passes it on descriptors. It then
// starts this binary again inside as pid 1, a first stage that makes the
// mounts private, installs this package's seccomp filter, starts the
// command, and reaps. A control socket carries its settings in and its
// listeners out, and a lifeline pipe ends the sandbox when the caller does.
// The package's init finds a run of the binary that is part of the sandbox
// by a variable in its environment, which Start sets, and plays it before the
// program's main, so a program needs no call of its own and keeps its
// arguments. [Command] makes a [Cmd] for a
// server that starts sandboxes, and [Run] is the form for a process of its
// own.
//
// On macOS, /usr/bin/sandbox-exec applies a deny-by-default Seatbelt profile
// that this package generates from the Spec. The same init finds a
// supervisor that runs outside the profile: it sets the limits, starts the
// command in a process group of its own, and ends every process that runs
// under the profile, whatever its group or parent, when the command does or
// the caller dies. macOS has no pid namespace, so the sandbox's processes see
// the caller's, and read its environment, and docs/security-model.md lists what
// that costs.
// Elsewhere [Command] and [Run] return [errors.ErrUnsupported].
package sandbox
