// Package sandbox runs a command in a sandbox that shows it the host's files
// read-only, with the paths that hold the caller's data, people's homes, and
// other services' state covered by empty directories, and only its own
// directories writable. docs/sandbox.md describes how it holds, and every
// way past it found so far, with what stops it and the test that checks it.
//
// On Linux, bubblewrap builds the sandbox from new namespaces without root,
// from options this package works out and passes it on descriptors. It then
// starts this binary again inside as pid 1, a first stage that makes the
// mounts private, installs this package's seccomp filter, starts the
// command, and reaps. A control socket carries its settings in and its
// listeners out, and a lifeline pipe ends the sandbox when the caller does.
// A program that uses this package calls [Stage] first in main, so that the
// first stage is found before anything else. [Command] makes a [Cmd] for a
// server that starts sandboxes, and [Run] is the form for a process of its
// own. Elsewhere both return [errors.ErrUnsupported].
package sandbox
