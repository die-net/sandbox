// Package sandbox runs a command in a sandbox that shows it the host's files
// read-only, with the paths that hold the caller's data, people's homes, and
// other services' state covered by empty directories, and only its own
// directories writable. docs/one-binary.md describes the design.
//
// On Linux, bubblewrap builds the sandbox from new namespaces without root,
// from options this package works out and passes it on descriptors. It then
// starts this binary again inside, as a first stage that makes the mounts
// private, installs this package's seccomp filter, and execs the command. A
// program that uses this package calls [Stage] first in main, so that the
// first stage is found before anything else. Elsewhere [Run] returns
// [errors.ErrUnsupported].
package sandbox
