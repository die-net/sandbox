package sandbox

import (
	"context"
	"io"
	"time"
)

// Cmd is a command in a sandbox, made by [Command]. Set its fields, then
// call Start and Wait, as with an os/exec Cmd. It wraps one rather than
// embedding it, since the options bubblewrap is given name descriptor
// numbers, and a caller that changed the descriptors or the path would break
// the sandbox. A Cmd is for one use.
//
// On Linux the sandbox runs in a process group of its own, inside the
// caller's session, so a signal or a priority change aimed at its group
// reaches nothing outside. When Stdin is a terminal that the caller is the
// foreground of, the sandbox's group takes the foreground until Wait, which
// gives it back, so a command that reads the terminal is not stopped.
type Cmd struct {
	// Stdin, Stdout, and Stderr are the command's standard streams, as on
	// os/exec's Cmd. Nil means /dev/null.
	//
	// A stream that is an *os.File reaches the command as that descriptor,
	// and the command gets whatever the underlying object lets its uid do,
	// whatever mode the caller opened it in and whatever the sandbox covers.
	// On Linux it can reopen it through /proc/self/fd with more access: an
	// append-only log opened for stdout can be truncated, and a file opened
	// read-only can be rewritten. Pass a pipe or a socket, which cannot be
	// reopened, or any other io.Reader or io.Writer, which the package
	// copies through a pipe, where that matters.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Env is the command's environment. Nil means empty, never the
	// caller's own. Start sets HOME, TMPDIR, and the XDG_* variables,
	// XDG_RUNTIME_DIR included, to the sandbox's own over whatever Env
	// holds, since the caller's would point into a path the sandbox covers.
	Env []string
	// WaitDelay is how long Wait waits for the command's streams after it
	// exits or ctx is done, as os/exec's.
	WaitDelay time.Duration
	// CgroupFD is the descriptor of a cgroup directory to start the sandbox
	// in, on Linux. Command sets it to -1, and 0 or less means none, so a
	// Cmd that was not made by Command still has none.
	CgroupFD int

	ctx  context.Context
	spec Spec
	run  run
}
