package sandbox

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrSurvivors is matched, with errors.Is, by the error Wait and Run return on
// macOS when teardown could not confirm that no process still runs under the
// sandbox's profile. A process that forks again before each signal lands can
// keep ahead of the scan that looks for the sandbox's processes, so one may
// be left running with the access the profile gave it. Teardown gives up on
// that after about a tenth of a second, once scan after scan has found a
// process it had signaled to be replaced, and says so at once; it never returns
// nil while a process of the sandbox may still run. Nothing lists the
// survivors, so a caller that sees this should treat the host as dirty. The
// error wraps what Wait would otherwise have returned, so errors.As still
// finds the command's *exec.ExitError. The scan can also fail to settle,
// without a survivor, when other processes of the same account start and exit
// faster than it can account for them, which takes thousands of exits a second
// with the CPUs busy (a parallel build, or a fork loop in another sandbox of the
// account), and then teardown keeps trying for five seconds, which has been
// enough for every load measured; a caller that does get the error there has a
// host that is clean. Linux
// never returns it: the sandbox's pid namespace ends with its pid 1 and takes
// every process with it.
var ErrSurvivors = errors.New("sandbox: teardown could not confirm that no process still runs under the sandbox's profile")

// Cmd is a command in a sandbox, made by [Command]. Set its fields, then
// call Start and Wait, as with an os/exec Cmd. It wraps one rather than
// embedding it, since the options the backend is given name descriptor
// numbers, and a caller that changed the descriptors or the path would break
// the sandbox. A Cmd is for one use.
//
// The sandbox runs in a process group of its own, inside the caller's
// session, so a signal or a priority change aimed at its group reaches
// nothing outside. When Stdin is a terminal that the caller is the foreground
// of, the sandbox's group takes the foreground until Wait, which gives it
// back, so a command that reads the terminal is not stopped. On macOS the
// group is the command's, and the stage that supervises it stays outside the
// profile, in the caller's group.
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
	// caller's own. On macOS the caller's own environment is still readable
	// by the command through sysctl(KERN_PROCARGS2), which no profile can
	// stop, so a caller must hold no secret in its environment there. Start sets HOME, TMPDIR, and the XDG_* variables,
	// XDG_RUNTIME_DIR included, to the sandbox's own over whatever Env
	// holds, since the caller's would point into a path the sandbox covers.
	// On macOS TMPDIR and XDG_RUNTIME_DIR are a directory named tmp in the
	// home, which Start makes, and CFFIXED_USER_HOME is the home too, since
	// Cocoa finds ~/Library by it and not by $HOME.
	Env []string
	// WaitDelay is how long Wait waits for the command's streams after it
	// exits or ctx is done, as os/exec's. On macOS teardown ends the processes
	// it finds under the sandbox's profile, so one that left the command's
	// process group does not hold a stream open past Wait. A process that keeps
	// forking ahead of the scan can, and a caller that must not wait on one sets
	// WaitDelay, after which Wait returns an error that says it could not
	// confirm the sandbox empty.
	WaitDelay time.Duration
	// CgroupFD is the descriptor of a cgroup directory to start the sandbox
	// in, on Linux. macOS has no cgroups and ignores it; Footprint is what
	// bounds memory there. Command sets it to -1, and 0 or less means none, so a
	// Cmd that was not made by Command still has none.
	CgroupFD int

	ctx  context.Context
	spec Spec
	run  run
}
