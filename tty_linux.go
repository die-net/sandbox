package sandbox

import (
	"io"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// terminal is a terminal on the caller's standard input that the sandbox has
// taken the foreground of. The sandbox runs in a process group of its own, so
// without this a command that read the terminal would be in a background
// group and stop on SIGTTIN.
type terminal struct {
	fd      int // a duplicate of the descriptor, which this owns
	callers int // the caller's own process group
}

// foregroundTerminal returns the terminal in, if in is a terminal whose
// foreground process group is the caller's own, and nil otherwise. A caller
// that is itself in the background has no foreground to hand over.
func foregroundTerminal(in io.Reader) *terminal {
	f, ok := in.(*os.File)
	if !ok {
		return nil
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return nil
	}
	var t *terminal
	_ = rc.Control(func(fd uintptr) {
		pgrp, err := unix.IoctlGetInt(int(fd), unix.TIOCGPGRP)
		if err != nil || pgrp != unix.Getpgrp() {
			return
		}
		// A copy, so that the descriptor stays valid however the caller
		// uses its own until Start and Wait are done.
		if nfd, err := unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 3); err == nil {
			t = &terminal{fd: nfd, callers: pgrp}
		}
	})
	return t
}

// restore makes the caller's process group the foreground one again, if the
// sandbox's still is, and closes the descriptor. Setting the foreground group
// from a background one raises SIGTTOU, so the calling thread blocks it for
// the call. If the user has moved the foreground on, to a shell after a
// suspend for instance, it is left alone.
func (t *terminal) restore(sandboxPgrp int) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var set, old uint64 = 1 << (unix.SIGTTOU - 1), 0
	_, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, 0 /* SIG_BLOCK */, uintptr(unsafe.Pointer(&set)), uintptr(unsafe.Pointer(&old)), 8, 0, 0) //nolint:gosec // G103: the kernel reads set and writes old during the call.
	if errno == 0 {
		defer unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, 2 /* SIG_SETMASK */, uintptr(unsafe.Pointer(&old)), 0, 8, 0, 0) //nolint:gosec,errcheck // G103: the kernel reads old during the call. The restore can only fail on a bad pointer, and no caller could act on that.
	}
	if pgrp, err := unix.IoctlGetInt(t.fd, unix.TIOCGPGRP); err == nil && (sandboxPgrp == 0 || pgrp == sandboxPgrp) {
		_ = unix.IoctlSetPointerInt(t.fd, unix.TIOCSPGRP, t.callers)
	}
	_ = unix.Close(t.fd)
}
