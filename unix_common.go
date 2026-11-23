//go:build linux || darwin

package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// hostHomes returns the homes to cover for the accounts in /etc/passwd. It
// reads the file itself, since without cgo Go cannot list a directory
// service's accounts either.
func hostHomes() ([]string, error) {
	passwd, err := os.ReadFile("/etc/passwd")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read /etc/passwd: %w", err)
	}
	return accountHomes(passwd, ownerOf), nil
}

// ownerOf returns the uid that owns path, following symlinks.
func ownerOf(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat %s: no owner", path)
	}
	return uint64(st.Uid), nil
}

// exitStatus turns the error from waiting on the sandbox into its exit
// status, which is the command's.
func exitStatus(err error) (int, error) {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return 0, err
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return ee.ExitCode(), nil
}

// dupFile returns a close-on-exec copy of f that the launch may own, without
// switching f to blocking mode as its Fd method would.
func dupFile(f *os.File) (*os.File, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("file %s: %w", f.Name(), err)
	}
	var nfd int
	var dupErr error
	if err := rc.Control(func(fd uintptr) {
		nfd, dupErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 3)
	}); err != nil {
		return nil, fmt.Errorf("file %s: %w", f.Name(), err)
	}
	if dupErr != nil {
		return nil, fmt.Errorf("file %s: %w", f.Name(), dupErr)
	}
	return os.NewFile(uintptr(nfd), f.Name()), nil
}

// maxListen is the most Listen and Loopback may each be, which keeps their
// fixed Linux ports apart.
const maxListen = 1000

// checkRequest checks the parts of spec that need no host: the
// network and listener counts, the limits, and the files. It is shared by
// every backend.
func (s Spec) checkRequest() error {
	if len(s.Command) == 0 {
		return errors.New("no command")
	}
	if s.Network != NetworkNone && s.Network != NetworkHost {
		return fmt.Errorf("unknown network %d", int(s.Network))
	}
	if s.Listen < 0 || s.Listen > maxListen || s.Loopback < 0 || s.Loopback > maxListen {
		return fmt.Errorf("listen and loopback must each be from 0 to %d", maxListen)
	}
	if s.Network == NetworkHost && (s.Listen > 0 || s.Loopback > 0) {
		return errors.New("listeners and loopback ports need NetworkNone, since the host's network has no private loopback")
	}
	if s.ScratchSize < 0 {
		return fmt.Errorf("scratch size %d is negative", s.ScratchSize)
	}
	for _, f := range s.Files {
		if f == nil {
			return errors.New("a nil file in Files")
		}
	}
	for _, r := range s.Rlimits {
		if r.Resource < ResourceCPU || r.Resource > ResourceAddressSpace {
			return fmt.Errorf("unknown resource %d", int(r.Resource))
		}
		if r.Soft > r.Hard {
			return fmt.Errorf("limit %d has a soft limit above its hard limit", int(r.Resource))
		}
	}
	return nil
}
