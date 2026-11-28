//go:build linux || darwin

package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
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

// markListedCloseOnExec sets close-on-exec on every descriptor from 3 up that
// dir lists, as /dev/fd and /proc/self/fd do. It fails only if it can't read
// the list, since it can't tell then which descriptors it missed.
func markListedCloseOnExec(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: /dev/fd or /proc/self/fd, or a test's stageOptions.fdDir.
	if err != nil {
		return fmt.Errorf("mark descriptors close-on-exec: %w", err)
	}
	defer d.Close()
	fds, err := listedFds(d)
	if err != nil {
		return fmt.Errorf("mark descriptors close-on-exec: %w", err)
	}
	for _, fd := range fds {
		// A descriptor that has closed since makes fcntl fail with EBADF,
		// which CloseOnExec ignores, and there is nothing left to mark.
		unix.CloseOnExec(fd)
	}
	return nil
}

// listedFds returns the descriptors from 3 up that d, a directory such as
// /dev/fd, lists from where its reading stands. It reads names alone.
// os.ReadDir also stats an entry whose type the directory doesn't give, which
// on macOS is every entry of /dev/fd, and that stat fails with EBADF for a
// descriptor that closed after the directory was read, and on macOS 15 and
// 26 for an open kqueue (go.dev/issue/80143). Go 1.26 returns that as
// ReadDir's error, and Go 1.27 drops the entry, which would leave an open
// descriptor unmarked. TestListedFdsKeepsADescriptorThatClosed arranges the
// first.
func listedFds(d *os.File) ([]int, error) {
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	fds := make([]int, 0, len(names))
	for _, n := range names {
		if fd, err := strconv.Atoi(n); err == nil && fd >= 3 {
			fds = append(fds, fd)
		}
	}
	return fds, nil
}

// byteArgs is an argv as the bytes it holds, for the stage's settings.
// encoding/json writes a []byte in base64, and writes U+FFFD for each byte of a
// string that isn't UTF-8, so an argument that isn't, such as a Latin-1 file
// name, would otherwise reach the command changed.
type byteArgs [][]byte

// toByteArgs returns args as byteArgs.
func toByteArgs(args []string) byteArgs {
	out := make(byteArgs, len(args))
	for i, a := range args {
		out[i] = []byte(a)
	}
	return out
}

// strings returns the argv as strings.
func (b byteArgs) strings() []string {
	out := make([]string, len(b))
	for i, a := range b {
		out[i] = string(a)
	}
	return out
}
