package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A bubblewrap whose outer process leaves a child behind holding the stages'
// descriptors, as a real one killed before it lets its clone child go on does,
// doesn't hang Start, whether the caller's context is canceled or bubblewrap
// exits, and the child is gone after. Start is blocked in its read of the
// info, which the child keeps from ending.
//
// The child is either in bubblewrap's process group, or in a session of its
// own, as pid 1 is with OwnSession when bubblewrap dies before pid 1 has set
// its death signal. That one ends, as pid 1 does, only when the lifeline
// reaches its end (descriptor 6, fdLifeline). It also holds the command's
// stdout, which os/exec copies from a pipe, so a failed Start that waits for
// bubblewrap before it closes the lifeline waits on it for good, as a fake
// that writes a bad --info-fd shows.
func TestStartEndsWhenBubblewrapLeavesAChild(t *testing.T) {
	// Each child says it is ready on the fifo $R, once it is in its own
	// session if it is to be, so that no kill of the group can reach it
	// first.
	const (
		inGroup    = `/bin/sh -c 'echo >"$R"; exec /bin/sleep 1000'`
		ownSession = `/usr/bin/setsid /bin/sh -c 'echo >"$R"; read x <&6'`
	)
	for _, tc := range []struct {
		name   string
		child  string // the child the fake bubblewrap leaves running
		last   string // what the fake does once its child is running
		cancel bool
	}{
		{"canceled", inGroup, "exec /bin/sleep 1000", true},
		{"exited", inGroup, "exit 1", false},
		{"own session, canceled", ownSession, "exec /bin/sleep 1000", true},
		{"own session, exited", ownSession, "exit 1", false},
		{"own session, bad info", ownSession, "echo bad >&4\nexec /bin/sleep 1000", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// The fake waits for its child on one fifo, says it has started it
			// on another, and waits on a third until the test holds a pidfd
			// of the child.
			ready, fifo, goOn := filepath.Join(dir, "ready"), filepath.Join(dir, "started"), filepath.Join(dir, "go-on")
			for _, f := range []string{ready, fifo, goOn} {
				if err := unix.Mkfifo(f, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			script := "#!/bin/sh\nexport R='" + ready + "'\n" + tc.child + " &\nread x <\"$R\"\necho $$ $! >'" + fifo + "'\nread x <'" + goOn + "'\n" + tc.last + "\n"
			if err := os.WriteFile(filepath.Join(dir, "bwrap"), []byte(script), 0o700); err != nil { //nolint:gosec // G306: the file is a program the test runs, which needs its owner to execute it.
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			c, err := Command(ctx, Spec{Command: []string{"/bin/true"}, Home: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			c.Stdout = &stdout
			started := make(chan error, 1)
			go func() { started <- c.Start() }()
			pidc := make(chan [2]int, 1)
			go func() {
				b, _ := os.ReadFile(fifo) //nolint:gosec // G304: a fifo the test made.
				var pids [2]int
				for i, f := range strings.Fields(string(b)) {
					if i < 2 {
						pids[i], _ = strconv.Atoi(f)
					}
				}
				pidc <- pids
			}()
			var pid, child int
			select {
			case pids := <-pidc:
				pid, child = pids[0], pids[1]
			case err := <-started:
				t.Fatalf("Start returned %v before the fake bubblewrap ran", err)
			case <-time.After(10 * time.Second):
				t.Fatal("the fake bubblewrap never ran")
			}
			if pid <= 0 || child <= 0 {
				t.Fatal("the fake bubblewrap gave no pids")
			}
			// The fake and its child are ended, if they are still there, and
			// the child's exit watched, through pidfds opened now, while both
			// run, so that neither number can have gone to another process.
			// A kill of the group by its number could, once it is empty.
			fakefd, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.PidfdSendSignal(fakefd, unix.SIGKILL, nil, 0); _ = unix.Close(fakefd) })
			// Opened as watchExit opens its own, so that this runs from 5.3.
			childfd, err := unix.PidfdOpen(child, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.SetNonblock(childfd, true); err != nil {
				t.Fatal(err)
			}
			childf := os.NewFile(uintptr(childfd), "pidfd")
			t.Cleanup(func() {
				if rc, err := childf.SyscallConn(); err == nil {
					_ = rc.Control(func(fd uintptr) { _ = unix.PidfdSendSignal(int(fd), unix.SIGKILL, nil, 0) })
				}
				_ = childf.Close()
			})
			if err := os.WriteFile(goOn, []byte("go\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.cancel {
				cancel()
			}
			select {
			case err := <-started:
				if err == nil {
					t.Fatal("Start succeeded")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Start hung on the child bubblewrap left")
			}
			// The kill has been sent when Start returns, and the child ends
			// a moment after, when its pidfd is readable (pidfd_open(2)).
			rc, err := childf.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			if err := childf.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := rc.Read(pidfdExited); err != nil {
				t.Errorf("the child bubblewrap left outlived Start: %v", err)
			}
		})
	}
}

// watchExit tells an exit that came before the watch started, as well as one
// that comes after. The first is a child that has exited and not been reaped
// when the watch starts: the poller registers its pidfd already readable, and
// RawRead clears that before it looks, so only a check of its own finds it.
// Whether the poller has taken the readiness before RawRead clears it depends
// on the scheduler, and a watch without the check missed it in 9 runs of 40,
// so that case starts 20 watches of the one child.
func TestWatchExit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		before bool // whether the child exits before the watch starts
	}{
		{"exited before", true},
		{"exits after", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd := exec.CommandContext(t.Context(), "/bin/sleep", "1000")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			pid := cmd.Process.Pid
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			if tc.before {
				_ = cmd.Process.Kill()
				// Waits for the exit and leaves the child unreaped.
				var info unix.Siginfo
				if err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil); err != nil {
					t.Fatal(err)
				}
			}
			watches := 1
			if tc.before {
				watches = 20
			}
			for i := range watches {
				exited := make(chan struct{})
				stop, err := watchExit(pid, func() { close(exited) })
				if err != nil {
					t.Fatal(err)
				}
				if !tc.before {
					_ = cmd.Process.Kill()
				}
				select {
				case <-exited:
				case <-time.After(10 * time.Second):
					t.Fatalf("watch %d missed the exit", i)
				}
				stop()
			}
		})
	}
}

// watchExitEMFILEMode is a child mode that starts a child, lowers its own
// descriptor limit to the lowest free descriptor, and starts a watch of the
// child, whose pidfd then can't be opened. It prints the watch's error.
const watchExitEMFILEMode = "watch-exit-emfile"

var _ = func() bool {
	childModes[watchExitEMFILEMode] = func([]string) int {
		cmd := exec.CommandContext(context.Background(), "/bin/sleep", "1000")
		if err := cmd.Start(); err != nil {
			fmt.Println(err)
			return 1
		}
		defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
		// The limit bounds a descriptor's number, and the kernel gives the
		// lowest free one, so a limit at that number leaves no room.
		free, err := unix.Dup(0)
		if err != nil {
			fmt.Println(err)
			return 1
		}
		_ = unix.Close(free)
		var lim unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
			fmt.Println(err)
			return 1
		}
		lim.Cur = uint64(free)
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
			fmt.Println(err)
			return 1
		}
		_, err = watchExit(cmd.Process.Pid, func() {})
		fmt.Println(err)
		return 0
	}
	return true
}()

// A watch that can't open its pidfd for want of a descriptor fails, and so
// fails Start, which would otherwise go on without the watch and hang on a
// child bubblewrap leaves behind. Only a host that gives no pidfds goes on
// without one.
func TestWatchExitDescriptorLimit(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/proc/self/exe", watchExitEMFILEMode).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(string(out), "watch bubblewrap: too many open files") {
		t.Errorf("the watch at the descriptor limit gave %q, want EMFILE", out)
	}
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{unix.ENOSYS, true},
		{unix.EPERM, true},
		{unix.EACCES, true},
		{unix.EMFILE, false},
		{unix.ENFILE, false},
		{unix.ENOMEM, false},
		{nil, false},
	} {
		if got := pidfdUnsupported(tc.err); got != tc.want {
			t.Errorf("pidfdUnsupported(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
