package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// stageArg is the first argument of the run of this binary that bubblewrap
// starts inside the sandbox ahead of the command, and reaperArg that of the
// run the first stage execs. Each is followed by "--" and the command.
// stagePath is where the binary is bound in. /dev is a tmpfs bubblewrap
// makes, so the bind lands in no directory a sandbox writes.
const (
	stageArg  = "--sandbox-stage"
	reaperArg = "--sandbox-reaper"
	stagePath = "/dev/sandbox-stage"
)

// failed is the exit status of a sandbox whose stages could not set up, as
// distinct from the command's own.
const failed = 125

// The descriptors bubblewrap hands the stages, which Start numbers by the
// order of its ExtraFiles. fd 3 holds bubblewrap's options and goes no
// further. bubblewrap consumes its --info-fd, its bind sources, and its
// data pipes, and passes the rest on at the same numbers, as docs/linux.md
// (Descriptor passthrough) found on 0.12.0.
const (
	fdArgs     = 3
	fdInfo     = 4
	fdControl  = 5
	fdLifeline = 6
	// fdFiles is where Spec.Files start in the stages. The command gets
	// them from 3.
	fdFiles = 7
)

// Where the stage binds Spec.Listen's listeners, and where Spec.Loopback's
// ports start. Both are inside the sandbox's own network namespace.
const (
	listenPort   = 3128
	loopbackPort = 4444
)

// stageSettings is what the parent sends the stage on the control socket:
// what the command line used to carry, less the command itself, which
// bubblewrap must take from its own arguments.
type stageSettings struct {
	Kernel  Kernel       `json:"kernel"`
	Listen  int          `json:"listen"`
	Files   int          `json:"files"`
	Rlimits []stageLimit `json:"rlimits,omitempty"`
}

// stageLimit is a Linux resource limit.
type stageLimit struct {
	Resource int    `json:"resource"`
	Soft     uint64 `json:"soft"`
	Hard     uint64 `json:"hard"`
}

// stageReply is the stage's one message back: the setup error if there was
// one, and otherwise, with the Listen listeners as descriptors, that setup is
// done.
type stageReply struct {
	Error string `json:"error,omitempty"`
}

// maxMessage is the most the control socket's messages hold.
const maxMessage = 1 << 16

// Stage runs one of the sandbox's stages if this process was started as it,
// and reports false otherwise. A program that uses this package calls it
// first in main, before it reads its arguments.
func Stage() (int, bool) {
	// The check child is started with checkArg, and runs the checks and
	// nothing else.
	if len(os.Args) > 1 && os.Args[1] == checkArg {
		return checkStage(), true
	}
	if len(os.Args) < 4 || (os.Args[1] != stageArg && os.Args[1] != reaperArg) || os.Args[2] != "--" {
		return 0, false
	}
	var err error
	code := failed
	if os.Args[1] == stageArg {
		err = firstStage()
	} else {
		code, err = reaperStage(os.Args[3:])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: %v\n", err)
		return failed, true
	}
	return code, true
}

// firstStage runs inside the sandbox as pid 1, which bubblewrap starts with
// --as-pid-1, holding CAP_SYS_ADMIN and CAP_SETPCAP in the sandbox's user
// namespace, before anything untrusted runs. bubblewrap leaves the view a
// slave of the host's mounts, so a mount made on the host later, such as a
// bind of a covered path, would appear inside. Run unprivileged, bubblewrap
// puts pid 1 in a user namespace nested in the one that owns the view's
// mounts, so the capabilities cannot change those. This copies the view
// into a mount namespace of its own and makes every mount in it private.
// unshare moves only the calling thread, so it then execs this binary again
// as the reaper, which leaves the whole of pid 1 in the new namespace and
// none in bubblewrap's.
//
// It also joins a new, empty session keyring, since the caller's would
// otherwise be inherited, and a key in it is readable by the same uid. And it
// gives up every capability and sets no_new_privs before that exec.
// Both belong to a thread, not a process, and bubblewrap raised the
// capabilities as ambient ones before it started this binary, so every
// thread the Go runtime made holds them. Dropping them on any thread but the
// one that execs would leave the others holding them, and the command could
// be forked from one of those. execve carries only this locked thread's
// empty sets into the new image, which starts with that one thread, so every
// thread of the reaper, and the command, starts with none.
func firstStage() error {
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("copy the view into a mount namespace of its own: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	if err := joinAnonymousSessionKeyring(); err != nil {
		return err
	}
	if err := dropCapabilities(); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	// Die with bubblewrap's outer process, which is the parent of pid 1.
	// bubblewrap is single-threaded, so this has no thread problem, unlike
	// the same call on the caller's side. Without it a bubblewrap killed on
	// its own would leave pid 1 and the command holding the caller's output
	// pipes until the lifeline closes, which only Wait does, after those
	// pipes have closed. It is set on the thread that execs, which becomes
	// the reaper's only thread.
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return fmt.Errorf("die with bubblewrap: %w", err)
	}
	args := slices.Concat([]string{os.Args[0], reaperArg}, os.Args[2:])
	return syscall.Exec("/proc/self/exe", args, os.Environ()) //nolint:gosec // This is the sandbox's own binary, not a shell.
}

// reaperStage runs as pid 1 in the sandbox's own mount namespace, with no
// capabilities and no_new_privs set, which the first stage left it. It makes
// itself undumpable, so the command cannot read its memory or descriptors
// through /proc, and takes its settings from the control socket. It then
// binds the listeners, sets the limits, installs the filter on all its
// threads, sends the parent the listeners or the error, closes the control
// socket, and starts the command, which holds no descriptor but its own.
// Then it relays signals to the command, reaps every orphan in the
// namespace, and exits with the command's status, which also kills whatever
// is left. It exits as well when the lifeline reaches EOF, which is when
// the parent has gone, however it went. The filter goes on here rather than
// through bubblewrap, since it refuses the calls the first stage makes.
func reaperStage(command []string) (int, error) {
	// Undumpable belongs to the process, and execve resets it, so it is
	// set here rather than in the first stage.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return 0, fmt.Errorf("make pid 1 undumpable: %w", err)
	}
	// Without the lifeline, watchLifeline's first read fails with EBADF
	// and exits 137, racing the clean error below. Fail here instead.
	if _, err := unix.FcntlInt(fdLifeline, unix.F_GETFD, 0); err != nil {
		return 0, fmt.Errorf("descriptor %d is not the lifeline: %w", fdLifeline, err)
	}
	// Watch from the first moment, so a parent that died during setup
	// leaves no command running, even briefly. Its write end closing is
	// EOF whenever this first reads it.
	go watchLifeline()
	settings, err := receiveSettings()
	if err != nil {
		return 0, err
	}
	path, listeners, err := setup(settings, command)
	if err != nil {
		// The parent is waiting for the control socket's one message.
		_ = send(stageReply{Error: err.Error()}, nil)
		return 0, err
	}
	if err := send(stageReply{}, listeners); err != nil {
		return 0, fmt.Errorf("send the listeners: %w", err)
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	// Setup is over, and nothing untrusted has run. The command never
	// holds this socket: the parent trusts nothing it says.
	if err := os.NewFile(fdControl, "control").Close(); err != nil {
		return 0, fmt.Errorf("close the control socket: %w", err)
	}
	files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	for i := range settings.Files {
		files = append(files, os.NewFile(uintptr(fdFiles+i), "file"))
	}
	child, err := os.StartProcess(path, command, &os.ProcAttr{ //nolint:gosec // Running the configured command is the sandbox's job, and it is not a shell.
		Env:   os.Environ(),
		Files: files,
	})
	if err != nil {
		return 0, fmt.Errorf("start command: %w", err)
	}
	// Held until here, so that nothing closes one of them while it is
	// being passed on.
	runtime.KeepAlive(files)
	stop := relaySignals(child)
	defer stop()
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("wait: %w", err)
		}
		if pid != child.Pid {
			continue
		}
		if ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return ws.ExitStatus(), nil
	}
}

// receiveSettings reads the settings from the control socket.
func receiveSettings() (stageSettings, error) {
	var settings stageSettings
	if typ, err := unix.GetsockoptInt(fdControl, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || typ != unix.SOCK_SEQPACKET {
		return settings, fmt.Errorf("descriptor %d is not the control socket: %v", fdControl, err)
	}
	buf := make([]byte, maxMessage)
	for {
		n, _, flags, _, err := unix.Recvmsg(fdControl, buf, nil, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return settings, fmt.Errorf("read the settings: %w", err)
		}
		if flags&unix.MSG_TRUNC != 0 || n == 0 {
			return settings, errors.New("read the settings: the message is empty or too long")
		}
		if err := json.Unmarshal(buf[:n], &settings); err != nil {
			return settings, fmt.Errorf("read the settings: %w", err)
		}
		return settings, nil
	}
}

// setup does everything the command needs of pid 1 before it starts, and
// returns the path to start and the listeners it bound.
func setup(s stageSettings, command []string) (string, []*net.TCPListener, error) {
	if err := s.Kernel.Set(string(s.Kernel)); err != nil {
		return "", nil, err
	}
	// bubblewrap gave the stages the command's environment, so its PATH is
	// the one to look the command up on.
	path, err := exec.LookPath(command[0])
	if err != nil {
		return "", nil, err
	}
	var listeners []*net.TCPListener
	fail := func(err error) (string, []*net.TCPListener, error) {
		for _, l := range listeners {
			_ = l.Close()
		}
		return "", nil, err
	}
	var lc net.ListenConfig
	for i := range s.Listen {
		l, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort+i)))
		if err != nil {
			return fail(fmt.Errorf("bind a listener: %w", err))
		}
		listeners = append(listeners, l.(*net.TCPListener))
	}
	// The limits go last but for the filter, so that a low one does not
	// stop the setup above. They apply to pid 1 too. Go's syscall package
	// is used because x/sys' Setrlimit leaves the original NOFILE limit
	// that os/exec restores for the child.
	for _, r := range s.Rlimits {
		if err := syscall.Setrlimit(r.Resource, &syscall.Rlimit{Cur: r.Soft, Max: r.Hard}); err != nil {
			return fail(fmt.Errorf("set limit %d: %w", r.Resource, err))
		}
	}
	// Every inherited descriptor but the command's own gets
	// close-on-exec, and none is closed by number: once the Go runtime is
	// up, a number may be one of its own, such as its epoll descriptor.
	markCloseOnExec()
	if err := installSeccomp(s.Kernel); err != nil {
		return fail(err)
	}
	return path, listeners, nil
}

// markCloseOnExec sets close-on-exec on every open descriptor from 3 up,
// including the ones the command is given, which os.StartProcess maps to
// their places in it and which lose the flag there.
func markCloseOnExec() {
	if err := unix.CloseRange(3, math.MaxUint32, unix.CLOSE_RANGE_CLOEXEC); err == nil {
		return
	}
	// Before Linux 5.11.
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range ents {
		if fd, err := strconv.Atoi(e.Name()); err == nil && fd >= 3 {
			unix.CloseOnExec(fd)
		}
	}
}

// send sends the parent the one message the control socket carries back,
// with listeners' descriptors.
func send(reply stageReply, listeners []*net.TCPListener) error {
	body, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	var oob []byte
	if len(listeners) > 0 {
		fds := make([]int, 0, len(listeners))
		for _, l := range listeners {
			f, err := l.File()
			if err != nil {
				return err
			}
			defer f.Close()
			fds = append(fds, int(f.Fd()))
		}
		oob = unix.UnixRights(fds...)
	}
	for {
		err := unix.Sendmsg(fdControl, body, oob, nil, 0)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// watchLifeline exits pid 1 when the lifeline reaches EOF, which the kernel
// does once the parent, the only holder of its write end, has closed it or
// died. pid 1 exiting kills every other process in the sandbox.
func watchLifeline() {
	var b [1]byte
	for {
		if _, err := unix.Read(fdLifeline, b[:]); !errors.Is(err, unix.EINTR) {
			os.Exit(128 + int(unix.SIGKILL))
		}
	}
}

// joinAnonymousSessionKeyring makes the calling thread's session keyring a
// new, empty, anonymous one, which the reaper and the command inherit from the
// thread that execs. Without it they share the caller's session keyring, which
// may hold Kerberos tickets or tokens, and the kernel's permission check on a
// key looks only at the uid, which the sandbox keeps. strict and nested refuse
// keyctl, but open does not. A kernel with no key support has nothing to
// share. A host filter that refuses keyctl, as Docker's does with EPERM,
// refuses it to the command as well.
func joinAnonymousSessionKeyring() error {
	const keyctlJoinSessionKeyring = 1
	_, _, errno := unix.Syscall(unix.SYS_KEYCTL, keyctlJoinSessionKeyring, 0, 0)
	if errno != 0 && errno != unix.ENOSYS && errno != unix.EPERM {
		return fmt.Errorf("join a new session keyring: %w", errno)
	}
	return nil
}

// dropCapabilities empties the calling thread's bounding set and clears all
// its other sets. The calls act on that thread alone, so the caller must be
// locked to it and exec from it. What it then runs holds none, even as uid 0
// inside, and the empty bounding set is inherited by everything that starts.
func dropCapabilities() error {
	for c := 0; ; c++ {
		err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
		if errors.Is(err, unix.EINVAL) {
			break
		}
		if err != nil {
			return fmt.Errorf("drop capability %d from the bounding set: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("clear capabilities: %w", err)
	}
	return nil
}

// relaySignals passes the signals a supervisor sends on to p, and returns a
// function that stops. An interrupt from a terminal already reaches the
// whole process group, so it is not relayed.
func relaySignals(p *os.Process) func() {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				_ = p.Signal(s)
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(sigs)
		close(done)
	}
}
