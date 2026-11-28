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
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// stagePath is where the binary is bound in, and the whole of the argv of
// both of the stages: bubblewrap starts the first with roleStage, and it execs
// the reaper with roleReaper. /dev is a tmpfs bubblewrap makes, so the bind
// lands in no directory a sandbox writes.
const stagePath = "/dev/sandbox-stage"

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

// stageSettings is what the parent sends the reaper on the control socket:
// everything the stages need, the command included, so that no argv holds
// any of it.
type stageSettings struct {
	// Command is the command's argv, which the reaper looks up on the
	// command's PATH.
	Command byteArgs     `json:"command"`
	Kernel  Kernel       `json:"kernel"`
	Listen  int          `json:"listen"`
	Files   int          `json:"files"`
	Rlimits []stageLimit `json:"rlimits,omitempty"`
	// Role, if set, is the part of the sandbox the command plays, which
	// the reaper gives it as roleVar: Check's child and Probe's trial are
	// this binary. Empty, the command's environment holds no roleVar.
	Role string `json:"role,omitempty"`
}

// stageLimit is a Linux resource limit.
type stageLimit struct {
	Resource int    `json:"resource"`
	Soft     uint64 `json:"soft"`
	Hard     uint64 `json:"hard"`
}

// stageReply is one of the stage's two messages back. The first is the setup
// error if there was one, and otherwise, with the Listen listeners as
// descriptors, that setup is done. The second, after the command's start, is
// the start's error or Started.
type stageReply struct {
	Error string `json:"error,omitempty"`
	// Started is set in the second message, which says the command started.
	Started bool `json:"started,omitempty"`
}

// maxMessage is the most one of the control socket's messages holds. The
// settings take as many as they need, since the command's argv can be far
// longer than the socket's buffer lets one message be (unix_dgram_sendmsg in
// net/unix/af_unix.c refuses one longer than its send buffer).
const maxMessage = 1 << 16

// The first byte of each message of the settings says whether more follow.
// A message can't be empty, since a read of none is the end of the socket.
const (
	settingsMore = 1
	settingsLast = 0
)

// stageOptions changes what a stage does, for a test binary, which sets
// stageOpts. A program runs the zero value.
type stageOptions struct {
	// noCloseRange, if set, makes markCloseOnExec skip close_range, as on a
	// kernel before 5.11, so that a test reaches the listing it falls back to.
	noCloseRange bool
	// fdDir, if set, is the directory markCloseOnExec lists the stage's
	// descriptors from in place of /proc/self/fd, so that a test can make the
	// listing fail.
	fdDir string
	// afterStart, if set, is called once the command has started and before
	// the reaper says so, so that a test can hold it there while the command
	// ends the sandbox.
	afterStart func()
}

// platformRole plays the Linux parts of the sandbox: the two stages, and the
// check child's namespace attempts. It reports false for a role that isn't
// one of them.
func platformRole(role string, opts stageOptions) (int, bool) {
	var err error
	code := failed
	switch role {
	case roleStage:
		err = firstStage()
	case roleReaper:
		code, err = reaperStage(opts)
	case roleCheckNS:
		return grandchild(), true
	default:
		return 0, false
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
// none in bubblewrap's. The reaper is found by roleReaper in its
// environment, which the init of this run removed roleStage from.
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
	return syscall.Exec("/proc/self/exe", []string{stagePath}, withRole(os.Environ(), roleReaper)) //nolint:gosec // This is the sandbox's own binary, not a shell.
}

// reaperStage runs as pid 1 in the sandbox's own mount namespace, with no
// capabilities and no_new_privs set, which the first stage left it. It makes
// itself undumpable, so the command cannot read its memory or descriptors
// through /proc, and takes its settings, the command among them, from the
// control socket. It then
// binds the listeners, sets the limits, installs the filter on all its
// threads, sends the parent the listeners or the setup error, and starts the
// command, which holds no descriptor but its own. Then it sends the start's
// error or that the command started, and closes the control socket, so that
// Start fails for a command that can't be started, as on macOS, and nothing
// the command does can fail it.
// Then it relays signals to the command, reaps every orphan in the
// namespace, and exits with the command's status, which also kills whatever
// is left. It exits as well when the lifeline reaches EOF, which is when
// the parent has gone, however it went. The filter goes on here rather than
// through bubblewrap, since it refuses the calls the first stage makes.
func reaperStage(opts stageOptions) (int, error) {
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
	settings, err := receiveSettings(fdControl)
	if err != nil {
		return 0, err
	}
	path, listeners, err := setup(settings, opts)
	if err != nil {
		// The parent is waiting for the first message.
		_ = send(stageReply{Error: err.Error()}, nil)
		return 0, err
	}
	// The first message: setup is done, with the listeners. It goes before
	// the command starts, so that nothing the command does, such as ending
	// the sandbox at once, can stand between the parent and it.
	if err := send(stageReply{}, listeners); err != nil {
		return 0, fmt.Errorf("send the listeners: %w", err)
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	for i := range settings.Files {
		files = append(files, os.NewFile(uintptr(fdFiles+i), "file"))
	}
	// The command doesn't inherit the control socket or the listeners,
	// which setup marked close-on-exec, and it can't reach pid 1's
	// descriptors, so it can't touch the second reply.
	child, err := os.StartProcess(path, settings.Command.strings(), &os.ProcAttr{
		Env:   withRole(os.Environ(), settings.Role),
		Files: files,
	})
	// Held until here, so that nothing closes one of them while it is
	// being passed on.
	runtime.KeepAlive(files)
	if err != nil {
		// The second message: the start's error, which fails Start.
		err = fmt.Errorf("start command: %w", err)
		_ = send(stageReply{Error: err.Error()}, nil)
		return 0, err
	}
	// Relayed from the command's start, so that a SIGTERM or SIGHUP from
	// then on reaches it, and doesn't end pid 1 by Go's default.
	stop := relaySignals(child)
	defer stop()
	if opts.afterStart != nil {
		opts.afterStart()
	}
	// The second message: the command started. A parent that reads the end
	// of the socket here instead, as when the command ended the sandbox
	// first, takes it as started too, and Wait has the status. A parent
	// that can't be told has gone, and pid 1's exit ends the command.
	if err := send(stageReply{Started: true}, nil); err != nil {
		return 0, fmt.Errorf("say the command started: %w", err)
	}
	// The parent trusts nothing the socket says from here.
	if err := os.NewFile(fdControl, "control").Close(); err != nil {
		return 0, fmt.Errorf("close the control socket: %w", err)
	}
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

// receiveSettings reads the settings from the control socket, fd, in as many
// messages as sendSettings made of them, and refuses settings with no
// command.
func receiveSettings(fd int) (stageSettings, error) {
	var settings stageSettings
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return settings, fmt.Errorf("descriptor %d is not the control socket: %w", fd, err)
	}
	if typ != unix.SOCK_SEQPACKET {
		return settings, fmt.Errorf("descriptor %d is not the control socket: its type is %d", fd, typ)
	}
	var body []byte
	buf := make([]byte, maxMessage)
	for {
		n, _, flags, _, err := unix.Recvmsg(fd, buf, nil, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return settings, fmt.Errorf("read the settings: %w", err)
		}
		if flags&unix.MSG_TRUNC != 0 || n == 0 {
			return settings, errors.New("read the settings: a message is empty or too long")
		}
		body = append(body, buf[1:n]...)
		if buf[0] == settingsLast {
			break
		}
		if buf[0] != settingsMore {
			return settings, fmt.Errorf("read the settings: a message starts with %d", buf[0])
		}
	}
	if err := json.Unmarshal(body, &settings); err != nil {
		return settings, fmt.Errorf("read the settings: %w", err)
	}
	if len(settings.Command) == 0 || len(settings.Command[0]) == 0 {
		return settings, errors.New("read the settings: they carry no command")
	}
	return settings, nil
}

// sendSettings writes body to the control socket in messages of at most
// maxMessage bytes, each led by a byte that says whether more follow. Those
// that don't fit in the socket's buffer wait for the reaper to read the ones
// before, so it is called once bubblewrap has started. A message is also no
// longer than the send buffer takes, less the 32 bytes unix_dgram_sendmsg
// keeps back, for a host whose buffer is smaller than maxMessage.
func sendSettings(ctl *os.File, body []byte) error {
	size := maxMessage
	if buf, err := unix.GetsockoptInt(int(ctl.Fd()), unix.SOL_SOCKET, unix.SO_SNDBUF); err == nil && buf-32 < size {
		size = buf - 32
	}
	if size < 2 {
		return fmt.Errorf("the control socket's send buffer holds only %d bytes", size)
	}
	msg := make([]byte, 0, size)
	for {
		n := min(len(body), size-1)
		more := byte(settingsLast)
		if n < len(body) {
			more = settingsMore
		}
		msg = append(append(msg[:0], more), body[:n]...)
		if _, err := ctl.Write(msg); err != nil {
			return err
		}
		body = body[n:]
		if more == settingsLast {
			return nil
		}
	}
}

// setup does everything the command needs of pid 1 before it starts, and
// returns the path to start and the listeners it bound.
func setup(s stageSettings, opts stageOptions) (string, []*net.TCPListener, error) {
	if err := s.Kernel.Set(string(s.Kernel)); err != nil {
		return "", nil, err
	}
	// bubblewrap gave the stages the command's environment, so its PATH is
	// the one to look the command up on.
	path, err := exec.LookPath(string(s.Command[0]))
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
	// up, a number may be one of its own, such as its epoll descriptor. A
	// stage that can't mark them starts nothing, since the command would
	// inherit the stage's.
	if err := opts.markCloseOnExec(); err != nil {
		return fail(err)
	}
	if err := installSeccomp(s.Kernel); err != nil {
		return fail(err)
	}
	return path, listeners, nil
}

// markCloseOnExec sets close-on-exec on every open descriptor from 3 up,
// including the ones the command is given, which os.StartProcess maps to
// their places in it and which lose the flag there. It fails if neither
// close_range nor a listing of /proc/self/fd works, since it can't tell which
// descriptors it missed.
func (o stageOptions) markCloseOnExec() error {
	if !o.noCloseRange {
		if err := unix.CloseRange(3, math.MaxUint32, unix.CLOSE_RANGE_CLOEXEC); err == nil {
			return nil
		}
	}
	// Before Linux 5.11.
	dir := o.fdDir
	if dir == "" {
		dir = "/proc/self/fd"
	}
	return markListedCloseOnExec(dir)
}

// send sends the parent one of the control socket's two messages back, with
// listeners' descriptors.
func send(reply stageReply, listeners []*net.TCPListener) error {
	body, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	var oob []byte
	if len(listeners) > 0 {
		files := make([]*os.File, 0, len(listeners))
		defer func() {
			for _, f := range files {
				f.Close() //nolint:gosec // G104: l.File made these as copies of the listeners' descriptors, and a failed close changes nothing.
			}
		}()
		fds := make([]int, 0, len(listeners))
		for _, l := range listeners {
			f, err := l.File()
			if err != nil {
				return err
			}
			files = append(files, f)
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
			os.Exit(128 + int(unix.SIGKILL)) //nolint:revive // deep-exit: pid 1 must end the whole sandbox from this goroutine, and nothing above it could take an exit status.
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
