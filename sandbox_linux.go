package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// backend is what the platform's implementation holds in a Cmd.
type backend struct {
	ctx  context.Context
	spec Spec
	run  run
}

// run is what a started Cmd holds.
type run struct {
	started, waited bool
	cmd             *exec.Cmd
	pid             int
	// lifeline is the write end of the pipe pid 1 watches. Only this
	// process holds it, and it is close-on-exec, so when this process
	// goes, however it goes, pid 1 reads EOF and ends the sandbox.
	lifeline  *os.File
	sent      <-chan error
	listeners []net.Listener
	// tty is the terminal whose foreground the sandbox took, if any.
	tty *terminal
}

// giveBackTerminal returns the terminal's foreground to the caller's process
// group, once the sandbox, whose group id is its bubblewrap's pid, has ended.
func (r *run) giveBackTerminal(sandboxPgrp int) {
	if r.tty != nil {
		r.tty.restore(sandboxPgrp)
		r.tty = nil
	}
}

// resources maps each Resource to its Linux number.
var resources = map[Resource]int{
	ResourceCPU:          unix.RLIMIT_CPU,
	ResourceFileSize:     unix.RLIMIT_FSIZE,
	ResourceCore:         unix.RLIMIT_CORE,
	ResourceOpenFiles:    unix.RLIMIT_NOFILE,
	ResourceProcesses:    unix.RLIMIT_NPROC,
	ResourceAddressSpace: unix.RLIMIT_AS,
}

// Command returns a Cmd that will run spec's command in a sandbox that
// bubblewrap builds. It checks what needs no look at the host and starts
// nothing; Start does the rest. ctx kills the sandbox when it is done, once
// Start has been called.
//
// It refuses to run as root, and there is no way to ask for another
// account, since it opens paths and writes the sandbox's passwd in this
// process. A caller that runs as root switches to the sandbox's uid first.
// It refuses a kernel level the host cannot give, such as strict on an
// architecture with no system call list, and never starts a weaker one.
func Command(ctx context.Context, spec Spec) (*Cmd, error) {
	if os.Geteuid() == 0 {
		return nil, errors.New("the sandbox will not run as root: switch to the sandbox's own uid first")
	}
	if err := spec.checkRequest(); err != nil {
		return nil, err
	}
	if strings.ContainsRune(spec.Hostname, 0) {
		return nil, errors.New("the hostname holds a NUL")
	}
	if spec.Kernel == "" {
		spec.Kernel = KernelStrict
	}
	if err := spec.Kernel.Set(string(spec.Kernel)); err != nil {
		return nil, err
	}
	// pid 1 builds the filter again to install it, but a filter that
	// cannot be built is refused here, before bubblewrap builds the view.
	if _, err := filterProgram(spec.Kernel); err != nil {
		return nil, err
	}
	spec.Command = slices.Clone(spec.Command)
	spec.Files = slices.Clone(spec.Files)
	spec.Rlimits = slices.Clone(spec.Rlimits)
	return &Cmd{backend: backend{ctx: ctx, spec: spec}, CgroupFD: -1}, nil
}

// ListenAddrs returns the addresses of the Listen listeners, which the
// command reaches. They are known before Start, so Env can carry them.
func (c *Cmd) ListenAddrs() []string {
	if c.spec.Listen == 0 {
		return nil
	}
	addrs := make([]string, 0, c.spec.Listen)
	for i := range c.spec.Listen {
		addrs = append(addrs, net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort+i)))
	}
	return addrs
}

// LoopbackPorts returns the Loopback ports the command may bind and dial.
// On Linux they are fixed, 4444 and up, and private to the sandbox's network
// namespace, so two sandboxes use the same ones without meeting.
func (c *Cmd) LoopbackPorts() []int {
	if c.spec.Loopback == 0 {
		return nil
	}
	ports := make([]int, 0, c.spec.Loopback)
	for i := range c.spec.Loopback {
		ports = append(ports, loopbackPort+i)
	}
	return ports
}

// Listeners returns the Listen listeners, in order, once Start has
// returned. The caller serves them, and closes them when it is done.
func (c *Cmd) Listeners() []net.Listener {
	return c.run.listeners
}

// Pid returns the host pid of the sandbox's pid 1, which bubblewrap reports
// on its --info-fd, after Start. It never comes from the control socket,
// which the stages trust only during setup.
func (c *Cmd) Pid() int {
	return c.run.pid
}

// Start resolves the spec's paths, opens what bubblewrap binds, and starts
// bubblewrap. It returns once pid 1 has set the sandbox up and handed over
// its listeners, and before the command's own start, so a command that
// fails to run shows in Wait's status.
func (c *Cmd) Start() error {
	if c.run.started {
		return errors.New("sandbox: already started")
	}
	c.run.started = true
	spec := c.spec
	bwrap, err := findBwrap()
	if err != nil {
		return err
	}
	h, err := currentHost()
	if err != nil {
		return err
	}
	spec, err = prepare(spec, h)
	if err != nil {
		return err
	}
	settings := stageSettings{Kernel: spec.Kernel, Listen: spec.Listen, Files: len(spec.Files)}
	for _, r := range spec.Rlimits {
		settings.Rlimits = append(settings.Rlimits, stageLimit{resources[r.Resource], r.Soft, r.Hard})
	}
	body, err := json.Marshal(settings)
	if err != nil {
		return err
	}

	// What the parent keeps is closed on any failure below, and what
	// bubblewrap is given is closed by the launch.
	var parent []*os.File
	ok := false
	defer func() {
		if !ok {
			for _, f := range parent {
				_ = f.Close()
			}
		}
	}()
	infoR, infoW, err := os.Pipe()
	if err != nil {
		return err
	}
	parent = append(parent, infoR)
	lifeR, lifeW, err := os.Pipe()
	if err != nil {
		_ = infoW.Close()
		return err
	}
	parent = append(parent, lifeW)
	ctlP, ctlC, err := socketpair()
	if err != nil {
		_ = infoW.Close()
		_ = lifeR.Close()
		return err
	}
	parent = append(parent, ctlP)
	// bubblewrap passes these on to pid 1 at the same numbers: the control
	// socket, the lifeline's read end, and the command's files.
	inherit := []*os.File{infoW, ctlC, lifeR}
	for _, f := range spec.Files {
		d, err := dupFile(f)
		if err != nil {
			for _, f := range inherit {
				_ = f.Close()
			}
			return err
		}
		inherit = append(inherit, d)
	}
	l, err := newLaunch(spec, lookupAccount(), inherit)
	if err != nil {
		for _, f := range inherit {
			_ = f.Close()
		}
		return err
	}
	defer l.close()
	// The message waits in the socket's buffer until pid 1 reads it.
	if _, err := ctlP.Write(body); err != nil {
		return fmt.Errorf("send the settings: %w", err)
	}

	// The options go on a descriptor so that pid 1's command line, which
	// any process inside can read, does not list them. bubblewrap takes the
	// command only from its own arguments, and the command is the first
	// stage, with the real one after it.
	args := append([]string{"--args", strconv.Itoa(fdArgs), "--", stagePath, stageArg, "--"}, spec.Command...)
	cmd := exec.CommandContext(c.ctx, bwrap, args...) //nolint:gosec // Running the configured command in the sandbox is its job, and bubblewrap is not a shell.
	cmd.Args[0] = "bwrap"
	cmd.Env = commandEnv(c.Env, spec)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	cmd.WaitDelay = c.WaitDelay
	cmd.ExtraFiles = l.inherit
	// No Pdeathsig, and no --die-with-parent, which is the same call made
	// in bubblewrap: it fires when the OS thread that started bubblewrap
	// exits, and a Go server's threads come and go. The lifeline does it.
	// A process group of its own, always, and the caller's session, which pid
	// 1 leaves with OwnSession.
	// The filter allows kill, tgkill and setpriority, so a sandbox that
	// shared its caller's group could signal and renice the caller and
	// everything else in it, through kill(0, ...) and setpriority(PRIO_PGRP).
	// The kernel allows both across a pid namespace, since the uid is the same.
	//
	// The group is also what ends bubblewrap during Start: its clone child
	// can outlive the outer process, as one killed before it lets the child
	// go on does, and that child holds the stages' descriptors, so the read
	// of --info-fd below would wait on it for good. A failed Start kills the
	// whole group, and so does bubblewrap's exit during Start, which a pidfd
	// tells (watchExit), as when a canceled ctx kills the outer process. The
	// ctx's own kill stays the default, through the process's pidfd: os/exec
	// can call Cancel after Wait has reaped bubblewrap, when the group's
	// number may be another's.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, UseCgroupFD: c.CgroupFD > 0, CgroupFD: max(c.CgroupFD, 0)}
	// A background group is stopped when it reads the caller's terminal, so
	// an interactive command gets the foreground until Wait gives it back.
	// With OwnSession the sandbox has no controlling terminal, so job control
	// doesn't stop its reads (tty_check_change in drivers/tty/tty_jobctrl.c
	// checks only a process's own one), and no group of the sandbox's session
	// could hold the terminal's foreground. Handed to bubblewrap's group,
	// which then holds only bubblewrap's outer process, it would send a
	// Ctrl-C there and not to the caller (TestOwnSessionTerminal).
	var tty *terminal
	if !spec.OwnSession {
		tty = foregroundTerminal(c.Stdin)
	}
	if tty != nil {
		cmd.SysProcAttr.Foreground, cmd.SysProcAttr.Ctty = true, tty.fd
	}
	if err := cmd.Start(); err != nil {
		if tty != nil {
			tty.restore(0)
		}
		return fmt.Errorf("start bubblewrap: %w", err)
	}
	c.run.tty = tty
	sent := l.send()
	// Bubblewrap gone during Start ends the sandbox: the kill ends its group,
	// and the lifeline's close ends pid 1, which has left the group with
	// OwnSession. pid 1's death signal can't stand in for the close: it is
	// set in the first stage, and does nothing if bubblewrap died before
	// then, and getppid can't tell pid 1 that it has, since bubblewrap is
	// outside pid 1's pid namespace (getppid in kernel/sys.c gives 0 for a
	// parent there).
	stopWatch, watchErr := watchExit(cmd.Process.Pid, func() {
		_ = killProcessGroup(cmd.Process.Pid)
		_ = lifeW.Close()
	})
	if watchErr != nil {
		stopWatch = func() {}
	}
	// From here the sandbox may be running, so a failure kills it. The
	// watch ends first, so that its kill never comes after the reap below,
	// when the group's number may be free. The lifeline closes before the
	// wait, which waits on the streams pid 1 may hold.
	fail := func(err error) error {
		stopWatch()
		_ = killProcessGroup(cmd.Process.Pid)
		_ = lifeW.Close()
		waitErr := cmd.Wait()
		c.run.giveBackTerminal(cmd.Process.Pid)
		<-sent //nolint:errcheck // Start is already failing and returns its own error. This only waits for the settings writer to end.
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			err = fmt.Errorf("%w (bubblewrap: %w)", err, ee)
		}
		return err
	}
	if watchErr != nil {
		return fail(watchErr)
	}
	// bubblewrap writes its --info-fd once it has made pid 1.
	var info struct {
		ChildPid int `json:"child-pid"`
	}
	if err := json.NewDecoder(infoR).Decode(&info); err != nil || info.ChildPid <= 0 {
		return fail(errors.New("the sandbox did not start"))
	}
	listeners, err := receiveReply(ctlP, spec.Listen)
	if err != nil {
		return fail(err)
	}
	stopWatch()
	// Nothing more on the control socket is read. Pid 1 closed its end
	// before the command started, and the command never held it.
	_ = ctlP.Close()
	_ = infoR.Close()
	c.run.cmd, c.run.pid, c.run.lifeline, c.run.sent, c.run.listeners = cmd, info.ChildPid, lifeW, sent, listeners
	ok = true
	return nil
}

// killProcessGroup ends bubblewrap's process group, which Start gives it,
// with every process in it. The group's number is held until bubblewrap is
// reaped, which only cmd.Wait does, and Start calls this only before then.
func killProcessGroup(pid int) error {
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}

// watchExit calls exited if the process pid, a child of this one that hasn't
// been reaped, exits before the function it returns is called, and returns a
// function that ends the watch and waits for it. The watch is a pidfd of its
// own, which waits in the runtime's poller and so holds no thread. It is made
// non-blocking with fcntl, not with pidfd_open's PIDFD_NONBLOCK, which only
// Linux 5.10 takes: pidfd_open takes no flags in 5.3, and polls from then
// (pidfd_poll in kernel/fork.c), and a pidfd has no check_flags to refuse
// O_NONBLOCK (setfl in fs/fcntl.c). The pidfd os/exec holds for the child
// shares no open file with it, so its blocking wait is unchanged. The watch
// only keeps Start from hanging and enforces nothing, so where the host gives
// no pidfds (pidfdUnsupported) there is no watch and Start goes on, as os
// does without them. Any other failure, such as a descriptor limit, is an
// error, which fails Start as such a limit would anywhere else in it.
func watchExit(pid int, exited func()) (stop func(), err error) {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if pidfdUnsupported(err) {
		return func() {}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("watch bubblewrap: %w", err)
	}
	if err := unix.SetNonblock(pidfd, true); err != nil {
		_ = unix.Close(pidfd)
		return nil, fmt.Errorf("watch bubblewrap: %w", err)
	}
	f := os.NewFile(uintptr(pidfd), "pidfd")
	rc, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("watch bubblewrap: %w", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := rc.Read(pidfdExited); err == nil {
			exited()
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = f.Close()
			<-done
		})
	}, nil
}

// pidfdUnsupported reports whether err, from pidfd_open, says that the host
// gives no pidfds: a kernel before 5.3, which has no such call (ENOSYS), or a
// seccomp filter or a security module that refuses it (EPERM, EACCES). A
// descriptor limit or a lack of memory says nothing of the kind.
func pidfdUnsupported(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
}

// pidfdExited reports whether the process of the pidfd fd has exited, which
// is when the pidfd is readable (pidfd_open(2)). It asks poll with no wait,
// since RawRead clears the poller's readiness before its first call of this
// (prepareRead in internal/poll/fd_unix.go), and an exit before then would
// otherwise be missed for good: the poller is edge-triggered.
func pidfdExited(fd uintptr) bool {
	if fd > math.MaxInt32 {
		return false
	}
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(pfd, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err == nil && n > 0
	}
}

// Wait waits for the sandbox to exit and returns what exec's Wait does for
// bubblewrap, whose exit status is the command's. It closes the lifeline.
func (c *Cmd) Wait() error {
	if c.run.cmd == nil {
		return errors.New("sandbox: not started")
	}
	if c.run.waited {
		return errors.New("sandbox: Wait was already called")
	}
	c.run.waited = true
	err := c.run.cmd.Wait()
	c.run.giveBackTerminal(c.run.cmd.Process.Pid)
	_ = c.run.lifeline.Close()
	// A write fails only when bubblewrap exited before it read everything,
	// which its status already says.
	if serr := <-c.run.sent; serr != nil && err == nil {
		err = serr
	}
	return err
}

// receiveReply reads the stage's one message from the control socket: its
// setup error, or the n listeners it bound.
func receiveReply(ctl *os.File, n int) ([]net.Listener, error) {
	buf := make([]byte, maxMessage)
	oob := make([]byte, unix.CmsgSpace(4*max(n, 1)))
	var got, oobn, flags int
	for {
		var err error
		got, oobn, flags, _, err = unix.Recvmsg(int(ctl.Fd()), buf, oob, unix.MSG_CMSG_CLOEXEC)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read the sandbox's setup: %w", err)
		}
		break
	}
	var fds []int
	if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
		for i := range msgs {
			if rights, err := unix.ParseUnixRights(&msgs[i]); err == nil {
				fds = append(fds, rights...)
			}
		}
	}
	files := make([]*os.File, len(fds))
	for i, fd := range fds {
		files[i] = os.NewFile(uintptr(fd), "listener")
	}
	closeAll := func() {
		for _, f := range files {
			_ = f.Close()
		}
	}
	// Zero bytes is an end of file: pid 1 or bubblewrap ended first.
	var reply stageReply
	switch {
	case got == 0:
		closeAll()
		return nil, errors.New("the sandbox ended during setup")
	case flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || json.Unmarshal(buf[:got], &reply) != nil:
		closeAll()
		return nil, errors.New("the sandbox sent a malformed reply")
	case reply.Error != "":
		closeAll()
		return nil, errors.New(reply.Error)
	case len(files) != n:
		closeAll()
		return nil, fmt.Errorf("the sandbox sent %d listeners, not %d", len(files), n)
	}
	listeners := make([]net.Listener, 0, n)
	for i, f := range files {
		ln, err := net.FileListener(f)
		_ = f.Close()
		if err == nil {
			want := net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort+i))
			if got := ln.Addr().String(); got != want {
				_ = ln.Close()
				err = fmt.Errorf("listener %d is on %s, not %s", i, got, want)
			}
		}
		if err != nil {
			for _, ln := range listeners {
				_ = ln.Close()
			}
			for _, f := range files[i+1:] {
				_ = f.Close()
			}
			return nil, err
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}

// socketpair makes the control socket: a connected pair, close-on-exec,
// that keeps message boundaries.
func socketpair() (parent, child *os.File, err error) {
	fd, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("make the control socket: %w", err)
	}
	return os.NewFile(uintptr(fd[0]), "control-parent"), os.NewFile(uintptr(fd[1]), "control-child"), nil
}

// Run runs spec's command in a sandbox that bubblewrap builds, with this
// process's own standard streams and environment, and returns its exit
// status. A status from a signal is 128 plus the signal's number, as a shell
// reports it. It is for a process that does nothing else: it relays
// SIGTERM and SIGHUP, and an empty Dir means the working directory. Spec's
// Listen is refused, since nothing here serves a listener.
func Run(ctx context.Context, spec Spec) (int, error) {
	if spec.Listen > 0 {
		return 0, errors.New("Run cannot serve listeners; use Command")
	}
	if spec.Dir == "" {
		dir, err := os.Getwd()
		if err != nil {
			return 0, fmt.Errorf("find working directory: %w", err)
		}
		spec.Dir = dir
	}
	c, err := Command(ctx, spec)
	if err != nil {
		return 0, err
	}
	c.Env = os.Environ()
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		return 0, err
	}
	// bubblewrap's outer process does not pass signals on, so a SIGTERM
	// or SIGHUP relayed to it ends it, and Wait's close of the lifeline then
	// makes pid 1 kill everything inside. Relaying rather than dying lets
	// Run still wait for it and return its status.
	stop := relaySignals(c.run.cmd.Process)
	defer stop()
	return exitStatus(c.Wait())
}

// findBwrap finds bubblewrap on the PATH. It refuses a setuid copy, since
// bubblewrap's serious past flaws were in its setuid mode, and the sandbox
// needs nothing that mode adds.
func findBwrap() (string, error) {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return "", fmt.Errorf("find bubblewrap, which the sandbox needs on Linux: %w", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("find bubblewrap: %w", err)
	}
	if fi.Mode()&fs.ModeSetuid != 0 {
		return "", fmt.Errorf("%s is setuid, which the sandbox refuses", path)
	}
	return path, nil
}

// hostMounts reads the host's mount table, as this process sees it.
func hostMounts() ([]mount, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("read mount table: %w", err)
	}
	defer f.Close()
	return parseMountinfo(f)
}

// launch is what Run hands bubblewrap: its options, which it reads from the
// first inherited descriptor, and the descriptors they name.
type launch struct {
	// inherit are bubblewrap's descriptors from 3 on.
	inherit []*os.File
	// writes are the pipes whose other ends are in inherit, with what to
	// send on each once bubblewrap is running.
	writes []pendingWrite
}

// pendingWrite is a pipe to fill and close once bubblewrap has started.
type pendingWrite struct {
	w    *os.File
	body []byte
}

// Mount kinds, which order mounts at the same path.
const (
	coverMount = iota
	scratchMount
	bindMount
)

// mountOp is one of bubblewrap's mount options, at path.
type mountOp struct {
	path string
	kind int
	args []string
}

// SelfPath is the path under which a sandbox's command names this binary,
// for a command that runs it again: Spec.Command = []string{SelfPath, "mode"}. The
// binary must call Stage first in main, which handles the mode's marker or
// returns false so main can. On Linux it is a constant, the copy Command
// binds in at /dev/sandbox-stage, so it holds on any host. Elsewhere it is
// a variable set at start-up, since the path is the executable's real one.
const SelfPath = stagePath

// scratchDirs are the covered paths that get a writable tmpfs of the
// sandbox's own rather than an empty, read-only one: temporary files and
// shared memory.
var scratchDirs = []string{"/tmp", "/var/tmp", "/dev/shm"}

// scratchSize is the most each of scratchDirs holds unless Spec.ScratchSize
// says otherwise. A tmpfs is otherwise as large as the host's memory, so one
// sandbox could fill it, and only a delegated cgroup's memory limit would
// stop it.
const scratchSize = 1 << 30

// newLaunch builds bubblewrap's options for spec. Each bind source is opened
// here without following links and passed as a descriptor, so nothing
// changed between prepare and bubblewrap's setup can redirect it. Mounts go
// parent first, since bubblewrap makes them in the order given.
//
// stageFiles are the descriptors the stages are passed, from fdInfo up, in
// the order stage_linux.go numbers them. The launch owns them, and closes
// them once bubblewrap has them.
func newLaunch(spec Spec, acct account, stageFiles []*os.File) (*launch, error) {
	l := &launch{}
	ok := false
	defer func() {
		if !ok {
			l.close()
		}
	}()
	argsPipe, argsFd, err := l.pipe()
	if err != nil {
		return nil, err
	}
	if argsFd != strconv.Itoa(fdArgs) {
		return nil, fmt.Errorf("bubblewrap's options are on descriptor %s, not %d", argsFd, fdArgs)
	}
	for i, f := range stageFiles {
		if fd := l.fd(f); fd != strconv.Itoa(fdInfo+i) {
			return nil, fmt.Errorf("stage descriptor %d is numbered %s", fdInfo+i, fd)
		}
	}
	hostname := spec.Hostname
	if hostname == "" {
		hostname = "sandbox"
	}
	args := []string{
		"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
		"--hostname", hostname,
		"--info-fd", strconv.Itoa(fdInfo),
		// The first stage is pid 1 and the reaper, so bubblewrap's own
		// does not stay in the mount namespace the stage leaves.
		"--as-pid-1",
		// For the first stage alone, which drops them before the command.
		"--cap-add", "CAP_SYS_ADMIN", "--cap-add", "CAP_SETPCAP",
		"--ro-bind", "/", "/",
	}
	// The caller's session by default: a caller may check that a bridge is
	// in the session of the command's starter, and the filter refuses
	// TIOCSTI, which a new session would otherwise guard against. With
	// OwnSession, bubblewrap calls setsid in the namespace's first process,
	// which --as-pid-1 makes the first stage, so pid 1 leads the session
	// (TestEscapeOwnSession). It is not a process group leader, since Start
	// puts bubblewrap in a group of its own, so the call can't fail with
	// EPERM.
	if spec.OwnSession {
		args = append(args, "--new-session")
	}
	if spec.Network == NetworkNone {
		// A network namespace with only a loopback, and abstract sockets
		// of its own.
		args = append(args, "--unshare-net")
	}
	var ops []mountOp
	var readOnly []string
	for _, c := range spec.Cover {
		if slices.Contains(scratchDirs, c) {
			continue
		}
		fi, err := os.Lstat(c)
		if err != nil {
			return nil, fmt.Errorf("cover %s: %w", c, err)
		}
		// A directory gets an empty tmpfs. Anything else, a socket or a
		// pipe as much as a file, gets /dev/null, which nothing can connect
		// to or read anything from. A link here was made since prepare
		// resolved the path, and bubblewrap would follow it.
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			return nil, fmt.Errorf("cover %s: it has become a link since it was resolved", c)
		case fi.IsDir():
			ops = append(ops, mountOp{c, coverMount, []string{"--perms", "0755", "--tmpfs", c}})
			readOnly = append(readOnly, c)
		default:
			ops = append(ops, mountOp{c, coverMount, []string{"--ro-bind", "/dev/null", c}})
		}
	}
	size := spec.ScratchSize
	if size == 0 {
		size = scratchSize
	}
	for _, d := range scratchDirs {
		if fi, err := os.Stat(filepath.Dir(d)); err == nil && fi.IsDir() {
			ops = append(ops, mountOp{d, scratchMount, []string{"--perms", "01777", "--size", strconv.FormatInt(size, 10), "--tmpfs", d}})
		}
	}
	self, err := unix.Open("/proc/self/exe", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open this binary for the first stage: %w", err)
	}
	ops = append(ops,
		mountOp{"/proc", bindMount, []string{"--proc", "/proc"}},
		mountOp{"/dev", bindMount, []string{"--dev", "/dev"}},
		mountOp{stagePath, bindMount, []string{"--ro-bind-fd", l.fd(os.NewFile(uintptr(self), "sandbox")), stagePath}},
	)
	for _, b := range []struct {
		paths []string
		flag  string
	}{
		{append([]string{spec.Home}, spec.Write...), "--bind-fd"},
		{spec.Read, "--ro-bind-fd"},
	} {
		for _, p := range b.paths {
			f, err := openNoLinks(p)
			if err != nil {
				return nil, err
			}
			ops = append(ops, mountOp{p, bindMount, []string{b.flag, l.fd(f), p}})
		}
	}
	slices.SortStableFunc(ops, func(a, b mountOp) int {
		if d := strings.Count(a.path, "/") - strings.Count(b.path, "/"); d != 0 {
			return d
		}
		return a.kind - b.kind
	})
	for _, op := range ops {
		args = append(args, op.args...)
	}

	// Only the sandbox's uid and gid are mapped, so the host's entries for
	// anyone else would show ids that do not exist inside, and programs
	// that look themselves up fail without an entry.
	uid, gid := os.Getuid(), os.Getgid()
	for _, f := range []struct{ path, body string }{
		{"/etc/passwd", fmt.Sprintf("%s:x:%d:%d::%s:/bin/sh\n", acct.user, uid, gid, spec.Home)},
		{"/etc/group", fmt.Sprintf("%s:x:%d:\n", acct.group, gid)},
	} {
		fd, err := l.data([]byte(f.body))
		if err != nil {
			return nil, err
		}
		args = append(args, "--perms", "0444", "--ro-bind-data", fd, f.path)
	}
	// /dev is a tmpfs bubblewrap makes with no size limit, which a sandbox
	// could fill past ScratchSize. Nothing in it is meant to be written but
	// /dev/shm and /dev/pts, which are mounts of their own, and the device
	// nodes, which the remount leaves alone.
	readOnly = append(readOnly, "/dev")
	for _, c := range readOnly {
		args = append(args, "--remount-ro", c)
	}
	args = append(args, "--chdir", spec.Dir)

	var body []byte
	for _, a := range args {
		body = append(append(body, a...), 0)
	}
	l.writes[argsPipe].body = body
	ok = true
	return l, nil
}

// openNoLinks opens path, which prepare resolved, for bubblewrap to bind
// from, refusing a link anywhere in it. A link found here was put there
// since prepare looked, and following it could bind the caller's data in the
// place of what was meant.
func openNoLinks(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("open %s without following links: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

// fd adds f to bubblewrap's descriptors and returns the number it will have
// there.
func (l *launch) fd(f *os.File) string {
	l.inherit = append(l.inherit, f)
	return strconv.Itoa(2 + len(l.inherit))
}

// pipe adds a pipe for bubblewrap to read, and returns its index in writes
// and the number of its descriptor in bubblewrap.
func (l *launch) pipe() (int, string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return 0, "", fmt.Errorf("make pipe for bubblewrap: %w", err)
	}
	fd := l.fd(r)
	l.writes = append(l.writes, pendingWrite{w: w})
	return len(l.writes) - 1, fd, nil
}

// data adds a pipe that will carry body, and returns its descriptor's
// number in bubblewrap.
func (l *launch) data(body []byte) (string, error) {
	i, fd, err := l.pipe()
	if err != nil {
		return "", err
	}
	l.writes[i].body = body
	return fd, nil
}

// send closes this process's copies of bubblewrap's descriptors, which
// bubblewrap now holds, and fills each pipe in the background, since
// bubblewrap reads them in turn. It sends the result on the channel when
// all are done.
func (l *launch) send() <-chan error {
	var errs []error
	for _, f := range l.inherit {
		errs = append(errs, f.Close())
	}
	l.inherit = nil
	writes := l.writes
	l.writes = nil
	done := make(chan error, 1)
	go func() {
		for _, pw := range writes {
			_, err := pw.w.Write(pw.body)
			errs = append(errs, err, pw.w.Close())
		}
		done <- errors.Join(errs...)
	}()
	return done
}

// close closes every descriptor the launch still holds.
func (l *launch) close() {
	for _, f := range l.inherit {
		_ = f.Close()
	}
	for _, pw := range l.writes {
		_ = pw.w.Close()
	}
	l.inherit, l.writes = nil, nil
}

// account is the user and group name the sandbox's passwd and group give
// its uid and gid.
type account struct {
	user, group string
}

// lookupAccount finds this process's user and group names in the host's
// files.
func lookupAccount() account {
	acct := account{user: "sandbox", group: "sandbox"}
	if u, err := user.LookupId(strconv.Itoa(os.Getuid())); err == nil {
		acct.user = u.Username
	}
	if g, err := user.LookupGroupId(strconv.Itoa(os.Getgid())); err == nil {
		acct.group = g.Name
	}
	return acct
}

// commandEnv returns env with the sandbox's home and its own temporary
// directory in the variables programs read them from. XDG_RUNTIME_DIR is
// the private /tmp too, since the host's /run/user/<uid> is covered, and a
// program that was given the caller's would look for it there.
func commandEnv(env []string, spec Spec) []string {
	set := map[string]string{
		"HOME":            spec.Home,
		"TMPDIR":          "/tmp",
		"XDG_RUNTIME_DIR": "/tmp",
		"XDG_CONFIG_HOME": filepath.Join(spec.Home, ".config"),
		"XDG_CACHE_HOME":  filepath.Join(spec.Home, ".cache"),
		"XDG_DATA_HOME":   filepath.Join(spec.Home, ".local", "share"),
		"XDG_STATE_HOME":  filepath.Join(spec.Home, ".local", "state"),
	}
	out := slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		_, ok := set[name]
		return ok
	})
	for name, value := range set {
		out = append(out, name+"="+value)
	}
	return out
}
