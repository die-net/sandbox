package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	// group is the command's process group, which is its pid, and the one the
	// stage ends. It is set from the stage's reply.
	group int
	// mark is the pair of names that tells the sandbox's processes from
	// others, for teardown and Footprint.
	mark marker
	// status is the read end of the stage's pipe, and statusDec reads its
	// messages. The stage's first is the reply Start reads, and its last, sent
	// as it exits, says whether its teardown proved the sandbox empty.
	status    *os.File
	statusDec *json.Decoder
	// readReport makes the one read of the stage's last message, which Wait and
	// the watch of a stage that has gone both need, and report and reported are
	// what it read.
	readReport sync.Once
	report     stageDone
	reported   bool
	// stageScans is how many scans the stage's teardown made, callerScans how
	// many Wait's own have, and watchScans how many the watch of a stage that
	// has gone has, which tests read.
	stageScans  int
	callerScans atomic.Int64
	watchScans  atomic.Int64
	// lifeline is the write end of the pipe the stage watches. Only this
	// process holds it, and it is close-on-exec, so when this process goes,
	// however it goes, the stage reads EOF and ends the command's group.
	lifeline     *os.File
	closeLife    sync.Once
	sent         <-chan error
	listeners    []net.Listener
	reservedPort []net.Listener
	// keepOpen stops the close of the unstarted Cmd's sockets that ctx's end
	// would make, and reports false if that close has begun.
	keepOpen func() bool
	// budget is how long the caller's teardown keeps scanning before it gives
	// up (teardownBudget, which Command sets). A test sets it, and the fields
	// below, on its own Cmd between Command and Start, so that sandboxes that
	// run at the same time do not share a setting. They stay as they are in a
	// program.
	budget time.Duration
	// proberHook changes the prober of the caller's teardown, to give it a
	// system that a scan cannot settle, or signals that land nowhere.
	proberHook func(*prober)
	// ignoreStageReport makes Wait act as if the stage had sent no report that
	// it proved the sandbox empty.
	ignoreStageReport bool
}

// teardown ends every process under the sandbox's profile from the caller's
// side, and says how many scans it took and how it ended. It scans for
// run.budget, with the prober that run.proberHook changed.
func (c *Cmd) teardown() (scans int, end endKind) {
	p := c.run.mark.prober(c.run.group)
	if c.run.proberHook != nil {
		c.run.proberHook(&p)
	}
	return p.run(c.run.budget)
}

// resources maps each Resource to its macOS number. ResourceAddressSpace has
// none: RLIMIT_AS shares its number with RLIMIT_RSS in XNU, which nothing
// enforces, so a limit that looks set would hold nothing.
var resources = map[Resource]int{
	ResourceCPU:       unix.RLIMIT_CPU,
	ResourceFileSize:  unix.RLIMIT_FSIZE,
	ResourceCore:      unix.RLIMIT_CORE,
	ResourceOpenFiles: unix.RLIMIT_NOFILE,
	ResourceProcesses: unix.RLIMIT_NPROC,
}

// tmpName is the directory in the home that TMPDIR and XDG_RUNTIME_DIR name,
// since there is no private /tmp on macOS.
const tmpName = "tmp"

// selfPath is this binary's real path.
func selfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		return r
	}
	return exe
}

// SelfPath is the path under which a sandbox's command names this binary, for
// a command that runs it again: Spec.Command = []string{SelfPath, "mode"}. That
// run is the program's own main, with the arguments the command names, since
// the command's environment never holds roleVar. On macOS it is the binary's
// real path, found at
// start-up, which every profile lets the command read and run. It is empty if
// the path cannot be found. Callers must not change it.
var SelfPath = selfPath()

// Command returns a Cmd that will run spec's command under a Seatbelt profile
// that /usr/bin/sandbox-exec applies. It checks what needs no look at the host
// and starts nothing; Start does the rest. ctx kills the sandbox when it is
// done, once Start has been called. It binds the Listen listeners and
// reserves the Loopback ports now, so that ListenAddrs and LoopbackPorts have
// answers before Start.
//
// It refuses to run as root, as on Linux, and there is no way to ask for
// another account. It also refuses a process whose real uid differs from its
// effective uid: the command inherits both, and teardown lists the sandbox's
// processes by effective uid, so a command that set its effective uid to its
// real one would leave the list. It refuses a Service it does not know, and a resource limit
// macOS does not enforce: ResourceAddressSpace.
func Command(ctx context.Context, spec Spec) (*Cmd, error) {
	return commandAs(ctx, spec, os.Geteuid(), os.Getuid())
}

// commandAs is Command for a process whose effective uid is euid and real uid
// is ruid, which a test sets to be root, or a setuid process, without being one.
func commandAs(ctx context.Context, spec Spec, euid, ruid int) (*Cmd, error) {
	if euid == 0 {
		return nil, errors.New("the sandbox will not run as root: switch to the sandbox's own uid first")
	}
	if ruid != euid {
		// The command gets both ids, and can set its effective uid to the real
		// one. Teardown finds the sandbox's processes among those of the
		// effective uid (PROC_UID_ONLY compares the credential's uid), so the
		// command would leave the list, and a scan would be clean with it alive.
		return nil, fmt.Errorf("the sandbox will not run with real uid %d and effective uid %d: make them the same first", ruid, euid)
	}
	if err := spec.checkRequest(); err != nil {
		return nil, err
	}
	if spec.Kernel == "" {
		spec.Kernel = KernelStrict
	}
	if err := spec.Kernel.Set(string(spec.Kernel)); err != nil {
		return nil, err
	}
	for _, s := range spec.Services {
		if _, ok := serviceRules[s]; !ok {
			return nil, fmt.Errorf("unknown service %q", s)
		}
	}
	for _, r := range spec.Rlimits {
		if _, ok := resources[r.Resource]; !ok {
			return nil, fmt.Errorf("macOS does not enforce limit %d: RLIMIT_AS is the same number as RLIMIT_RSS there, which nothing enforces", int(r.Resource))
		}
	}
	spec.Command = slices.Clone(spec.Command)
	spec.Files = slices.Clone(spec.Files)
	spec.Rlimits = slices.Clone(spec.Rlimits)
	spec.Services = slices.Clone(spec.Services)
	c := &Cmd{backend: backend{ctx: ctx, spec: spec}, CgroupFD: -1}
	c.run.budget = teardownBudget
	closeAll := func() {
		for _, l := range slices.Concat(c.run.listeners, c.run.reservedPort) {
			_ = l.Close()
		}
	}
	var lc net.ListenConfig
	for range spec.Listen {
		l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("bind a listener: %w", err)
		}
		c.run.listeners = append(c.run.listeners, l)
	}
	for range spec.Loopback {
		l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("reserve a loopback port: %w", err)
		}
		c.run.reservedPort = append(c.run.reservedPort, l)
	}
	// A Cmd that is never started would hold its sockets for good, so ctx's
	// end closes them, until Start takes them over.
	c.run.keepOpen = context.AfterFunc(ctx, closeAll)
	return c, nil
}

// ListenAddrs returns the addresses of the Listen listeners, which the command
// reaches. The parent binds them on 127.0.0.1 in Command, so they are known
// before Start, and the profile lets the command connect to exactly those
// ports.
func (c *Cmd) ListenAddrs() []string {
	if len(c.run.listeners) == 0 {
		return nil
	}
	addrs := make([]string, 0, len(c.run.listeners))
	for _, l := range c.run.listeners {
		addrs = append(addrs, l.Addr().String())
	}
	return addrs
}

// LoopbackPorts returns the Loopback ports the command may bind and dial.
// macOS has no private loopback, so Command picks free ports, and the profile
// allows the command exactly those. Another process could take one between
// Start closing its reservation and the command binding it.
func (c *Cmd) LoopbackPorts() []int {
	if len(c.run.reservedPort) == 0 {
		return nil
	}
	ports := make([]int, 0, len(c.run.reservedPort))
	for _, l := range c.run.reservedPort {
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

// Listeners returns the Listen listeners, in order, once Start has returned.
// The caller serves them, and closes them when it is done.
func (c *Cmd) Listeners() []net.Listener {
	if !c.run.started || c.run.cmd == nil {
		return nil
	}
	return c.run.listeners
}

// Pid returns the pid of the stage, after Start, which is this process's own
// child and the sandbox's top process. The command is its child, in a process
// group of its own.
func (c *Cmd) Pid() int {
	if c.run.cmd == nil {
		return 0
	}
	return c.run.cmd.Process.Pid
}

// stop closes the lifeline, which makes the stage end the command's group
// with SIGKILL and exit.
func (c *Cmd) stop() {
	c.run.closeLife.Do(func() {
		if c.run.lifeline != nil {
			_ = c.run.lifeline.Close()
		}
	})
}

// checkSandboxExec reports whether path is an executable file, as the sandbox
// needs of /usr/bin/sandbox-exec. A missing file is wrapped in its error, and a
// file with no execute bit has none to wrap.
func checkSandboxExec(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("find %s, which the sandbox needs on macOS: %w", path, err)
	}
	if fi.Mode()&0o111 == 0 {
		return fmt.Errorf("%s, which the sandbox needs on macOS, is not executable", path)
	}
	return nil
}

// Start resolves the spec's paths, writes the profile, and starts the stage,
// which runs sandbox-exec. It returns once the stage has started the command,
// or has failed to, and before the command's own start, so a command that
// fails to run shows in Wait's status.
func (c *Cmd) Start() error {
	if c.run.keepOpen == nil {
		return errors.New("sandbox: the Cmd was not made by Command")
	}
	if c.run.started {
		return errors.New("sandbox: already started")
	}
	c.run.started = true
	if !c.run.keepOpen() {
		return fmt.Errorf("sandbox: %w", context.Cause(c.ctx))
	}
	spec := c.spec
	releasePorts := func() {
		for _, l := range c.run.reservedPort {
			_ = l.Close()
		}
	}
	listeners := c.run.listeners
	ok := false
	defer func() {
		if !ok {
			releasePorts()
			for _, l := range listeners {
				_ = l.Close()
			}
		}
	}()
	if err := checkSandboxExec(sandboxExec); err != nil {
		return err
	}
	self := selfPath()
	if self == "" {
		return errors.New("find this binary, which the stage runs")
	}
	h, err := currentHost()
	if err != nil {
		return err
	}
	spec, err = prepare(spec, h)
	if err != nil {
		return err
	}
	mark, err := newMarker()
	if err != nil {
		return err
	}
	in := profileInput{
		Marker: mark,
		Home:   spec.Home, Write: spec.Write, Read: spec.Read, Cover: spec.Cover,
		Self: self, Network: spec.Network, BroadLoopback: spec.BroadLoopback,
		Services: spec.Services, Loopback: c.LoopbackPorts(),
	}
	for _, l := range listeners {
		in.Listen = append(in.Listen, l.Addr().(*net.TCPAddr).Port)
	}
	for _, w := range spec.Write {
		if fi, err := os.Lstat(w); err == nil && fi.Mode()&os.ModeSocket != 0 {
			in.Sockets = append(in.Sockets, w)
		}
	}
	prof, err := profile(in)
	if err != nil {
		return err
	}
	settings := stageSettings{Command: toByteArgs(spec.Command), Profile: prof, Marker: mark, Files: len(spec.Files), Role: c.role}
	for _, r := range spec.Rlimits {
		lim, err := rlimitFor(r)
		if err != nil {
			return err
		}
		settings.Rlimits = append(settings.Rlimits, lim)
	}
	body, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	// TMPDIR is in the home, since there is no private /tmp here.
	if err := os.Mkdir(filepath.Join(spec.Home, tmpName), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("make the sandbox's temporary directory: %w", err)
	}

	// What the stage keeps is closed once it has them, and what this process
	// keeps is closed on any failure below.
	var parent, child []*os.File
	defer func() {
		for _, f := range child {
			_ = f.Close()
		}
		if !ok {
			for _, f := range parent {
				_ = f.Close()
			}
		}
	}()
	pipe := os.Pipe
	lifeR, lifeW, err := pipe()
	if err != nil {
		return err
	}
	child, parent = append(child, lifeR), append(parent, lifeW)
	setR, setW, err := pipe()
	if err != nil {
		return err
	}
	child = append(child, setR)
	statR, statW, err := pipe()
	if err != nil {
		return err
	}
	child, parent = append(child, statW), append(parent, statR)
	// The settings wait in the pipe until the stage reads them, written from
	// here in the background, since a profile may be longer than a pipe holds.
	// If the stage never starts, closing its end ends the write.
	sent := make(chan error, 1)
	go func() {
		_, err := setW.Write(body)
		sent <- errors.Join(err, setW.Close())
	}()
	extra := []*os.File{lifeR, setR, statW}
	for _, f := range spec.Files {
		d, err := dupFile(f)
		if err != nil {
			return err
		}
		child = append(child, d)
		extra = append(extra, d)
	}
	releasePorts()
	// The stage is found by roleStage in its environment, and its argv is a
	// name alone: the command goes in the settings.
	cmd := exec.CommandContext(c.ctx, self) //nolint:gosec // G204: the stage is this binary, run with no arguments.
	cmd.Args[0] = stageName
	cmd.Dir = spec.Dir
	cmd.Env = withRole(commandEnv(c.Env, spec), roleStage)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	cmd.WaitDelay = c.WaitDelay
	cmd.ExtraFiles = extra
	// With OwnSession the stage leads a session of its own, which the command
	// and everything it starts are in, unless they call setsid. The stage
	// starts sandbox-exec in a process group of its own, inside it. The
	// session has no controlling terminal, so the stage gives the command no
	// foreground (foregroundOf) and job control doesn't stop its reads.
	if spec.OwnSession {
		cmd.SysProcAttr = &unix.SysProcAttr{Setsid: true}
	}
	// Canceling ctx closes the lifeline, so that the stage ends the command's
	// whole group. A stage that has not gone a little later is killed.
	cmd.Cancel = func() error {
		c.stop()
		time.AfterFunc(5*time.Second, func() { _ = cmd.Process.Kill() })
		return nil
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the stage: %w", err)
	}
	child = nil
	for _, f := range extra {
		_ = f.Close()
	}
	c.run.lifeline = lifeW
	// From here the sandbox may be running, so a failure ends it.
	fail := func(err error) error {
		abortStart(c, cmd, mark, sent)
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("the sandbox did not start: %w", ee)
		}
		return err
	}
	dec := json.NewDecoder(io.LimitReader(statR, 1<<16))
	reply, err := readReply(dec)
	if err != nil {
		return fail(errors.New("the sandbox ended during setup"))
	}
	if reply.Error != "" {
		return fail(errors.New(reply.Error))
	}
	// The pipe stays open: the stage's last message comes on it.
	c.run.cmd, c.run.group, c.run.sent, c.run.mark = cmd, reply.Group, sent, mark
	c.run.status, c.run.statusDec = statR, dec
	ok = true
	parent = nil
	return nil
}

// abortStart ends a sandbox that Start could not finish: it closes the
// lifeline, kills the stage, and then ends whatever runs under the profile,
// since the stage may have died before it read the lifeline, with a command
// already running, and nothing else would end that. It waits for the stage and
// for the settings writer.
func abortStart(c *Cmd, cmd *exec.Cmd, mark marker, sent <-chan error) {
	c.stop()
	_ = cmd.Process.Kill()
	// The command is not known here, so a sandbox-exec of any pid may be the one
	// that has yet to apply the profile.
	mark.kill(time.Second, 0)
	_ = cmd.Wait()
	<-sent //nolint:errcheck // Start is already failing and returns its own error. This only waits for the settings writer to end.
}

// rlimitFor returns r as a macOS limit. A limit of none is the most this
// process may set: RLIM_INFINITY there is 2^63-1 and not 2^64-1, an unprivileged
// process cannot raise a hard limit, and an open-file limit above what the
// kernel allows per process is refused outright. The stage inherits this
// process's limits, so what this process holds is what it can set.
func rlimitFor(r Rlimit) (stageLimit, error) {
	res, ok := resources[r.Resource]
	if !ok {
		return stageLimit{}, fmt.Errorf("macOS does not enforce limit %d", int(r.Resource))
	}
	var cur unix.Rlimit
	if err := unix.Getrlimit(res, &cur); err != nil {
		return stageLimit{}, fmt.Errorf("read limit %d: %w", res, err)
	}
	conv := func(v uint64) uint64 {
		switch {
		case v == math.MaxUint64:
			v = cur.Max
		case v > math.MaxInt64:
			v = math.MaxInt64
		}
		if res == unix.RLIMIT_NOFILE {
			if most, err := unix.SysctlUint32("kern.maxfilesperproc"); err == nil && v > uint64(most) {
				v = uint64(most)
			}
		}
		return v
	}
	lim := stageLimit{Resource: res, Soft: conv(r.Soft), Hard: conv(r.Hard)}
	// A soft limit of none under a hard one is the hard one.
	lim.Soft = min(lim.Soft, lim.Hard)
	return lim, nil
}

// Wait waits for the sandbox to exit and returns what exec's Wait does for the
// stage, whose exit status is the command's. It closes the lifeline. If the
// stage was itself killed, it ends the sandbox, which the stage could not. The
// stage says before it exits whether a scan proved no process was left under
// the profile, and Wait takes its word. If the stage was killed or could not
// prove it, Wait scans itself after the stage has gone, until a scan does. If
// none can in the time allowed, which a process that forks again before each
// signal lands can bring about, the error matches [ErrSurvivors]
// with errors.Is, and wraps the command's own result, so errors.As still finds
// its *exec.ExitError. It also waits, as exec's Wait does, for the command's
// output streams to close, which a process left running holds open, so a
// caller that must not wait on one sets WaitDelay.
func (c *Cmd) Wait() error {
	if c.run.cmd == nil {
		return errors.New("sandbox: not started")
	}
	if c.run.waited {
		return errors.New("sandbox: Wait was already called")
	}
	c.run.waited = true
	// A stage that was killed ended nothing, and a process it left behind may
	// hold the command's output open, which keeps the wait below from
	// returning. So this ends them as soon as the stage is gone.
	stopWatch := c.watchStage()
	err := c.run.cmd.Wait()
	stopWatch()
	// The stage ends the sandbox when the command does, and says so when a scan
	// proved it empty, which nothing can undo: nothing under the profile can
	// start again. If it did not, because it was killed or could not prove it,
	// this scans, from outside the profile. Only the profile's marker names the
	// processes: the command's process group is a number that the kernel may
	// have given to someone else by now.
	switch judgeReport(c.stageReport()) {
	case reportGaveUp:
		err = &survivorsError{err}
	case reportEmpty:
	default:
		scans, end := c.teardown()
		c.run.callerScans.Add(int64(scans))
		if end != endEmpty {
			err = &survivorsError{err}
		}
	}
	c.stop()
	if serr := <-c.run.sent; serr != nil && err == nil {
		err = serr
	}
	return err
}

// reportVerdict is what Wait takes from the stage's last message.
type reportVerdict int

const (
	// reportNone is that there is no usable report, and Wait scans for itself.
	reportNone reportVerdict = iota
	// reportEmpty is that the stage proved the sandbox empty.
	reportEmpty
	// reportGaveUp is that the stage scanned until members kept turning up, and
	// gave up. Another budget would go the same way.
	reportGaveUp
)

// judgeReport says what a report that was read, or not, comes to. A report that
// says both that the sandbox is empty and that members are left is one the stage
// never sends, so it fails closed: the members come first.
func judgeReport(done stageDone, reported bool) reportVerdict {
	switch {
	case reported && done.Members:
		return reportGaveUp
	case reported && done.Empty:
		return reportEmpty
	}
	return reportNone
}

// stageReport reads the stage's last message, which is there if the stage has
// exited on its own and not been killed, and reports whether there was one. The
// stage has exited, so the pipe holds the message and then ends, unless
// something else holds its write end, so the read is bounded. It closes the
// pipe. It reads once, for whoever asks first, and gives the same answer after.
func (c *Cmd) stageReport() (done stageDone, ok bool) {
	c.run.readReport.Do(func() {
		defer c.run.status.Close()
		if c.run.ignoreStageReport {
			return
		}
		_ = c.run.status.SetReadDeadline(time.Now().Add(time.Second))
		done, err := readDone(c.run.statusDec)
		if err != nil {
			return
		}
		c.run.stageScans = done.Scans
		c.run.report, c.run.reported = done, true
	})
	return c.run.report, c.run.reported
}

// survivorsError is Wait's error when teardown could not confirm that no
// process still runs under the sandbox's profile. A process that forks again
// before each signal lands can outlast the scan, and Wait cannot say more than
// that one may be left. It wraps what Wait would have returned, so the
// command's exit status is still found with errors.As, and it matches
// ErrSurvivors with errors.Is.
type survivorsError struct{ cause error }

func (e *survivorsError) Error() string {
	msg := ErrSurvivors.Error()
	if e.cause != nil {
		msg += " (" + e.cause.Error() + ")"
	}
	return msg
}

func (e *survivorsError) Unwrap() error { return e.cause }

// Is makes the error match ErrSurvivors, which Unwrap alone would not, since
// it leads to the cause.
func (*survivorsError) Is(target error) bool { return target == ErrSurvivors }

// watchStage ends the sandbox's processes once the stage has exited, which is
// when the stage did not, as when it was killed. A stage that exited after
// reporting the sandbox empty has left nothing to end, so the watch reads that
// report and stops: scans would only race Wait, which takes the stage's word. A
// stage that reported it gave up has left members, and the watch keeps ending
// them, since one may hold the command's output open and keep Wait from
// returning. It returns a function that stops the watch.
func (c *Cmd) watchStage() func() {
	pid := c.run.cmd.Process.Pid
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
			}
			// The stage is this process's child, so it stays listed as a zombie
			// until Wait reaps it.
			if p, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err == nil && p.Proc.P_stat != stateZombie {
				continue
			}
			// The stage can be gone while Wait still reads the command's output, which
			// the stage's exit does not end for a writer that is slow, and the stage sent
			// its report before it exited. A stage that said the sandbox is empty has
			// left nothing to end, and Wait takes its word, so a scan here would only
			// race Wait. One that gave up, or sent nothing usable, has left members
			// that nothing else ends before Wait returns: Wait itself scans only after
			// the output is closed, which a member may hold open.
			if judgeReport(c.stageReport()) == reportEmpty {
				return
			}
			// Marker only: the group's number may be someone else's by now.
			// Keep at it while Wait still waits, since a survivor may hold
			// the command's output open.
			for {
				scans, end := c.teardown()
				c.run.watchScans.Add(int64(scans))
				if end == endEmpty {
					return
				}
				// Keep at it, but not flat out: a teardown that gave up on members
				// stands for a process that forks against it, and the ones that
				// ran out of time for noise.
				select {
				case <-done:
					return
				case <-time.After(50 * time.Millisecond):
				}
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

// Run runs spec's command in a sandbox, with this process's own standard
// streams and environment, and returns its exit status. A status from a
// signal is 128 plus the signal's number, as a shell reports it. It is for a
// process that does nothing else: SIGTERM and SIGHUP end the sandbox, and an
// empty Dir means the working directory. Spec's Listen is refused, since
// nothing here serves a listener. Like Wait, it returns an error that matches [ErrSurvivors] when
// teardown could not confirm the sandbox empty, with the status still returned.
func Run(ctx context.Context, spec Spec) (int, error) {
	return runAs(ctx, spec, os.Geteuid(), os.Getuid())
}

// runAs is Run for a process whose effective uid is euid and real uid is ruid,
// as commandAs is for Command.
func runAs(ctx context.Context, spec Spec, euid, ruid int) (int, error) {
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
	c, err := commandAs(ctx, spec, euid, ruid)
	if err != nil {
		return 0, err
	}
	c.Env = os.Environ()
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		return 0, err
	}
	// A SIGTERM or SIGHUP to this process ends the sandbox, whose command
	// gets no chance to save its state, as on Linux. Relaying rather than
	// dying lets Run still wait for it and return its status.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGHUP)
	defer signal.Stop(sigs)
	go func() {
		if _, ok := <-sigs; ok {
			c.stop()
		}
	}()
	err = c.Wait()
	code, serr := exitStatus(err)
	if se := new(survivorsError); serr == nil && errors.As(err, &se) {
		serr = se
	}
	return code, serr
}

// commandEnv returns env with the sandbox's home and its own temporary
// directory in the variables programs read them from. CFFIXED_USER_HOME is
// what Cocoa resolves ~/Library from, which $HOME alone does not move: without
// it a Cocoa program reaches for the real ~/Library, which the profile covers
// and TCC guards.
func commandEnv(env []string, spec Spec) []string {
	tmp := filepath.Join(spec.Home, tmpName)
	set := [][2]string{
		{"HOME", spec.Home},
		{"CFFIXED_USER_HOME", spec.Home},
		{"TMPDIR", tmp},
		{"XDG_RUNTIME_DIR", tmp},
		{"XDG_CONFIG_HOME", filepath.Join(spec.Home, ".config")},
		{"XDG_CACHE_HOME", filepath.Join(spec.Home, ".cache")},
		{"XDG_DATA_HOME", filepath.Join(spec.Home, ".local", "share")},
		{"XDG_STATE_HOME", filepath.Join(spec.Home, ".local", "state")},
	}
	out := slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.ContainsFunc(set, func(p [2]string) bool { return p[0] == name })
	})
	for _, p := range set {
		out = append(out, p[0]+"="+p[1])
	}
	return out
}
