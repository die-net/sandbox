package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// stageArg is the first argument of the run of this binary that Start makes
// ahead of the command, followed by "--" and the command. The stage runs
// outside the profile, as the caller, and supervises: it sets the limits,
// starts /usr/bin/sandbox-exec with the profile on a pipe, and ends every
// process under the profile when the command or the caller does.
const stageArg = "--sandbox-stage"

// failed is the exit status of a stage that could not set up, as distinct from
// the command's own.
const failed = 125

// sandboxExec is the one program that applies a profile without cgo. It is
// named by its path and never found on PATH, so nothing the caller's
// environment holds can stand in for it.
const sandboxExec = "/usr/bin/sandbox-exec"

// The descriptors the stage is started with, which Start numbers by the order
// of its ExtraFiles.
const (
	fdLifeline = 3 // the read end of the pipe the caller holds the write end of
	fdSettings = 4 // the settings, as JSON, then end of file
	fdStatus   = 5 // the stage's one reply, then end of file
	fdFiles    = 6 // Spec.Files, which the command gets as 3 and up
)

// stageSettings is what the caller sends the stage on its settings pipe.
type stageSettings struct {
	Profile string `json:"profile"`
	// Marker is the pair of names the profile carries, by which the stage finds
	// every process under it, wherever it has gone.
	Marker  marker       `json:"marker"`
	Files   int          `json:"files"`
	Rlimits []stageLimit `json:"rlimits,omitempty"`
}

// stageLimit is a macOS resource limit.
type stageLimit struct {
	Resource int    `json:"resource"`
	Soft     uint64 `json:"soft"`
	Hard     uint64 `json:"hard"`
}

// stageReply is the stage's first message back, once the command has been
// started or the setup has failed. Group is the command's process group,
// which the caller's Footprint and a stage that was killed need, as the
// processes that never left it.
type stageReply struct {
	// Kind is kindReply. The stage sends two messages on one pipe, and the
	// lifeline's watcher can send the last before the main goroutine has sent the
	// first, so each says what it is and a reader rejects the wrong one.
	Kind  string `json:"kind"`
	Error string `json:"error,omitempty"`
	Group int    `json:"group,omitempty"`
}

// The kinds of message the stage sends.
const (
	kindReply = "reply"
	kindDone  = "done"
)

// readReply reads the stage's first message, and refuses any other kind.
func readReply(dec *json.Decoder) (stageReply, error) {
	var r stageReply
	if err := dec.Decode(&r); err != nil {
		return stageReply{}, err
	}
	if r.Kind != kindReply {
		return stageReply{}, fmt.Errorf("the stage's first message is a %q, not a reply", r.Kind)
	}
	return r, nil
}

// readDone reads the stage's last message, and refuses any other kind.
func readDone(dec *json.Decoder) (stageDone, error) {
	var d stageDone
	if err := dec.Decode(&d); err != nil {
		return stageDone{}, err
	}
	if d.Kind != kindDone {
		return stageDone{}, fmt.Errorf("the stage's last message is a %q, not a report", d.Kind)
	}
	return d, nil
}

// stageDone is the stage's last message, sent after its teardown and before it
// exits. Empty says that a scan proved the sandbox empty (scan_darwin.go), so
// that the caller's Wait need not scan again. Members says the stage gave up
// because scan after scan found members of the sandbox again after signaling
// the ones before, which is a process forking against the teardown, so that
// Wait does not spend another budget on it and returns ErrSurvivors. The caller
// takes the stage's word for either: the stage runs outside the profile, and a
// command in the sandbox cannot signal it, since the profile allows signals
// only within the sandbox, nor reach its status pipe, which nothing in the
// sandbox is given. Neither can make Wait return nil unless a scan proved the
// sandbox empty. A stage that was killed, or that ran out of its budget on
// processes it could not account for, says neither, and the caller scans
// itself. Scans is how many scans the teardown made, for tests and diagnosis.
type stageDone struct {
	Kind    string `json:"kind"`
	Empty   bool   `json:"empty,omitempty"`
	Members bool   `json:"members,omitempty"`
	Scans   int    `json:"scans,omitempty"`
}

// Stage runs the sandbox's stage if this process was started as it, and
// reports false otherwise. A program that uses this package calls it first in
// main, before it reads its arguments.
func Stage() (int, bool) {
	return runStage(stageOptions{})
}

// stageOptions changes what a stage does, for a test binary. A test binary is
// its own stage, so only its TestMain can configure the stage, and it calls
// runStage with the options. Stage passes the zero value, which is what a
// program runs, and nothing a caller sends the stage can set these.
type stageOptions struct {
	// beforeReply, if set, is called once sandbox-exec has started and before the
	// stage replies, so that a test can end the stage there.
	beforeReply func()
	// proberHook, if set, changes the prober of the stage's teardowns, to make one
	// that cannot prove the sandbox empty without a process that keeps ahead of
	// it. The stage has no Cmd to carry a hook (see run.proberHook).
	proberHook func(*prober)
	// budget is how long the stage's teardowns keep scanning. Zero is
	// teardownBudget.
	budget time.Duration
	// fdDir, if set, is the directory markCloseOnExec lists the stage's
	// descriptors from in place of /dev/fd, so that a test can make the listing
	// fail.
	fdDir string
}

// killAll ends the command's group and every other process under the
// sandbox's profile, whatever its group or parent. The group goes first, which
// is quick and holds what never left it, and the marker finds the rest. It
// returns how many scans that took, and how the teardown ended.
func (o stageOptions) killAll(group int, m marker) (scans int, end endKind) {
	killGroup(group)
	p := m.prober(group)
	if o.proberHook != nil {
		o.proberHook(&p)
	}
	budget := o.budget
	if budget == 0 {
		budget = teardownBudget
	}
	return p.run(budget)
}

// runStage is Stage with options.
func runStage(opts stageOptions) (int, bool) {
	// The check child is started with checkArg, and runs the checks and
	// nothing else.
	if len(os.Args) > 1 && os.Args[1] == checkArg {
		return checkStage(), true
	}
	if len(os.Args) < 4 || os.Args[1] != stageArg || os.Args[2] != "--" {
		return 0, false
	}
	code, err := supervise(os.Args[3:], opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: %v\n", err)
		return failed, true
	}
	return code, true
}

// supervise runs outside the profile and does what the command's start and
// end need of a process that holds more than the command may: it takes the
// caller's settings, sets the limits, and starts the command in a process
// group of its own under sandbox-exec, with the profile on a pipe so that no
// command line names it. It then relays SIGTERM and SIGHUP, and ends the
// command's group, and every process that left it with setpgid or a shell's
// job control or lost its parent, with SIGKILL, when the command exits or when
// the lifeline reaches EOF, which is when the caller has gone, however it
// went. Those are found by the profile's marker (member_darwin.go), until a
// scan proves none is left (scan_darwin.go). It then tells the caller whether
// it did (stageDone), and exits with the command's status.
func supervise(command []string, opts stageOptions) (int, error) {
	var st stageState
	// Watch from the first moment, so a caller that died during setup leaves
	// no command running. The lock is held from before the command starts
	// until its group is known, so either this ends the process before the
	// command exists, or it ends the command's group.
	go func() {
		var b [1]byte
		for {
			if _, err := unix.Read(fdLifeline, b[:]); !errors.Is(err, unix.EINTR) {
				break
			}
		}
		if st.lifelineClosed(opts.killAll) {
			os.Exit(128 + int(unix.SIGKILL)) //nolint:revive // deep-exit: the stage must end from this goroutine once the lifeline closes, and nothing above it could take an exit status.
		}
	}()
	// Without the lifeline the watcher's first read fails and ends the
	// process, racing the clean error below. Fail here instead.
	for _, fd := range []int{fdLifeline, fdSettings, fdStatus} {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			return 0, fmt.Errorf("descriptor %d is not open: %w", fd, err)
		}
	}
	var settings stageSettings
	if err := json.NewDecoder(os.NewFile(fdSettings, "settings")).Decode(&settings); err != nil {
		return 0, fmt.Errorf("read the settings: %w", err)
	}
	st.status = os.NewFile(fdStatus, "status")
	if err := settings.check(); err != nil {
		_ = json.NewEncoder(st.status).Encode(stageReply{Kind: kindReply, Error: err.Error()})
		_ = st.status.Close()
		return 0, err
	}
	st.mark = settings.Marker
	child, send, err := startCommand(settings, command, opts, &st.mu, &st.group)
	if err != nil {
		_ = json.NewEncoder(st.status).Encode(stageReply{Kind: kindReply, Error: err.Error()})
		_ = st.status.Close()
		return 0, err
	}
	if opts.beforeReply != nil {
		opts.beforeReply()
	}
	// The pipe stays open for the last message.
	st.mu.Lock()
	replied := json.NewEncoder(st.status).Encode(stageReply{Kind: kindReply, Group: st.group}) == nil
	st.mu.Unlock()
	// Only now, with the caller holding the pid, does sandbox-exec get its
	// profile, and so a command to run. A caller that could not be told has gone,
	// and the lifeline ends the command's group.
	if replied {
		go send()
	}
	stop := relayToChild(child)
	defer stop()
	var ws unix.WaitStatus
	for {
		_, err := unix.Wait4(child.Pid, &ws, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("wait: %w", err)
		}
		break
	}
	// The command is reaped, so its pid is no one's yet. A signal relayed now
	// would go to the number, and the teardown below can take seconds.
	stop()
	st.mu.Lock()
	st.finish(opts.killAll(st.group, st.mark))
	st.mu.Unlock()
	giveBackTerminal(st.group)
	if ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return ws.ExitStatus(), nil
}

// stageState is what the stage's main path and its lifeline watcher share.
type stageState struct {
	// mu is held from before the command starts until group is set, and while a
	// teardown runs, so that only one of the two ends the sandbox.
	mu sync.Mutex
	// group is the command's process group, which is 0 until it is started.
	group int
	mark  marker
	// status is the pipe to the caller. finish sends the last message on it.
	status *os.File
	// finished is whether finish has run.
	finished bool
}

// finish sends the caller the stage's last message, once, and closes the pipe.
// mu is held.
func (s *stageState) finish(scans int, end endKind) {
	if s.finished {
		return
	}
	s.finished = true
	_ = json.NewEncoder(s.status).Encode(stageDone{Kind: kindDone, Empty: end == endEmpty, Members: end == endMembers, Scans: scans})
	_ = s.status.Close()
}

// lifelineClosed is what the stage does when the lifeline reaches EOF, which
// is when the caller has closed it or gone. It ends the command's group and the
// sandbox with end, if the command has started, and reports that the stage
// should now exit at once with the status of a killed one. It holds mu then, so
// that the main path cannot go on and take the command's status over this one.
//
// If the main path has already ended the sandbox, which it did if it finished
// before the lifeline closed or while this waited for mu, there is nothing left
// to end, and the command has been reaped: a second kill of its group's number
// would go to a number that is no one's, or someone else's. This returns false
// with mu released, and the main path exits with the command's status.
func (s *stageState) lifelineClosed(end func(group int, m marker) (int, endKind)) (exit bool) {
	s.mu.Lock()
	if s.finished {
		s.mu.Unlock()
		return false
	}
	if s.group != 0 {
		s.finish(end(s.group, s.mark))
	}
	return true
}

// check refuses settings that would leave the stage unable to find the
// sandbox's processes. A marker with no names matches nothing, so a teardown
// would take every pid for a process outside the sandbox and report the
// sandbox empty without looking.
func (s stageSettings) check() error {
	if s.Marker.In == "" || s.Marker.Out == "" {
		return errors.New("the settings carry no marker, so the sandbox's processes could not be found")
	}
	return nil
}

// startCommand sets the limits and starts sandbox-exec, which applies the
// profile and runs the command. It holds mu until the command's group is
// recorded in group.
//
// It does not give sandbox-exec the profile: sandbox-exec waits for it on its
// pipe, and send writes it, which the caller of startCommand does once the
// caller of the stage has the reply. A stage that is killed before then leaves
// a sandbox-exec, or the child that is to become one, with no profile, and
// that one reads an empty one and refuses it (sandbox-exec exits with status
// 65, "no version specified") without running the command. Written before the
// start, as it was, a profile was in the pipe whole already, and the child of a
// stage killed after the fork and before the exec went on to apply it and run
// the command, which the caller, with no reply, had no pid to look for
// (docs/findings.md).
func startCommand(s stageSettings, command []string, opts stageOptions, mu *sync.Mutex, group *int) (p *os.Process, send func(), err error) {
	// The command is looked up on the PATH the stage was given, which is the
	// command's, from the working directory the command starts in.
	path, err := exec.LookPath(command[0])
	if err != nil {
		return nil, nil, err
	}
	command = append([]string{path}, command[1:]...)
	// The limits go before the command starts, and apply to the stage too,
	// as they do to pid 1 on Linux. Go's syscall package is used because
	// x/sys' Setrlimit leaves the original NOFILE limit that os/exec restores
	// for the child.
	for _, r := range s.Rlimits {
		if err := syscall.Setrlimit(r.Resource, &syscall.Rlimit{Cur: r.Soft, Max: r.Hard}); err != nil {
			return nil, nil, fmt.Errorf("set limit %d: %w", r.Resource, err)
		}
	}
	// Every inherited descriptor but the command's own is marked close-on-exec,
	// and none is closed by number: once the Go runtime is up, a number may be
	// one of its own. A stage that can't mark them starts nothing, since the
	// command would inherit the stage's.
	if err := opts.markCloseOnExec(); err != nil {
		return nil, nil, err
	}
	// Stdin, stdout and stderr, then the caller's files, then the profile.
	files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	for i := range s.Files {
		files = append(files, os.NewFile(uintptr(fdFiles+i), "file"))
	}
	profR, profW, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("make the profile pipe: %w", err)
	}
	defer profR.Close()
	profFd := len(files)
	files = append(files, profR)
	args := make([]string, 0, 4+len(command))
	args = append(args, "sandbox-exec", "-f", "/dev/fd/"+strconv.Itoa(profFd), "--")
	args = append(args, command...)
	attr := &os.ProcAttr{
		Env:   os.Environ(),
		Files: files,
		Sys:   &syscall.SysProcAttr{Setpgid: true},
	}
	// A background group is stopped when it reads the caller's terminal, so a
	// command on a terminal the caller is the foreground of gets the
	// foreground until it ends.
	if foregroundOf(os.Stdin) {
		attr.Sys.Foreground, attr.Sys.Ctty = true, 0
		takenTerminal = true
	}
	mu.Lock()
	defer mu.Unlock()
	p, err = os.StartProcess(sandboxExec, args, attr) //nolint:gosec // G702: sandboxExec is a constant path, and running the configured command under it is the library's job.
	runtime.KeepAlive(files)
	if err != nil {
		_ = profW.Close()
		return nil, nil, fmt.Errorf("start %s: %w", sandboxExec, err)
	}
	// The caller's files are the command's now, and the profile's pipe too.
	for _, f := range files[3:profFd] {
		_ = f.Close()
	}
	*group = p.Pid
	// sandbox-exec reads the whole profile before it starts anything, so this
	// is written in the background, in case it is larger than the pipe.
	return p, func() {
		_, _ = profW.WriteString(s.Profile)
		_ = profW.Close()
	}, nil
}

// markCloseOnExec sets close-on-exec on every open descriptor from 3 up,
// including the ones the command is given, which os.StartProcess maps to
// their places in it and which lose the flag there. /dev/fd lists them. It
// fails if it can't list them, since it can't tell which it missed.
func (o stageOptions) markCloseOnExec() error {
	dir := o.fdDir
	if dir == "" {
		dir = "/dev/fd"
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("mark descriptors close-on-exec: %w", err)
	}
	for _, e := range ents {
		if fd, err := strconv.Atoi(e.Name()); err == nil && fd >= 3 {
			unix.CloseOnExec(fd)
		}
	}
	return nil
}

// killGroup ends every process in the group, and keeps going until none is
// left, since a process that forks while the signal is sent can leave a
// child that missed it.
//
// It signals a number, and after the command is reaped the group's number can
// belong to no one, and then to someone else. That needs forkproc
// (bsd/kern/kern_fork.c) to give it out again within the milliseconds of this
// loop. It hands out pids in sequence from the last one, up to 99999, and
// skips any that is in use as a pid, a group or a session, so the counter would
// have to wrap onto this number in that time. The race is not worth a fix that
// costs a process lookup.
func killGroup(group int) {
	for range 100 {
		if err := syscall.Kill(-group, syscall.SIGKILL); err != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// relayToChild passes the signals a supervisor is sent on to the command,
// and returns a function that stops. A Ctrl-C at a terminal reaches the
// command's own group when it holds the foreground, and the stage's
// otherwise, where it is relayed.
func relayToChild(p *os.Process) func() {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGHUP, unix.SIGINT)
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
	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(sigs)
			close(done)
		})
	}
}

// takenTerminal is whether the command was given the terminal's foreground.
var takenTerminal bool

// foregroundOf reports whether f is a terminal whose foreground process group
// is this process's own, which the command's group may take over.
func foregroundOf(f *os.File) bool {
	pgrp, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGPGRP)
	return err == nil && pgrp == unix.Getpgrp()
}

// giveBackTerminal makes the stage's own process group the foreground one
// again, if the command's group still is. Setting the foreground from a
// background group raises SIGTTOU, which is ignored for the call. If the user
// has moved the foreground on, to a shell after a suspend for instance, it is
// left alone.
func giveBackTerminal(group int) {
	if !takenTerminal {
		return
	}
	signal.Ignore(syscall.SIGTTOU)
	if pgrp, err := unix.IoctlGetInt(0, unix.TIOCGPGRP); err == nil && pgrp == group {
		_ = unix.IoctlSetPointerInt(0, unix.TIOCSPGRP, unix.Getpgrp())
	}
}
