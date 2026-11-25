package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func registerOwnSession() {
	escChecks["session-tree"] = escSessionTree
	escChecks["join-group"] = func(_ *escT, a []string) {
		g, _ := strconv.Atoi(a[0])
		fmt.Println(unix.Setpgid(0, g))
	}
	childModes["esc-tty"] = escTTYMode
}

// escSessionTree starts a child that starts a grandchild, a child in a process
// group of its own, and a child that calls setsid, whose pid it writes to
// args[0]/setsid. If args[1] is a process group other than 0, a child tries to
// join it with setpgid, and what that returned goes to args[0]/join. It writes
// args[0]/ready once all that is done, and waits.
func escSessionTree(e *escT, args []string) {
	dir := args[0]
	start := func(attr *syscall.SysProcAttr, a ...string) *exec.Cmd {
		cmd := exec.CommandContext(context.Background(), a[0], a[1:]...) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		cmd.SysProcAttr = attr
		if err := cmd.Start(); err != nil {
			e.failf("start %v: %v", a, err)
			return nil
		}
		return cmd
	}
	start(nil, "/bin/sh", "-c", "/bin/sleep 600 & wait")
	start(&syscall.SysProcAttr{Setpgid: true}, self1(), "esc", "hold")
	s := start(&syscall.SysProcAttr{Setsid: true}, self1(), "esc", "hold")
	if s == nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "setsid"), []byte(strconv.Itoa(s.Process.Pid)), 0o600) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
	if args[1] != "0" {
		out, err := exec.CommandContext(context.Background(), self1(), "esc", "join-group", args[1]).Output() //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		if err != nil {
			e.failf("join-group: %v", err)
		}
		_ = os.WriteFile(filepath.Join(dir, "join"), out, 0o600) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
	}
	_ = os.WriteFile(filepath.Join(dir, "ready"), []byte("1"), 0o600) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
	time.Sleep(time.Minute)
}

// sessionBox is a sandbox the session tests started, and its home.
type sessionBox struct {
	c    *Cmd
	home string
}

// startSessionTree starts escSessionTree in a sandbox from spec, with join as
// the group to try to join, and waits until it is ready and every process it
// starts runs.
func startSessionTree(ctx context.Context, t *testing.T, spec Spec, join int) sessionBox {
	t.Helper()
	home := realTemp(t)
	spec.Home = home
	c := escCmd(ctx, t, spec, "session-tree", home, strconv.Itoa(join))
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c)
	readPid(t, filepath.Join(home, "ready"))
	// The command, sh, sleep and the two holds.
	eventually(t, 10*time.Second, "the sandbox's processes did not all start", func() bool {
		pids, err := c.run.mark.processes()
		return err == nil && len(pids) >= 5
	})
	return sessionBox{c, home}
}

// sessions returns the session of each process under b's profile but the one
// that called setsid, which it returns apart.
func (b sessionBox) sessions(t *testing.T) (sids map[int]int, setsidPid, setsidSid int) {
	t.Helper()
	pids, err := b.c.run.mark.processes()
	if err != nil {
		t.Fatal(err)
	}
	setsidPid = readPid(t, filepath.Join(b.home, "setsid"))
	sids = map[int]int{}
	for _, p := range pids {
		sid, err := unix.Getsid(p)
		if err != nil {
			continue
		}
		if p == setsidPid {
			setsidSid = sid
			continue
		}
		sids[p] = sid
	}
	return sids, setsidPid, setsidSid
}

// Row: "The sandbox's pid", with OwnSession: every process of a sandbox, in
// whichever process group, is in the session the stage leads, which Pid names,
// and two sandboxes are in two sessions, neither the caller's. A process that
// calls setsid leaves it for a session of its own, which a caller that checks
// the session refuses. One sandbox can't join another's process group, which
// is in another session.
func TestEscapeOwnSession(t *testing.T) {
	t.Parallel()
	caller, _ := unix.Getsid(0)
	a := startSessionTree(t.Context(), t, Spec{OwnSession: true}, 0)
	b := startSessionTree(t.Context(), t, Spec{OwnSession: true}, a.c.run.group)
	for _, box := range []sessionBox{a, b} {
		leader := box.c.Pid()
		if sid, _ := unix.Getsid(leader); sid != leader {
			t.Errorf("the stage %d is in session %d, not one it leads", leader, sid)
		}
		if leader == caller {
			t.Errorf("the stage %d leads the caller's session", leader)
		}
		sids, setsidPid, setsidSid := box.sessions(t)
		for p, sid := range sids {
			if sid != leader {
				t.Errorf("process %d is in session %d, not the stage's %d (the caller's is %d)", p, sid, leader, caller)
			}
		}
		if setsidSid != setsidPid {
			t.Errorf("the process that called setsid is in session %d, not its own", setsidSid)
		}
	}
	if a.c.Pid() == b.c.Pid() {
		t.Error("two sandboxes share a session")
	}
	join, err := readFile(filepath.Join(b.home, "join"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(join)); got != unix.EPERM.Error() {
		t.Errorf("setpgid into the other sandbox's group returned %q, want %q", got, unix.EPERM.Error())
	}
}

// Row: "Signals and priority": without OwnSession, every process of the
// sandbox stays in the caller's session, in process groups that aren't the
// caller's.
func TestEscapeSessionKept(t *testing.T) {
	t.Parallel()
	caller, _ := unix.Getsid(0)
	box := startSessionTree(t.Context(), t, Spec{}, 0)
	if sid, _ := unix.Getsid(box.c.Pid()); sid != caller {
		t.Errorf("the stage is in session %d, the caller's is %d", sid, caller)
	}
	sids, _, _ := box.sessions(t)
	for p, sid := range sids {
		if sid != caller {
			t.Errorf("process %d is in session %d, the caller's is %d", p, sid, caller)
		}
		if g, _ := unix.Getpgid(p); g == unix.Getpgrp() {
			t.Errorf("process %d is in the caller's process group %d", p, g)
		}
	}
}

// escTTYMode is a process whose controlling terminal is its standard input, as
// a shell's job's is. It starts the Spec in args[0] on that terminal, and says
// whether it holds the terminal's foreground while the sandbox runs and after.
func escTTYMode(args []string) int {
	var spec Spec
	if err := json.Unmarshal([]byte(args[0]), &spec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c, err := Command(context.Background(), spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c.Env = []string{shellPath}
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// The command reads a line, which the test types once it sees this.
	time.Sleep(300 * time.Millisecond)
	fg, _ := unix.IoctlGetInt(0, unix.TIOCGPGRP)
	fmt.Println("caller-foreground", fg == unix.Getpgrp())
	if err := c.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fg, _ = unix.IoctlGetInt(0, unix.TIOCGPGRP)
	fmt.Println("caller-foreground-again", fg == unix.Getpgrp())
	return 0
}

// Row: "Terminal", with OwnSession: the session has no controlling terminal,
// so the stage gives the command no foreground, and the caller keeps it. The
// command still reads the terminal on its standard input, since job control
// stops only a process that reads its own controlling terminal from the
// background.
func TestOwnSessionTerminal(t *testing.T) {
	t.Parallel()
	master, slaveName := openPty(t)
	slave, err := openFileFlags(slaveName, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	home := realTemp(t)
	body := jsonArg(t, Spec{Home: home, OwnSession: true, Command: []string{"/bin/sh", "-c", `read line; printf 'got %s\n' "$line"`}})
	cmd := exec.CommandContext(t.Context(), self(t), "esc-tty", body) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	cmd.Dir = home
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	go func() { _, _ = io.Copy(&out, master) }()
	text := func() string { out.mu.Lock(); defer out.mu.Unlock(); return out.buf.String() }
	eventually(t, 10*time.Second, "the caller never said whose the foreground is\n", func() bool {
		return strings.Contains(text(), "caller-foreground ")
	})
	_, _ = master.WriteString("typed-line\n")
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("esc-tty: %v\n%s", err, text())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("the command did not read the line: it was stopped, or never got it\n%s", text())
	}
	_ = master.Close()
	for _, want := range []string{"caller-foreground true", "got typed-line", "caller-foreground-again true"} {
		if !strings.Contains(text(), want) {
			t.Errorf("output lacks %q:\n%s", want, text())
		}
	}
}
