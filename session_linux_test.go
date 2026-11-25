package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func registerOwnSession() {
	escChecks["session-tree"] = escSessionTree
	escChecks["session-child"] = func(e *escT, _ []string) {
		if startHold(e, nil) {
			time.Sleep(time.Minute)
		}
	}
}

// startHold starts this binary as `esc hold` with attr, and reports whether it
// did.
func startHold(e *escT, attr *syscall.SysProcAttr) bool {
	cmd := exec.CommandContext(context.Background(), "/proc/self/exe", "esc", "hold")
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		e.failf("start a hold: %v", err)
		return false
	}
	return true
}

// escSessionTree prints its pid namespace, starts a child that starts a
// grandchild, a child in a process group of its own, and a child that calls
// setsid, prints "ready", and waits.
func escSessionTree(e *escT, _ []string) {
	fmt.Println("ns", nsLink("self", "pid"))
	child := exec.CommandContext(context.Background(), "/proc/self/exe", "esc", "session-child")
	if err := child.Start(); err != nil {
		e.failf("start session-child: %v", err)
		return
	}
	if !startHold(e, &syscall.SysProcAttr{Setpgid: true}) || !startHold(e, &syscall.SysProcAttr{Setsid: true}) {
		return
	}
	fmt.Println("ready")
	time.Sleep(time.Minute)
}

// procSession returns the session of the host's pid.
func procSession(pid int) (int, error) {
	st, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(st[bytes.LastIndexByte(st, ')')+2:]))
	return strconv.Atoi(f[3])
}

// startSessionTree starts escSessionTree in a sandbox from spec and returns it
// and its pid namespace, once the six processes it makes all run: pid 1, the
// command, its child and grandchild, and the two that leave its group.
func startSessionTree(ctx context.Context, t *testing.T, spec Spec) (*Cmd, string) {
	t.Helper()
	c, stdout, stderr := escCmd(ctx, t, spec, "esc", "session-tree")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Wait() })
	var ns string
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if strings.Contains(stdout.String(), "ready\n") {
			ns = lineWith(stdout.String(), "ns ")
			if len(nsMembers(ns)) >= 6 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sandbox's processes did not all start: %s\n%s", stdout, stderr)
		}
	}
	return c, ns
}

// Row: "The sandbox's pid", with OwnSession: every process of a sandbox, in
// whichever process group, is in the session pid 1 leads, which Pid names, and
// two sandboxes are in two sessions, neither the caller's. A process that calls
// setsid leaves it for a session of its own, which a caller that checks the
// session refuses.
func TestEscapeOwnSession(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	caller := mySid()
	leaders := make([]int, 0, 2)
	for range 2 {
		c, ns := startSessionTree(ctx, t, Spec{OwnSession: true})
		leader := c.Pid()
		leaders = append(leaders, leader)
		if sid, _ := procSession(leader); sid != leader {
			t.Errorf("pid 1 (%d) is in session %d, not one it leads", leader, sid)
		}
		if leader == caller {
			t.Errorf("pid 1 (%d) leads the caller's session", leader)
		}
		var own int
		for _, m := range nsMembers(ns) {
			sid, err := procSession(m)
			if err != nil {
				continue
			}
			switch sid {
			case leader:
			case m:
				// The child that called setsid, which leads a session of its own.
				own++
			default:
				t.Errorf("process %d is in session %d, not pid 1's %d (the caller's is %d)", m, sid, leader, caller)
			}
		}
		if own != 1 {
			t.Errorf("%d processes lead a session of their own, want the one that called setsid", own)
		}
	}
	if leaders[0] == leaders[1] {
		t.Error("two sandboxes share a session")
	}
}

// Row: "Terminal", with OwnSession: the session has no controlling terminal,
// so the caller keeps the terminal's foreground, and the command still reads
// the terminal on its standard input without it, since job control stops only
// a process that reads its own controlling terminal from the background. It
// can't open /dev/tty.
func TestOwnSessionTerminal(t *testing.T) {
	t.Parallel()
	spec := Spec{Home: t.TempDir(), OwnSession: true, Command: []string{"/bin/sh", "-c", `read line; printf 'got %s\n' "$line"; if (: </dev/tty) 2>/dev/null; then echo dev-tty-opens; else echo dev-tty-refused; fi`}}
	out := onTerminal(t, spec)
	for _, want := range []string{"caller-foreground true", "got ping", "dev-tty-refused", "caller-foreground-again true"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: %s", want, out)
		}
	}
}
