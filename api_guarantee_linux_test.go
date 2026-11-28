package sandbox

// API guarantee tests: each exported function, method, type and field of the
// package gets a test of its documented contract, including its error paths.
// The escape tests are in escape_guarantee_linux_test.go, whose harness
// (escRun, escCmd, the "esc" child checks) these use.
//
// Not testable here: Command's refusal of euid 0 by a real root, since the
// tests run unprivileged. It is driven from a user namespace that maps the
// caller to uid 0 (TestAPIRefusesEuid0), which is what the check reads.
// Probe, Check and Report are another agent's.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func registerAPIModes() {
	childModes["esc-run"] = escRunMode
	childModes["leak"] = leakMode
	escChecks["pwd"] = func(e *escT, _ []string) { wd, err := os.Getwd(); e.is("getwd", err); fmt.Println(wd) }
	escChecks["gate-read-fds"] = func(e *escT, a []string) { _, _ = io.Copy(io.Discard, os.Stdin); readFds(e, a) }
	escChecks["dial-each"] = dialEach
	escChecks["fill-scratch"] = fillScratch
	childModes["self-hello"] = func(args []string) int { fmt.Println("hello from", strings.Join(args, " ")); return 0 }
	escChecks["hostname"] = func(*escT, []string) { h, _ := os.Hostname(); fmt.Println(h) }
}

// escRunMode runs Run on the Spec in args[0], as a process that does nothing
// else, and exits with its status, or 99 and a message for its error.
func escRunMode(args []string) int {
	var spec Spec
	if err := json.Unmarshal([]byte(args[0]), &spec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 98
	}
	code, err := Run(context.Background(), spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run error:", err)
		return 99
	}
	return code
}

// dialEach dials each address in args and tells it its index.
func dialEach(e *escT, args []string) {
	for i, a := range args {
		c, err := dialTimeout("tcp", a, 3*time.Second)
		if err != nil {
			e.failf("dial %s: %v", a, err)
			continue
		}
		if _, err := fmt.Fprintln(c, i); err != nil {
			e.failf("tell %s its index: %v", a, err)
		}
		_ = c.Close()
	}
}

// leakScenario is what a leak child runs.
type leakScenario struct {
	// Kind is "command" (Command alone), "failed-start" (a Start that must
	// fail with Want in its error), "canceled-start" (a Start after the
	// context ended) or "closed-file" (a Start with a closed file in Files).
	Kind string
	Spec Spec
	Want string
}

// leakCheck runs sc in a fresh process, and fails the test with what it says
// unless it finds no leak. A test cannot count its own process's descriptors
// and children while others run in it, since they open and close their own,
// so each count is made by a child that runs one scenario alone.
func leakCheck(t *testing.T, sc leakScenario) {
	t.Helper()
	exe, _ := escBinary(t)
	cmd := exec.CommandContext(t.Context(), exe, "leak", jsonArg(t, sc)) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("%v: %s", err, out)
	}
}

// leakMode runs the leakScenario in args[0] and exits with 0, or with 1 and
// what it found on standard error.
func leakMode(args []string) (code int) {
	var sc leakScenario
	if err := json.Unmarshal([]byte(args[0]), &sc); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
		return 1
	}
	before, fds := children(), fdCount()
	// settled waits for the processes and descriptors a failed Start left to
	// go, and reports whether they are as they were.
	settled := func() bool {
		for range 50 {
			if len(children()) == len(before) && fdCount() == fds {
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}
	home, err := os.MkdirTemp("", "sbx-leak")
	if err != nil {
		return fail("%v", err)
	}
	defer func() {
		if err := os.RemoveAll(home); err != nil && code == 0 {
			code = fail("remove %s: %v", home, err)
		}
	}()
	ctx := context.Background()
	switch sc.Kind {
	case "command":
		if _, err := Command(ctx, sc.Spec); err != nil {
			return fail("Command: %v", err)
		}
		if got := children(); !slices.Equal(got, before) {
			return fail("Command started processes: %v", got)
		}
		if fdCount() != fds {
			return fail("Command holds descriptors: %d, want %d", fdCount(), fds)
		}
	case "failed-start":
		c, err := Command(ctx, sc.Spec)
		if err != nil {
			return fail("Command: %v", err)
		}
		err = c.Start()
		if err == nil {
			_ = c.run.lifeline.Close()
			_ = c.Wait()
			return fail("Start succeeded")
		}
		if !strings.Contains(strings.ToLower(err.Error()), sc.Want) {
			return fail("Start = %q, want it to mention %q", err, sc.Want)
		}
		if c.Pid() != 0 || c.Listeners() != nil {
			return fail("a failed Start left a pid or listeners")
		}
		if err := c.Wait(); err == nil {
			return fail("Wait after a failed Start returned nil")
		}
		if !settled() {
			return fail("a failed Start left processes %v (before %v) or descriptors %d (before %d)", children(), before, fdCount(), fds)
		}
	case "canceled-start":
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		c, err := Command(cctx, Spec{Home: home, Command: []string{"/bin/true"}})
		if err != nil {
			return fail("Command: %v", err)
		}
		cancel()
		before, fds = children(), fdCount()
		if err := c.Start(); err == nil {
			_ = c.Wait()
			return fail("Start with a canceled context returned nil")
		}
		if !settled() {
			return fail("a refused Start left processes %v or descriptors %d (before %v, %d)", children(), fdCount(), before, fds)
		}
	case "closed-file":
		f, err := os.Open(os.DevNull)
		if err != nil {
			return fail("%v", err)
		}
		_ = f.Close()
		c, err := Command(ctx, Spec{Home: home, Command: []string{"/bin/true"}, Files: []*os.File{f}})
		if err != nil {
			return fail("Command: %v", err)
		}
		before, fds = children(), fdCount()
		if err := c.Start(); err == nil {
			_ = c.Wait()
			return fail("Start accepted a closed file")
		}
		if !settled() {
			return fail("a refused Start leaked a process or descriptor")
		}
	default:
		return fail("unknown scenario %q", sc.Kind)
	}
	return 0
}

// children returns the pids of this process's child processes.
func children() []int {
	ents, _ := os.ReadDir("/proc")
	var kids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		st, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		f := strings.Fields(string(st[bytes.LastIndexByte(st, ')')+2:]))
		if len(f) > 1 && f[1] == strconv.Itoa(os.Getpid()) {
			kids = append(kids, pid)
		}
	}
	return kids
}

// fdCount returns how many descriptors this process holds.
func fdCount() int {
	ents, _ := os.ReadDir("/proc/self/fd")
	return len(ents)
}

// baseSpec is a valid Spec for tests of Command that never start it.
func baseSpec() Spec {
	return Spec{Command: []string{"/bin/true"}, Home: "/nonexistent-home"}
}

// Command: its refusals, with what each says.
func TestAPICommandErrors(t *testing.T) {
	t.Parallel()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	mod := func(f func(*Spec)) Spec { s := baseSpec(); f(&s); return s }
	for _, tc := range []struct {
		name string
		spec Spec
		want string
	}{
		{"no command", mod(func(s *Spec) { s.Command = nil }), "no command"},
		{"an empty command", mod(func(s *Spec) { s.Command = []string{} }), "no command"},
		{"an unknown kernel", mod(func(s *Spec) { s.Kernel = "loose" }), "loose"},
		{"a kernel in the wrong case", mod(func(s *Spec) { s.Kernel = "Strict" }), "Strict"},
		{"an unknown network", mod(func(s *Spec) { s.Network = 2 }), "network"},
		{"a negative network", mod(func(s *Spec) { s.Network = -1 }), "network"},
		{"Listen with NetworkHost", mod(func(s *Spec) { s.Network, s.Listen = NetworkHost, 1 }), "NetworkNone"},
		{"Loopback with NetworkHost", mod(func(s *Spec) { s.Network, s.Loopback = NetworkHost, 1 }), "NetworkNone"},
		{"Listen and Loopback with NetworkHost", mod(func(s *Spec) { s.Network, s.Listen, s.Loopback = NetworkHost, 2, 2 }), "NetworkNone"},
		{"too many listeners", mod(func(s *Spec) { s.Listen = maxListen + 1 }), "listen"},
		{"too much loopback", mod(func(s *Spec) { s.Loopback = maxListen + 1 }), "loopback"},
		{"a negative Listen", mod(func(s *Spec) { s.Listen = -1 }), "listen"},
		{"a negative Loopback", mod(func(s *Spec) { s.Loopback = -1 }), "loopback"},
		{"a nil file", mod(func(s *Spec) { s.Files = []*os.File{f, nil} }), "nil"},
		{"resource zero", mod(func(s *Spec) { s.Rlimits = []Rlimit{{Resource: 0}} }), "resource"},
		{"an unknown resource", mod(func(s *Spec) { s.Rlimits = []Rlimit{{Resource: ResourceAddressSpace + 1}} }), "resource"},
		{"a soft limit above the hard one", mod(func(s *Spec) { s.Rlimits = []Rlimit{{ResourceCore, 2, 1}} }), "soft"},
		{"a negative ScratchSize", mod(func(s *Spec) { s.ScratchSize = -1 }), "scratch"},
		{"a NUL in the hostname", mod(func(s *Spec) { s.Hostname = "a\x00b" }), "NUL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Command(t.Context(), tc.spec)
			if err == nil {
				t.Fatalf("Command returned %v and no error", c)
			}
			if c != nil {
				t.Error("Command returned a Cmd with its error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
	// What it accepts, at the edges, without starting anything.
	for _, tc := range []struct {
		name string
		spec Spec
	}{
		{"the most listeners and loopback ports", mod(func(s *Spec) { s.Listen, s.Loopback = maxListen, maxListen })},
		{"limits equal", mod(func(s *Spec) { s.Rlimits = []Rlimit{{ResourceCore, 1, 1}} })},
		{"no limit at all", mod(func(s *Spec) { s.Rlimits = []Rlimit{{ResourceFileSize, ^uint64(0), ^uint64(0)}} })},
		{"every resource", mod(func(s *Spec) {
			for r := ResourceCPU; r <= ResourceAddressSpace; r++ {
				s.Rlimits = append(s.Rlimits, Rlimit{r, 1, 2})
			}
		})},
		{"a small ScratchSize", mod(func(s *Spec) { s.ScratchSize = 4096 })},
		{"NetworkHost with none of either", mod(func(s *Spec) { s.Network = NetworkHost })},
		{"macOS fields, which Linux ignores", mod(func(s *Spec) { s.Services, s.BroadLoopback = []Service{"fonts"}, true })},
		{"a long hostname, which Start checks", mod(func(s *Spec) { s.Hostname = strings.Repeat("h", 100) })},
		{"no Home, which Start checks", mod(func(s *Spec) { s.Home = "" })},
	} {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Command(t.Context(), tc.spec); err != nil {
				t.Errorf("Command: %v", err)
			}
		})
	}
}

// Command does not start anything, and copies the slices it is given.
func TestAPICommandStartsNothingAndCopies(t *testing.T) {
	t.Parallel()
	spec := baseSpec()
	spec.Command = []string{"/bin/true", "arg"}
	spec.Rlimits = []Rlimit{{ResourceCore, 0, 0}}
	leakCheck(t, leakScenario{Kind: "command", Spec: spec})
	c, err := Command(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Command[0], spec.Command[1] = "/bin/false", "changed"
	spec.Rlimits[0].Soft = 99
	if c.spec.Command[0] != "/bin/true" || c.spec.Command[1] != "arg" || c.spec.Rlimits[0].Soft != 0 {
		t.Errorf("Command kept the caller's slices: %+v", c.spec)
	}
	if c.CgroupFD != -1 {
		t.Errorf("CgroupFD = %d, want -1", c.CgroupFD)
	}
	if c.Env != nil || c.Stdin != nil || c.Stdout != nil || c.Stderr != nil || c.WaitDelay != 0 {
		t.Errorf("a new Cmd has options set: %+v", c)
	}
	if c.Pid() != 0 || c.Listeners() != nil {
		t.Error("a new Cmd has a pid or listeners")
	}
}

// Start's refusals of a Spec that Command accepted.
func TestAPIStartErrors(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	for _, tc := range []struct {
		name string
		spec Spec
		want string
	}{
		{"no Home", Spec{Command: []string{"/bin/true"}}, "home"},
		{"a missing Home", Spec{Command: []string{"/bin/true"}, Home: filepath.Join(home, "missing")}, "does not exist"},
		{"a relative Home", Spec{Command: []string{"/bin/true"}, Home: "relative"}, "absolute"},
		{"a command that is not there", Spec{Command: []string{"/nonexistent/cmd"}, Home: home}, "/nonexistent/cmd"},
		{"a name not on the PATH, which is empty", Spec{Command: []string{"no-such-command"}, Home: home}, "no-such-command"},
		{"a hostname too long", Spec{Command: []string{"/bin/true"}, Home: home, Hostname: strings.Repeat("h", 100)}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			leakCheck(t, leakScenario{Kind: "failed-start", Spec: tc.spec, Want: tc.want})
		})
	}
}

// Cmd used wrongly: Wait before Start, Start twice, Wait twice, a zero Cmd,
// and a canceled context.
func TestAPICmdMisuse(t *testing.T) {
	t.Parallel()
	t.Run("Wait before Start", func(t *testing.T) {
		t.Parallel()
		c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "env")
		if err := c.Wait(); err == nil {
			t.Error("Wait before Start returned nil")
		}
		// The Cmd is still good for its one use.
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Start twice", func(t *testing.T) {
		t.Parallel()
		c, stdout, stderr := escCmd(t.Context(), t, Spec{}, "esc", "env")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		pid := c.Pid()
		if err := c.Start(); err == nil {
			t.Error("a second Start returned nil")
		}
		if c.Pid() != pid {
			t.Errorf("the second Start changed Pid from %d to %d", pid, c.Pid())
		}
		// The first run is untouched.
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, stderr)
		}
		if !strings.Contains(stdout.String(), "HOME=") {
			t.Errorf("the first run's output is %q", stdout)
		}
		if err := c.Start(); err == nil {
			t.Error("Start after Wait returned nil")
		}
	})
	t.Run("Wait twice", func(t *testing.T) {
		t.Parallel()
		c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "env")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err == nil {
			t.Error("a second Wait returned nil")
		}
	})
	t.Run("a Cmd that Command did not make", func(t *testing.T) {
		t.Parallel()
		c := &Cmd{}
		if err := c.Start(); err == nil {
			t.Error("Start of a zero Cmd returned nil")
		}
		if err := c.Wait(); err == nil {
			t.Error("Wait of a zero Cmd returned nil")
		}
		if c.Pid() != 0 || c.ListenAddrs() != nil || c.LoopbackPorts() != nil || c.Listeners() != nil {
			t.Error("a zero Cmd has a pid, addresses or listeners")
		}
	})
	t.Run("a context done before Start", func(t *testing.T) {
		t.Parallel()
		leakCheck(t, leakScenario{Kind: "canceled-start"})
	})
	t.Run("options changed after Start do nothing", func(t *testing.T) {
		t.Parallel()
		c, stdout, stderr := escCmd(t.Context(), t, Spec{}, "esc", "both")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		var other bytes.Buffer
		c.Stdout, c.Stderr, c.Env, c.WaitDelay, c.CgroupFD = &other, &other, []string{"X=1"}, time.Hour, 999999
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
		if stdout.String() != "to stdout" || stderr.String() != "to stderr" || other.Len() != 0 {
			t.Errorf("output went to %q, %q and %q", stdout, stderr, &other)
		}
	})
}

// Stdin, Stdout, Stderr: the streams are the command's 0, 1 and 2, and nil
// means /dev/null.
func TestAPIStdio(t *testing.T) {
	t.Parallel()
	t.Run("stdin to stdout", func(t *testing.T) {
		t.Parallel()
		c, stdout, stderr := escCmd(t.Context(), t, Spec{}, "esc", "cat")
		in := strings.Repeat("0123456789abcdef", 1<<16) // 1 MiB
		c.Stdin = strings.NewReader(in)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, stderr)
		}
		if stdout.String() != in {
			t.Errorf("echoed %d bytes, want %d", len(stdout.String()), len(in))
		}
	})
	t.Run("separate stdout and stderr", func(t *testing.T) {
		t.Parallel()
		c, stdout, stderr := escCmd(t.Context(), t, Spec{}, "esc", "both")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
		if stdout.String() != "to stdout" || stderr.String() != "to stderr" {
			t.Errorf("stdout %q, stderr %q", stdout, stderr)
		}
	})
	t.Run("files", func(t *testing.T) {
		t.Parallel()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "both")
		c.Stdout, c.Stderr = w, w
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(r)
		if len(out) != len("to stdoutto stderr") {
			t.Errorf("a pipe got %q", out)
		}
	})
	t.Run("nil is /dev/null", func(t *testing.T) {
		t.Parallel()
		c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "cat")
		c.Stdin, c.Stdout, c.Stderr = nil, nil, nil
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- c.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Wait = %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a command with a nil Stdin never saw EOF")
		}
	})
}

// Env: nil means empty, never the caller's; Start's variables win.
//
//nolint:paralleltest // uses t.Setenv, which t.Parallel forbids, so its subtests, which share what it sets, are serial too.
func TestAPIEnv(t *testing.T) {
	t.Setenv("SANDBOX_API_LEAK", "leaked")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent")
	run := func(t *testing.T, spec Spec, env []string) []string {
		t.Helper()
		c, stdout, stderr := escCmd(t.Context(), t, spec, "esc", "env")
		c.Env = env
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, stderr)
		}
		return strings.Fields(stdout.String())
	}
	t.Run("nil and empty pass nothing", func(t *testing.T) {
		for _, env := range [][]string{nil, {}} {
			got := run(t, Spec{}, env)
			for _, kv := range got {
				name, _, _ := strings.Cut(kv, "=")
				if !strings.HasPrefix(name, "XDG_") && !slices.Contains([]string{"HOME", "TMPDIR", "PWD"}, name) {
					t.Errorf("Env %#v passed %s", env, kv)
				}
			}
		}
	})
	t.Run("the caller's own are overridden, the rest kept", func(t *testing.T) {
		home := t.TempDir()
		given := []string{
			"HOME=/home/someone", "TMPDIR=/var/tmp/x", "XDG_RUNTIME_DIR=/run/user/1000",
			"XDG_CONFIG_HOME=/x/config", "XDG_CACHE_HOME=/x/cache", "XDG_DATA_HOME=/x/data", "XDG_STATE_HOME=/x/state",
			"KEEP=me", "PATH=/usr/bin:/bin", "XDG_DATA_DIRS=/usr/share",
		}
		before := slices.Clone(given)
		c, stdout, stderr := escCmd(t.Context(), t, Spec{Home: home}, "esc", "env")
		c.Env = given
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, stderr)
		}
		got := strings.Fields(stdout.String())
		for _, kv := range []string{
			"HOME=" + home, "TMPDIR=/tmp", "XDG_RUNTIME_DIR=/tmp",
			"XDG_CONFIG_HOME=" + home + "/.config", "XDG_CACHE_HOME=" + home + "/.cache",
			"XDG_DATA_HOME=" + home + "/.local/share", "XDG_STATE_HOME=" + home + "/.local/state",
			"KEEP=me", "PATH=/usr/bin:/bin", "XDG_DATA_DIRS=/usr/share",
		} {
			if !slices.Contains(got, kv) {
				t.Errorf("env lacks %s: %q", kv, got)
			}
		}
		for _, kv := range got {
			for _, bad := range []string{"/home/someone", "/var/tmp/x", "/run/user", "/x/"} {
				if strings.Contains(kv, bad) {
					t.Errorf("env holds the caller's %s", kv)
				}
			}
			if strings.Contains(kv, "SANDBOX_API_LEAK") || strings.Contains(kv, "SSH_AUTH_SOCK") {
				t.Errorf("env holds the caller process's own %s", kv)
			}
		}
		for name := range map[string]bool{"HOME": true, "TMPDIR": true, "XDG_RUNTIME_DIR": true} {
			n := 0
			for _, kv := range got {
				if strings.HasPrefix(kv, name+"=") {
					n++
				}
			}
			if n != 1 {
				t.Errorf("%s appears %d times", name, n)
			}
		}
		if !slices.Equal(given, before) {
			t.Errorf("Start changed Env: %q, was %q", given, before)
		}
	})
}

// Spec.Command: a name without a slash is looked up on the PATH inside the
// sandbox, which is the one Env gives, so with a nil Env nothing is found.
func TestAPICommandLookup(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	c, err := Command(t.Context(), Spec{Command: []string{"true"}, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err == nil {
		_ = c.Wait()
		t.Error("a bare name was found with no PATH")
	}
	c, err = Command(t.Context(), Spec{Command: []string{"true"}, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	c.Env = []string{"PATH=/usr/bin:/bin"}
	if err := c.Start(); err != nil {
		t.Fatalf("with PATH: %v", err)
	}
	if err := c.Wait(); err != nil {
		t.Errorf("true: %v", err)
	}
	// A command's arguments reach it as given.
	c, err = Command(t.Context(), Spec{Command: []string{"/bin/sh", "-c", `test "$1" = "a b" && test "$2" = "" && exit 7`, "sh", "a b", ""}, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	var ee *exec.ExitError
	if err := c.Wait(); !errors.As(err, &ee) || ee.ExitCode() != 7 {
		t.Errorf("Wait = %v, want the command's exit status 7", err)
	}
}

// Wait returns the command's status as an *exec.ExitError, and a command that
// cannot be run shows there too, not in Start.
func TestAPIWaitStatus(t *testing.T) {
	t.Parallel()
	for _, code := range []int{1, 3, 42} {
		c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "exit", strconv.Itoa(code))
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		var ee *exec.ExitError
		if err := c.Wait(); !errors.As(err, &ee) || ee.ExitCode() != code {
			t.Errorf("exit %d: Wait = %v", code, err)
		}
	}
	t.Run("killed by a signal", func(t *testing.T) {
		t.Parallel()
		c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "selfkill", strconv.Itoa(int(unix.SIGKILL)))
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		var ee *exec.ExitError
		if err := c.Wait(); !errors.As(err, &ee) || ee.ExitCode() != 128+9 {
			t.Errorf("Wait = %v, want status 137", err)
		}
	})
	// The reaper replies once the command has started, so Start fails for
	// one that can't be, as the doc comment on Start says.
	t.Run("a file that cannot be executed", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		bad := filepath.Join(home, "bad")
		if err := os.WriteFile(bad, []byte("not a program\n"), 0o700); err != nil { //nolint:gosec // G306: the file is a program the test runs, which needs its owner to execute it.
			t.Fatal(err)
		}
		c, err := Command(t.Context(), Spec{Command: []string{bad}, Home: home})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Start(); err == nil || !strings.Contains(err.Error(), "exec format error") {
			t.Errorf("Start = %v, want the exec's error", err)
			if err == nil {
				_ = c.Wait()
			}
		}
	})
}

// Hostname: the sandbox's own, "sandbox" when empty.
func TestAPIHostname(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, want string }{
		{"", "sandbox"}, {"box", "box"}, {strings.Repeat("h", 63), strings.Repeat("h", 63)},
	} {
		c, stdout, stderr := escCmd(t.Context(), t, Spec{Hostname: tc.name}, "esc", "hostname")
		if err := c.Start(); err != nil {
			t.Fatalf("%q: %v", tc.name, err)
		}
		if err := c.Wait(); err != nil {
			t.Fatalf("hostname %q: %v: %s", tc.name, err, stderr)
		}
		if got := strings.TrimSpace(stdout.String()); got != tc.want {
			t.Errorf("hostname = %q, want %q", got, tc.want)
		}
	}
}

// Dir: empty means Home; it may be a subdirectory of Home, a Write or Read
// path, or a directory no cover hides.
func TestAPIDir(t *testing.T) {
	t.Parallel()
	home, write, read := t.TempDir(), t.TempDir(), t.TempDir()
	sub := filepath.Join(home, "sub")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, dir, want string }{
		{"empty", "", home},
		{"a subdirectory of Home", sub, sub},
		{"a Write path", write, write},
		{"a Read path", read, read},
		{"a directory nothing covers", "/usr/share", "/usr/share"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, stdout, stderr := escCmd(t.Context(), t, Spec{Home: home, Dir: tc.dir, Write: []string{write}, Read: []string{read}}, "esc", "pwd")
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			if err := c.Wait(); err != nil {
				t.Fatalf("%v: %s", err, stderr)
			}
			if got := strings.TrimSpace(stdout.String()); got != tc.want {
				t.Errorf("working directory = %q, want %q", got, tc.want)
			}
		})
	}
}

// Files: numbered from 3, in order, however many; the caller may close its
// own copies once Start returns; a closed one is refused.
func TestAPIFiles(t *testing.T) {
	t.Parallel()
	t.Run("many, closed after Start", func(t *testing.T) {
		t.Parallel()
		files := make([]*os.File, 0, 6)
		var want strings.Builder
		for i := range 6 {
			f, err := os.CreateTemp(t.TempDir(), "f")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(f, "content %d", i); err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
			fmt.Fprintf(&want, "%d:content %d\n", 3+i, i)
		}
		pr, pw, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer pr.Close()
		c, stdout, stderr := escCmd(t.Context(), t, Spec{Files: files}, "esc", "gate-read-fds", "6")
		c.Stdin = pr
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		_ = pr.Close()
		// Close them before the command reads, which it does once its
		// stdin ends.
		for _, f := range files {
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}
		_ = pw.Close()
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, stderr)
		}
		if stdout.String() != want.String() {
			t.Errorf("read %q, want %q", stdout, want.String())
		}
	})
	t.Run("a closed file", func(t *testing.T) {
		t.Parallel()
		leakCheck(t, leakScenario{Kind: "closed-file"})
	})
	t.Run("the caller's copy stays usable", func(t *testing.T) {
		t.Parallel()
		f, err := os.CreateTemp(t.TempDir(), "f")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		_, _ = f.WriteString("0123456789")
		c, _, stderr := escCmd(t.Context(), t, Spec{Files: []*os.File{f}}, "esc", "read-fds", "1")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, stderr)
		}
		if _, err := f.WriteString("more"); err != nil {
			t.Errorf("the caller's file was closed or changed: %v", err)
		}
	})
}

// Listen, ListenAddrs, LoopbackPorts, Listeners: addresses are known before
// Start, each listener serves the address of its index.
func TestAPIListeners(t *testing.T) {
	t.Parallel()
	t.Run("none", func(t *testing.T) {
		t.Parallel()
		c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "env")
		if c.ListenAddrs() != nil || c.LoopbackPorts() != nil || c.Listeners() != nil {
			t.Errorf("addresses %v, ports %v", c.ListenAddrs(), c.LoopbackPorts())
		}
	})
	t.Run("addresses", func(t *testing.T) {
		t.Parallel()
		c, _, _ := escCmd(t.Context(), t, Spec{Listen: 3, Loopback: 2}, "esc", "env")
		if want := []string{"127.0.0.1:3128", "127.0.0.1:3129", "127.0.0.1:3130"}; !slices.Equal(c.ListenAddrs(), want) {
			t.Errorf("ListenAddrs = %v, want %v", c.ListenAddrs(), want)
		}
		if want := []int{4444, 4445}; !slices.Equal(c.LoopbackPorts(), want) {
			t.Errorf("LoopbackPorts = %v, want %v", c.LoopbackPorts(), want)
		}
		c2, _, _ := escCmd(t.Context(), t, Spec{Listen: maxListen, Loopback: maxListen}, "esc", "env")
		if n := len(c2.ListenAddrs()); n != maxListen {
			t.Errorf("%d addresses", n)
		}
		if p := c2.LoopbackPorts(); p[len(p)-1] != 4444+maxListen-1 {
			t.Errorf("last loopback port %d", p[len(p)-1])
		}
		first := c.ListenAddrs()
		if again := c.ListenAddrs(); first[0] != again[0] {
			t.Error("addresses change")
		}
	})
	t.Run("each listener serves its own", func(t *testing.T) {
		t.Parallel()
		c, _, stderr := escCmd(t.Context(), t, Spec{Listen: 3}, "esc", "dial-each")
		c.spec.Command = append(c.spec.Command, c.ListenAddrs()...)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		lns := c.Listeners()
		if len(lns) != 3 {
			t.Fatalf("%d listeners, want 3", len(lns))
		}
		got := make([]chan string, len(lns))
		for i, ln := range lns {
			t.Cleanup(func() { _ = ln.Close() })
			if ln.Addr().String() != c.ListenAddrs()[i] {
				t.Errorf("listener %d is on %s, want %s", i, ln.Addr(), c.ListenAddrs()[i])
			}
			got[i] = make(chan string, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					got[i] <- err.Error()
					return
				}
				defer conn.Close()
				var b [8]byte
				n, _ := io.ReadAtLeast(conn, b[:], 2)
				got[i] <- strings.TrimSpace(string(b[:n]))
			}()
		}
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, stderr)
		}
		for i := range lns {
			if g := <-got[i]; g != strconv.Itoa(i) {
				t.Errorf("listener %d was dialed as %q", i, g)
			}
		}
		// Still there after Wait.
		if len(c.Listeners()) != 3 {
			t.Error("Listeners changed after Wait")
		}
	})
	t.Run("two sandboxes share the addresses without meeting", func(t *testing.T) {
		t.Parallel()
		cs := make([]*Cmd, 0, 2)
		for range 2 {
			c, _, _ := escCmd(t.Context(), t, Spec{Listen: 1}, "esc", "env")
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Listeners()[0].Close() })
			cs = append(cs, c)
		}
		if cs[0].Listeners()[0].Addr().String() != cs[1].Listeners()[0].Addr().String() {
			t.Error("the two sandboxes' listeners differ")
		}
		for _, c := range cs {
			_ = c.Wait()
		}
	})
	t.Run("Run refuses Listen", func(t *testing.T) {
		t.Parallel()
		if _, err := Run(t.Context(), Spec{Command: []string{"/bin/true"}, Home: t.TempDir(), Listen: 1}); err == nil {
			t.Error("Run served a listener it cannot")
		}
	})
}

// Run: the dedicated-process form. It uses the process's own streams,
// environment and working directory, and returns the command's status.
func TestAPIRun(t *testing.T) {
	t.Parallel()
	exe, dir := escBinary(t)
	run := func(t *testing.T, spec Spec, env []string, wd string, check string, args ...string) (int, string, string) {
		t.Helper()
		spec.Command = append([]string{exe, "esc", check}, args...)
		spec.Read = append(slices.Clone(spec.Read), dir)
		cmd := exec.CommandContext(t.Context(), "/proc/self/exe", "esc-run", jsonArg(t, spec)) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		cmd.Dir = wd
		cmd.Env = append(os.Environ(), env...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), stdout.String(), stderr.String()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, stdout.String(), stderr.String()
	}
	home := t.TempDir()
	t.Run("status", func(t *testing.T) {
		t.Parallel()
		for _, want := range []int{0, 1, 7} {
			if code, _, stderr := run(t, Spec{Home: home}, nil, home, "exit", strconv.Itoa(want)); code != want {
				t.Errorf("exit %d: Run returned %d: %s", want, code, stderr)
			}
		}
	})
	t.Run("a signal is 128 plus its number", func(t *testing.T) {
		t.Parallel()
		if code, _, stderr := run(t, Spec{Home: home}, nil, home, "selfkill", "15"); code != 128+15 {
			t.Errorf("Run returned %d: %s", code, stderr)
		}
	})
	t.Run("its environment and directory", func(t *testing.T) {
		t.Parallel()
		sub := filepath.Join(home, "sub")
		if err := os.Mkdir(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		code, out, stderr := run(t, Spec{Home: home}, []string{"RUN_API_VAR=seen", "HOME=/evil"}, sub, "env")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if !strings.Contains(out, "RUN_API_VAR=seen") {
			t.Errorf("Run did not pass its environment: %q", out)
		}
		if !strings.Contains(out, "HOME="+home+"\n") || strings.Contains(out, "evil") {
			t.Errorf("HOME was not the sandbox's: %q", out)
		}
		code, out, _ = run(t, Spec{Home: home}, nil, sub, "pwd")
		if got := strings.TrimSpace(out); code != 0 || got != sub {
			t.Errorf("working directory = %q (exit %d), want the process's %q", got, code, sub)
		}
	})
	t.Run("errors are errors", func(t *testing.T) {
		t.Parallel()
		code, _, stderr := run(t, Spec{Home: filepath.Join(home, "missing")}, nil, home, "env")
		if code != 99 || !strings.Contains(stderr, "run error") {
			t.Errorf("Run with a missing home: exit %d: %s", code, stderr)
		}
		code, _, _ = run(t, Spec{Home: home, Kernel: "nope"}, nil, home, "env")
		if code != 99 {
			t.Errorf("Run with a bad kernel: exit %d", code)
		}
	})
	t.Run("a signal to Run ends the sandbox", func(t *testing.T) {
		t.Parallel()
		spec := Spec{Home: home, Command: []string{exe, "esc", "hold"}, Read: []string{dir}}
		cmd := exec.CommandContext(t.Context(), "/proc/self/exe", "esc-run", jsonArg(t, spec)) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		cmd.Dir = home
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		line := make([]byte, 128)
		n, _ := out.Read(line)
		ns := strings.TrimSpace(strings.TrimPrefix(string(line[:n]), "ns "))
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if ee := new(exec.ExitError); err != nil && !errors.As(err, &ee) {
				t.Errorf("Wait for Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatal("Run did not end after SIGTERM")
		}
		if left := waitNoMembers(ns); len(left) > 0 {
			t.Errorf("processes %v outlived Run", left)
		}
	})
}

// RegisterFlags: every flag sets its field, repeatable ones accumulate, the
// command is what is left, and a Spec built from flags runs.
func TestAPIRegisterFlags(t *testing.T) {
	t.Parallel()
	parse := func(t *testing.T, args ...string) (Spec, *flag.FlagSet, error) {
		t.Helper()
		var spec Spec
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		spec.RegisterFlags(fs)
		err := fs.Parse(args)
		return spec, fs, err
	}
	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		want := Spec{
			Home: "/h", Dir: "/h/d", Write: []string{"/w1", "/w2", "/w3"}, Read: []string{"/r1", "/r2"},
			Cover: []string{"/c1", "/c2"}, Kernel: KernelOpen, Network: NetworkHost,
		}
		args := make([]string, 0, 8+2*(len(want.Write)+len(want.Read)+len(want.Cover))+4)
		args = append(args, "-home", want.Home, "-dir", want.Dir, "-kernel", string(want.Kernel), "-network", want.Network.String())
		for _, w := range want.Write {
			args = append(args, "-write", w)
		}
		for _, r := range want.Read {
			args = append(args, "-read", r)
		}
		for _, c := range want.Cover {
			args = append(args, "-cover", c)
		}
		args = append(args, "--", "prog", "-x", "arg")
		got, fs, err := parse(t, args...)
		if err != nil {
			t.Fatal(err)
		}
		got.Command = fs.Args()
		want.Command = []string{"prog", "-x", "arg"}
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		if !bytes.Equal(a, b) {
			t.Errorf("parsed %s, want %s", a, b)
		}
	})
	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		got, fs, err := parse(t)
		if err != nil {
			t.Fatal(err)
		}
		if a, _ := json.Marshal(got); string(a) != `{"command":null,"home":""}` {
			t.Errorf("a Spec with no flags is %s", a)
		}
		if len(fs.Args()) != 0 {
			t.Errorf("arguments %v", fs.Args())
		}
		for name, want := range map[string]string{"home": "", "dir": "", "kernel": "", "network": "none", "write": "", "read": "", "cover": ""} {
			f := fs.Lookup(name)
			if f == nil {
				t.Errorf("no -%s flag", name)
				continue
			}
			if f.Value.String() != want {
				t.Errorf("-%s default %q, want %q", name, f.Value.String(), want)
			}
		}
	})
	t.Run("errors", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{
			{"-kernel", "loose"}, {"-network", "all"}, {"-nope"}, {"-home"}, {"-write"},
		} {
			if _, _, err := parse(t, args...); err == nil {
				t.Errorf("%v parsed", args)
			}
		}
	})
	t.Run("two Specs are independent", func(t *testing.T) {
		t.Parallel()
		a, _, _ := parse(t, "-home", "/a", "-write", "/wa")
		b, _, _ := parse(t, "-home", "/b", "-write", "/wb")
		if a.Home != "/a" || b.Home != "/b" || !slices.Equal(a.Write, []string{"/wa"}) || !slices.Equal(b.Write, []string{"/wb"}) {
			t.Errorf("%+v %+v", a, b)
		}
	})
	t.Run("usage lists every flag", func(t *testing.T) {
		t.Parallel()
		var spec Spec
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		var buf bytes.Buffer
		fs.SetOutput(&buf)
		spec.RegisterFlags(fs)
		fs.PrintDefaults()
		for _, name := range []string{"-home", "-dir", "-write", "-read", "-cover", "-kernel", "-network"} {
			if !strings.Contains(buf.String(), name) {
				t.Errorf("usage lacks %s: %s", name, &buf)
			}
		}
	})
	t.Run("a Spec from flags runs", func(t *testing.T) {
		t.Parallel()
		exe, dir := escBinary(t)
		home, write := t.TempDir(), t.TempDir()
		view := viewSpec{Writable: []string{home, write}, ReadOnly: []string{"/etc", dir}}
		spec, fs, err := parse(t, "-home", home, "-write", write, "-read", dir, "-kernel", "nested", "-network", "none",
			"--", exe, "esc", "view", jsonArg(t, view))
		if err != nil {
			t.Fatal(err)
		}
		spec.Command = fs.Args()
		c, err := Command(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		c.Stderr = &stderr
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, &stderr)
		}
	})
}

// Network and Kernel: String and Set, as the flag package calls them.
func TestAPIStringSet(t *testing.T) {
	t.Parallel()
	var n, five, host Network = NetworkNone, 5, NetworkHost
	if n.String() != "none" || (*Network)(nil).String() != "none" || five.String() != "Network(5)" || host.String() != "host" {
		t.Errorf("Network strings: %q %q %q", n.String(), five.String(), host.String())
	}
	if err := n.Set("host"); err != nil || n != NetworkHost {
		t.Errorf("Set host: %v, %v", n, err)
	}
	if err := n.Set("bogus"); err == nil || n != NetworkHost {
		t.Errorf("Set bogus: %v, %v (want an error and no change)", n, err)
	}
	if err := n.Set(""); err == nil {
		t.Error("Set empty succeeded")
	}
	if err := n.Set("none"); err != nil || n != NetworkNone {
		t.Errorf("Set none: %v, %v", n, err)
	}
	var k Kernel
	if k.String() != "" || (*Kernel)(nil).String() != "" {
		t.Errorf("Kernel string %q", k.String())
	}
	for _, v := range []Kernel{KernelStrict, KernelNested, KernelOpen} {
		if err := k.Set(string(v)); err != nil || k != v || k.String() != string(v) {
			t.Errorf("Set %s: %v, %v", v, k, err)
		}
	}
	if err := k.Set("loose"); err == nil || k != KernelOpen {
		t.Errorf("Set loose: %v, %v (want an error and no change)", k, err)
	}
	// The constants are what their docs say.
	if KernelStrict != "strict" || KernelNested != "nested" || KernelOpen != "open" || NetworkNone != 0 || NetworkHost == NetworkNone {
		t.Error("constants changed")
	}
	if ResourceCPU != 1 || ResourceFileSize != 2 || ResourceCore != 3 || ResourceOpenFiles != 4 || ResourceProcesses != 5 || ResourceAddressSpace != 6 {
		t.Error("resource numbers changed")
	}
}

// Rlimits: a limit of math.MaxUint64 is none, and a limit the host will not
// allow is an error from Start naming it.
func TestAPIRlimits(t *testing.T) {
	t.Parallel()
	r := runReport(t, Spec{Rlimits: []Rlimit{{ResourceFileSize, ^uint64(0), ^uint64(0)}}}, nil)
	if got := r.Limits["fsize"]; got.Soft != ^uint64(0) || got.Hard != ^uint64(0) {
		t.Errorf("no limit became %+v", got)
	}
	var cur syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &cur); err != nil {
		t.Fatal(err)
	}
	if cur.Max == ^uint64(0) {
		t.Skip("the host's hard core limit is unlimited, so no higher limit can be asked for")
	}
	c, _, _ := escCmd(t.Context(), t, Spec{Rlimits: []Rlimit{{ResourceCore, cur.Max + 1, cur.Max + 1}}}, "esc", "env")
	if err := c.Start(); err == nil {
		_ = c.Wait()
		t.Error("a limit above the host's hard limit was set")
	}
}

// Services and BroadLoopback mean nothing on Linux and are ignored.
func TestAPIMacOSFieldsIgnored(t *testing.T) {
	t.Parallel()
	escRun(t, Spec{Home: t.TempDir(), Services: []Service{"fonts", "anything"}, BroadLoopback: true}, "env")
}

// Process group: the sandbox is always a process group of its own, and
// signaling it ends it.
func TestAPIProcessGroup(t *testing.T) {
	t.Parallel()
	c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "hold")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	bw := c.run.cmd.Process.Pid
	if pgid, _ := unix.Getpgid(bw); pgid != bw {
		t.Fatalf("pgid = %d, want %d", pgid, bw)
	}
	pid := c.Pid()
	if err := unix.Kill(-bw, unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err == nil {
		t.Error("Wait returned nil for a killed group")
	}
	if !gone(pid) {
		t.Error("pid 1 outlived its group")
	}
}

// CgroupFD: a cgroup directory to start in, where the host delegates one.
func TestAPICgroupFD(t *testing.T) {
	t.Parallel()
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip("no /proc/self/cgroup: " + err.Error())
	}
	rel := strings.TrimSpace(strings.TrimPrefix(string(self), "0::"))
	uid := strconv.Itoa(os.Getuid())
	var made string
	for _, parent := range []string{
		"/sys/fs/cgroup" + rel,
		"/sys/fs/cgroup/user.slice/user-" + uid + ".slice/user@" + uid + ".service",
		"/sys/fs/cgroup/user.slice/user-" + uid + ".slice/user@" + uid + ".service/app.slice",
	} {
		dir := filepath.Join(parent, fmt.Sprintf("sandbox-api-test-%d", os.Getpid()))
		if err := os.Mkdir(dir, 0o750); err == nil { //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
			made = dir
			break
		}
	}
	if made == "" {
		t.Skip("no cgroup this account may create a child of: the VM's user session does not delegate one")
	}
	removeAtCleanup(t, made)
	d, err := openFile(made)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	c, _, stderr := escCmd(t.Context(), t, Spec{}, "esc", "hold")
	c.CgroupFD = int(d.Fd())
	if err := c.Start(); errors.Is(err, unix.EACCES) {
		t.Skipf("the kernel refused to start a process in %s: %v. Starting in a cgroup needs write access to the common ancestor's cgroup.procs too, which this VM session does not delegate", made, err)
	} else if err != nil {
		t.Fatalf("%v: %s", err, stderr)
	}
	defer func() { _ = c.run.lifeline.Close(); _ = c.Wait() }()
	for _, pid := range []int{c.run.cmd.Process.Pid, c.Pid()} {
		cg, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
		if !strings.HasSuffix(strings.TrimSpace(string(cg)), filepath.Base(made)) {
			t.Errorf("pid %d is in %q, want %s", pid, cg, made)
		}
	}
	// A negative or zero value means none.
	for _, fd := range []int{-5, -1, 0} {
		c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "env")
		c.CgroupFD = fd
		if err := c.Start(); err != nil {
			t.Errorf("CgroupFD %d: %v", fd, err)
			continue
		}
		_ = c.Wait()
	}
}

// WaitDelay and ctx: canceling kills the sandbox, and Wait returns within
// WaitDelay even when the output is a writer the caller supplied.
func TestAPIContextAndWaitDelay(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	c, stdout, _ := escCmd(ctx, t, Spec{}, "esc", "hold")
	c.WaitDelay = 2 * time.Second
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if strings.Contains(stdout.String(), "ns ") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	ns := lineWith(stdout.String(), "ns ")
	start := time.Now()
	cancel()
	err := c.Wait()
	if err == nil {
		t.Error("Wait returned nil for a canceled sandbox")
	}
	if d := time.Since(start); d > 6*time.Second {
		t.Errorf("Wait took %v after the context ended", d)
	}
	if left := waitNoMembers(ns); len(left) > 0 {
		t.Errorf("processes %v outlived the context", left)
	}
}

// Pid: the host pid of pid 1, known after Start only, and it is not
// bubblewrap's.
func TestAPIPid(t *testing.T) {
	t.Parallel()
	c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "hold")
	if c.Pid() != 0 {
		t.Errorf("Pid = %d before Start", c.Pid())
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pid := c.Pid()
	defer func() { _ = c.run.lifeline.Close(); _ = c.Wait() }()
	if pid <= 1 || pid == c.run.cmd.Process.Pid {
		t.Fatalf("Pid = %d, bubblewrap is %d", pid, c.run.cmd.Process.Pid)
	}
	// It is pid 1 of a namespace that is not ours: its comm is the stage's.
	if comm, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status"); !strings.Contains(string(comm), "NSpid:\t"+strconv.Itoa(pid)+"\t1\n") {
		t.Errorf("status of %d lacks NSpid %d 1: %s", pid, pid, comm)
	}
	if c.Pid() != pid {
		t.Error("Pid changed")
	}
}

// fillScratch writes 1 MiB at a time into each scratch directory until a
// write fails, and prints the directory, the bytes that fit and the error.
func fillScratch(e *escT, _ []string) {
	chunk := make([]byte, 1<<20)
	for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		f, err := createFile(d + "/fill")
		if err != nil {
			e.failf("create in %s: %v", d, err)
			continue
		}
		total := 0
		for total < 64<<20 {
			n, err := f.Write(chunk)
			total += n
			if err != nil {
				fmt.Printf("%s %d %v\n", d, total, errors.Is(err, unix.ENOSPC))
				break
			}
		}
		if total >= 64<<20 {
			fmt.Printf("%s %d unlimited\n", d, total)
		}
		_ = f.Close()
	}
}

// ScratchSize: each private tmpfs holds no more than it says, and a write
// past it fails with ENOSPC.
func TestAPIScratchSize(t *testing.T) {
	t.Parallel()
	const limit = 4 << 20
	c, stdout, stderr := escCmd(t.Context(), t, Spec{ScratchSize: limit}, "esc", "fill-scratch")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("%v: %s", err, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("output %q, want a line for each of three directories", stdout)
	}
	for _, l := range lines {
		var dir string
		var n int
		var enospc string
		if _, err := fmt.Sscan(l, &dir, &n, &enospc); err != nil || enospc != "true" || n > limit || n < limit/2 {
			t.Errorf("%q: want ENOSPC after about %d bytes", l, limit)
		}
	}
}

// SelfPath: a command that runs this binary again by it gets that binary's
// mode.
func TestAPISelfPath(t *testing.T) {
	t.Parallel()
	c, err := Command(t.Context(), Spec{Home: t.TempDir(), Command: []string{SelfPath, "self-hello", "a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("%v: %s", err, stderr.String())
	}
	if got, want := stdout.String(), "hello from a b\n"; got != want {
		t.Errorf("output %q, want %q", got, want)
	}
}

// A server's threads come and go: a sandbox started from a goroutine whose
// thread then exits must not be killed, which docs/linux.md (The lifeline)
// gives as the reason there is a lifeline and neither Pdeathsig nor
// --die-with-parent.
func TestAPIStartThreadExits(t *testing.T) {
	t.Parallel()
	for i := range 3 {
		ctx, cancel := context.WithCancel(t.Context())
		c, stdout, _ := escCmd(ctx, t, Spec{}, "esc", "hold")
		started := make(chan error, 1)
		go func() {
			// A goroutine that exits while locked ends its thread.
			runtime.LockOSThread()
			started <- c.Start()
		}()
		if err := <-started; err != nil {
			t.Fatal(err)
		}
		var ns string
		for range 100 {
			if ns = lineWith(stdout.String(), "ns "); ns != "" {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(300 * time.Millisecond)
		if ns == "" || len(nsMembers(ns)) == 0 {
			t.Errorf("run %d: the sandbox died with the thread that started it", i)
		}
		cancel()
		_ = c.Wait()
	}
}

// Many sandboxes at once from one process, as a server does.
func TestAPIConcurrent(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := range 8 {
		wg.Go(func() {
			home, err := os.MkdirTemp("", "sbx-conc")
			if err != nil {
				errs <- err
				return
			}
			defer func() {
				if err := os.RemoveAll(home); err != nil {
					errs <- err
				}
			}()
			exe, dir := escBinary(t)
			c, err := Command(t.Context(), Spec{Home: home, Command: []string{exe, "esc", "exit", strconv.Itoa(i)}, Read: []string{dir}, Listen: 1})
			if err != nil {
				errs <- err
				return
			}
			if err := c.Start(); err != nil {
				errs <- fmt.Errorf("sandbox %d: %w", i, err)
				return
			}
			defer c.Listeners()[0].Close()
			var ee *exec.ExitError
			if err := c.Wait(); i == 0 && err != nil || i != 0 && (!errors.As(err, &ee) || ee.ExitCode() != i) {
				errs <- fmt.Errorf("sandbox %d: Wait = %w", i, err)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// Bubblewrap from the PATH, setuid refused. Row: "bwrap from the distro,
// setuid refused".
func TestAPIBubblewrapDiscovery(t *testing.T) {
	dir := t.TempDir()
	t.Run("a setuid copy is refused", func(t *testing.T) {
		fake := filepath.Join(dir, "bwrap")
		if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306: the file is a program the test runs, which needs its owner to execute it.
			t.Fatal(err)
		}
		if err := os.Chmod(fake, 0o755|os.ModeSetuid); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
		c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "env")
		err := c.Start()
		if err == nil {
			_ = c.Wait()
			t.Fatal("Start ran a setuid bwrap")
		}
		if !strings.Contains(err.Error(), "setuid") {
			t.Errorf("error %q does not say setuid", err)
		}
	})
	t.Run("none on the PATH", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		c, _, _ := escCmd(t.Context(), t, Spec{}, "esc", "env")
		err := c.Start()
		if err == nil {
			_ = c.Wait()
			t.Fatal("Start ran with no bubblewrap")
		}
		if !strings.Contains(err.Error(), "bubblewrap") {
			t.Errorf("error %q does not name bubblewrap", err)
		}
	})
}

func registerAPIAllocCheck() {
	escChecks["alloc"] = func(_ *escT, a []string) {
		mb, _ := strconv.Atoi(a[0])
		buf := make([]byte, mb<<20)
		for i := 0; i < len(buf); i += 4096 {
			buf[i] = 1
		}
		fmt.Println("touched", len(buf))
		time.Sleep(time.Minute)
	}
}

// TestAPIFootprint checks that Footprint counts the resident memory of the
// sandbox's processes, which a watchdog polls where there is no cgroup.
func TestAPIFootprint(t *testing.T) {
	t.Parallel()
	c, stdout, _ := escCmd(t.Context(), t, Spec{}, "esc", "alloc", "200")
	if _, err := c.Footprint(); err == nil {
		t.Error("Footprint before Start succeeded")
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.run.lifeline.Close(); _ = c.Wait() }()
	eventually(t, 20*time.Second, "the command did not touch its memory", func() bool { return strings.Contains(stdout.String(), "touched") })
	fp, err := c.Footprint()
	if err != nil {
		t.Fatal(err)
	}
	if fp < 150<<20 || fp > 2<<30 {
		t.Errorf("Footprint = %d MiB, want about 200", fp>>20)
	}
}

// eventually polls cond until it is true, and fails the test after d.
func eventually(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("after %v: %s", d, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
