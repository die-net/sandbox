package sandbox

// The macOS test harness. Tests start real sandboxes with sandbox-exec, as the
// account's own uid, and run either /bin/sh or this test binary inside them.
// The test binary is the code that runs inside: it is its own stage, and its
// first argument names a mode in childModes. "esc" runs a check from escChecks
// and exits 1 with what went wrong on stderr when the sandbox lets something
// through that it should not have.
//
// Every path a test gives a Spec is a real one: t.TempDir() leads through /var,
// which is a link to /private/var, and Command refuses a link in the home.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// childModes are the modes the test binary runs as when a sandbox's command
// is this binary: the first argument names one.
var childModes = map[string]func(args []string) int{}

// stageUnprovableEnv, in the environment of a sandbox's stage, which is this
// test binary again, gives the stage a scan that is never clean and a short
// budget, so that it reports it could not prove the sandbox empty.
const stageUnprovableEnv = "SANDBOX_TEST_STAGE_UNPROVABLE"

// stageOrphanZombiesEnv, in the same place, hides the parent of every zombie and
// exiting process from the stage's scan, so that none is taken as a non-member's
// child and a lingering zombie costs the scan that sees it.
const stageOrphanZombiesEnv = "SANDBOX_TEST_STAGE_ORPHAN_ZOMBIES"

// stageNoKillEnv, in the same place, makes the stage's scan signal nothing, so
// that a member it finds is there again at the next scan, as a process that
// keeps forking against the teardown is.
const stageNoKillEnv = "SANDBOX_TEST_STAGE_NO_KILL"

// TestMain lets the test binary be each part of a sandbox: the process that
// starts it, its stage, and the command inside it.
func TestMain(m *testing.M) {
	registerAPIModes()
	registerAPIResourceChecks()
	registerEscapeChecks()
	registerDialInSession()
	registerDaemonChild()
	registerSignalsFromFile()
	registerEscParent()
	registerReviewChecks()
	registerServeChecks()
	registerProcargsParent()
	registerDevOK()
	registerInheritServe()
	registerRootsChecks()
	registerProbeMode()
	registerSleepForever()
	registerEscMode()
	var hooks []func(*prober)
	if os.Getenv(stageOrphanZombiesEnv) != "" {
		hooks = append(hooks, func(p *prober) {
			stat := p.stat
			p.stat = func(pid int) (procStat, error) {
				st, err := stat(pid)
				if st.Zombie || st.Exiting {
					st.PPid = 1
				}
				return st, err
			}
		})
	}
	if os.Getenv(stageNoKillEnv) != "" {
		hooks = append(hooks, func(p *prober) { p.kill = func(int) {} })
	}
	if os.Getenv(stageUnprovableEnv) != "" {
		teardownBudget = 200 * time.Millisecond
		hooks = append(hooks, func(p *prober) {
			list := p.list
			p.list = func() ([]int, error) {
				pids, err := list()
				return append(pids, math.MaxInt32), err
			}
		})
	}
	if len(hooks) > 0 {
		testProberHook = func(p *prober) {
			for _, h := range hooks {
				h(p)
			}
		}
	}
	if code, ok := Stage(); ok {
		os.Exit(code)
	}
	if len(os.Args) >= 2 {
		if mode, ok := childModes[os.Args[1]]; ok {
			os.Exit(mode(os.Args[2:]))
		}
	}
	os.Exit(m.Run())
}

// listen is net.Listen with a context that is never canceled, for the same
// reason.
func listen(network, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(context.Background(), network, addr)
}

// listenPacket is net.ListenPacket with a context that is never canceled, for
// the helpers and the processes the tests run inside a sandbox, which have no
// context of their own to give.
func listenPacket(network, addr string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), network, addr)
}

// shellPath is what a shell script in a sandbox finds its tools by, since the
// sandbox's environment starts empty.
const shellPath = "PATH=/usr/bin:/bin:/usr/sbin:/sbin"

// realTemp returns a fresh directory with its links resolved.
func realTemp(t testing.TB) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// mkdirs makes the directory at the join of parts, and returns it.
func mkdirs(t testing.TB, parts ...string) string {
	t.Helper()
	p := filepath.Join(parts...)
	if err := os.MkdirAll(p, 0o750); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeFile writes content to the join of parts, and returns the path.
func writeFile(t testing.TB, content string, parts ...string) string {
	t.Helper()
	p := filepath.Join(parts...)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// result is how a sandbox ended.
type result struct {
	code           int
	stdout, stderr string
}

func (r result) String() string {
	return fmt.Sprintf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
}

// execute starts c, waits for it, and returns how it ended. The sandbox's
// environment is what the Cmd's Env holds, or the shell's PATH if it holds
// nothing.
func execute(t testing.TB, c *Cmd) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if c.Stdout == nil {
		c.Stdout = &stdout
	}
	if c.Stderr == nil {
		c.Stderr = &stderr
	}
	if c.Env == nil {
		c.Env = []string{shellPath}
	}
	if err := c.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	code, err := exitStatus(c.Wait())
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	return result{code, stdout.String(), stderr.String()}
}

// sh runs the script in /bin/sh in a sandbox from spec, whose Home is a fresh
// directory if it names none, with args as $1 and up.
func sh(t testing.TB, spec Spec, script string, args ...string) result {
	t.Helper()
	if spec.Home == "" {
		spec.Home = realTemp(t)
	}
	spec.Command = append([]string{"/bin/sh", "-c", script, "sh"}, args...)
	c, err := Command(context.Background(), spec)
	if err != nil {
		t.Fatalf("command: %v", err)
	}
	return execute(t, c)
}

// shOK is sh that fails the test unless the script exits 0, and returns its
// standard output.
func shOK(t testing.TB, spec Spec, script string) string {
	t.Helper()
	r := sh(t, spec, script)
	if r.code != 0 {
		t.Fatalf("script failed: %s", r)
	}
	return r.stdout
}

// hostSecret writes a file with content under a covered directory, a
// directory of its own in the test's temporary one, and returns its path.
// Temporary directories are under /private/var, which every sandbox covers.
func hostSecret(t testing.TB) string {
	t.Helper()
	dir := mkdirs(t, realTemp(t), "app")
	return writeFile(t, "top secret\n", dir, "secret")
}

// self returns this test binary's path.
func self(t testing.TB) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// escT collects what an in-sandbox check finds wrong.
type escT struct{ failed bool }

func (e *escT) failf(format string, a ...any) {
	e.failed = true
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

// is records a failure unless got matches one of want, or is nil when want
// is empty.
func (e *escT) is(name string, got error, want ...error) {
	if len(want) == 0 {
		if got != nil {
			e.failf("%s: %v, want success", name, got)
		}
		return
	}
	for _, w := range want {
		if errors.Is(got, w) {
			return
		}
	}
	e.failf("%s: %v, want one of %v", name, got, want)
}

// escChecks are the checks the test binary runs inside a sandbox.
var escChecks = map[string]func(e *escT, args []string){}

func registerEscMode() {
	childModes["esc"] = func(args []string) int {
		if len(args) == 0 || escChecks[args[0]] == nil {
			fmt.Fprintln(os.Stderr, "no such check", args)
			return 2
		}
		e := &escT{}
		escChecks[args[0]](e, args[1:])
		if e.failed {
			return 1
		}
		return 0
	}
}

// escCmd returns a Cmd, made by Command, that runs this binary in a sandbox
// from spec as `esc check args...`. An empty Home is a fresh directory.
func escCmd(ctx context.Context, t testing.TB, spec Spec, check string, args ...string) *Cmd {
	t.Helper()
	if spec.Home == "" {
		spec.Home = realTemp(t)
	}
	spec.Command = append([]string{self(t), "esc", check}, args...)
	c, err := Command(ctx, spec)
	if err != nil {
		t.Fatalf("command: %v", err)
	}
	return c
}

// escRun runs the check in a sandbox from spec, fails the test unless it
// exits 0, and returns its standard output.
func escRun(t testing.TB, spec Spec, check string, args ...string) string {
	t.Helper()
	r := execute(t, escCmd(t.Context(), t, spec, check, args...))
	if r.code != 0 {
		t.Fatalf("%s: %s", check, r)
	}
	return r.stdout
}

// escResult is escRun that does not require success.
func escResult(t testing.TB, spec Spec, check string, args ...string) result {
	t.Helper()
	return execute(t, escCmd(t.Context(), t, spec, check, args...))
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

// alive reports whether a process with pid exists.
func alive(pid int) bool {
	p, err := os.FindProcess(pid)
	return err == nil && p.Signal(syscall.Signal(0)) == nil
}

// pids returns the pids of every process whose command line holds substr,
// as ps lists them, not counting ps itself.
func pids(t testing.TB, substr string) []int {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "/bin/ps", "-axww", "-o", "pid=,command=").Output()
	if err != nil {
		t.Fatal(err)
	}
	var found []int
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		pidStr, cmdline, ok := strings.Cut(line, " ")
		if !ok || !strings.Contains(cmdline, substr) || strings.Contains(cmdline, "ps -axww") {
			continue
		}
		var pid int
		if _, err := fmt.Sscan(pidStr, &pid); err == nil && pid != os.Getpid() {
			found = append(found, pid)
		}
	}
	return found
}

// signalNotifyAll asks for every signal a canary records.
func signalNotifyAll(c chan<- os.Signal) {
	signal.Notify(c, syscall.SIGWINCH, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT)
}

// signalIgnore ignores sig.
func signalIgnore(sig os.Signal) { signal.Ignore(sig) }

// jsonArg returns v as the one JSON argument a mode takes.
func jsonArg(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

// newTestProcess starts a canary with env, which stays until the test ends,
// and returns its pid.
func newTestProcess(t *testing.T, dir string, env []string) int {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), self(t), "canary", dir) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	eventually(t, 10*time.Second, "the canary did not start", func() bool { _, err := os.Stat(filepath.Join(dir, "ready")); return err == nil })
	return cmd.Process.Pid
}

// tree returns root and every process that descends from it, as the kernel
// lists them.
func tree(t testing.TB, root int) []int {
	t.Helper()
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		t.Fatal(err)
	}
	in := map[int]bool{root: true}
	for grew := true; grew; {
		grew = false
		for i := range procs {
			p := &procs[i]
			if pid, ppid := int(p.Proc.P_pid), int(p.Eproc.Ppid); !in[pid] && in[ppid] {
				in[pid], grew = true, true
			}
		}
	}
	out := make([]int, 0, len(in))
	for pid := range in {
		out = append(out, pid)
	}
	return out
}

// args returns the command line of each of pids that still exists.
func args(t testing.TB, pids []int) []string {
	t.Helper()
	var out []string
	for _, pid := range pids {
		b, err := exec.CommandContext(context.Background(), "/bin/ps", "-ww", "-o", "command=", "-p", fmt.Sprint(pid)).Output() //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		if err == nil {
			out = append(out, strings.TrimSpace(string(b)))
		}
	}
	return out
}
