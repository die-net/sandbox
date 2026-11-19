package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// childModes are the parts of the test binary that run as the command inside
// a sandbox, or as a process that starts one. TestMain looks the first
// argument up here.
var childModes = map[string]func(args []string) int{
	"report":         reportMode,
	"files":          filesMode,
	"sleep":          sleepMode,
	"dial-listen":    dialListenMode,
	"refuses-root":   refusesRootMode,
	"start-and-hang": startAndHangMode,
}

// report is what reportMode tells the process that started its sandbox.
type report struct {
	Env      []string          `json:"env"`
	Dir      string            `json:"dir"`
	Hostname string            `json:"hostname"`
	Ifaces   []string          `json:"ifaces"`
	Fds      map[int]string    `json:"fds"`
	Limits   map[string]Rlimit `json:"limits"`
	Uid      int               `json:"uid"`
}

// openFds returns every descriptor from 3 up that the process holds, by
// number, with where it leads. The directory read to list them, which is the
// one that leads into /proc, and the Go runtime's own anonymous descriptors,
// are left out.
func openFds() map[int]string {
	fds := map[int]string{}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return fds
	}
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n < 3 {
			continue
		}
		target, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil || strings.HasPrefix(target, "/proc/") || strings.HasPrefix(target, "anon_inode:") || strings.HasPrefix(target, "/sys/fs/cgroup/") {
			continue
		}
		fds[n] = target
	}
	return fds
}

// reportMode prints a report of what the command can see of itself.
func reportMode([]string) int {
	r := report{Env: os.Environ(), Fds: openFds(), Limits: map[string]Rlimit{}, Uid: os.Getuid()}
	r.Dir, _ = os.Getwd()
	r.Hostname, _ = os.Hostname()
	if dev, err := os.ReadFile("/proc/net/dev"); err == nil {
		for line := range strings.Lines(string(dev)) {
			if name, _, ok := strings.Cut(line, ":"); ok {
				r.Ifaces = append(r.Ifaces, strings.TrimSpace(name))
			}
		}
	}
	for name, res := range map[string]int{"core": unix.RLIMIT_CORE, "fsize": unix.RLIMIT_FSIZE, "nofile": unix.RLIMIT_NOFILE} {
		var l syscall.Rlimit
		if err := syscall.Getrlimit(res, &l); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		r.Limits[name] = Rlimit{Soft: l.Cur, Hard: l.Max}
	}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		return 1
	}
	return 0
}

// filesMode reads descriptor 3 from the start, writes to descriptor 4, and
// prints what it read and the descriptors it holds.
func filesMode([]string) int {
	buf := make([]byte, 64)
	n, err := unix.Pread(3, buf, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read fd 3:", err)
		return 1
	}
	if _, err := unix.Write(4, []byte("from the command")); err != nil {
		fmt.Fprintln(os.Stderr, "write fd 4:", err)
		return 1
	}
	fmt.Printf("%s\n", buf[:n])
	if err := json.NewEncoder(os.Stdout).Encode(openFds()); err != nil {
		return 1
	}
	return 0
}

// sleepMode waits to be killed, after saying it has started.
func sleepMode([]string) int {
	fmt.Println("started")
	time.Sleep(time.Minute)
	return 0
}

// dialListenMode dials the address in args[0], says hello, and expects
// "world" back. With a second argument it first binds that address and
// dials it, as a command does with its own loopback port.
func dialListenMode(args []string) int {
	if len(args) == 2 {
		ln, err := net.Listen("tcp", args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		go func() {
			if c, err := ln.Accept(); err == nil {
				c.Close()
			}
		}()
		c, err := net.Dial("tcp", args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		c.Close()
	}
	c, err := net.Dial("tcp", args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	fmt.Fprintln(c, "hello")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "world\n" {
		fmt.Fprintf(os.Stderr, "reply %q: %v\n", line, err)
		return 1
	}
	return 0
}

// refusesRootMode runs as uid 0 in a user namespace, and reports whether
// Command refuses.
func refusesRootMode([]string) int {
	_, err := Command(context.Background(), Spec{Command: []string{"true"}, Home: os.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "root") {
		fmt.Fprintf(os.Stderr, "Command as root: %v\n", err)
		return 1
	}
	return 0
}

// startAndHangMode starts a sandbox, prints pid 1's host pid, and waits to
// be killed without waiting for the sandbox.
func startAndHangMode(args []string) int {
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
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(c.Pid())
	time.Sleep(time.Minute)
	return 0
}

// testCmd returns a Cmd for the test binary run in a sandbox as mode with
// args, which starts in spec's home. The test binary's directory is
// readable, since it is under the host's covered /tmp. Env is a minimal
// one, and Stdout and Stderr collect into the returned buffers.
func testCmd(t *testing.T, ctx context.Context, spec Spec, mode string, args ...string) (*Cmd, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if spec.Home == "" {
		spec.Home = t.TempDir()
	}
	spec.Command = append([]string{exe, mode}, args...)
	spec.Read = append(spec.Read, filepath.Dir(exe))
	c, err := Command(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	return c, &stdout, &stderr
}

// runReport runs reportMode in a sandbox from spec, with env, and returns
// what it reported.
func runReport(t *testing.T, spec Spec, env []string) report {
	t.Helper()
	c, stdout, stderr := testCmd(t, t.Context(), spec, "report")
	c.Env = env
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("report: %v: %s", err, stderr)
	}
	var r report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("report %q: %v", stdout, err)
	}
	return r
}

func TestCommandEnv(t *testing.T) {
	home := t.TempDir()
	t.Run("nil means empty", func(t *testing.T) {
		r := runReport(t, Spec{Home: home}, nil)
		// Set by Start, and nothing of the caller's, but for the PWD
		// bubblewrap sets to the working directory.
		want := []string{
			"HOME=" + home,
			"PWD=" + home,
			"TMPDIR=/tmp",
			"XDG_CACHE_HOME=" + home + "/.cache",
			"XDG_CONFIG_HOME=" + home + "/.config",
			"XDG_DATA_HOME=" + home + "/.local/share",
			"XDG_RUNTIME_DIR=/tmp",
			"XDG_STATE_HOME=" + home + "/.local/state",
		}
		got := slices.Clone(r.Env)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("env = %q, want %q", got, want)
		}
	})
	t.Run("the sandbox's own wins", func(t *testing.T) {
		r := runReport(t, Spec{Home: home}, []string{
			"FOO=bar", "HOME=/evil", "TMPDIR=/evil", "XDG_RUNTIME_DIR=/run/user/1000", "XDG_DATA_HOME=/evil",
		})
		for _, kv := range []string{"FOO=bar", "HOME=" + home, "TMPDIR=/tmp", "XDG_RUNTIME_DIR=/tmp", "XDG_DATA_HOME=" + home + "/.local/share"} {
			if !slices.Contains(r.Env, kv) {
				t.Errorf("env lacks %s: %q", kv, r.Env)
			}
		}
		for _, kv := range r.Env {
			if strings.Contains(kv, "evil") || strings.Contains(kv, "/run/user") {
				t.Errorf("env has the caller's %s", kv)
			}
		}
	})
}

func TestCommandDefaults(t *testing.T) {
	home := t.TempDir()
	r := runReport(t, Spec{Home: home}, nil)
	if r.Dir != home {
		t.Errorf("working directory = %s, want the home %s", r.Dir, home)
	}
	if r.Hostname != "sandbox" {
		t.Errorf("hostname = %q, want sandbox", r.Hostname)
	}
	if r = runReport(t, Spec{Home: home, Hostname: "box"}, nil); r.Hostname != "box" {
		t.Errorf("hostname = %q, want box", r.Hostname)
	}
}

func TestCommandRefusesRoot(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "/proc/self/exe", "refuses-root")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  unix.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}

func TestCommandRefusals(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, tc := range []struct {
		name string
		spec Spec
	}{
		{"no command", Spec{Home: "/h"}},
		{"an unknown kernel", Spec{Command: []string{"true"}, Home: "/h", Kernel: "loose"}},
		{"an unknown network", Spec{Command: []string{"true"}, Home: "/h", Network: 7}},
		{"listeners on the host's network", Spec{Command: []string{"true"}, Home: "/h", Network: NetworkHost, Listen: 1}},
		{"loopback ports on the host's network", Spec{Command: []string{"true"}, Home: "/h", Network: NetworkHost, Loopback: 1}},
		{"too many listeners", Spec{Command: []string{"true"}, Home: "/h", Listen: maxListen + 1}},
		{"a negative count", Spec{Command: []string{"true"}, Home: "/h", Loopback: -1}},
		{"a nil file", Spec{Command: []string{"true"}, Home: "/h", Files: []*os.File{f, nil}}},
		{"an unknown resource", Spec{Command: []string{"true"}, Home: "/h", Rlimits: []Rlimit{{Resource: 99}}}},
		{"a soft limit above the hard one", Spec{Command: []string{"true"}, Home: "/h", Rlimits: []Rlimit{{ResourceCore, 2, 1}}}},
		{"a NUL in the hostname", Spec{Command: []string{"true"}, Home: "/h", Hostname: "a\x00b"}},
	} {
		if c, err := Command(t.Context(), tc.spec); err == nil {
			t.Errorf("%s: Command returned %v and no error", tc.name, c)
		}
	}
}

// TestCommandKernel checks that Command keeps the level it was given or
// refuses it, and never starts a weaker one. kernelFilterBuilds says whether
// this architecture has a system call list.
func TestCommandKernel(t *testing.T) {
	for _, level := range []Kernel{"", KernelStrict, KernelNested, KernelOpen} {
		c, err := Command(t.Context(), Spec{Command: []string{"true"}, Home: "/h", Kernel: level})
		if level != KernelOpen && !kernelFilterBuilds {
			if err == nil {
				t.Errorf("kernel %q was accepted without a system call list", level)
			}
			continue
		}
		if err != nil {
			t.Errorf("kernel %q: %v", level, err)
			continue
		}
		want := level
		if want == "" {
			want = KernelStrict
		}
		if c.spec.Kernel != want {
			t.Errorf("kernel %q became %q", level, c.spec.Kernel)
		}
	}
}

func TestCommandFiles(t *testing.T) {
	in, err := os.CreateTemp(t.TempDir(), "in")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if _, err := in.WriteString("from the caller"); err != nil {
		t.Fatal(err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	c, stdout, stderr := testCmd(t, t.Context(), Spec{Files: []*os.File{in, pw}}, "files")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	// The command has its own copy, and the caller's is still open, so
	// closing it ends the pipe once the command exits.
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("files: %v: %s", err, stderr)
	}
	got, err := io.ReadAll(pr)
	if err != nil || string(got) != "from the command" {
		t.Errorf("the pipe held %q, %v", got, err)
	}
	// The caller's file is still its own.
	if _, err := in.Stat(); err != nil {
		t.Errorf("the caller's file was closed: %v", err)
	}
	line, rest, _ := strings.Cut(stdout.String(), "\n")
	if line != "from the caller" {
		t.Errorf("read %q from descriptor 3", line)
	}
	// The command holds exactly its two files, at 3 and 4: not the control
	// socket, the lifeline, bubblewrap's options or info descriptor, nor any
	// of the bind sources.
	var fds map[int]string
	if err := json.Unmarshal([]byte(rest), &fds); err != nil {
		t.Fatalf("descriptors %q: %v", rest, err)
	}
	if _, ok := fds[3]; len(fds) != 2 || !ok || !strings.HasPrefix(fds[4], "pipe:") {
		t.Errorf("descriptors from 3 up = %v", fds)
	}
}

func TestCommandHoldsNoSetupDescriptors(t *testing.T) {
	r := runReport(t, Spec{}, nil)
	if len(r.Fds) != 0 {
		t.Errorf("the command holds descriptors from 3 up: %v", r.Fds)
	}
}

// startSleeper starts a sandbox whose command waits to be killed, once it
// has said so.
func startSleeper(t *testing.T, ctx context.Context) *Cmd {
	t.Helper()
	c, _, stderr := testCmd(t, ctx, Spec{}, "sleep")
	if err := c.Start(); err != nil {
		t.Fatalf("%v: %s", err, stderr)
	}
	return c
}

// gone reports, within a few seconds, whether the process pid has exited.
func gone(pid int) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}

func TestCommandPid(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := startSleeper(t, ctx)
	pid := c.Pid()
	if pid <= 0 || pid == c.run.cmd.Process.Pid {
		t.Fatalf("Pid = %d, bubblewrap is %d", pid, c.run.cmd.Process.Pid)
	}
	// The host's pid of a process that is pid 1 in its own namespace shows
	// both numbers in NSpid.
	status, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	var nspid []string
	for line := range strings.Lines(string(status)) {
		if v, ok := strings.CutPrefix(line, "NSpid:"); ok {
			nspid = strings.Fields(v)
		}
	}
	if !slices.Equal(nspid, []string{strconv.Itoa(pid), "1"}) {
		t.Errorf("NSpid of %d = %q, want it and 1", pid, nspid)
	}
	cancel()
	_ = c.Wait()
	if !gone(pid) {
		t.Errorf("pid 1 (%d) outlived the cancelled context", pid)
	}
}

func TestCommandLifeline(t *testing.T) {
	c := startSleeper(t, t.Context())
	pid := c.Pid()
	// Only the lifeline's close can end it: bubblewrap and the parent are
	// both running.
	if err := c.run.lifeline.Close(); err != nil {
		t.Fatal(err)
	}
	if !gone(pid) {
		t.Fatalf("pid 1 (%d) is still there after the lifeline closed", pid)
	}
	if err := c.Wait(); err == nil {
		t.Error("Wait returned no error for a sandbox that was ended")
	}
}

// TestCommandParentKilled checks that a parent killed without a chance to
// clean up takes its sandbox with it.
func TestCommandParentKilled(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(Spec{Home: t.TempDir(), Command: []string{exe, "sleep"}, Read: []string{filepath.Dir(exe)}})
	if err != nil {
		t.Fatal(err)
	}
	parent := exec.CommandContext(t.Context(), "/proc/self/exe", "start-and-hang", string(body))
	out, err := parent.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Wait() }()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if !gone(pid) {
		t.Errorf("pid 1 (%d) outlived its parent", pid)
	}
}

func TestCommandContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	c := startSleeper(t, ctx)
	pid := c.Pid()
	cancel()
	if err := c.Wait(); err == nil {
		t.Error("Wait returned no error for a cancelled sandbox")
	}
	if !gone(pid) {
		t.Errorf("pid 1 (%d) outlived the cancelled context", pid)
	}
}

func TestNetworkNone(t *testing.T) {
	r := runReport(t, Spec{}, nil)
	if !slices.Equal(r.Ifaces, []string{"lo"}) {
		t.Errorf("interfaces = %q, want only lo", r.Ifaces)
	}
}

func TestListen(t *testing.T) {
	c, _, stderr := testCmd(t, t.Context(), Spec{Listen: 2, Loopback: 1}, "dial-listen")
	if want := []string{"127.0.0.1:3128", "127.0.0.1:3129"}; !slices.Equal(c.ListenAddrs(), want) {
		t.Fatalf("ListenAddrs = %q, want %q", c.ListenAddrs(), want)
	}
	if want := []int{4444}; !slices.Equal(c.LoopbackPorts(), want) {
		t.Fatalf("LoopbackPorts = %v, want %v", c.LoopbackPorts(), want)
	}
	if c.Listeners() != nil {
		t.Fatal("Listeners before Start")
	}
	// Built again with the arguments the addresses decide.
	c.spec.Command = append(c.spec.Command, c.ListenAddrs()[1], net.JoinHostPort("127.0.0.1", strconv.Itoa(c.LoopbackPorts()[0])))
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	lns := c.Listeners()
	if len(lns) != 2 {
		t.Fatalf("%d listeners, want 2", len(lns))
	}
	for i, ln := range lns {
		if ln.Addr().String() != c.ListenAddrs()[i] {
			t.Errorf("listener %d is on %s, want %s", i, ln.Addr(), c.ListenAddrs()[i])
		}
		defer ln.Close()
	}
	// The listeners are the sandbox's, not the host's: nothing on the host
	// answers on the same address.
	if conn, err := net.DialTimeout("tcp", c.ListenAddrs()[0], time.Second); err == nil {
		// Only the sandbox's own network namespace has it, and the caller's
		// listener answers there. Reaching it from here means it is not private.
		conn.Close()
		t.Errorf("the host reached %s", c.ListenAddrs()[0])
	}
	served := make(chan string, 1)
	go func() {
		conn, err := lns[1].Accept()
		if err != nil {
			served <- err.Error()
			return
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		fmt.Fprintln(conn, "world")
		served <- line
	}()
	if err := c.Wait(); err != nil {
		t.Fatalf("dial the listener: %v: %s", err, stderr)
	}
	if got := <-served; got != "hello\n" {
		t.Errorf("the listener read %q", got)
	}
}

func TestStartFailureIsReported(t *testing.T) {
	c, _, _ := testCmd(t, t.Context(), Spec{Listen: 1}, "sleep")
	c.spec.Command = []string{"/nonexistent/command"}
	err := c.Start()
	if err == nil || !strings.Contains(err.Error(), "/nonexistent/command") {
		t.Fatalf("Start = %v, want an error naming the command", err)
	}
	if c.Pid() != 0 || c.Listeners() != nil {
		t.Error("a failed Start left a pid or listeners")
	}
	if err := c.Start(); err == nil {
		t.Error("a second Start succeeded")
	}
}

func TestRlimits(t *testing.T) {
	r := runReport(t, Spec{Rlimits: []Rlimit{
		{ResourceCore, 0, 4096},
		{ResourceFileSize, 1 << 20, 1 << 21},
		{ResourceOpenFiles, 100, 200},
	}}, nil)
	want := map[string]Rlimit{"core": {Soft: 0, Hard: 4096}, "fsize": {Soft: 1 << 20, Hard: 1 << 21}}
	for name, w := range want {
		if got := r.Limits[name]; got != w {
			t.Errorf("%s limit = %+v, want %+v", name, got, w)
		}
	}
	// Go raises its own soft limit to the hard one, so only the hard one
	// shows that os/exec did not put the original back.
	if got := r.Limits["nofile"]; got.Hard != 200 {
		t.Errorf("nofile limit = %+v, want a hard limit of 200", got)
	}
}

func TestCmdOptions(t *testing.T) {
	c, _, _ := testCmd(t, t.Context(), Spec{}, "sleep")
	if c.CgroupFD != -1 {
		t.Errorf("CgroupFD = %d, want -1", c.CgroupFD)
	}
	c.WaitDelay = 3 * time.Second
	c.CgroupFD = 0 // none, as -1 is
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if got := c.run.cmd.WaitDelay; got != 3*time.Second {
		t.Errorf("WaitDelay = %v", got)
	}
	bwrap := c.run.cmd.Process.Pid
	if pgid, err := unix.Getpgid(bwrap); err != nil || pgid != bwrap {
		t.Errorf("process group = %d, %v, want its own, %d", pgid, err, bwrap)
	}
	pid := c.Pid()
	if err := c.run.lifeline.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.Wait()
	if !gone(pid) {
		t.Error("pid 1 stayed")
	}

	// A descriptor that is no cgroup is passed to the kernel, which refuses
	// it, so the option is used.
	dir, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	c, _, _ = testCmd(t, t.Context(), Spec{}, "sleep")
	c.CgroupFD = int(dir.Fd())
	if err := c.Start(); err == nil {
		t.Error("Start in a cgroup that is /: no error")
	}
}
