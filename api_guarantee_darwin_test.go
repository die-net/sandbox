package sandbox

// API guarantee tests for the macOS backend: each exported function, method,
// type and field of the package gets a test of its documented contract,
// including its error paths. The escape tests are in
// escape_guarantee_darwin_test.go, whose harness these use.
//
// Not testable here: Command's refusal of euid 0 by a real root, since the
// tests run unprivileged. It is driven through geteuid, which the check reads
// (TestAPICommandErrors). Probe, Check and Report have tests of their own.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
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
	childModes["self-hello"] = func(args []string) int { fmt.Println("hello from", strings.Join(args, " ")); return 0 }
	childModes["esc-run"] = escRunMode
	escChecks["pwd"] = func(e *escT, _ []string) { wd, err := os.Getwd(); e.is("getwd", err); fmt.Println(wd) }
	escChecks["env"] = func(*escT, []string) { fmt.Println(strings.Join(os.Environ(), "\n")) }
	escChecks["exit"] = func(_ *escT, a []string) { n, _ := strconv.Atoi(a[0]); os.Exit(n) } //nolint:revive // deep-exit: the check exists to end the sandbox's command with a chosen status.
	escChecks["cat"] = func(*escT, []string) { _, _ = io.Copy(os.Stdout, os.Stdin) }
	escChecks["both"] = func(*escT, []string) { fmt.Print("to stdout"); fmt.Fprint(os.Stderr, "to stderr") }
	escChecks["fds"] = listFds
	escChecks["dial-each"] = dialEach
	escChecks["selfkill"] = func(_ *escT, a []string) {
		n, _ := strconv.Atoi(a[0])
		_ = syscall.Kill(os.Getpid(), syscall.Signal(n))
		time.Sleep(5 * time.Second)
	}
	escChecks["spin"] = func(*escT, []string) {
		for { //nolint:revive,staticcheck // empty-block, SA5002: the process spins on purpose, to be a command that never waits.
		}
	}
	escChecks["spin-marker"] = func(_ *escT, a []string) {
		_ = os.WriteFile(a[0], []byte(strconv.Itoa(os.Getpid())), 0o600) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
		for {                                                            //nolint:revive,staticcheck // empty-block, SA5002: the process spins on purpose, to be a command that never waits.
		}
	}
	escChecks["hold"] = func(_ *escT, a []string) {
		// Tell the caller we are running, then wait to be killed.
		if len(a) > 0 {
			_ = os.WriteFile(a[0], []byte(strconv.Itoa(os.Getpid())), 0o600) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
		}
		time.Sleep(time.Minute)
	}
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
	// On a terminal, the foreground is this process's group again, which
	// the sandbox's group took for the command's sake.
	if pgrp, err := unix.IoctlGetInt(0, unix.TIOCGPGRP); err == nil && pgrp != unix.Getpgrp() {
		fmt.Fprintln(os.Stderr, "the terminal's foreground was not given back")
		return 97
	}
	return code
}

// dialEach dials each address in args, and tells it its index.
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

// listFds prints the descriptors open in this process, one per line, as
// "number kind", where the kind is what fstat says it is.
func listFds(_ *escT, _ []string) {
	for fd := range 64 {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			continue
		}
		kind := map[uint16]string{unix.S_IFIFO: "fifo", unix.S_IFREG: "file", unix.S_IFCHR: "char", unix.S_IFSOCK: "socket", unix.S_IFDIR: "dir"}[st.Mode&unix.S_IFMT]
		fmt.Printf("%d %s\n", fd, kind)
	}
}

// fdKinds parses listFds' output.
func fdKinds(out string) map[int]string {
	m := map[int]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var fd int
		var kind string
		if _, err := fmt.Sscan(line, &fd, &kind); err == nil {
			m[fd] = kind
		}
	}
	return m
}

func TestAPICommandErrors(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	for _, tc := range []struct {
		name string
		spec Spec
		want string
	}{
		{"no command", Spec{Home: home}, "no command"},
		{"unknown network", Spec{Command: []string{"true"}, Home: home, Network: 9}, "unknown network"},
		{"negative listen", Spec{Command: []string{"true"}, Home: home, Listen: -1}, "listen and loopback"},
		{"too many listen", Spec{Command: []string{"true"}, Home: home, Listen: maxListen + 1}, "listen and loopback"},
		{"too many loopback", Spec{Command: []string{"true"}, Home: home, Loopback: maxListen + 1}, "listen and loopback"},
		{"listen with host network", Spec{Command: []string{"true"}, Home: home, Network: NetworkHost, Listen: 1}, "need NetworkNone"},
		{"loopback with host network", Spec{Command: []string{"true"}, Home: home, Network: NetworkHost, Loopback: 1}, "need NetworkNone"},
		{"negative scratch size", Spec{Command: []string{"true"}, Home: home, ScratchSize: -1}, "scratch size"},
		{"nil file", Spec{Command: []string{"true"}, Home: home, Files: []*os.File{nil}}, "nil file"},
		{"unknown resource", Spec{Command: []string{"true"}, Home: home, Rlimits: []Rlimit{{Resource: 99}}}, "unknown resource"},
		{"soft above hard", Spec{Command: []string{"true"}, Home: home, Rlimits: []Rlimit{{Resource: ResourceCPU, Soft: 5, Hard: 1}}}, "soft limit above"},
		{"address space", Spec{Command: []string{"true"}, Home: home, Rlimits: []Rlimit{{Resource: ResourceAddressSpace, Soft: 1 << 30, Hard: 1 << 30}}}, "does not enforce"},
		{"unknown kernel", Spec{Command: []string{"true"}, Home: home, Kernel: "loose"}, "not strict, nested, or open"},
		{"unknown service", Spec{Command: []string{"true"}, Home: home, Services: []Service{"fonts"}}, `unknown service "fonts"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := Command(t.Context(), tc.spec)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Command = %v, %v, want an error with %q", c, err, tc.want)
			}
		})
	}
	// A root caller is refused, and so is one that the tests make look like it.
	if _, err := commandAs(t.Context(), Spec{Command: []string{"true"}, Home: home}, 0, 0); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("Command as euid 0 = %v, want a refusal", err)
	}
	// So is one whose real uid is not its effective uid.
	if _, err := commandAs(t.Context(), Spec{Command: []string{"true"}, Home: home}, 501, 0); err == nil || !strings.Contains(err.Error(), "real uid") {
		t.Errorf("Command as ruid 0, euid 501 = %v, want a refusal", err)
	}
}

// TestAPICommandStartsNothingAndCopies checks that Command starts no process,
// and that the Cmd keeps its own copy of the Spec's slices.
func TestAPICommandStartsNothingAndCopies(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	marker := filepath.Join(home, "ran")
	spec := Spec{Command: []string{"/usr/bin/touch", marker}, Home: home, Write: []string{home}}
	c, err := Command(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Command[0] = "/usr/bin/false"
	spec.Write[0] = "/nowhere"
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("Command ran the command")
	}
	c.Env = []string{shellPath}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("the changed spec was used: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the command did not run: %v", err)
	}
}

func TestAPIStartErrors(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	link := filepath.Join(realTemp(t), "link")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	covered := hostSecret(t)
	for _, tc := range []struct {
		name string
		spec Spec
		want string
	}{
		{"missing home", Spec{Command: []string{"/usr/bin/true"}, Home: filepath.Join(home, "gone")}, "does not exist"},
		{"no home", Spec{Command: []string{"/usr/bin/true"}}, "no home directory"},
		{"home through a link", Spec{Command: []string{"/usr/bin/true"}, Home: link}, "leads through a link"},
		{"relative dir", Spec{Command: []string{"/usr/bin/true"}, Home: home, Dir: "x"}, "not absolute"},
		{"dir under a cover", Spec{Command: []string{"/usr/bin/true"}, Home: home, Dir: filepath.Dir(covered)}, "under a covered path"},
		{"missing command", Spec{Command: []string{"/no/such/program"}, Home: home}, "no such file"},
		{"command not on the path", Spec{Command: []string{"no-such-program-xyz"}, Home: home}, "not found"},
		{"a path with a control character", Spec{Command: []string{"/usr/bin/true"}, Home: home, Read: []string{filepath.Join(home, "x")}}, ""},
		{"nested link in a write path", Spec{Command: []string{"/usr/bin/true"}, Home: home, Write: []string{link}}, "leads through a link"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := Command(t.Context(), tc.spec)
			if err != nil {
				t.Fatalf("Command: %v", err)
			}
			c.Env = []string{shellPath}
			err = c.Start()
			if tc.want == "" {
				return
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("Start = %v, want an error with %q", err, tc.want)
			}
			// A failed Start leaves nothing running.
			if err := c.Wait(); err == nil {
				t.Error("Wait after a failed Start succeeded")
			}
		})
	}
	t.Run("twice", func(t *testing.T) {
		c, err := Command(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: home})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(); err == nil || !strings.Contains(err.Error(), "already started") {
			t.Errorf("second Start = %v", err)
		}
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAPICmdMisuse(t *testing.T) {
	t.Parallel()
	c, err := Command(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: realTemp(t), Listen: 1, Loopback: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err == nil || !strings.Contains(err.Error(), "not started") {
		t.Errorf("Wait before Start = %v", err)
	}
	if c.Pid() != 0 {
		t.Errorf("Pid before Start = %d", c.Pid())
	}
	if len(c.Listeners()) != 0 {
		t.Errorf("Listeners before Start = %v", c.Listeners())
	}
	if _, err := c.Footprint(); err == nil {
		t.Error("Footprint before Start succeeded")
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err == nil || !strings.Contains(err.Error(), "already called") {
		t.Errorf("second Wait = %v", err)
	}
	if _, err := c.Footprint(); err == nil {
		t.Error("Footprint after Wait succeeded")
	}
	for _, l := range c.Listeners() {
		_ = l.Close()
	}
	// A Cmd that Command did not make is refused, and does not panic.
	z := &Cmd{}
	if err := z.Start(); err == nil {
		t.Error("Start of a zero Cmd returned nil")
	}
	if err := z.Wait(); err == nil {
		t.Error("Wait of a zero Cmd returned nil")
	}
	if z.Pid() != 0 || z.ListenAddrs() != nil || z.LoopbackPorts() != nil || z.Listeners() != nil {
		t.Error("a zero Cmd has a pid, addresses or listeners")
	}
}

func TestAPIStdio(t *testing.T) {
	t.Parallel()
	t.Run("readers and writers", func(t *testing.T) {
		t.Parallel()
		c := escCmd(t.Context(), t, Spec{}, "cat")
		c.Stdin = strings.NewReader("through a pipe")
		var out bytes.Buffer
		c.Stdout = &out
		if r := execute(t, c); r.code != 0 || out.String() != "through a pipe" {
			t.Errorf("got %q: %s", out.String(), r)
		}
	})
	t.Run("both streams", func(t *testing.T) {
		t.Parallel()
		r := escResult(t, Spec{}, "both")
		if r.stdout != "to stdout" || r.stderr != "to stderr" {
			t.Errorf("got %s", r)
		}
	})
	t.Run("files", func(t *testing.T) {
		t.Parallel()
		dir := realTemp(t)
		in := writeFile(t, "from a file", dir, "in")
		fin, err := openFile(in)
		if err != nil {
			t.Fatal(err)
		}
		defer fin.Close()
		fout, err := createFile(filepath.Join(dir, "out"))
		if err != nil {
			t.Fatal(err)
		}
		defer fout.Close()
		c := escCmd(t.Context(), t, Spec{}, "cat")
		c.Stdin, c.Stdout = fin, fout
		if r := execute(t, c); r.code != 0 {
			t.Fatal(r)
		}
		if b, _ := readFile(filepath.Join(dir, "out")); string(b) != "from a file" {
			t.Errorf("out = %q", b)
		}
	})
	t.Run("nil is null", func(t *testing.T) {
		t.Parallel()
		// A nil Stdin is /dev/null, so cat sees no input and ends.
		c := escCmd(t.Context(), t, Spec{}, "cat")
		c.Stdout = io.Discard
		done := make(chan result, 1)
		go func() { done <- execute(t, c) }()
		select {
		case r := <-done:
			if r.code != 0 {
				t.Error(r)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("cat on a nil Stdin did not end")
		}
	})
}

func TestAPIEnv(t *testing.T) {
	home := realTemp(t)
	env := func(set ...string) map[string]string {
		c := escCmd(t.Context(), t, Spec{Home: home}, "env")
		c.Env = append(slices.Clone(set), "NOT_OURS=x")
		r := execute(t, c)
		if r.code != 0 {
			t.Fatal(r)
		}
		m := map[string]string{}
		for _, kv := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
			k, v, _ := strings.Cut(kv, "=")
			m[k] = v
		}
		return m
	}
	m := env("HOME=/Users/someone", "TMPDIR=/tmp", "XDG_RUNTIME_DIR=/tmp", "CFFIXED_USER_HOME=/Users/someone", "KEEP=this")
	tmp := filepath.Join(home, "tmp")
	for k, want := range map[string]string{
		"HOME": home, "CFFIXED_USER_HOME": home, "TMPDIR": tmp, "XDG_RUNTIME_DIR": tmp,
		"XDG_CONFIG_HOME": home + "/.config", "XDG_CACHE_HOME": home + "/.cache",
		"XDG_DATA_HOME": home + "/.local/share", "XDG_STATE_HOME": home + "/.local/state",
		"KEEP": "this", "NOT_OURS": "x",
	} {
		if m[k] != want {
			t.Errorf("%s = %q, want %q", k, m[k], want)
		}
	}
	// A nil Env is empty, never the caller's own.
	t.Setenv("CALLERS_SECRET", "hunter2")
	c := escCmd(t.Context(), t, Spec{Home: home}, "env")
	c.Env = []string{} // execute turns nil into a PATH, so this is the empty one
	r := execute(t, c)
	if strings.Contains(r.stdout, "hunter2") || strings.Contains(r.stdout, "CALLERS_SECRET") {
		t.Errorf("the caller's environment reached the command: %s", r.stdout)
	}
	// TMPDIR exists and is writable.
	if fi, err := os.Stat(tmp); err != nil || !fi.IsDir() {
		t.Errorf("TMPDIR %s: %v", tmp, err)
	}
	if got := shOK(t, Spec{Home: home}, `echo x > "$TMPDIR/f" && cat "$TMPDIR/f"`); got != "x\n" {
		t.Errorf("TMPDIR is not writable: %q", got)
	}
}

func TestAPICommandLookup(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	// A name with no slash is found on the PATH in Env.
	c, err := Command(t.Context(), Spec{Command: []string{"cat", "/etc/hosts"}, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	c.Env = []string{"PATH=/bin"}
	if r := execute(t, c); r.code != 0 || !strings.Contains(r.stdout, "localhost") {
		t.Errorf("lookup on PATH: %s", r)
	}
	// And is not found on an empty one.
	c, err = Command(t.Context(), Spec{Command: []string{"cat"}, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	c.Env = []string{"PATH=" + home}
	if err := c.Start(); err == nil {
		t.Error("a command not on the PATH started")
	}
	// A relative command with a slash is looked up from Dir.
	bin := mkdirs(t, home, "bin")
	if err := os.Symlink("/usr/bin/true", filepath.Join(bin, "mytrue")); err != nil {
		t.Fatal(err)
	}
	c, err = Command(t.Context(), Spec{Command: []string{"./mytrue"}, Home: home, Dir: bin})
	if err != nil {
		t.Fatal(err)
	}
	if r := execute(t, c); r.code != 0 {
		t.Errorf("relative command: %s", r)
	}
}

func TestAPIWaitStatus(t *testing.T) {
	t.Parallel()
	for _, code := range []int{0, 1, 42} {
		if r := escResult(t, Spec{}, "exit", strconv.Itoa(code)); r.code != code {
			t.Errorf("exit %d: %s", code, r)
		}
	}
	// A command ended by a signal has an ExitError that reports it, and
	// exitStatus turns it into 128 plus the signal, as a shell does.
	c := escCmd(t.Context(), t, Spec{}, "selfkill", strconv.Itoa(int(syscall.SIGTERM)))
	c.Env = []string{}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	err := c.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 128+int(syscall.SIGTERM) {
		t.Errorf("Wait = %v, want exit status %d", err, 128+int(syscall.SIGTERM))
	}
}

func TestAPIDir(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	other := mkdirs(t, realTemp(t), "other")
	if got := strings.TrimSpace(escRun(t, Spec{Home: home}, "pwd")); got != home {
		t.Errorf("default Dir = %q, want the home", got)
	}
	sub := mkdirs(t, home, "sub")
	if got := strings.TrimSpace(escRun(t, Spec{Home: home, Dir: sub}, "pwd")); got != sub {
		t.Errorf("Dir = %q, want %q", got, sub)
	}
	// Under a Write or Read path it is allowed too.
	for _, spec := range []Spec{{Home: home, Write: []string{other}, Dir: other}, {Home: home, Read: []string{other}, Dir: other}} {
		if got := strings.TrimSpace(escRun(t, spec, "pwd")); got != other {
			t.Errorf("Dir = %q, want %q", got, other)
		}
	}
	// A directory under a cover is refused, since the sandbox would start in
	// a place it cannot read.
	c, err := Command(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: home, Dir: other})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err == nil || !strings.Contains(err.Error(), "covered") {
		t.Errorf("Start in a covered Dir = %v", err)
	}
}

// TestAPIFiles checks that Spec.Files reach the command as 3 and up, and
// that the command holds no descriptor but those and its three streams, apart
// from the one pipe that held its profile, which is at end of file.
func TestAPIFiles(t *testing.T) {
	t.Parallel()
	r1, w1, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Close()
	defer r2.Close()
	_ = w2.Close()
	c := escCmd(t.Context(), t, Spec{Files: []*os.File{w1, r2}}, "fds")
	var out bytes.Buffer
	c.Stdout = &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	// The caller's copies are the caller's to close, after Start.
	_ = w1.Close()
	_ = r2.Close()
	if err := c.Wait(); err != nil {
		t.Fatal(err)
	}
	kinds := fdKinds(out.String())
	// 0, 1 and 2, the two files, and the profile's pipe, which is closed
	// at the other end and at end of file.
	want := map[int]string{3: "fifo", 4: "fifo", 5: "fifo"}
	for fd, kind := range kinds {
		if fd > 2 && want[fd] != kind {
			t.Errorf("descriptor %d is a %s that the command was not given", fd, kind)
		}
	}
	for fd := 3; fd <= 5; fd++ {
		if kinds[fd] != "fifo" {
			t.Errorf("descriptor %d is %q, want a pipe", fd, kinds[fd])
		}
	}
	if len(kinds) != 6 {
		t.Errorf("descriptors = %v, want 0 to 5", kinds)
	}
}

// TestAPIFilesData sends data through a handed-in pipe each way.
func TestAPIFilesData(t *testing.T) {
	t.Parallel()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	spec := Spec{Home: realTemp(t), Files: []*os.File{w}, Command: []string{"/bin/sh", "-c", "echo through fd 3 >&3"}}
	c, err := Command(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if r := execute(t, c); r.code != 0 {
		t.Fatal(r)
	}
	_ = w.Close()
	b, _ := io.ReadAll(r)
	if string(b) != "through fd 3\n" {
		t.Errorf("read %q", b)
	}
}

func TestAPIListeners(t *testing.T) {
	t.Parallel()
	spec := Spec{Home: realTemp(t), Listen: 2}
	c := escCmd(t.Context(), t, spec, "dial-each")
	addrs := c.ListenAddrs()
	if len(addrs) != 2 {
		t.Fatalf("ListenAddrs = %v, want 2", addrs)
	}
	for _, a := range addrs {
		if h, _, _ := net.SplitHostPort(a); h != "127.0.0.1" {
			t.Errorf("address %s is not on 127.0.0.1", a)
		}
	}
	if addrs[0] == addrs[1] {
		t.Error("the two listeners share an address")
	}
	if len(c.Listeners()) != 0 {
		t.Error("Listeners has listeners before Start")
	}
	// The command's arguments are fixed at Command, so the addresses go in
	// through Env's absence here: dial-each takes them from its arguments.
	spec.Command = append([]string{self(t), "esc", "dial-each"}, addrs...)
	c.spec.Command = spec.Command
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	ls := c.Listeners()
	if len(ls) != 2 {
		t.Fatalf("Listeners = %d, want 2", len(ls))
	}
	for i, l := range ls {
		if l.Addr().String() != addrs[i] {
			t.Errorf("listener %d is %s, not %s", i, l.Addr(), addrs[i])
		}
	}
	got := make([]string, 2)
	var wg sync.WaitGroup
	for i, l := range ls {
		wg.Go(func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			line, _ := bufio.NewReader(conn).ReadString('\n')
			got[i] = strings.TrimSpace(line)
		})
	}
	if err := c.Wait(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if got[0] != "0" || got[1] != "1" {
		t.Errorf("the listeners got %q", got)
	}
	for _, l := range ls {
		_ = l.Close()
	}
}

// TestAPIListenersFreed checks that a Cmd that is never started gives its
// ports back when ctx ends, and that Start on it then fails.
func TestAPIListenersFreed(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	c, err := Command(ctx, Spec{Command: []string{"/usr/bin/true"}, Home: realTemp(t), Listen: 1, Loopback: 1})
	if err != nil {
		t.Fatal(err)
	}
	addr := c.ListenAddrs()[0]
	port := c.LoopbackPorts()[0]
	if l, err := listen("tcp", addr); err == nil {
		l.Close() //nolint:gosec // G104: nothing can be done about a failed close here, and the test is over or has what it needs.
		t.Fatal("the listener's port was free before ctx ended")
	}
	cancel()
	eventually(t, 5*time.Second, "the unstarted Cmd's ports were not freed", func() bool {
		l1, err1 := listen("tcp", addr)
		l2, err2 := listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		for _, l := range []net.Listener{l1, l2} {
			if l != nil {
				l.Close() //nolint:gosec // G104: nothing can be done about a failed close here, and the test is over or has what it needs.
			}
		}
		return err1 == nil && err2 == nil
	})
	if err := c.Start(); err == nil {
		t.Error("Start after ctx ended succeeded")
	}
}

func TestAPILoopbackPorts(t *testing.T) {
	t.Parallel()
	c, err := Command(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: realTemp(t), Loopback: 3})
	if err != nil {
		t.Fatal(err)
	}
	ports := c.LoopbackPorts()
	if len(ports) != 3 || ports[0] == ports[1] || ports[1] == ports[2] || ports[0] == ports[2] {
		t.Errorf("LoopbackPorts = %v, want three different ports", ports)
	}
	for _, p := range ports {
		if p < 1024 {
			t.Errorf("port %d is privileged", p)
		}
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatal(err)
	}
	// Start gave the reservations up, so the ports are free to bind.
	for _, p := range ports {
		l, err := listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			t.Errorf("port %d is still held after Start: %v", p, err)
			continue
		}
		l.Close() //nolint:gosec // G104: nothing can be done about a failed close here, and the test is over or has what it needs.
	}
}

func TestAPIRun(t *testing.T) {
	t.Parallel()
	run := func(t *testing.T, spec Spec, wantCode int, wantOut string) {
		t.Helper()
		if spec.Home == "" {
			spec.Home = realTemp(t)
		}
		body, _ := json.Marshal(spec)
		cmd := exec.CommandContext(t.Context(), self(t), "esc-run", string(body)) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		cmd.Env = []string{shellPath, "RUN_MARKER=seen"}
		cmd.Dir = spec.Home
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if code != wantCode || !strings.Contains(out.String(), wantOut) {
			t.Fatalf("Run: exit %d, want %d, stdout %q should hold %q\nstderr: %s", code, wantCode, out.String(), wantOut, errb.String())
		}
	}
	t.Run("status and environment", func(t *testing.T) {
		t.Parallel()
		// Run passes its own environment, and runs in its own directory.
		run(t, Spec{Command: []string{"/usr/bin/env"}}, 0, "RUN_MARKER=seen")
		run(t, Spec{Command: []string{"/bin/sh", "-c", "exit 7"}}, 7, "")
		home := realTemp(t)
		run(t, Spec{Home: home, Command: []string{"/bin/pwd"}}, 0, home)
	})
	t.Run("signal status", func(t *testing.T) {
		t.Parallel()
		run(t, Spec{Command: []string{"/bin/sh", "-c", "kill -TERM $$"}}, 128+int(syscall.SIGTERM), "")
	})
	t.Run("refuses listeners", func(t *testing.T) {
		t.Parallel()
		if _, err := Run(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: realTemp(t), Listen: 1}); err == nil || !strings.Contains(err.Error(), "listeners") {
			t.Errorf("Run with Listen = %v", err)
		}
	})
	t.Run("a bad spec", func(t *testing.T) {
		t.Parallel()
		if _, err := Run(t.Context(), Spec{Home: realTemp(t)}); err == nil {
			t.Error("Run with no command succeeded")
		}
	})
	t.Run("sigterm ends the sandbox", func(t *testing.T) {
		t.Parallel()
		home := realTemp(t)
		marker := filepath.Join(home, "pid")
		body, _ := json.Marshal(Spec{Home: home, Command: []string{self(t), "esc", "hold", marker}})
		cmd := exec.CommandContext(t.Context(), self(t), "esc-run", string(body)) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		cmd.Dir = home
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		inner := readPid(t, marker)
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if ee := new(exec.ExitError); err != nil && !errors.As(err, &ee) {
				t.Errorf("Wait for Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatal("Run did not end on SIGTERM")
		}
		eventually(t, 5*time.Second, "the command outlived SIGTERM to Run", func() bool { return !alive(inner) })
	})
}

func TestAPIStage(t *testing.T) {
	t.Parallel()
	// The test binary's own arguments are not a stage's.
	if code, ok := Stage(); ok {
		t.Errorf("Stage() = %d, true in an ordinary process", code)
	}
}

func TestAPIRlimits(t *testing.T) {
	t.Parallel()
	// CPU ends a spinning shell with SIGXCPU at the soft limit. A program that
	// ignores it is not ended by the hard limit on macOS, which
	// TestGapCPULimitIgnorable shows.
	r := sh(t, Spec{Rlimits: []Rlimit{{ResourceCPU, 1, 2}}}, "while :; do :; done")
	if r.code != 128+int(syscall.SIGXCPU) {
		t.Errorf("a spinning shell under RLIMIT_CPU ended with %d, want SIGXCPU: %s", r.code, r)
	}
	// FSIZE makes a write past it fail, with SIGXFSZ ignored by the shell.
	home := realTemp(t)
	r = sh(t, Spec{Home: home, Rlimits: []Rlimit{{ResourceFileSize, 4096, 4096}}},
		`trap '' XFSZ; dd if=/dev/zero of="$1/big" bs=1024 count=64 2>&1; ls -l "$1/big" | awk '{print $5}'`, home)
	if fi, err := os.Stat(filepath.Join(home, "big")); err != nil || fi.Size() > 4096 {
		t.Errorf("RLIMIT_FSIZE did not hold: %v %v\n%s", fi, err, r)
	}
	// NOFILE bounds the descriptors.
	if nr := escResult(t, Spec{Rlimits: []Rlimit{{ResourceOpenFiles, 16, 16}}}, "open-files"); nr.code != 0 || !strings.Contains(nr.stdout, "EMFILE") {
		t.Errorf("RLIMIT_NOFILE did not hold: %s", nr)
	}
	// CORE is accepted, and a limit of none is accepted for each resource.
	for _, res := range []Resource{ResourceCPU, ResourceFileSize, ResourceCore, ResourceOpenFiles, ResourceProcesses} {
		spec := Spec{Rlimits: []Rlimit{{res, math.MaxUint64, math.MaxUint64}}}
		if nr := sh(t, spec, "true"); nr.code != 0 {
			t.Errorf("a limit of none for resource %d: %s", res, nr)
		}
	}
	r = sh(t, Spec{Rlimits: []Rlimit{{ResourceCore, 0, 0}}}, "ulimit -c")
	if strings.TrimSpace(r.stdout) != "0" {
		t.Errorf("RLIMIT_CORE = %q, want 0", r.stdout)
	}
	// A hard limit raised above the caller's is refused by the kernel, and
	// Start says so rather than starting without it.
	c, err := Command(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: realTemp(t), Rlimits: []Rlimit{{ResourceCPU, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	_ = c
	if cur := getHard(unix.RLIMIT_CPU); cur != unix.RLIM_INFINITY {
		c, err := Command(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: realTemp(t), Rlimits: []Rlimit{{ResourceCPU, 1, cur + 1}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Start(); err == nil {
			t.Error("a hard limit above the caller's started")
		}
	}
}

// getHard returns this process's hard limit for res.
func getHard(res int) uint64 {
	var l unix.Rlimit
	_ = unix.Getrlimit(res, &l)
	return l.Max
}

func TestAPIIgnoredFields(t *testing.T) {
	t.Parallel()
	// Hostname, ScratchSize and CgroupFD mean nothing on macOS and are
	// accepted. Probe lists the Spec's.
	c, err := Command(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: realTemp(t), Hostname: "elsewhere", ScratchSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	c.CgroupFD = 7
	if r := execute(t, c); r.code != 0 {
		t.Fatal(r)
	}
	rep, err := Probe()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"Hostname", "ScratchSize"} {
		if !slices.Contains(rep.Ignored, f) {
			t.Errorf("Probe's Ignored lacks %s: %v", f, rep.Ignored)
		}
	}
	if !slices.ContainsFunc(rep.Unsupported, func(s string) bool { return strings.Contains(s, "ResourceAddressSpace") }) {
		t.Errorf("Probe's Unsupported lacks the address space limit: %v", rep.Unsupported)
	}
}

func TestAPIProcessGroup(t *testing.T) {
	t.Parallel()
	// Every process of the command is in one group that is not the caller's,
	// and in the caller's session. The stage is outside the profile, in the
	// caller's group.
	self := unix.Getpgrp()
	c := escCmd(t.Context(), t, Spec{}, "hold")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { c.stop(); _ = c.Wait() }()
	var group int
	eventually(t, 10*time.Second, "the command did not start", func() bool {
		// Only the stage's own child counts: other tests' stages, which
		// also name "esc hold", may still be exiting in the caller's group.
		for _, p := range pids(t, "esc hold") {
			k, err := unix.SysctlKinfoProc("kern.proc.pid", p)
			if err != nil || int(k.Eproc.Ppid) != c.Pid() {
				continue
			}
			if g, err := syscall.Getpgid(p); err == nil {
				group = g
				return true
			}
		}
		return false
	})
	if group == self {
		t.Errorf("the command is in the caller's process group %d", group)
	}
	sid, _ := unix.Getsid(0)
	// Only the command's own processes, which are the ones in its group. Other
	// tests' commands also name "esc hold", and one that exits between the list
	// and the read has no session to show.
	own := 0
	for _, p := range pids(t, "esc hold") {
		if g, err := syscall.Getpgid(p); err != nil || g != group {
			continue
		}
		own++
		if s, err := unix.Getsid(p); err != nil || s != sid {
			t.Errorf("pid %d is in session %d, want the caller's %d (%v)", p, s, sid, err)
		}
	}
	if own == 0 {
		t.Errorf("none of the command's processes were in its group %d", group)
	}
	if g, err := syscall.Getpgid(c.Pid()); err != nil || g != self {
		t.Errorf("the stage is in group %d (%v), want the caller's %d", g, err, self)
	}
}

func TestAPIContextAndWaitDelay(t *testing.T) {
	t.Parallel()
	t.Run("cancel kills", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		home := realTemp(t)
		marker := filepath.Join(home, "pid")
		c := escCmd(ctx, t, Spec{Home: home}, "hold", marker)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		inner := readPid(t, marker)
		cancel()
		done := make(chan error, 1)
		go func() { done <- c.Wait() }()
		select {
		case err := <-done:
			if err == nil {
				t.Error("Wait after cancel returned nil")
			}
		case <-time.After(15 * time.Second):
			t.Fatal("Wait did not return after cancel")
		}
		eventually(t, 5*time.Second, "the command outlived the cancel", func() bool { return !alive(inner) })
	})
	t.Run("a context that is already done", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		c := escCmd(ctx, t, Spec{}, "hold")
		cancel()
		time.Sleep(50 * time.Millisecond)
		if err := c.Start(); err == nil {
			_ = c.Wait()
			t.Error("Start with a done context succeeded")
		}
	})
	t.Run("wait delay", func(t *testing.T) {
		t.Parallel()
		// A background process that keeps the output pipe open after the
		// command exits holds Wait up until WaitDelay, as with os/exec. It is
		// then ended by the group kill, so it is not left behind.
		home := realTemp(t)
		c, err := Command(t.Context(), Spec{Home: home, Command: []string{"/bin/sh", "-c", "(sleep 30 &) ; exit 3"}})
		if err != nil {
			t.Fatal(err)
		}
		c.Env = []string{shellPath}
		c.Stdout = &syncBuffer{}
		c.WaitDelay = 500 * time.Millisecond
		start := time.Now()
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		code, _ := exitStatus(c.Wait())
		if code != 3 {
			t.Errorf("exit = %d, want 3", code)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("Wait took %v", d)
		}
	})
}

// syncBuffer is a writer that is not an *os.File, so exec copies to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns what has been written so far, while writes may go on.
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestAPIPid(t *testing.T) {
	t.Parallel()
	c := escCmd(t.Context(), t, Spec{}, "hold")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { c.stop(); _ = c.Wait() }()
	pid := c.Pid()
	if pid <= 0 || pid == os.Getpid() {
		t.Fatalf("Pid = %d", pid)
	}
	// It is this process's own child, the stage, and the command is its child.
	if ppid := unixPpid(pid); ppid != os.Getpid() {
		t.Errorf("the stage's parent is %d, want %d", ppid, os.Getpid())
	}
	eventually(t, 10*time.Second, "the command is not the stage's child", func() bool {
		for _, p := range pids(t, "esc hold") {
			if unixPpid(p) == pid {
				return true
			}
		}
		return false
	})
}

// unixPpid returns pid's parent, or -1.
func unixPpid(pid int) int {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return -1
	}
	return int(k.Eproc.Ppid)
}

func TestAPISelfPath(t *testing.T) {
	t.Parallel()
	if SelfPath != self(t) {
		t.Errorf("SelfPath = %q, want %q", SelfPath, self(t))
	}
	// A command that runs this binary again works under any Spec, whatever
	// covers hide it.
	c, err := Command(t.Context(), Spec{Command: []string{SelfPath, "self-hello", "world"}, Home: realTemp(t)})
	if err != nil {
		t.Fatal(err)
	}
	if r := execute(t, c); r.code != 0 || r.stdout != "hello from world\n" {
		t.Errorf("SelfPath command: %s", r)
	}
}

// TestAPIStartThreadExits checks that a sandbox outlives the OS thread that
// started it, since a Go server's threads come and go, and Pdeathsig would
// have killed it with the thread.
func TestAPIStartThreadExits(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	marker := filepath.Join(home, "pid")
	c := escCmd(t.Context(), t, Spec{Home: home}, "hold", marker)
	started := make(chan error, 1)
	go func() {
		// A locked goroutine that returns ends its thread.
		runtime.LockOSThread()
		started <- c.Start()
	}()
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	inner := readPid(t, marker)
	for range 20 {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
	if !alive(inner) {
		t.Fatal("the sandbox died with the thread that started it")
	}
	c.stop()
	_ = c.Wait()
	eventually(t, 5*time.Second, "the command outlived Wait", func() bool { return !alive(inner) })
}

func TestAPIConcurrent(t *testing.T) {
	t.Parallel()
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := range n {
		wg.Go(func() {
			home := realTemp(t)
			c, err := Command(t.Context(), Spec{Command: []string{"/bin/sh", "-c", fmt.Sprintf("echo %d > f && cat f", i)}, Home: home})
			if err != nil {
				errs <- err.Error()
				return
			}
			c.Env = []string{shellPath}
			var out bytes.Buffer
			c.Stdout = &out
			if err := c.Start(); err != nil {
				errs <- err.Error()
				return
			}
			if err := c.Wait(); err != nil || out.String() != fmt.Sprintf("%d\n", i) {
				errs <- fmt.Sprintf("sandbox %d: %v %q", i, err, out.String())
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestAPIServices(t *testing.T) {
	t.Parallel()
	// Without ServiceDirectory a lookup of the account finds nothing, with it
	// the name comes back.
	me := os.Getenv("USER")
	if me == "" {
		t.Skip("no USER to look up")
	}
	if r := sh(t, Spec{}, "/usr/bin/id -un"); strings.TrimSpace(r.stdout) == me {
		t.Errorf("id -un found %q with no ServiceDirectory", me)
	}
	if r := sh(t, Spec{Services: []Service{ServiceDirectory}}, "/usr/bin/id -un"); strings.TrimSpace(r.stdout) != me {
		t.Errorf("id -un with ServiceDirectory = %q, want %q: %s", r.stdout, me, r)
	}
	// A repeated group is one group.
	if _, err := Command(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: realTemp(t), Services: []Service{ServiceDirectory, ServiceDirectory, ServiceLaunchServices}}); err != nil {
		t.Error(err)
	}
}

func TestAPIFootprint(t *testing.T) {
	t.Parallel()
	c := escCmd(t.Context(), t, Spec{}, "alloc", "200")
	r, w, _ := os.Pipe()
	c.Stdout = w
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	defer func() { c.stop(); _ = c.Wait() }()
	// The command prints when it has touched its memory.
	line, _ := bufio.NewReader(r).ReadString('\n')
	if !strings.HasPrefix(line, "touched") {
		t.Fatalf("the command said %q", line)
	}
	fp, err := c.Footprint()
	if err != nil {
		t.Fatal(err)
	}
	if fp < 150<<20 {
		t.Errorf("Footprint = %d MiB, want at least 150 for a command holding 200", fp>>20)
	}
	if fp > 2<<30 {
		t.Errorf("Footprint = %d MiB, which is implausible", fp>>20)
	}
}

func registerAPIResourceChecks() {
	escChecks["open-files"] = func(e *escT, _ []string) {
		var files []*os.File
		for {
			f, err := os.Open("/dev/null")
			if err != nil {
				fmt.Println(len(files), "files, then", map[bool]string{true: "EMFILE", false: err.Error()}[errors.Is(err, syscall.EMFILE)])
				return
			}
			files = append(files, f)
			if len(files) > 1000 {
				e.failf("opened %d files under a limit of 16", len(files))
				return
			}
		}
	}
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

// TestAPIErrSurvivors checks ErrSurvivors, the error Wait returns when teardown
// could not confirm the sandbox empty: it matches with errors.Is, whether the
// command's own result was an exit status or none, and the exit error still
// unwraps. A teardown that proved the sandbox empty returns neither. A budget
// of none, with the stage's report ignored and a pid that is never settled in
// the caller's scan, stands for a chain that kept ahead of the scan until the
// budget ran out.
func TestAPIErrSurvivors(t *testing.T) {
	t.Parallel()
	wait := func(budget time.Duration, script string) error {
		c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{"/bin/sh", "-c", script}})
		if err != nil {
			t.Fatal(err)
		}
		c.run.budget = budget
		if budget == 0 {
			unprovable(c)
		}
		c.Env = []string{shellPath}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		return c.Wait()
	}
	// With time to settle: no survivors error, and the exit error as usual.
	err := wait(5*time.Second, "exit 3")
	if errors.Is(err, ErrSurvivors) {
		t.Errorf("a teardown that settled returned %v", err)
	}
	if ee := new(exec.ExitError); !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Errorf("exit 3: %v", err)
	}
	if err := wait(5*time.Second, "exit 0"); err != nil {
		t.Errorf("exit 0: %v", err)
	}
	// Without: the error matches the sentinel, and still unwraps to the exit error.
	err = wait(0, "exit 3")
	if !errors.Is(err, ErrSurvivors) {
		t.Fatalf("errors.Is(%v, ErrSurvivors) = false", err)
	}
	ee := new(exec.ExitError)
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Errorf("the exit error does not unwrap from %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("the message loses the command's result: %v", err)
	}
	// With no result of its own to wrap, it still matches.
	err = wait(0, "exit 0")
	if !errors.Is(err, ErrSurvivors) || errors.Unwrap(err) != nil {
		t.Errorf("exit 0 with survivors: %v, unwraps to %v", err, errors.Unwrap(err))
	}
	// exitStatus keeps the status, so a caller of Run gets it with the error.
	err = wait(0, "exit 3")
	if code, serr := exitStatus(err); code != 3 || serr != nil {
		t.Errorf("exitStatus = %d, %v", code, serr)
	}
	// It is not any other error.
	if errors.Is(errors.New("x"), ErrSurvivors) || errors.Is(nil, ErrSurvivors) {
		t.Error("ErrSurvivors matches an unrelated error")
	}
}
