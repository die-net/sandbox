package sandbox

// Tests for the findings of the macOS backend's security review: the ways out
// of teardown and Footprint, a sandbox replacing its own Home, the caller's
// environment, a Cover named through /System/Volumes/Data, signals that
// F_SETOWN delivers outside, Loopback ports on other addresses, the device
// rules, and one sandbox signaling another. Each attack is run inside a
// sandbox and the test asserts it fails, or, for a gap that is documented
// instead of closed, that it still works, so the docs change when it stops.
//
// Host safety: no test sends a signal but 0 or SIGWINCH to a process it did not
// start, and the processes a test ends are found by the sandbox's marker, which
// only names processes under that sandbox's own profile.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func registerReviewChecks() {
	// rename calls rename(2) on its two arguments and exits 1 if it fails.
	// os.Rename would refuse a directory as the new name before it asked the
	// kernel, and mv would move the directory inside it.
	childModes["rename"] = func(args []string) int {
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "rename old new")
			return 2
		}
		if err := unix.Rename(args[0], args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	// stat-denied stats each path and fails unless the profile refuses it. A
	// path that is not there gives ENOENT before the profile is asked, so it is
	// printed as gone, for the test to check that the host no longer has it
	// either: a pty can close between the test's listing and this stat.
	escChecks["stat-denied"] = func(e *escT, args []string) {
		for _, p := range args {
			if _, err := os.Lstat(p); err == nil { //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
				e.failf("stat %s: worked", p)
			} else if errors.Is(err, fs.ErrNotExist) {
				fmt.Printf("gone %s\n", p)
			} else if !isPerm(err) {
				e.failf("stat %s: %v, want a refusal by the profile", p, err)
			}
		}
	}
	escChecks["leave"] = escLeave
	childModes["canary-io"] = canaryIOMode
	escChecks["set-owner"] = escSetOwner
	escChecks["udp-bind"] = escUDPBind
	escChecks["bind-addrs"] = escBindAddrs
}

// ------------------------------------------------------------------ teardown

// escLeave leaves the command's process group, or starts a process that does,
// as args[0] says, and records the pid of the one that left in the file
// args[1]. The process that left holds the command's standard output, as a
// daemon does, and touches args[2] MiB.
//
//	setpgid   a child in a process group of its own
//	setsid    a child in a session of its own
//	self-join the command itself joins its parent's group, which is the stage's
//	          and so the caller's
//
// The command then waits, unless args[3] is "exit".
func escLeave(e *escT, args []string) {
	how, pidfile, mb := args[0], args[1], args[2]
	exit := len(args) > 3 && args[3] == "exit"
	switch how {
	case "self-join":
		pg, err := unix.Getpgid(os.Getppid())
		if err != nil {
			e.failf("getpgid(parent): %v", err)
			return
		}
		if err := unix.Setpgid(0, pg); err != nil {
			e.failf("setpgid(0, the caller's group): %v", err)
			return
		}
		_ = os.WriteFile(pidfile, []byte(strconv.Itoa(os.Getpid())), 0o600) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
		escChecks["alloc"](e, []string{mb})
	case "setpgid", "setsid":
		cmd := exec.CommandContext(context.Background(), self1(), "esc", "alloc", mb) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: how == "setpgid", Setsid: how == "setsid"}
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			e.failf("start the escapee: %v", err)
			return
		}
		_ = os.WriteFile(pidfile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
		if !exit {
			time.Sleep(time.Minute)
		}
	default:
		e.failf("no way out called %q", how)
	}
}

// readPid reads the pid a sandbox wrote to path, once it has.
func readPid(t *testing.T, path string) int {
	t.Helper()
	var pid int
	eventually(t, 10*time.Second, "no pid in "+path, func() bool {
		b, err := readFile(path)
		if err != nil {
			return false
		}
		pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		return pid > 0
	})
	return pid
}

// endAtCleanup ends whatever still runs under c's profile when the test ends,
// so a teardown that fails leaves nothing behind. It names processes by the
// marker, never by a pid it was told.
func endAtCleanup(t *testing.T, c *Cmd) {
	t.Helper()
	t.Cleanup(func() { c.run.mark.kill(2*time.Second, c.run.group) })
}

// waitWithin waits for c and fails the test if that takes longer than d. It
// returns what Wait did.
func waitWithin(t *testing.T, c *Cmd, d time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("Wait did not return within %v", d)
		return nil
	}
}

// Row: "Teardown: pid 1 dies, all die", for the ways a process leaves its
// command's process group: a shell's job control, setpgid in a child, setsid in
// a child. Each holds the command's standard output, which is a pipe to a
// writer that is not a file, so a survivor would keep Wait from returning. They
// are all ended, and Wait comes back at once, with OwnSession as without.
func TestEscapeSetpgidAndJobControl(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cmd  func(home string) []string
	}{
		{"job control", func(home string) []string {
			return []string{"/bin/sh", "-c", `set -m; /bin/sleep 600 & echo $! > "$1"; exit 0`, "sh", filepath.Join(home, "pid")}
		}},
		{"setpgid child", func(home string) []string {
			return []string{self(t), "esc", "leave", "setpgid", filepath.Join(home, "pid"), "1", "exit"}
		}},
		{"setsid child", func(home string) []string {
			return []string{self(t), "esc", "leave", "setsid", filepath.Join(home, "pid"), "1", "exit"}
		}},
	} {
		for _, own := range []bool{false, true} {
			name := tc.name
			if own {
				name += ", own session"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				home := realTemp(t)
				c, err := Command(t.Context(), Spec{Home: home, Command: tc.cmd(home), OwnSession: own})
				if err != nil {
					t.Fatal(err)
				}
				c.Env = []string{shellPath}
				c.Stdout = &syncBuffer{} // not an *os.File: exec waits for it to close
				if err := c.Start(); err != nil {
					t.Fatal(err)
				}
				endAtCleanup(t, c)
				pid := readPid(t, filepath.Join(home, "pid"))
				if g, err := unix.Getpgid(pid); err == nil && g == c.run.group {
					t.Fatalf("the process is still in the command's group %d, so it did not leave it", g)
				}
				if err := waitWithin(t, c, 20*time.Second); err != nil {
					t.Fatalf("Wait: %v", err)
				}
				eventually(t, 5*time.Second, "a process that left the group outlived the sandbox", func() bool { return !alive(pid) })
			})
		}
	}
}

// Row: "Teardown", for a process that holds a Footprint it must be counted in: a
// process that left the command's group, and the command itself after it joined
// the caller's group by setpgid(0, parent's), which the review used to hide
// from Footprint ("no process of the sandbox is left") while it ran. Both are
// counted, and both end with the sandbox.
func TestEscapeFootprintCountsEscapees(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"setpgid", "setsid", "self-join"} {
		t.Run(how, func(t *testing.T) {
			t.Parallel()
			home := realTemp(t)
			pidfile := filepath.Join(home, "pid")
			c := escCmd(t.Context(), t, Spec{Home: home}, "leave", how, pidfile, "150")
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			endAtCleanup(t, c)
			pid := readPid(t, pidfile)
			if g, _ := unix.Getpgid(pid); g == c.run.group {
				t.Fatalf("the process is in the command's group %d", g)
			}
			// 150 MiB is held by the process that left. The command is a few MiB
			// at most, and the stage is not counted.
			var fp int64
			var err error
			eventually(t, 15*time.Second, "the footprint of the process that left was not counted", func() bool {
				fp, err = c.Footprint()
				return err == nil && fp >= 120<<20
			})
			_ = fp
			// Ending the sandbox ends it, whatever its group.
			c.stop()
			_ = waitWithin(t, c, 20*time.Second)
			eventually(t, 5*time.Second, "the process outlived the sandbox", func() bool { return !alive(pid) })
		})
	}
}

// Row: "Teardown ... on stage death": a stage that is killed ends nothing, and a
// process the command left behind in a group of its own holds the output pipe.
// Wait still returns, and ends the process.
func TestEscapeStageKilledEscapeeHoldsOutput(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	pidfile := filepath.Join(home, "pid")
	c := escCmd(t.Context(), t, Spec{Home: home}, "leave", "setpgid", pidfile, "1")
	c.Stdout = &syncBuffer{}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c)
	pid := readPid(t, pidfile)
	_ = syscall.Kill(c.Pid(), syscall.SIGKILL)
	err := waitWithin(t, c, 20*time.Second)
	if err == nil {
		t.Error("Wait after the stage was killed returned nil")
	}
	eventually(t, 5*time.Second, "the escapee outlived its killed stage", func() bool { return !alive(pid) })
}

// Row: "Teardown ... on parent death": the caller's death, however it dies,
// ends a process that left the group too, since the stage finds it by the
// profile and not by the group.
func TestEscapeParentKilledEndsEscapees(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	pidfile := filepath.Join(home, "pid")
	body := jsonArg(t, Spec{Home: home, Command: []string{self(t), "esc", "leave", "setpgid", pidfile, "1"}})
	parent := exec.CommandContext(t.Context(), self(t), "esc-parent", body) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	pid := readPid(t, pidfile)
	_ = parent.Process.Signal(syscall.SIGKILL)
	_ = parent.Wait()
	eventually(t, 10*time.Second, "a process in a group of its own outlived its caller", func() bool { return !alive(pid) })
}

// Row: "Teardown: pid 1 dies, all die": a process that makes its own session, as a
// daemon does, used to outlive the sandbox with the profile it was started
// under (TestGapSetsidSurvivesTeardown). It is ended with the sandbox now,
// including a CPU limit's SIGXCPU, which it could ignore, so that is not what
// ends it.
func TestEscapeSetsidDiesWithTeardown(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	secret := hostSecret(t)
	log := filepath.Join(home, "log")
	// A listener on the host's LAN address is the network it must not reach.
	target := net.JoinHostPort(lanAddr(t), strconv.Itoa(listenAny(t)))
	c := escCmd(t.Context(), t, Spec{Home: home, Rlimits: []Rlimit{{ResourceCPU, 600, 600}}}, "daemon", log, target, secret, "/etc/hosts")
	var out bytes.Buffer
	c.Stdout = &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c) // a teardown that fails leaves no daemon behind
	if code, err := exitStatus(c.Wait()); err != nil || code != 0 {
		t.Fatalf("exit %d, %v", code, err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(out.String()))
	if pid == 0 {
		t.Fatalf("no daemon pid in %q", out.String())
	}
	eventually(t, 5*time.Second, "the process that made its own session outlived the sandbox", func() bool { return !alive(pid) })
	// And while it ran it saw nothing but /etc/hosts and reached no network. The
	// command waited for its first record.
	b, _ := readFile(log)
	text := strings.TrimSpace(string(b))
	if text == "" {
		t.Error("the daemon recorded nothing, so nothing was checked")
	}
	for line := range strings.Lines(text) {
		if !strings.Contains(line, "worked=[/etc/hosts]") {
			t.Errorf("the daemon reached more than /etc/hosts: %q", line)
		}
	}
}

// ------------------------------------------------------------------ marker

// Row: "No pid namespace": the marker names the processes under one sandbox's
// profile and no others. A process with no sandbox, one under a profile that
// allows everything, one under a deny-default profile (which denies both names),
// one under a profile that treats the names as this one does but with other
// names, and one in another sandbox of this package are all passed over, and
// every process of the sandbox is found, whatever its group or parent.
func TestMarkerNamesOnlyItsSandbox(t *testing.T) {
	t.Parallel()
	startHold := func(home string) *Cmd {
		c := escCmd(t.Context(), t, Spec{Home: home}, "leave", "setpgid", filepath.Join(home, "pid"), "1")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		endAtCleanup(t, c)
		return c
	}
	homeA, homeB := realTemp(t), realTemp(t)
	a, b := startHold(homeA), startHold(homeB)
	escapeeA, escapeeB := readPid(t, filepath.Join(homeA, "pid")), readPid(t, filepath.Join(homeB, "pid"))

	// Processes under other profiles, each one this test starts and ends.
	other, err := newMarker()
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) int {
		cmd := exec.CommandContext(t.Context(), args[0], args[1:]...) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd.Process.Pid
	}
	plain := run("/bin/sleep", "300")
	allowAll := run(sandboxExec, "-p", "(version 1)(allow default)", "/bin/sleep", "300")
	denyDefault := run(sandboxExec, "-p", "(version 1)(deny default)(allow process-exec*)(allow process-fork)(allow file-read*)(allow sysctl-read)", "/bin/sleep", "300")
	otherNames := run(sandboxExec, "-p", fmt.Sprintf(`(version 1)(deny default)(allow process-exec*)(allow process-fork)(allow file-read*)(allow sysctl-read)(allow mach-lookup (global-name %q))(deny mach-lookup (global-name %q))`, other.In, other.Out), "/bin/sleep", "300")
	// A profile that is A's own, but for the names, as if it were allow-all
	// with the same deny: A's In allowed, A's Out also allowed.
	bothAllowed := run(sandboxExec, "-p", fmt.Sprintf(`(version 1)(allow default)(allow mach-lookup (global-name %q))`, a.run.mark.In), "/bin/sleep", "300")
	time.Sleep(500 * time.Millisecond)

	for _, tc := range []struct {
		name string
		c    *Cmd
		mine int // the escapee of this sandbox
		not  int // the escapee of the other
	}{{"A", a, escapeeA, escapeeB}, {"B", b, escapeeB, escapeeA}} {
		got, err := tc.c.run.mark.processes()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(got, tc.mine) {
			t.Errorf("sandbox %s: the process that left its group, %d, is not found in %v", tc.name, tc.mine, got)
		}
		for _, pid := range []int{tc.not, plain, allowAll, denyDefault, otherNames, bothAllowed, os.Getpid(), os.Getppid(), 1, tc.c.Pid()} {
			if slices.Contains(got, pid) {
				t.Errorf("sandbox %s: found %d, which is not under its profile", tc.name, pid)
			}
		}
		// Everything it found descends from its stage or its escapee: nothing
		// of the user's is in it.
		for _, pid := range got {
			if !slices.Contains(tree(t, tc.c.Pid()), pid) && pid != tc.mine {
				t.Errorf("sandbox %s: found %d, which is not its stage's descendant", tc.name, pid)
			}
		}
	}
	// With no marker nothing is found.
	if got, _ := (marker{}).processes(); len(got) != 0 {
		t.Errorf("an empty marker found %v", got)
	}
}

// Row: "Seatbelt profile": a profile with a marker allows one lookup and denies the
// other, and a profile with none has neither rule.
func TestProfileMarker(t *testing.T) {
	t.Parallel()
	m, err := newMarker()
	if err != nil {
		t.Fatal(err)
	}
	if m.In == m.Out || !strings.HasPrefix(m.In, "com.die-net.sandbox.in.") || !strings.HasPrefix(m.Out, "com.die-net.sandbox.out.") {
		t.Errorf("marker = %+v", m)
	}
	m2, _ := newMarker()
	if m.In == m2.In {
		t.Error("two markers share a name")
	}
	p, err := profile(profileInput{Home: "/h", Marker: m})
	if err != nil {
		t.Fatal(err)
	}
	if indexOf(p, `(allow mach-lookup (global-name "`+m.In+`"))`) < 0 || indexOf(p, `(deny mach-lookup (global-name "`+m.Out+`"))`) < 0 {
		t.Errorf("the profile lacks the marker rules:\n%s", p)
	}
	p, _ = profile(profileInput{Home: "/h"})
	if strings.Contains(p, "com.die-net.sandbox") {
		t.Error("a profile with no marker names one")
	}
	if _, err := profile(profileInput{Home: "/h", Marker: marker{In: `x") (allow default`, Out: "y"}}); err == nil {
		t.Error("a marker name with a quote was accepted")
	}
}

// ------------------------------------------------------------------ roots

// Row: "Path and link rules": a sandbox cannot replace its Home, or a Write
// directory or socket, with a link or anything else, so what the caller reads
// there by name is what it wrote. The review removed Home and put a link to the
// caller's private directory in its place, and the caller read a file from
// there. Every way of removing, renaming, and renaming over a root is refused,
// the root is intact afterwards, and the sandbox still writes inside it.
func TestEscapeRootsCannotBeSwapped(t *testing.T) {
	t.Parallel()
	base := realTemp(t)
	home := mkdirs(t, base, "home")
	w := mkdirs(t, base, "w")
	w2 := mkdirs(t, base, "w2")
	// A unix socket's path is limited to 104 bytes, which a test's temporary
	// directory exceeds.
	short, err := os.MkdirTemp("/private/tmp", "sbxr")
	if err != nil {
		t.Skipf("no short directory for a socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	sock := filepath.Join(short, "b.sock")
	l, err := listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	private := mkdirs(t, base, "caller-private")
	writeFile(t, "caller data\n", private, "out.png")
	writeFile(t, "gone", w2, "file")

	res := sh(t, Spec{Home: home, Dir: "/", Write: []string{w, w2, sock}}, `
cd /
rmdir "$HOME/tmp"
worked=""
try() { if "$@" 2>/dev/null; then worked="$worked [$*]"; fi; }
try rmdir "$HOME"
try mv "$HOME" "$HOME.moved"
try rmdir "$1"
try mv "$1" "$1.moved"
try rm "$3"
try mv "$3" "$3.moved"
# A directory made in Home renamed over an empty Write root, with rename(2)
# itself, since mv would move it inside.
mkdir "$HOME/empty"; try "$5" rename "$HOME/empty" "$1"
rmdir "$HOME/empty" 2>/dev/null
# A root moved out of the way.
try mv "$2" "$HOME/stolen"
# rm -r empties a root, which is allowed, and then cannot remove it.
try rm -rf "$2"
# What it may do: write inside each root.
echo ok > "$HOME/inside" && echo ok > "$1/inside" || worked="$worked [could not write inside]"
echo "$worked"
`, w, w2, sock, private, self(t))
	if res.code != 0 {
		t.Fatalf("%s", res)
	}
	if out := strings.TrimSpace(res.stdout); out != "" {
		t.Errorf("the sandbox did what it must not: %s", out)
	}
	// The host sees what it made, by name.
	for _, p := range []string{home, w, w2} {
		fi, err := os.Lstat(p)
		if err != nil || !fi.IsDir() {
			t.Errorf("%s is now %v, %v", p, fi, err)
		}
	}
	if fi, err := os.Lstat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("the socket is now %v, %v", fi, err)
	}
	if b, err := readFile(filepath.Join(home, "out.png")); err == nil {
		t.Errorf("the caller reads %q from Home, which now leads to its private directory", b)
	}
	for _, p := range []string{home + ".moved", w + ".moved", sock + ".moved"} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s exists: a root was renamed", p)
		}
	}
}

// ------------------------------------------------------------------ firmlinks

func TestCanonicalName(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"/System/Volumes/Data/Users/a/b":                "/Users/a/b",
		"/System/Volumes/Data/private/var/folders/x":    "/private/var/folders/x",
		"/System/Volumes/Data/Applications/Firefox.app": "/Applications/Firefox.app",
		"/System/Volumes/Data/usr/local/bin":            "/usr/local/bin",
		"/System/Volumes/Data/opt":                      "/opt",
		// Not firmlinked: the data volume's own name is the only one.
		"/System/Volumes/Data/home/x":     "/System/Volumes/Data/home/x",
		"/System/Volumes/Data/.Spotlight": "/System/Volumes/Data/.Spotlight",
		"/System/Volumes/Data":            "/System/Volumes/Data",
		// Not under the data volume at all, or a lookalike of its name.
		"/Users/a":                       "/Users/a",
		"/System/Volumes/DataX/Users":    "/System/Volumes/DataX/Users",
		"/tmp/System/Volumes/Data/Users": "/tmp/System/Volumes/Data/Users",
	} {
		if got := canonicalName(in); got != want {
			t.Errorf("canonicalName(%q) = %q, want %q", in, got, want)
		}
	}
}

// Row: "Covers; default covers": a Cover, a Read and a Write path named through
// /System/Volumes/Data mean what they say. Seatbelt matches the name /Users or
// /private/var, so a deny for the data volume's name matched nothing, and a
// Cover written that way covered nothing, silently. Start maps the name, and
// both spellings of a Cover hide the same files, and of a Read show them.
func TestEscapeFirmlinkNames(t *testing.T) {
	t.Parallel()
	root := realTemp(t) // under /private/var, which is a firmlink
	if !strings.HasPrefix(root, "/private/var/") {
		t.Skipf("the temporary directory %s is not under /private/var", root)
	}
	data := dataVolume + root
	// The review's attack is the second row: a Read by the usual name and a
	// Cover by the data volume's. Each pair of spellings hides the same file.
	for _, sp := range []struct{ name, read, cover string }{
		{"both usual", "", ""},
		{"cover by the data volume name", "", dataVolume},
		{"read by the data volume name", dataVolume, ""},
		{"both by the data volume name", dataVolume, dataVolume},
	} {
		t.Run(sp.name, func(t *testing.T) {
			t.Parallel()
			dir := realTemp(t)
			shown := mkdirs(t, dir, "shown")
			hidden := mkdirs(t, shown, "hidden")
			writeFile(t, "top secret\n", hidden, "secret")
			writeFile(t, "fine\n", shown, "fine")
			home := realTemp(t)
			spec := Spec{Home: home, Read: []string{sp.read + shown}, Cover: []string{sp.cover + hidden}}
			got := sh(t, spec, `cat "$1/fine" && ! cat "$1/hidden/secret" 2>/dev/null && ! ls "$1/hidden" >/dev/null 2>&1`, shown)
			if got.code != 0 {
				t.Errorf("Read %s, Cover %s: the secret was readable, or the shown file was not: %s", sp.read+shown, sp.cover+hidden, got)
			}
			// And reached by the data volume's name of the path.
			got = sh(t, spec, `cat "$1/fine" && ! cat "$1/hidden/secret" 2>/dev/null`, dataVolume+shown)
			if got.code != 0 {
				t.Errorf("by the data volume's name: %s", got)
			}
		})
	}
	t.Run("home and write", func(t *testing.T) {
		// A Home or Write path named that way is refused, with the name to use,
		// and not run with a rule that matches nothing.
		home := mkdirs(t, root, "h")
		c, err := Command(t.Context(), Spec{Home: dataVolume + home, Command: []string{"/usr/bin/true"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Start(); err == nil || !strings.Contains(err.Error(), home) {
			t.Errorf("Start with Home %s = %v, want an error naming %s", dataVolume+home, err, home)
		}
	})
	_ = data
}

// ------------------------------------------------------------------ signals

// canaryIOMode is a process that records SIGIO, in the directory args[0], and
// writes "ready" when it is listening. (Go's runtime sends itself SIGURG, so
// that one says nothing.)
func canaryIOMode(args []string) int {
	dir := args[0]
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGIO)
	_ = os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
	for s := range sigs {
		f, err := openFileFlags(filepath.Join(dir, "got"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			if _, err := fmt.Fprintln(f, s); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
			_ = f.Close()
		}
	}
	return 0
}

// escSetOwner makes a socketpair deliver SIGIO to the pid in args[0], which is
// outside, by F_SETOWN and O_ASYNC, and writes to it.
func escSetOwner(e *escT, args []string) {
	pid, _ := strconv.Atoi(args[0])
	p, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		e.failf("socketpair: %v", err)
		return
	}
	for _, fd := range p {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETOWN, pid); err != nil {
			e.failf("F_SETOWN: %v", err)
			return
		}
		fl, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, fl|unix.O_ASYNC); err != nil {
			e.failf("O_ASYNC: %v", err)
			return
		}
	}
	for range 3 {
		_, _ = unix.Write(p[1], []byte("x"))
		time.Sleep(50 * time.Millisecond)
	}
}

// Row: "No pid namespace ... signal": a gap, shown and not closed. The profile
// denies signals to a process outside, but fcntl(F_SETOWN) with O_ASYNC makes
// the kernel send SIGIO to it itself when the descriptor is ready, and Seatbelt's
// signal hook is not asked. The target is a canary this test started.
// SIGIO's default action is to ignore it, so a program is hurt only if it
// handles it. The test fails if the gap closes, so the docs change.
func TestGapSetOwnSignalsOutside(t *testing.T) {
	t.Parallel()
	dir := realTemp(t)
	cmd := exec.CommandContext(t.Context(), self(t), "canary-io", dir) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	eventually(t, 10*time.Second, "the canary did not start", func() bool { _, err := os.Stat(filepath.Join(dir, "ready")); return err == nil })
	// The profile does stop a signal the sandbox sends itself.
	escRun(t, Spec{}, "signals", strconv.Itoa(cmd.Process.Pid))
	escRun(t, Spec{}, "set-owner", strconv.Itoa(cmd.Process.Pid))
	eventually(t, 5*time.Second, "SIGIO did not reach the canary by F_SETOWN: the gap closed, so change the docs", func() bool {
		return strings.Contains(gotSignals(dir), "I/O")
	})
}

// Row: "No pid namespace ... signal": one sandbox cannot signal, reprioritize or
// inspect another's processes, the command or its stage, any more than the
// caller's. Both are of the same uid and in no process group of each other's.
func TestEscapeOneSandboxCannotSignalAnother(t *testing.T) {
	t.Parallel()
	homeA := realTemp(t)
	a := escCmd(t.Context(), t, Spec{Home: homeA}, "hold", filepath.Join(homeA, "pid"))
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, a)
	cmdA := readPid(t, filepath.Join(homeA, "pid"))
	// B tries signal 0, setpriority and process-info on A's command and stage,
	// and a broadcast, which only reaches B's own.
	escRun(t, Spec{}, "signals", strconv.Itoa(cmdA), strconv.Itoa(a.Pid()))
	escRun(t, Spec{}, "procinfo", strconv.Itoa(cmdA), strconv.Itoa(a.Pid()))
	if !alive(cmdA) {
		t.Fatal("A's command died")
	}
	// A was untouched: it still holds and its footprint is there.
	if _, err := a.Footprint(); err != nil {
		t.Errorf("A's footprint: %v", err)
	}
}

// --------------------------------------------------------------- loopback

// escBindAddrs binds each address in args, which is "tcp:host:port" or
// "tcp:host:port!" for one that must be refused, and fails the check for one
// that went the other way.
func escBindAddrs(e *escT, args []string) {
	for _, a := range args {
		must := !strings.HasSuffix(a, "!")
		a = strings.TrimSuffix(a, "!")
		network, addr, _ := strings.Cut(a, ":")
		l, err := listen(network, addr)
		switch {
		case err == nil && !must:
			e.failf("bind %s: worked", a)
		case err != nil && must:
			e.failf("bind %s: %v", a, err)
		case err != nil && !isPerm(err):
			e.failf("bind %s: %v, want a refusal by the profile", a, err)
		}
		if l != nil {
			_ = l.Close()
		}
	}
}

// escUDPBind fails if a UDP socket can be bound or sent to on any of the ports
// in args, on 127.0.0.1 and the wildcard.
func escUDPBind(e *escT, args []string) {
	for _, p := range args {
		for _, host := range []string{"127.0.0.1", ""} {
			c, err := listenPacket("udp", net.JoinHostPort(host, p))
			if err == nil {
				e.failf("udp bind %s:%s: worked", host, p)
				_ = c.Close()
			} else if !isPerm(err) {
				e.failf("udp bind %s:%s: %v, want a refusal", host, p, err)
			}
		}
		c, err := dialTimeout("udp", "127.0.0.1:"+p, 5*time.Second)
		if err == nil {
			if _, err := c.Write([]byte("x")); err == nil {
				e.failf("udp send to 127.0.0.1:%s: worked", p)
			}
			_ = c.Close()
		}
	}
}

// Row: "Network namespace ... Loopback": a Loopback port is TCP and nothing else,
// so UDP to it, which "ip" in a profile would allow, is refused, and the ports
// beside it are refused on every address, not only 127.0.0.1: the wildcard, the
// LAN address and ::1 as well. The given ports themselves bind on 127.0.0.1.
func TestEscapeLoopbackPortsAllAddresses(t *testing.T) {
	t.Parallel()
	c := escCmd(t.Context(), t, Spec{Loopback: 2}, "bind-addrs")
	ports := c.LoopbackPorts()
	p0, p1 := strconv.Itoa(ports[0]), strconv.Itoa(ports[1])
	other := listenAny(t) // a port in use outside, which the sandbox is not given
	lan := lanAddr(t)
	refused := []int{ports[1] + 1, ports[1] + 2, other, 80, 8080}
	args := make([]string, 0, 2+5*len(refused))
	args = append(args, "tcp:127.0.0.1:"+p0, "tcp:127.0.0.1:"+p1)
	for _, p := range refused {
		s := strconv.Itoa(p)
		args = append(args, "tcp:127.0.0.1:"+s+"!", "tcp:0.0.0.0:"+s+"!", "tcp:[::1]:"+s+"!", "tcp:[::]:"+s+"!", "tcp:"+lan+":"+s+"!")
	}
	c.spec.Command = append([]string{self(t), "esc", "bind-addrs"}, args...)
	var errb bytes.Buffer
	c.Stderr = &errb
	if r := execute(t, c); r.code != 0 {
		t.Errorf("%s", r)
	}
	// UDP on the given ports is refused.
	c2 := escCmd(t.Context(), t, Spec{Loopback: 1}, "udp-bind")
	port := strconv.Itoa(c2.LoopbackPorts()[0])
	c2.spec.Command = []string{self(t), "esc", "udp-bind", port}
	if r := execute(t, c2); r.code != 0 {
		t.Errorf("UDP on a Loopback port: %s", r)
	}
	// A process outside reaches a port the sandbox serves: there is no private
	// loopback, and the sandbox's server is for whoever connects.
	c3 := escCmd(t.Context(), t, Spec{Loopback: 1}, "serve-one")
	port3 := c3.LoopbackPorts()[0]
	c3.spec.Command = []string{self(t), "esc", "serve-one", strconv.Itoa(port3)}
	var out syncBuffer
	c3.Stdout = &out
	c3.Env = []string{shellPath}
	if err := c3.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c3)
	eventually(t, 10*time.Second, "the sandbox's server did not answer a process outside", func() bool {
		conn, err := dialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port3), time.Second)
		if err != nil {
			return false
		}
		defer conn.Close()
		b, _ := bufio.NewReader(conn).ReadString('\n')
		return strings.HasPrefix(b, "hello")
	})
	c3.stop()
	_ = c3.Wait()
}

func registerServeChecks() {
	// serve-one binds the port in args[0] on 127.0.0.1 and says hello to every
	// connection until it is ended.
	escChecks["serve-one"] = func(e *escT, args []string) {
		l, err := listen("tcp", "127.0.0.1:"+args[0])
		if err != nil {
			e.failf("listen: %v", err)
			return
		}
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("hello\n"))
			_ = c.Close()
		}
	}
	// serve-lan binds addr:port, args[0], and accepts one connection, then
	// prints who it came from. A connection from nowhere ends it after args[1]
	// seconds.
	escChecks["serve-addr"] = func(e *escT, args []string) {
		l, err := listen("tcp", args[0])
		if err != nil {
			e.failf("listen %s: %v", args[0], err)
			return
		}
		secs, _ := strconv.Atoi(args[1])
		fmt.Println("bound", l.Addr())
		_ = l.(*net.TCPListener).SetDeadline(time.Now().Add(time.Duration(secs) * time.Second))
		c, err := l.Accept()
		if err != nil {
			e.failf("accept: %v", err)
			return
		}
		fmt.Println("accepted", c.RemoteAddr(), "on", c.LocalAddr())
		_ = c.Close()
	}
}

// Row: "Network: NetworkNone ... Loopback": a gap that Seatbelt cannot close, shown
// here so the docs change when it does. A profile names a host only as "*" or
// "localhost", and "localhost" is every address the host has, so a Loopback
// port that the sandbox binds on the LAN address is accepted on it, with
// NetworkNone. Seatbelt checks a connection's remote address when it is made
// and not when it is accepted, so a peer of the sandbox's own cannot be
// limited to this host either: a `network-inbound` deny of every remote address
// but localhost, written after the allow, let a local connection through.
// The connection here is this host dialing its own LAN address, since another
// machine cannot be had: the Linux test host has no route to
// this Mac (its connections to any port time out with no sandbox at all).
func TestGapLoopbackBindsLANAddress(t *testing.T) {
	t.Parallel()
	lan := lanAddr(t)
	c := escCmd(t.Context(), t, Spec{Loopback: 1}, "serve-addr")
	port := strconv.Itoa(c.LoopbackPorts()[0])
	c.spec.Command = []string{self(t), "esc", "serve-addr", net.JoinHostPort(lan, port), "8"}
	var out syncBuffer
	c.Stdout = &out
	c.Env = []string{shellPath}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c)
	var conn net.Conn
	eventually(t, 10*time.Second, "the LAN address was refused: the gap closed, so change the docs", func() bool {
		var err error
		conn, err = dialTimeout("tcp", net.JoinHostPort(lan, port), time.Second)
		return err == nil
	})
	_ = conn.Close()
	if err := waitWithin(t, c, 20*time.Second); err != nil {
		t.Errorf("the sandbox's server: %v", err)
	}
	if got := out.buf.String(); !strings.Contains(got, "accepted "+lan) {
		t.Errorf("the sandbox did not accept on its LAN address: %q", got)
	}
}

// ---------------------------------------------------------------- environment

// Row: "No pid namespace ... KERN_PROCARGS2": the caller's own environment is
// readable by the command, whatever Cmd.Env holds, since the stage is the
// caller's child and Seatbelt cannot stop the sysctl. A caller must hold no
// secret in its environment. The test is a caller of its own with a token in
// its environment, which starts a sandbox with an empty one.
func TestGapCallerEnvironmentReadable(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	token := "SANDBOX_CALLER_TOKEN=caller-secret-" + strconv.Itoa(os.Getpid())
	body := jsonArg(t, Spec{Home: home, Command: []string{self(t), "esc", "procargs-parent", token}})
	parent := exec.CommandContext(t.Context(), self(t), "esc-parent", body) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	parent.Env = []string{token, shellPath}
	var stderr syncBuffer
	parent.Stderr = &stderr
	var stdout syncBuffer
	parent.Stdout = &stdout
	if err := parent.Run(); err != nil {
		t.Fatalf("the sandbox could not read the caller's environment: %v\n%s", err, stderr.buf.String())
	}
}

func registerProcargsParent() {
	// procargs-parent reads the environment of the stage's parent, the caller
	// of the sandbox, which holds args[0] and was handed the sandbox no
	// environment of its own.
	escChecks["procargs-parent"] = func(e *escT, args []string) {
		if os.Getenv("SANDBOX_CALLER_TOKEN") != "" {
			e.failf("the sandbox's own environment holds the token")
		}
		// This process's parent is the stage, whose parent is the caller.
		stage := os.Getppid()
		procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
		if err != nil {
			e.failf("list processes: %v", err)
			return
		}
		caller := 0
		for i := range procs {
			p := &procs[i]
			if int(p.Proc.P_pid) == stage {
				caller = int(p.Eproc.Ppid)
			}
		}
		escProcArgs(e, []string{strconv.Itoa(caller), args[0]})
	}
}

// ---------------------------------------------------------------- devices

func registerDevOK() {
	// dev-ok uses the devices a program needs: it reads random bytes, writes to
	// /dev/null and /dev/zero, and opens its standard descriptors by /dev/fd.
	escChecks["dev-ok"] = func(e *escT, _ []string) {
		for _, p := range []string{"/dev/zero", "/dev/urandom", "/dev/random", "/dev/null"} {
			f, err := openFile(p)
			if err != nil {
				e.failf("open %s: %v", p, err)
				continue
			}
			var b [16]byte
			if p != "/dev/null" {
				if n, err := f.Read(b[:]); err != nil || n == 0 {
					e.failf("read %s: %d, %v", p, n, err)
				}
			}
			_ = f.Close()
		}
		for _, p := range []string{"/dev/null", "/dev/zero"} {
			f, err := openFileFlags(p, os.O_WRONLY, 0)
			if err != nil {
				e.failf("open %s for writing: %v", p, err)
				continue
			}
			if _, err := f.WriteString("x"); err != nil {
				e.failf("write %s: %v", p, err)
			}
			_ = f.Close()
		}
		// Each descriptor is opened in the mode it has, since the kernel refuses
		// a wider one by itself: standard input is read, and output written.
		for fd, mode := range map[string]int{"0": os.O_RDONLY, "1": os.O_WRONLY, "2": os.O_WRONLY} {
			f, err := openFileFlags("/dev/fd/"+fd, mode|syscall.O_NONBLOCK, 0)
			if err != nil {
				e.failf("open /dev/fd/%s: %v", fd, err)
				continue
			}
			_ = f.Close()
		}
		// A descriptor handed in works through /dev/fd as well, which is what a
		// shell's <(...) opens.
		if _, err := os.Stat("/dev/fd"); err != nil {
			e.failf("stat /dev/fd: %v", err)
		}
	}
}

// Row: "Terminals, packet capture and disks open only as descriptors handed in":
// every device but a few is refused, not only the families a list named. The
// list left out /dev/console, /dev/cu.* and /dev/uart.*, which stayed openable
// by their permissions (a console is crw--w--w- owned by the login user, a
// serial port rw-rw-rw-). Each entry of /dev here is tried, and the ones a
// program uses work.
func TestEscapeDevices(t *testing.T) {
	t.Parallel()
	ents, err := os.ReadDir("/dev")
	if err != nil {
		t.Skipf("no /dev listing: %v", err)
	}
	allowed := map[string]bool{"null": true, "zero": true, "random": true, "urandom": true, "fd": true, "stdin": true, "stdout": true, "stderr": true}
	var denied []string
	for _, e := range ents {
		if !allowed[e.Name()] {
			denied = append(denied, "/dev/"+e.Name())
		}
	}
	// A device that may not be on this machine is named anyway: it is refused
	// whether or not it exists.
	for _, name := range []string{"console", "cu.usbserial-0001", "uart.debug", "tty", "ptmx", "bpf0", "disk0", "rdisk0", "ttys000", "ptyp0", "klog", "pf"} {
		if p := "/dev/" + name; !slices.Contains(denied, p) {
			denied = append(denied, p)
		}
	}
	// A name that does not exist gives ENOENT whether or not it is refused, so
	// only the ones this host has are tried.
	denied = slices.DeleteFunc(denied, func(p string) bool { _, err := os.Lstat(p); return err != nil })
	if !slices.ContainsFunc(denied, func(p string) bool { return p == "/dev/console" }) {
		t.Log("this host has no /dev/console to try")
	}
	t.Logf("trying %d entries of /dev", len(denied))
	// Only statted: if the profile ever let one through, opening a console or a
	// serial port here could block, or toggle a line on attached hardware. The
	// rule that refuses the stat is the one that refuses the open, since
	// file-read* covers both, and TestEscapeTerminals opens the terminals.
	gone := 0
	for line := range strings.Lines(escRun(t, Spec{}, "stat-denied", denied...)) {
		p, ok := strings.CutPrefix(strings.TrimSpace(line), "gone ")
		if !ok {
			continue
		}
		// Gone in the sandbox and still on the host would be the profile
		// hiding an entry rather than refusing it.
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("stat %s in the sandbox: not there, but the host has it; want a refusal by the profile", p)
		} else {
			t.Logf("%s went away during the test", p)
			gone++
		}
	}
	if gone == len(denied) {
		t.Fatal("every entry went away during the test, so none was tried")
	}
	escRun(t, Spec{}, "dev-ok")
	// The profile says it, whatever this host has.
	p, err := profile(profileInput{Home: "/h"})
	if err != nil {
		t.Fatal(err)
	}
	if indexOf(p, `(deny file-read* file-write* file-ioctl (subpath "/dev"))`) < 0 {
		t.Errorf("the profile does not deny /dev:\n%s", p)
	}
}

// ------------------------------------------------------ a process that re-forks

// refork defines a shell function, chain, that forks, and the parent exits,
// again and again, each child making a process group of its own and spinning
// for its second argument's count of loops first. It runs in /bin/bash, whose &
// forks without an exec. A child of the test binary could only fork and exec,
// which takes milliseconds. With a spin of 200, about 0.7 ms, one process is
// alive at a time for most of a generation, and a generation lives about a
// millisecond: the chain the first teardown failed on, which listed the whole
// table and signaled afterwards. Without the spin a generation lives about half
// a millisecond, and bash's work after the fork keeps the parent alive beside
// its child. set -m, which a subshell turns off, is set again in each
// generation, so that each puts its child in a new group, as job control does,
// and a signal to the command's group misses the chain. The chain stops by
// itself once $SECONDS, the shell's age in whole seconds, which subshells
// inherit, reaches the first argument, so between one second short of it and
// it. That is what keeps a teardown that fails from leaving anything running on
// this machine. bash, not sh: the chain needs $SECONDS, and set -m in a
// subshell.
const refork = `chain() {
	set -m
	i=0; while [ "$i" -lt "$2" ]; do i=$((i+1)); done
	[ "$SECONDS" -ge "$1" ] && exit 0
	chain "$1" "$2" & exit 0
}
`

// reforkCommand is the command of a sandbox whose shell runs script after
// defining chain.
func reforkCommand(script string) []string {
	return []string{"/bin/bash", "-c", refork + script}
}

// Row: "Teardown: pid 1 dies, all die": a single process that re-forks about
// every millisecond does not outlast the sandbox. The first teardown scanned
// the whole process table and signaled afterwards, so each generation had
// exited by the time it was signaled and the next had not been listed; it gave
// up after 200 scans with nothing said. Each process is signaled as the scan
// finds it, and the teardown stops only when a scan proves the sandbox empty.
// The chain ends by itself after 10 seconds whatever happens.
func TestEscapeReforkingProcessEnds(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	c, err := Command(t.Context(), Spec{Home: home, Command: reforkCommand("chain 10 200")})
	if err != nil {
		t.Fatal(err)
	}
	c.Env = []string{shellPath}
	c.Stdout = &syncBuffer{} // the chain holds it open, so Wait waits for the chain
	start := time.Now()
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c)
	if err := waitWithin(t, c, 9*time.Second); err != nil {
		t.Errorf("Wait: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("teardown took %v, with the chain due to stop by itself at 10 s", d)
	}
	// Nothing is left, and nothing comes back.
	for range 10 {
		if got, err := c.run.mark.processes(); err != nil || len(got) != 0 {
			t.Fatalf("processes of the sandbox after Wait: %v, %v", got, err)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// Row: the same: when teardown cannot confirm the sandbox empty, Wait says so.
// A budget of none, with the stage's report ignored and a pid that is never
// settled in the caller's scan, stands for a chain that kept ahead of the scan
// until the budget ran out. The error wraps the command's own result.
func TestTeardownReportsWhatItCouldNotConfirm(t *testing.T) {
	t.Parallel()
	run := func(budget time.Duration, script string) error {
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
	if err := run(5*time.Second, "exit 3"); err == nil || !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("with time to settle: %v, want the command's status only", err)
	} else if se := new(survivorsError); errors.As(err, &se) {
		t.Errorf("with time to settle: %v", err)
	}
	err := run(0, "exit 3")
	se := new(survivorsError)
	if !errors.As(err, &se) {
		t.Fatalf("with no time to settle: %v, want a survivorsError", err)
	}
	if ee := new(exec.ExitError); !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Errorf("the command's status is lost: %v", err)
	}
	if code, serr := exitStatus(err); code != 3 || serr != nil {
		t.Errorf("exitStatus = %d, %v", code, serr)
	}
}

// ------------------------------------------------- a listener handed in

func registerInheritServe() {
	// inherit-serve serves the listener handed in as descriptor 3, and tries to
	// bind the port itself on each address after the first argument, which
	// must be refused. It says hello to one connection.
	escChecks["inherit-serve"] = func(e *escT, args []string) {
		l, err := net.FileListener(os.NewFile(3, "listener"))
		if err != nil {
			e.failf("file listener: %v", err)
			return
		}
		for _, a := range args[1:] {
			escBindDenied(e, []string{net.JoinHostPort(a, args[0])})
		}
		_ = l.(*net.TCPListener).SetDeadline(time.Now().Add(8 * time.Second))
		c, err := l.Accept()
		if err != nil {
			e.failf("accept: %v", err)
			return
		}
		_, _ = c.Write([]byte("hello\n"))
		_ = c.Close()
	}
}

// Row: "Network namespace ... Loopback": the workaround for a command that takes
// an inherited socket. A listener the caller binds on 127.0.0.1 and passes in
// Spec.Files serves with no Loopback port and no network rule at all, and the
// command's own binds of that port on the LAN address and the wildcard are
// refused, so unlike a Loopback port it is on 127.0.0.1 and nowhere else. A
// connection from the LAN address is refused too.
func TestEscapeInheritedListenerIsLoopbackOnly(t *testing.T) {
	t.Parallel()
	l, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	f, err := l.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	lan := lanAddr(t)
	args := []string{port, "0.0.0.0", "::1", "::", lan}
	home := realTemp(t)
	c, err := Command(t.Context(), Spec{Home: home, Files: []*os.File{f}, Command: append([]string{self(t), "esc", "inherit-serve"}, args...)})
	if err != nil {
		t.Fatal(err)
	}
	var stderr syncBuffer
	c.Stderr = &stderr
	c.Env = []string{shellPath}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c)
	var got string
	eventually(t, 10*time.Second, "the command did not serve the listener it was handed", func() bool {
		conn, err := dialTimeout("tcp", "127.0.0.1:"+port, time.Second)
		if err != nil {
			return false
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		got, _ = bufio.NewReader(conn).ReadString('\n')
		return got != ""
	})
	if got != "hello\n" {
		t.Errorf("read %q", got)
	}
	if err := waitWithin(t, c, 10*time.Second); err != nil {
		t.Errorf("the command: %v\n%s", err, stderr.buf.String())
	}
	if conn, err := dialTimeout("tcp", net.JoinHostPort(lan, port), time.Second); err == nil {
		conn.Close() //nolint:gosec // G104: nothing can be done about a failed close here, and the test is over or has what it needs.
		t.Error("the LAN address reached a listener bound on 127.0.0.1")
	}
}

// ------------------------------------------------------ nested profiles

// Row: "Teardown": the marker rests on a process in a profile not being able to
// apply another, since a second profile could deny the marker's name. Under each
// Spec option the review tried, and the ones that add the most rules, a second
// profile is refused with EPERM, and the sandbox's processes still answer as
// the sandbox's afterwards.
func TestEscapeNestedProfileRefused(t *testing.T) {
	t.Parallel()
	base := realTemp(t)
	read := mkdirs(t, base, "r")
	cover := mkdirs(t, read, "c")
	write := mkdirs(t, base, "w")
	for _, tc := range []struct {
		name string
		spec Spec
	}{
		{"none", Spec{}},
		{"network host, broad loopback, both services", Spec{Network: NetworkHost, BroadLoopback: true, Services: []Service{ServiceFirefox, ServiceDirectory}}},
		{"services, loopback and listen", Spec{Services: []Service{ServiceFirefox, ServiceDirectory}, Loopback: 1, Listen: 1}},
		{"read, write and cover", Spec{Read: []string{read}, Write: []string{write}, Cover: []string{cover}}},
		{"rlimits and kernel open", Spec{Kernel: KernelOpen, Rlimits: []Rlimit{{ResourceCPU, 600, 600}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, prof := range []string{
				"(version 1)(allow default)",
				`(version 1)(allow default)(deny mach-lookup (global-name "com.die-net.sandbox.in.x"))`,
				"(version 1)(deny default)",
			} {
				r := sh(t, tc.spec, `/usr/bin/sandbox-exec -p "$1" /usr/bin/true; echo "rc=$?"`, prof)
				if r.code != 0 || strings.Contains(r.stdout, "rc=0") || !strings.Contains(r.stderr, "Operation not permitted") {
					t.Errorf("a second profile %q was not refused: %s", prof, r)
				}
			}
			// After the attempts, the command answers as the sandbox's.
			spec := tc.spec
			spec.Home = realTemp(t)
			spec.Command = []string{"/bin/sh", "-c", `/usr/bin/sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>/dev/null; echo ready; read x; exit 0`}
			c, err := Command(t.Context(), spec)
			if err != nil {
				t.Fatal(err)
			}
			stdinR, stdinW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdinW.Close()
			defer stdinR.Close()
			stdoutR, stdoutW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdoutR.Close()
			c.Stdin, c.Stdout, c.Env = stdinR, stdoutW, []string{shellPath}
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			_ = stdoutW.Close()
			endAtCleanup(t, c)
			if line, _ := bufio.NewReader(stdoutR).ReadString('\n'); line != "ready\n" {
				t.Fatalf("the command said %q", line)
			}
			if got, err := c.run.mark.processes(); err != nil || len(got) == 0 {
				t.Errorf("after a second profile was refused, no process answers as the sandbox's: %v, %v", got, err)
			}
			_ = stdinW.Close()
			if err := waitWithin(t, c, 10*time.Second); err != nil {
				t.Errorf("Wait: %v", err)
			}
		})
	}
}

// ------------------------------------------------- roots, every spelling

func registerRootsChecks() {
	escChecks["roots-ops"] = escRootsOps
	escChecks["roots-modes"] = escRootsModes
}

// escRootsOps tries to remove, rename, rename over and swap with each root, by
// every name the sandbox can give it, and fails for each that worked. args are
// Home, a Write directory, a Write file, a Write socket, the caller's private
// directory, and the /.vol names of the directory, the file and Home.
func escRootsOps(e *escT, args []string) {
	home, w, f, sock, private := args[0], args[1], args[2], args[3], args[4]
	volW, volF, volHome := args[5], args[6], args[7]
	up := func(p string) string { d, b := filepath.Split(p); return d + strings.ToUpper(b) }
	nfd := func(p string) string { return strings.ReplaceAll(p, "é", "é") }
	data := func(p string) string { return "/System/Volumes/Data" + p }
	// Each op's name, so a failure says which.
	try := func(name string, err error) {
		if err == nil {
			e.failf("WORKED: %s", name)
		}
	}
	n := 0
	fresh := func() string {
		n++
		p := filepath.Join(home, "e"+strconv.Itoa(n))
		_ = os.Mkdir(p, 0o750) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
		return p
	}
	freshFile := func() string {
		n++
		p := filepath.Join(home, "f"+strconv.Itoa(n))
		_ = os.WriteFile(p, []byte("planted\n"), 0o600) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
		return p
	}
	freshLink := func() string {
		n++
		p := filepath.Join(home, "l"+strconv.Itoa(n))
		_ = os.Symlink(filepath.Join(private, "out.png"), p)
		return p
	}
	spell := func(p, vol string, dir bool) map[string]string {
		m := map[string]string{"exact": p, "upper": up(p), "nfd": nfd(p), "upper-nfd": nfd(up(p)), "datavol": data(p), "datavol-upper": data(up(p)), "vol": vol}
		if dir {
			m["slash"], m["dotdot"] = p+"/", p+"/x/.."
		}
		return m
	}
	_ = os.Remove(filepath.Join(home, "tmp")) //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
	for name, p := range spell(w, volW, true) {
		try("rmdir W "+name, unix.Rmdir(p))
		try("rename W away "+name, unix.Rename(p, filepath.Join(home, "stolen-"+name)))
		try("rename dir over W "+name, unix.Rename(fresh(), p))
		try("swap dir with W "+name, unix.RenamexNp(fresh(), p, unix.RENAME_SWAP))
		try("swap file with W "+name, unix.RenamexNp(freshFile(), p, unix.RENAME_SWAP))
		try("symlink at W "+name, unix.Symlink(private, p))
	}
	_ = os.Mkdir(filepath.Join(w, "sw"), 0o750) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
	for name, p := range spell(home, volHome, true) {
		try("rmdir HOME "+name, unix.Rmdir(p))
		try("rename HOME away "+name, unix.Rename(p, w+"/stolen-"+name))
		try("swap dir with HOME "+name, unix.RenamexNp(filepath.Join(w, "sw"), p, unix.RENAME_SWAP))
	}
	// A Write path that is a regular file.
	for name, p := range spell(f, volF, false) {
		try("unlink F "+name, unix.Unlink(p))
		try("rename file over F "+name, unix.Rename(freshFile(), p))
		try("rename link over F "+name, unix.Rename(freshLink(), p))
		try("swap file with F "+name, unix.RenamexNp(freshFile(), p, unix.RENAME_SWAP))
		try("swap link with F "+name, unix.RenamexNp(freshLink(), p, unix.RENAME_SWAP))
		try("swap dir with F "+name, unix.RenamexNp(fresh(), p, unix.RENAME_SWAP))
		try("rename F away "+name, unix.Rename(p, filepath.Join(home, "stolenf-"+name)))
	}
	try("hard link F into home", unix.Link(f, filepath.Join(home, "hard")))
	for _, p := range []string{sock, up(sock), data(sock)} {
		try("unlink sock "+p, unix.Unlink(p))
		try("rename sock away "+p, unix.Rename(p, filepath.Join(home, "s")))
		try("rename file over sock "+p, unix.Rename(freshFile(), p))
		try("swap file with sock "+p, unix.RenamexNp(freshFile(), p, unix.RENAME_SWAP))
	}
	// What a root is for still works.
	if err := os.WriteFile(filepath.Join(w, "inside"), []byte("ok"), 0o600); err != nil { //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
		e.failf("write inside W: %v", err)
	}
	if err := os.WriteFile(f, []byte("rewritten\n"), 0o600); err != nil { //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
		e.failf("write the file root: %v", err)
	}
}

// escRootsModes does what a profile that denies unlink and create does not stop:
// changing a root's mode, flags and attributes, and making a FIFO in Home. It
// puts each back, and fails for one that was refused, since the docs say these
// work. args are Home and a Write directory.
func escRootsModes(e *escT, args []string) {
	home, w := args[0], args[1]
	for _, op := range []struct {
		name     string
		do, undo func() error
	}{
		{"chmod 0", func() error { return unix.Chmod(w, 0) }, func() error { return unix.Chmod(w, 0o755) }},
		{"chflags uchg", func() error { return unix.Chflags(w, unix.UF_IMMUTABLE) }, func() error { return unix.Chflags(w, 0) }},
		{"setxattr", func() error { return unix.Setxattr(w, "user.sbx", []byte("x"), 0) }, func() error { return unix.Removexattr(w, "user.sbx") }},
		{"mkfifo in home", func() error { return unix.Mkfifo(filepath.Join(home, "fifo"), 0o644) }, func() error { return unix.Unlink(filepath.Join(home, "fifo")) }},
	} {
		if err := op.do(); err != nil {
			e.failf("%s: %v: the gap closed", op.name, err)
			continue
		}
		if err := op.undo(); err != nil {
			e.failf("undo %s: %v", op.name, err)
		}
	}
}

// Row: "Path and link rules", for every name a root has: Home, a Write
// directory, a Write file and a Write socket are not removed, renamed away,
// renamed over, symlinked over or swapped (renamex_np with RENAME_SWAP) under
// their own name, in upper case, in the other Unicode form, through
// /System/Volumes/Data, through /.vol/<dev>/<inode>, with a trailing slash,
// or through "x/..". The names carry a non-ASCII letter. The review ran the same
// attempts and none worked.
func TestEscapeRootsEveryName(t *testing.T) {
	t.Parallel()
	base := realTemp(t)
	home := mkdirs(t, base, "homé")
	w := mkdirs(t, base, "wé")
	f := writeFile(t, "caller's file\n", base, "fé.txt")
	short, err := os.MkdirTemp("/private/tmp", "sbxr")
	if err != nil {
		t.Skipf("no short directory for a socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	sock := filepath.Join(short, "b.sock")
	l, err := listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	private := mkdirs(t, base, "caller-private")
	writeFile(t, "caller data\n", private, "out.png")
	ino := func(p string) (uint64, string) {
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			t.Fatal(err)
		}
		return st.Ino, fmt.Sprintf("/.vol/%d/%d", st.Dev, st.Ino)
	}
	iw, vw := ino(w)
	ifl, vf := ino(f)
	ih, vh := ino(home)
	is, _ := ino(sock)
	r := escResult(t, Spec{Home: home, Dir: "/", Write: []string{w, f, sock}}, "roots-ops", home, w, f, sock, private, vw, vf, vh)
	if r.code != 0 {
		t.Errorf("%s", r)
	}
	for _, x := range []struct {
		p   string
		ino uint64
	}{{w, iw}, {f, ifl}, {home, ih}, {sock, is}} {
		if got, _ := ino(x.p); got != x.ino {
			t.Errorf("%s is a different file now: inode %d, was %d", x.p, got, x.ino)
		}
	}
	if b, err := readFile(filepath.Join(home, "out.png")); err == nil {
		t.Errorf("Home leads to the caller's private directory: %q", b)
	}
}

// Row: the same, for what the profile does not stop and callers must allow for:
// a root's mode, flags and extended attributes can be changed, and a FIFO made
// in Home. A caller that finds Home unreadable or immutable after a run, or
// opens a result by name and blocks on a FIFO, is seeing this. The test fails
// when it stops being so.
func TestGapRootModeAndFifo(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	w := mkdirs(t, realTemp(t), "w")
	escRun(t, Spec{Home: home, Write: []string{w}}, "roots-modes", home, w)
	if fi, err := os.Stat(w); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("the Write directory after the sandbox put its mode back: %v, %v", fi, err)
	}
}

// ------------------------------------------------- a group number reused

// Row: "Teardown": the command's process group is a pid, and once the group is
// empty the kernel may give the number to another process, which a late Wait
// or Footprint must not signal or count. The test makes the number a canary's
// group, a process of its own holding 300 MiB, which is the situation a pid
// wrap would make, and shows Wait leaves it alone and Footprint does not count
// it. (Footprint counts a member of the group only if the stage is its
// ancestor, and Wait kills by the profile's marker only.)
func TestWaitAndFootprintIgnoreAReusedGroupNumber(t *testing.T) {
	t.Parallel()
	canary := exec.CommandContext(t.Context(), self(t), "esc", "alloc", "300") //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	canary.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := canary.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := canary.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = canary.Process.Kill(); _ = canary.Wait() })
	if line, _ := bufio.NewReader(out).ReadString('\n'); !strings.HasPrefix(line, "touched") {
		t.Fatalf("the canary said %q", line)
	}
	home := realTemp(t)
	c := escCmd(t.Context(), t, Spec{Home: home}, "hold", filepath.Join(home, "pid"))
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c)
	readPid(t, filepath.Join(home, "pid"))
	c.run.group = canary.Process.Pid
	fp, err := c.Footprint()
	if err != nil {
		t.Fatal(err)
	}
	if fp >= 200<<20 {
		t.Errorf("Footprint = %d MiB, which counts the canary's 300 MiB through a group number that is not the sandbox's", fp>>20)
	}
	c.stop()
	_ = waitWithin(t, c, 10*time.Second)
	time.Sleep(300 * time.Millisecond)
	// alive counts a zombie, which an ended process is until its parent reaps it.
	if p, err := unix.SysctlKinfoProc("kern.proc.pid", canary.Process.Pid); err != nil || p.Proc.P_stat == stateZombie {
		t.Errorf("Wait ended a process group that only shared the command's group number: %v", err)
	}
}

// ------------------------------------------------- a Start that fails late

// Row: "Teardown ... on stage death", for Start's failure path. If the stage
// dies after it has started the command and before it replies, Start fails with
// the command already running under the profile, and the lifeline it closes
// ends nothing, since the stage that would read it is gone. abortStart ends the
// sandbox by the profile's marker too. The stage cannot be made to die at that
// instant from outside, so the test makes the same state: a running command
// whose stage has been killed, and then runs the cleanup Start's failure path
// runs.
func TestStartFailureEndsACommandWhoseStageDied(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	pidfile := filepath.Join(home, "pid")
	c := escCmd(t.Context(), t, Spec{Home: home}, "leave", "setpgid", pidfile, "1")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c)
	escapee := readPid(t, pidfile)
	// The stage is this process's child, so it is ours to kill.
	if err := syscall.Kill(c.Pid(), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := c.run.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("the stage: %v", err)
	}
	// The stage is gone and ended nothing: its command, which left the group,
	// still runs. Wait a moment for the kill to land, then see.
	time.Sleep(300 * time.Millisecond)
	if got, err := c.run.mark.processes(); err != nil || len(got) == 0 {
		t.Fatalf("precondition: nothing runs under the profile after the stage was killed: %v, %v", got, err)
	}
	abortStart(c, c.run.cmd, c.run.mark, c.run.sent)
	if got, err := c.run.mark.processes(); err != nil || len(got) != 0 {
		t.Errorf("processes under the profile after Start's cleanup: %v, %v", got, err)
	}
	eventually(t, 5*time.Second, "the escapee outlived Start's cleanup", func() bool { return !alive(escapee) })
}

// Row: "Teardown": the command is a member whose parent, the stage, is not one,
// so a scan that excuses a dying process by its parent can't excuse it. This is
// the race that rule opened. The command forks a child after the scan's list is
// taken and exits before the scan reads it. The scan then reads the command as
// a zombie or exiting, with the stage, which is no member, as its parent, and
// the child, which is not in the list, runs under the profile. The scan must
// not be clean.
//
// The scan's window is under a millisecond, and a zombie of the command lasts
// as long as the stage takes to reap it, so the test fixes the order. The list's
// hook releases the command and waits until its child runs and the command is
// gone, and the scan's read of the command is the one thing that is not the
// kernel's: it answers as the kernel does for a process that is exiting, with
// the command's own start time and the stage as its parent. Everything else is
// real. The stage, which the test started, is stopped with SIGSTOP so that it
// doesn't end the child before the scan has run, and continued with SIGCONT.
// Nothing else is signaled. The list is cut to the stage and the command so
// that other tests' processes can't make the scan unclean for another reason.
func TestEscapeCommandForksAndExitsAfterTheList(t *testing.T) {
	t.Parallel()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pw.Close() })
	c, err := Command(t.Context(), Spec{
		Home:    realTemp(t),
		Command: []string{"/bin/sh", "-c", "read x; /bin/sleep 60 & exit 0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Env = []string{shellPath}
	c.Stdin = pr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	_ = pr.Close()
	endAtCleanup(t, c)
	stage, command, mark := c.Pid(), c.run.group, c.run.mark
	// The stage runs again before the sandbox is ended, so that nothing is left
	// stopped. Cleanups run last first.
	t.Cleanup(func() { _ = continueStage(c) })
	var started procStat
	eventually(t, 5*time.Second, "the command is not under the profile", func() bool {
		st, err := statPid(command)
		started = st
		return err == nil && st.Comm != sandboxExecName && mark.inSandbox(command)
	})
	if err := syscall.Kill(stage, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	p := mark.prober(command)
	list, stat := p.list, p.stat
	p.list = func() ([]int, error) {
		pids, err := list()
		if err != nil {
			return nil, err
		}
		// The command forks after the list was taken, and exits.
		if _, err := pw.WriteString("go\n"); err != nil {
			t.Error(err)
		}
		// The stopped stage reaps the command only if its thread was already
		// asleep in wait4, which finishes the wait before the thread stops. So
		// the command may be gone or a zombie, and either has exited.
		eventually(t, 5*time.Second, "the command did not exit", func() bool {
			st, err := statPid(command)
			return errors.Is(err, unix.ESRCH) || err == nil && st.Zombie
		})
		eventually(t, 5*time.Second, "the command's child is not under the profile", func() bool {
			got, err := mark.processes()
			return err == nil && len(got) > 0
		})
		return slices.DeleteFunc(pids, func(pid int) bool { return pid != stage && pid != command }), nil
	}
	p.stat = func(pid int) (procStat, error) {
		if pid == command {
			return procStat{Exiting: true, Start: started.Start, Comm: started.Comm, PPid: stage}, nil
		}
		return stat(pid)
	}
	clean, _, err := p.scan(memory{})
	if err != nil {
		t.Fatal(err)
	}
	if clean {
		t.Error("the scan was clean while the command's child runs under the profile")
	}
	if got, err := mark.processes(); err != nil || len(got) == 0 {
		t.Errorf("the child ended by itself, so the test shows nothing: %v, %v", got, err)
	}
	if err := continueStage(c); err != nil {
		t.Fatal(err)
	}
	if err := waitWithin(t, c, 9*time.Second); err != nil {
		t.Errorf("Wait: %v", err)
	}
	if got, err := mark.processes(); err != nil || len(got) != 0 {
		t.Errorf("processes of the sandbox after Wait: %v, %v", got, err)
	}
}

// continueStage sends SIGCONT to c's stage, which a test stopped. It signals
// through the stage's os.Process, which sends nothing once Wait has reaped the
// stage: the stage's number may be another process's by then, and a SIGCONT by
// number would resume a job the user stopped.
func continueStage(c *Cmd) error {
	return c.run.cmd.Process.Signal(syscall.SIGCONT)
}

// A cleanup that continues the stage runs after Wait has reaped it, and it must
// send nothing then, since its pid is free for another process to take. The
// number's reuse can't be made to happen, so this checks what tells the two
// ways apart: a signal by number to a pid that is free fails with ESRCH, and one
// through the os.Process is refused with ErrProcessDone, before anything is sent.
func TestContinueStageSendsNothingAfterWait(t *testing.T) {
	t.Parallel()
	c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{"/usr/bin/true"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := continueStage(c); err != nil {
		t.Errorf("continueStage on a stage that has not been waited for: %v", err)
	}
	if err := waitWithin(t, c, 9*time.Second); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if err := continueStage(c); !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("continueStage after Wait: %v, want %v, which means nothing was sent", err, os.ErrProcessDone)
	}
}
