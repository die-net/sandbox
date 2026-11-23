package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// checkWorld sets up what the rows that look for the caller's own secrets and
// sockets try: a home with a .ssh and a .aws in it, which is this process's
// HOME, and a unix socket that SSH_AUTH_SOCK names and that accepts. Neither is
// under a Read or Write path of a sandbox the tests build, so a refusal
// is the profile's. It returns the home and the socket's path.
func checkWorld(t *testing.T) (home, sock string) {
	t.Helper()
	home = realTemp(t)
	for _, d := range []string{".ssh", ".aws"} {
		writeFile(t, "secret\n", mkdirs(t, home, d), "credentials")
	}
	t.Setenv("HOME", home)
	// A unix socket's path is limited to 104 bytes, which a test's temporary
	// directory exceeds.
	short, err := os.MkdirTemp("/private/tmp", "sbxc")
	if err != nil {
		t.Skipf("no short directory for a socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	sock = filepath.Join(short, "agent.sock")
	l, err := listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
	return home, sock
}

// TestCheckSandboxDarwin runs the suite in a sandbox built from a Spec with no
// network and a home, and checks each result the macOS backend is meant to
// give: a pass where the profile holds, and a failure, with its reason, where
// the platform cannot hold.
//
//nolint:paralleltest // uses t.Setenv through checkWorld, which t.Parallel forbids.
func TestCheckSandboxDarwin(t *testing.T) {
	userHome, _ := checkWorld(t)
	home := realTemp(t)
	secret := hostSecret(t)
	inHome := mkdirs(t, home, "inside-home")
	listener, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	spec := Spec{Home: home, Network: NetworkNone}
	want := Expect{
		Unreadable:  []string{secret},
		Unwritable:  []string{inHome},
		Unreachable: []string{"tcp:" + listener.Addr().String()},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := Check(ctx, &spec, want)
	if err != nil {
		t.Fatal(err)
	}
	m := byName(t, res)
	for name, st := range map[string]Status{
		"egress.direct-tcp":           Pass,
		"egress.direct-udp":           Pass,
		"metadata.v4":                 Pass,
		"metadata.v6":                 Pass,
		"secrets.readable":            Pass,
		"sockets.reachable":           Pass,
		"proc.signal":                 Pass,
		"expect.unreadable:" + secret: Pass,
		"expect.unreachable:tcp:" + listener.Addr().String(): Pass,
		"uid.root-initial-ns":                                Pass,
		"covers:/Users":                                      Pass,
		"covers:/private/var":                                Pass,
		// Not vacuous: a path under Home is writable, so the check says so.
		"expect.unwritable:" + inHome: Fail,
		// The gaps, which the checks report as failures with their reason.
		"proc.visible": Fail,
		"proc.environ": Pass, // none of the processes outside whose environment is readable are Apple's, unless the suite is run beside one
		"proc.trace":   Skipped,
		// Linux-only checks, and limits nothing here can enforce.
		"userns.create": Skipped, "mount.tmpfs": Skipped, "io_uring.setup": Skipped, "cgroup.delegate": Skipped,
		"limits.memory": NotEnforceable, "limits.tasks": NotEnforceable,
	} {
		r, ok := m[name]
		if !ok {
			t.Errorf("no result named %s", name)
			continue
		}
		if r.Status != st && (name != "proc.environ" || r.Status != Fail) {
			t.Errorf("%s = %+v, want %v", name, r, st)
		}
	}
	for _, name := range []string{"writes.outside", "covers"} {
		ran := false
		for n, r := range m {
			if (n == name || strings.HasPrefix(n, name+":")) && r.Status != Skipped {
				ran = true
			}
		}
		if !ran {
			t.Errorf("%s did not run", name)
		}
	}
	// The rows that used to pass on macOS without trying anything now try the
	// caller's own secrets and socket, and say how many.
	if r := m["writes.outside"]; r.Status != Pass || !strings.Contains(r.Detail, os.TempDir()) {
		t.Errorf("writes.outside = %+v, want a pass that tried the directories this account can write, such as %s", r, os.TempDir())
	}
	// It tries the two under the test's HOME, and any the account's real home has.
	var tried int
	if _, err := fmt.Sscanf(m["secrets.readable"].Detail, "open of %d ", &tried); err != nil || tried < 2 {
		t.Errorf("secrets.readable = %+v, want it to have tried at least the two under %s", m["secrets.readable"], userHome)
	}
	if r := m["sockets.reachable"]; !strings.HasPrefix(r.Detail, "connect to ") || strings.HasPrefix(r.Detail, "connect to 0 ") {
		t.Errorf("sockets.reachable = %+v, want it to have tried SSH_AUTH_SOCK", r)
	}
	for _, r := range res {
		if r.Name == "check.internal" {
			t.Errorf("a check panicked: %s", r.Detail)
		}
	}
	// The child's files stayed in its home.
	if entries, _ := os.ReadDir(inHome); len(entries) != 0 {
		t.Errorf("Check left files in Home: %v", entries)
	}
}

// TestCheckCatchesEscapesDarwin runs the checks against sandboxes that have a
// hole, to see that they fail: host network, BroadLoopback, a Read path that
// shows a secret, a Write path that is writable.
//
//nolint:paralleltest // uses t.Setenv through checkWorld, which t.Parallel forbids.
func TestCheckCatchesEscapesDarwin(t *testing.T) {
	conn, err := dialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	haveNet := err == nil
	if haveNet {
		conn.Close() //nolint:gosec // G104: nothing can be done about a failed close here, and the test is over or has what it needs.
	}
	listener, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dir := realTemp(t)
	shown := mkdirs(t, dir, "shown")
	writeFile(t, "secret", shown, "secret")
	secret := filepath.Join(shown, "secret")
	userHome, sock := checkWorld(t)
	home := realTemp(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// The rows that look for the caller's own secrets, sockets, signals and
	// writable directories each fail when the guarantee is broken, and pass when
	// it holds, so none is a row that passes whatever happens.
	t.Run("secrets.readable", func(t *testing.T) {
		res, err := Check(ctx, &Spec{Home: home, Read: []string{userHome}}, Expect{})
		if err != nil {
			t.Fatal(err)
		}
		if r := byName(t, res)["secrets.readable"]; r.Status != Fail || !strings.Contains(r.Detail, filepath.Join(userHome, ".ssh")) {
			t.Errorf("a home shown by Read: %+v", r)
		}
		res, err = Check(ctx, nil, Expect{})
		if err != nil {
			t.Fatal(err)
		}
		if r := byName(t, res)["secrets.readable"]; r.Status != Fail {
			t.Errorf("no sandbox: %+v", r)
		}
	})
	t.Run("sockets.reachable", func(t *testing.T) {
		// A socket in Write is one the command may connect to, by design.
		res, err := Check(ctx, &Spec{Home: home, Write: []string{sock}}, Expect{})
		if err != nil {
			t.Fatal(err)
		}
		if r := byName(t, res)["sockets.reachable"]; r.Status != Fail || !strings.Contains(r.Detail, sock) {
			t.Errorf("a socket shown by Write: %+v", r)
		}
		res, err = Check(ctx, nil, Expect{})
		if err != nil {
			t.Fatal(err)
		}
		if r := byName(t, res)["sockets.reachable"]; r.Status != Fail {
			t.Errorf("no sandbox: %+v", r)
		}
	})
	t.Run("proc.signal", func(t *testing.T) {
		// With no sandbox the process can signal the caller's processes, which
		// are of its uid. The first it tries is its parent.
		res, err := Check(ctx, nil, Expect{})
		if err != nil {
			t.Fatal(err)
		}
		if r := byName(t, res)["proc.signal"]; r.Status != Fail {
			t.Errorf("no sandbox: %+v", r)
		}
		// And its candidates are this account's processes first, whose refusal
		// is the profile's and not the uid's.
		pids, err := foreignPIDs()
		if err != nil || len(pids) == 0 {
			t.Fatalf("foreignPIDs = %v, %v", pids, err)
		}
		if p, err := unix.SysctlKinfoProc("kern.proc.pid", pids[0]); err != nil || p.Eproc.Ucred.Uid != euid() {
			t.Errorf("the first outside process tried, %d, is not this account's: %v", pids[0], err)
		}
	})
	t.Run("writes.outside", func(t *testing.T) {
		// A directory outside the sandbox's own that is writable is a failure
		// when the check is run with no profile in the way, as here, and not
		// when it is not writable. A Check with a sandbox cannot fail this row
		// by a hole in the spec, since a Write path is the sandbox's own.
		open, closed := mkdirs(t, realTemp(t), "open"), mkdirs(t, realTemp(t), "closed")
		if err := os.Chmod(closed, 0o400); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(closed, 0o600) })
		env := &checkEnv{spec: &Spec{Home: home}, hints: checkHints{Set: true, WriteTargets: []string{open}}}
		if r := checkWrites(env)[0]; r.Status != Fail || !strings.Contains(r.Detail, open) {
			t.Errorf("a writable directory outside the sandbox: %+v", r)
		}
		env.hints.WriteTargets = []string{closed}
		if r := checkWrites(env)[0]; r.Status != Pass {
			t.Errorf("a directory that cannot be written: %+v", r)
		}
		// Nothing to try is a skip with the reason, not a pass.
		env.hints.WriteTargets = nil
		if r := checkWrites(env)[0]; r.Status != Skipped || r.Detail == "" {
			t.Errorf("no target: %+v", r)
		}
		// The hints the caller builds do name directories this account can write.
		h := platformHints(&Spec{Home: home})
		if !h.Set || !slices.Contains(h.WriteTargets, filepath.Dir(home)) {
			t.Errorf("platformHints = %+v, want the parent of Home among the write targets", h)
		}
	})

	// A Read path shows the secret, and the caller said it must not be seen.
	res, err := Check(ctx, &Spec{Home: home, Read: []string{shown}}, Expect{Unreadable: []string{secret}})
	if err != nil {
		t.Fatal(err)
	}
	if r := byName(t, res)["expect.unreadable:"+secret]; r.Status != Fail {
		t.Errorf("a secret under a Read path: %+v", r)
	}
	// The same Read path is writable by no one: writes.outside passes.
	if r := byName(t, res)["writes.outside"]; r.Status != Pass {
		t.Errorf("writes.outside with a Read path: %+v", r)
	}
	// A Write path is writable, and Unwritable names it.
	res, err = Check(ctx, &Spec{Home: home, Write: []string{shown}}, Expect{Unwritable: []string{shown}})
	if err != nil {
		t.Fatal(err)
	}
	if r := byName(t, res)["expect.unwritable:"+shown]; r.Status != Fail {
		t.Errorf("a Write path named Unwritable: %+v", r)
	}
	// BroadLoopback reaches the local listener, which Unreachable names.
	res, err = Check(ctx, &Spec{Home: home, BroadLoopback: true}, Expect{Unreachable: []string{"tcp:" + listener.Addr().String()}})
	if err != nil {
		t.Fatal(err)
	}
	if r := byName(t, res)["expect.unreachable:tcp:"+listener.Addr().String()]; r.Status != Fail {
		t.Errorf("a local listener under BroadLoopback: %+v", r)
	}
	if !haveNet {
		return
	}
	// The host's network reaches the internet.
	res, err = Check(ctx, &Spec{Home: home, Network: NetworkHost}, Expect{})
	if err != nil {
		t.Fatal(err)
	}
	if r := byName(t, res)["egress.direct-tcp"]; r.Status != Fail {
		t.Errorf("direct TCP under NetworkHost: %+v", r)
	}
}

// TestCheckNilDarwin runs the suite with no sandbox, as an operator's boundary
// gives it, and checks the macOS results: other processes are listed and can
// be signaled.
func TestCheckNilDarwin(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := Check(ctx, nil, Expect{})
	if err != nil {
		t.Fatal(err)
	}
	m := byName(t, res)
	for name, st := range map[string]Status{"proc.visible": Fail, "proc.signal": Fail, "proc.trace": Skipped, "limits.memory": NotEnforceable} {
		if m[name].Status != st {
			t.Errorf("%s = %+v, want %v", name, m[name], st)
		}
	}
	if !strings.Contains(m["proc.visible"].Detail, "no pid namespace") {
		t.Errorf("proc.visible does not say why: %q", m["proc.visible"].Detail)
	}
}

// TestProcEnvironment checks the KERN_PROCARGS2 parse: argv alone is not an
// environment, and a record with one is.
func TestProcEnvironment(t *testing.T) {
	t.Parallel()
	dir := realTemp(t)
	cmd := newTestProcess(t, dir, []string{"SBX_ENV_PARSE=1"})
	if !procEnvironment(cmd) {
		t.Error("the environment of a process that has one was not read")
	}
	if procEnvironment(1) {
		t.Error("launchd's environment was read")
	}
	if procEnvironment(-5) {
		t.Error("a bad pid gave an environment")
	}
}
