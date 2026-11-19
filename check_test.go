package sandbox

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// init stands in for the line Stage will have, which dispatches the check
// marker to checkStage, until that line is merged. It runs before TestMain.
func init() {
	if len(os.Args) > 1 && os.Args[1] == checkArg {
		os.Exit(checkStage())
	}
}

// fakeProxy answers CONNECT to ok with 200 and anything else with 403.
func fakeProxy(t *testing.T, ok string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				if strings.Fields(line)[1] == ok {
					c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				} else {
					c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func byName(t *testing.T, res []Result) map[string]Result {
	t.Helper()
	m := map[string]Result{}
	for _, r := range res {
		if _, dup := m[r.Name]; dup {
			t.Errorf("result name %q appears twice", r.Name)
		}
		m[r.Name] = r
	}
	return m
}

// TestCheckNil runs the whole suite in a child of the test binary, as an
// operator's container would, and checks the caller's Expect results and the
// results that hold on any plain host.
func TestCheckNil(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()

	want := Expect{
		Unreadable:  []string{secret, filepath.Join(dir, "absent")},
		Unwritable:  []string{dir},
		Unreachable: []string{"tcp:" + listener.Addr().String(), "tcp:" + closedAddr, "unix:" + filepath.Join(dir, "none.sock"), "bogus:x"},
		Proxy:       fakeProxy(t, "ok.example:443"),
		Allowed:     []string{"ok.example:443", "deny.example:443"},
		Refused:     []string{"deny.example:443", "ok.example:443"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	res, err := Check(ctx, nil, want)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("Check took %v", d)
	}
	m := byName(t, res)
	for name, st := range map[string]Status{
		"expect.unreadable:" + secret:                                Fail,
		"expect.unreadable:" + filepath.Join(dir, "absent"):          Pass,
		"expect.unwritable:" + dir:                                   Fail,
		"expect.unreachable:tcp:" + listener.Addr().String():         Fail,
		"expect.unreachable:tcp:" + closedAddr:                       Pass,
		"expect.unreachable:unix:" + filepath.Join(dir, "none.sock"): Pass,
		"expect.unreachable:bogus:x":                                 Fail,
		"proxy.allowed:ok.example:443":                               Pass,
		"proxy.allowed:deny.example:443":                             Fail,
		"proxy.refused:deny.example:443":                             Pass,
		"proxy.refused:ok.example:443":                               Fail,
		"writes.outside":                                             Skipped,
		"covers":                                                     Skipped,
	} {
		if r, ok := m[name]; !ok || r.Status != st {
			t.Errorf("%s = %+v, want %v", name, r, st)
		}
	}
	for _, name := range []string{"secrets.readable", "sockets.reachable", "egress.direct-tcp", "egress.direct-udp", "metadata.v4", "metadata.v6", "lan.gateway", "groups.supplementary", "uid.root-initial-ns", "limits.memory", "limits.tasks", "userns.create"} {
		r, ok := m[name]
		if !ok {
			t.Errorf("no result named %s", name)
			continue
		}
		if r.Detail == "" {
			t.Errorf("%s has no detail", name)
		}
	}
	for _, r := range res {
		if r.Name == "check.internal" {
			t.Errorf("a check panicked: %s", r.Detail)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("Check left files in the Unwritable directory: %v", entries)
	}
}

func TestCheckNilTimeoutIsPass(t *testing.T) {
	// A black hole: a listener whose backlog is full would do, but the
	// documented targets are enough to see the wording. Only the format of
	// a timeout is tested here.
	out, d := tryDial("tcp", "192.0.2.1:9", 200*time.Millisecond) // TEST-NET-1
	if out == timedOut && !strings.Contains(d, "timed out") {
		t.Errorf("timeout detail %q does not say so", d)
	}
	if r := reachResult("x", "y", out, d, false); out != connected && r.Status != Pass {
		t.Errorf("outcome %v gave %v", out, r.Status)
	}
}

func TestCheckSpecRefusesBadSpec(t *testing.T) {
	// An empty Spec has no home, so it is refused, before Command exists or after.
	if _, err := Check(context.Background(), &Spec{}, Expect{}); err == nil {
		t.Error("Check accepted an empty Spec")
	}
}

func TestStatusString(t *testing.T) {
	for st, want := range map[Status]string{Pass: "pass", Fail: "fail", NotEnforceable: "not-enforceable", Skipped: "skipped", 9: "status(9)"} {
		if st.String() != want {
			t.Errorf("%d = %q, want %q", st, st.String(), want)
		}
	}
}

func TestUnder(t *testing.T) {
	for _, tc := range []struct {
		p, root string
		want    bool
	}{{"/a/b", "/a", true}, {"/a", "/a", true}, {"/ab", "/a", false}, {"/", "/a", false}, {"/a/b", "/", true}} {
		if got := under(tc.p, tc.root); got != tc.want {
			t.Errorf("under(%s, %s) = %v", tc.p, tc.root, got)
		}
	}
}

// TestSpecDrivenChecks runs the checks that read the Spec, without a sandbox.
func TestSpecDrivenChecks(t *testing.T) {
	dir := t.TempDir()
	mk := func(p ...string) string {
		path := filepath.Join(append([]string{dir}, p...)...)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	home, ro := mk("home"), mk("ro")
	leaky, tidy := mk("leaky"), mk("tidy")
	if err := os.WriteFile(filepath.Join(leaky, "token"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mk("tidy", "ro-parent") // an empty directory
	shown := mk("tidy", "ro-parent", "shown")
	spec := &Spec{Home: home, Read: []string{ro, shown}, Cover: []string{leaky, tidy}}
	e := &checkEnv{spec: spec}

	m := byName(t, checkCovers(e))
	if m["covers:"+leaky].Status != Fail || !strings.Contains(m["covers:"+leaky].Detail, "token") {
		t.Errorf("leaky cover: %+v", m["covers:"+leaky])
	}
	if m["covers:"+tidy].Status != Pass {
		t.Errorf("a cover holding only the way to a Read path failed: %+v", m["covers:"+tidy])
	}
	// Both Read directories are writable here, so writes.outside must say so,
	// but a path under Home or Write must not be tried.
	w := checkWrites(e)[0]
	if w.Status != Fail || !strings.Contains(w.Detail, ro) {
		t.Errorf("writes.outside = %+v", w)
	}
	spec.Write = []string{ro, shown}
	if w := checkWrites(e)[0]; strings.Contains(w.Detail, ro) {
		t.Errorf("a Write path was counted as outside: %+v", w)
	}
	if entries, _ := os.ReadDir(ro); len(entries) != 0 {
		t.Errorf("writes.outside left %v", entries)
	}
}
