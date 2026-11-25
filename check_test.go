package sandbox

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeProxy answers CONNECT to ok with 200 and anything else with 403.
func fakeProxy(t *testing.T, ok string) string {
	t.Helper()
	ln, err := listenLocal()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:gosec // G104: nothing can be done about a failed close here, and the test is over or has what it needs.
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
				reply := "HTTP/1.1 403 Forbidden\r\n\r\n"
				if strings.Fields(line)[1] == ok {
					reply = "HTTP/1.1 200 Connection established\r\n\r\n"
				}
				// A reply that is not sent leaves the client's check without
				// the answer it expects, which that check reports.
				if _, err := c.Write([]byte(reply)); err != nil {
					return
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
	t.Parallel()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := listenLocal()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed, err := listenLocal()
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close() //nolint:gosec // G104: nothing can be done about a failed close here, and the test is over or has what it needs.

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
	t.Parallel()
	// A black hole: a listener whose backlog is full would do, but the
	// documented targets are enough to see the wording. Only the format of
	// a timeout is tested here.
	out, d := tryDial("tcp", "192.0.2.1:9", 200*time.Millisecond) // TEST-NET-1
	if out == timedOut && !strings.Contains(d, "timed out") {
		t.Errorf("timeout detail %q does not say so", d)
	}
	if r := reachResult("x", "y", out, d); out != connected && r.Status != Pass {
		t.Errorf("outcome %v gave %v", out, r.Status)
	}
}

func TestCheckSpecRefusesBadSpec(t *testing.T) {
	t.Parallel()
	// An empty Spec has no home, so it is refused, before Command exists or after.
	if _, err := Check(context.Background(), &Spec{}, Expect{}); err == nil {
		t.Error("Check accepted an empty Spec")
	}
}

func TestStatusString(t *testing.T) {
	t.Parallel()
	for st, want := range map[Status]string{Pass: "pass", Fail: "fail", NotEnforceable: "not-enforceable", Skipped: "skipped", 9: "status(9)"} {
		if st.String() != want {
			t.Errorf("%d = %q, want %q", st, st.String(), want)
		}
	}
}

func TestUnder(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	dir := t.TempDir()
	mk := func(p ...string) string {
		path := filepath.Join(append([]string{dir}, p...)...)
		if err := os.MkdirAll(path, 0o750); err != nil {
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

// TestCheckSpecCoversShowLinkedFiles checks the covers as the child does,
// against the Spec that checkSpec gives it, on a host where a link in /etc
// leads under a cover, as Ubuntu's /etc/resolv.conf leads into /run. prepare
// binds that file back, and bubblewrap makes its parent directories as empty
// mount points in the cover. They are not in the caller's Spec, so a check
// that judged by it failed every Ubuntu host, and the check stays strict for
// any other entry.
// Row: "Self-checks".
func TestCheckSpecCoversShowLinkedFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	run, home := filepath.Join(root, "run"), filepath.Join(root, "home")
	stub := filepath.Join(run, "systemd", "resolve", "stub-resolv.conf")
	// What the cover shows in the sandbox: the stub's empty parents and the
	// stub, as bubblewrap leaves them, on the real files so the check can walk them.
	if err := os.MkdirAll(filepath.Dir(stub), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stub, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// The host the spec is prepared against is a fake one with the same names.
	host := fakeHost(
		[]string{home, run},
		[]string{stub},
		map[string]string{"/etc/resolv.conf": stub},
	)
	h := hostView{fs: host, cover: []string{run}}
	name := "covers:" + run

	caller := Spec{Home: home}
	// The caller's Spec alone does not explain the stub's parents. Run is a
	// default cover of the host here, so the caller's Spec has to name it for
	// the check to look.
	named := Spec{Home: home, Cover: []string{run}}
	if m := byName(t, checkCovers(&checkEnv{spec: &named})); m[name].Status != Fail {
		t.Fatalf("the caller's Spec explains the linked file: %+v", m[name])
	}
	child, err := checkSpec(caller, h)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(child.Read, stub) || !slices.Contains(child.Cover, run) {
		t.Fatalf("checkSpec = Read %q, Cover %q, want %s read and %s covered", child.Read, child.Cover, stub, run)
	}
	if len(child.Command) != 0 {
		t.Errorf("checkSpec kept Command %q, which the child's own start sets", child.Command)
	}
	if m := byName(t, checkCovers(&checkEnv{spec: &child})); m[name].Status != Pass {
		t.Errorf("a cover that shows only the way to a linked file failed: %+v", m[name])
	}

	// Any other entry still fails: a sibling of the stub's parent, and one
	// beside the stub in its own directory.
	for _, extra := range []string{
		filepath.Join(run, "systemd", "other"),
		filepath.Join(run, "systemd", "resolve", "other"),
		filepath.Join(run, "user"),
	} {
		if err := os.Mkdir(extra, 0o750); err != nil {
			t.Fatal(err)
		}
		m := byName(t, checkCovers(&checkEnv{spec: &child}))
		if m[name].Status != Fail || !strings.Contains(m[name].Detail, extra) {
			t.Errorf("with %s, covers = %+v, want a failure naming it", extra, m[name])
		}
		if err := os.Remove(extra); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCheckedCoversListsEachOnce checks that a default cover that the prepared
// Spec names too is tried once. The child's Cover holds the defaults that exist
// on the host, and a list that kept both tried each one twice under
// KernelNested, a namespace child per copy.
// Row: "Self-checks".
func TestCheckedCoversListsEachOnce(t *testing.T) {
	t.Parallel()
	spec := &Spec{Cover: slices.Concat([]string{"/zz/extra"}, defaultCover, []string{"/zz/extra"})}
	got := checkedCovers(spec)
	want := slices.Compact(slices.Sorted(slices.Values(slices.Concat(defaultCover, []string{"/zz/extra"}))))
	if !slices.Equal(got, want) {
		t.Errorf("checkedCovers = %q, want %q", got, want)
	}
}

// TestExtraGroups checks that the process's own gid and egid, which Docker and
// initgroups put in getgroups' list, aren't counted as supplementary groups,
// and that any other group is.
func TestExtraGroups(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		gs                  []int
		gid, egid, overflow int
		want                []int
	}{
		{nil, 1000, 1000, 65534, nil},
		{[]int{1000}, 1000, 1000, 65534, nil},
		{[]int{1000, 999}, 1000, 1000, 65534, []int{999}},
		{[]int{5}, 1000, 5, 65534, nil},
		{[]int{65534}, 1000, 1000, 65534, []int{65534}},
		// An account whose own group is nogroup, with a group not mapped
		// into the namespace: both show as the overflow gid.
		{[]int{65534}, 65534, 65534, 65534, []int{65534}},
		{[]int{65534}, 65534, 65534, -1, nil},
	} {
		if got := extraGroups(tc.gs, tc.gid, tc.egid, tc.overflow); !slices.Equal(got, tc.want) {
			t.Errorf("extraGroups(%v, %d, %d, %d) = %v, want %v", tc.gs, tc.gid, tc.egid, tc.overflow, got, tc.want)
		}
	}
}

// TestCoverLeakWalksScratch checks that a scratch directory under a cover is
// explained without hiding what is in it, so a host file that showed through
// the sandbox's own tmpfs still fails the cover.
func TestCoverLeakWalksScratch(t *testing.T) {
	t.Parallel()
	cover := t.TempDir()
	scratch := filepath.Join(cover, "tmp")
	home := filepath.Join(cover, "home")
	for _, d := range []string{scratch, home} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if got := coverLeak(cover, []string{home}, []string{scratch}); got != "" {
		t.Errorf("an empty scratch directory and a shown home leak %q", got)
	}
	leaked := filepath.Join(scratch, "host-file")
	if err := os.WriteFile(leaked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := coverLeak(cover, []string{home}, []string{scratch}); got != leaked {
		t.Errorf("coverLeak = %q, want %q, the file in the scratch directory", got, leaked)
	}
}

// noDeadlineConn is a connection that refuses a deadline, and records a write.
type noDeadlineConn struct {
	net.Conn
	wrote bool
}

func (*noDeadlineConn) SetDeadline(time.Time) error { return errors.New("no deadlines here") }

func (c *noDeadlineConn) Write([]byte) (int, error) {
	c.wrote = true
	return 0, errors.New("nothing should be sent")
}

// A DNS probe that can't bound its wait sends nothing and says so, as skipped.
// It used to pass without probing, which counted as a guarantee shown.
func TestDNSQueryOnNeedsADeadline(t *testing.T) {
	t.Parallel()
	c := &noDeadlineConn{}
	res := dnsQueryOn("egress.test", "a query", c)
	if res.Status != Skipped || c.wrote {
		t.Errorf("status = %v, wrote = %v; want Skipped and nothing sent: %+v", res.Status, c.wrote, res)
	}
	// With a deadline it asks, and an answer is a failure.
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		var buf [512]byte
		if _, err := server.Read(buf[:]); err == nil {
			_, _ = server.Write(make([]byte, 20))
		}
	}()
	if res := dnsQueryOn("egress.test", "a query", client); res.Status != Fail {
		t.Errorf("status = %v for a resolver that answered, want Fail: %+v", res.Status, res)
	}
}
