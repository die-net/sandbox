package sandbox

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseStatus(t *testing.T) {
	const in = "Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t0000000000000400\nCapBnd:\t000001ffffffffff\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t3\nGroups:\t4 5\n"
	st, err := parseStatus(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := procStatus{NoNewPrivs: 1, Seccomp: 2, SeccompFilters: 3, CapEff: 0x400, CapPrm: 0x1ffffffffff, CapBnd: 0x1ffffffffff}
	if st != want {
		t.Errorf("got %+v, want %+v", st, want)
	}
	if got := capList(0x400); got != "CAP_NET_BIND_SERVICE" {
		t.Errorf("capList = %q", got)
	}
	if _, err := parseStatus(strings.NewReader("Seccomp:\tx\n")); err == nil {
		t.Error("a bad number was accepted")
	}
	// An old kernel has no Seccomp_filters, and that is not an error.
	if st, err := parseStatus(strings.NewReader("Seccomp:\t0\n")); err != nil || st.SeccompFilters != 0 {
		t.Errorf("old kernel: %+v, %v", st, err)
	}
}

func TestParseUIDMap(t *testing.T) {
	for in, want := range map[string]bool{
		"         0          0 4294967295\n":         true,
		"         0       1000          1\n":         false,
		"         0          0       1000\n":         false,
		"         0          0 4294967295\n 5 5 5\n": false,
		"": false,
	} {
		if got := parseUIDMap(strings.NewReader(in)); got != want {
			t.Errorf("parseUIDMap(%q) = %v", in, got)
		}
	}
}

func TestParseGateway(t *testing.T) {
	const in = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0100A8C0	0003	0	0	100	00000000	0	0	0
eth0	0000A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
`
	gw, err := parseGateway(strings.NewReader(in))
	if err != nil || gw != "192.168.0.1" {
		t.Errorf("parseGateway = %q, %v", gw, err)
	}
	if _, err := parseGateway(strings.NewReader(strings.Split(in, "\n")[0] + "\n")); err == nil {
		t.Error("no default route went unreported")
	}
}

func TestParseStatPPID(t *testing.T) {
	for in, want := range map[string]int{
		"12 (bash) S 7 12 12 0": 7,
		"12 (a b) c) S 9 1":     9,
	} {
		if got, ok := parseStatPPID(in); !ok || got != want {
			t.Errorf("parseStatPPID(%q) = %d, %v", in, got, ok)
		}
	}
	if _, ok := parseStatPPID("junk"); ok {
		t.Error("junk parsed")
	}
}

func TestMountPointAndSnapshots(t *testing.T) {
	mounts := []mount{{point: "/"}, {point: "/data"}, {point: "/data/deep"}, {point: "/datum"}}
	if m, _ := mountPoint(mounts, "/data/deep/x/y"); m.point != "/data/deep" {
		t.Errorf("mountPoint = %q", m.point)
	}
	if m, _ := mountPoint(mounts, "/datum2/x"); m.point != "/" {
		t.Errorf("mountPoint = %q", m.point)
	}
	list := func(dir string) []string {
		switch dir {
		case "/data/.zfs/snapshot":
			return []string{"daily"}
		case "/data/.snapshots":
			return []string{"1", "2"}
		}
		return nil
	}
	got := snapshotCandidates("/data", "/data/secret/key", list)
	want := []string{"/data/.zfs/snapshot/daily/secret/key", "/data/.snapshots/1/snapshot/secret/key", "/data/.snapshots/2/snapshot/secret/key"}
	if !slices.Equal(got, want) {
		t.Errorf("snapshotCandidates = %v, want %v", got, want)
	}
}

// TestCheckVM runs Check(ctx, nil, ...) on the plain VM, where nothing
// isolates the test binary. It goes through the check marker, which this
// package's init dispatches until Stage does.
func TestCheckVM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := Check(ctx, nil, Expect{})
	if err != nil {
		t.Fatal(err)
	}
	m := byName(t, res)
	// These attempts work on any ordinary Linux user.
	for _, name := range []string{"userns.create", "proc.visible", "proc.signal", "proc.trace"} {
		if r := m[name]; r.Status != Fail {
			t.Errorf("%s = %+v, want Fail on a plain host", name, r)
		}
	}
	if r := m["mount.tmpfs"]; r.Status != Fail {
		t.Errorf("mount.tmpfs = %+v, want Fail on a plain host", r)
	}
	for _, name := range []string{"proc.no_new_privs", "proc.seccomp"} {
		if r := m[name]; r.Status != Fail {
			t.Errorf("%s = %+v, want Fail with no sandbox", name, r)
		}
	}
	if m["nested.umount-cover"].Status != Skipped || m["nested.mount-outside"].Status != Skipped {
		t.Errorf("nested checks ran without a Spec: %+v", m["nested.umount-cover"])
	}
	for _, name := range []string{"limits.memory", "limits.tasks", "cgroup.delegate", "caps.bounding", "snapshots", "sockets.abstract", "io_uring.setup", "bpf.load", "netfilter.setsockopt"} {
		if _, ok := m[name]; !ok {
			t.Errorf("no result named %s", name)
		}
	}
	for _, r := range res {
		t.Logf("%-28s %-15v %s", r.Name, r.Status, firstLine(r.Detail))
	}
	// The set of Linux-only names the other platforms skip must exist here too.
	var other []string
	for _, r := range osNeutralNames() {
		if _, ok := m[r]; !ok {
			other = append(other, r)
		}
	}
	if len(other) > 0 {
		t.Errorf("checks skipped elsewhere but missing here: %v", other)
	}
}

// osNeutralNames are the names check_other.go reports, so the two files stay
// in step.
func osNeutralNames() []string {
	return []string{
		"proc.no_new_privs", "proc.seccomp", "caps.effective", "caps.permitted", "caps.bounding",
		"userns.create", "mount.tmpfs", "io_uring.setup", "netfilter.setsockopt", "bpf.load",
		"nested.umount-cover", "nested.remount-rw", "nested.mount-outside",
		"sockets.abstract", "cgroup.delegate", "limits.memory", "limits.tasks",
		"proc.visible", "proc.signal", "proc.trace", "proc.environ", "snapshots",
	}
}

func TestProbeVM(t *testing.T) {
	rep, err := Probe()
	if err != nil {
		for _, c := range rep.Checks {
			t.Logf("%s %v: %s", c.Name, c.Status, c.Detail)
		}
		t.Fatal(err)
	}
	if rep.Backend != "bubblewrap" || !rep.TreeKill || !rep.PrivateLoopback {
		t.Errorf("report = %+v", rep)
	}
	if rep.Kernel[KernelStrict] != KernelStrict || rep.Kernel[KernelNested] != KernelNested {
		t.Errorf("Kernel = %v", rep.Kernel)
	}
	if len(rep.Checks) == 0 || rep.Checks[len(rep.Checks)-1].Name != "probe.userns" {
		t.Errorf("Checks = %+v", rep.Checks)
	}
	for _, c := range rep.Checks {
		if c.Status != Pass {
			t.Errorf("%+v", c)
		}
	}
	if !slices.Contains(rep.Ignored, "Services") {
		t.Errorf("Ignored = %v", rep.Ignored)
	}
	t.Logf("container %q, checks %+v", rep.Container, rep.Checks)
}

func TestProbeNoBubblewrap(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	rep, err := Probe()
	if err == nil || len(rep.Checks) == 0 || rep.Checks[0].Name != "probe.bubblewrap" || rep.Checks[0].Status != Fail {
		t.Errorf("Probe = %+v, %v", rep, err)
	}
	if !strings.Contains(err.Error(), "bubblewrap") {
		t.Errorf("error %q", err)
	}
}

// TestNestedAttempts runs the nested extras in the VM against paths that are
// not mounts, so each is refused, and checks the data-driven plumbing.
func TestNestedAttempts(t *testing.T) {
	dir := t.TempDir()
	spec := &Spec{Kernel: KernelNested, Home: dir, Read: []string{dir}, Cover: []string{dir}}
	res := checkNested(&checkEnv{spec: spec})
	m := byName(t, res)
	if m["nested.umount-cover"].Status != Pass || m["nested.remount-rw"].Status == Skipped || m["nested.mount-outside"].Status != Skipped {
		t.Errorf("%+v", res)
	}
	for _, r := range res {
		t.Logf("%s %v %s", r.Name, r.Status, r.Detail)
	}
}
