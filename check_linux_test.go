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
)

func TestParseStatus(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := Check(ctx, nil, Expect{})
	if err != nil {
		t.Fatal(err)
	}
	m := byName(t, res)
	// These attempts work on any ordinary Linux user.
	// proc.trace is refused where Yama restricts ptrace to descendants
	// (ptrace_scope 1, Ubuntu's and some Proxmox hosts' default), or a
	// filter on the test process refuses it.
	traceable := true
	if b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil && strings.TrimSpace(string(b)) != "0" {
		traceable = false
		t.Logf("kernel.yama.ptrace_scope is %s, so proc.trace passes on this host", strings.TrimSpace(string(b)))
	}
	for _, name := range []string{"userns.create", "proc.visible", "proc.signal", "proc.trace"} {
		if name == "proc.trace" && !traceable {
			continue
		}
		if r := m[name]; r.Status != Fail {
			t.Errorf("%s = %+v, want Fail on a plain host", name, r)
		}
	}
	if r := m["mount.tmpfs"]; r.Status != Fail {
		t.Errorf("mount.tmpfs = %+v, want Fail on a plain host", r)
	}
	// An LXC container's seccomp profile is inherited by every process in it,
	// which makes proc.seccomp pass without any sandbox.
	inherited := hasSeccomp(t)
	if inherited {
		t.Log("the test process already runs under a seccomp filter (an LXC or systemd one), so proc.seccomp passes on this host")
	}
	for _, name := range []string{"proc.no_new_privs", "proc.seccomp"} {
		if name == "proc.seccomp" && inherited {
			continue
		}
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

// hasSeccomp reports whether this process already runs under a seccomp filter.
func hasSeccomp(t *testing.T) bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Seccomp:"); ok {
			return strings.TrimSpace(v) != "0"
		}
	}
	return false
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

// TestOutsidePIDs checks that only the sandbox's own pid 1, the parent of a
// check child that Check started in a sandbox, is left out of the processes
// outside the check's tree. Every other pid counts, and pid 1 counts too when
// it isn't the child's parent or the check runs with no Spec.
func TestOutsidePIDs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		pids      []int
		inSandbox bool
		ppid      int
		want      []int
	}{
		{"the sandbox's pid 1", []int{1}, true, 1, []int{}},
		{"pid 1 and another", []int{1, 40}, true, 1, []int{40}},
		{"a parent that isn't pid 1", []int{1, 40}, true, 7, []int{1, 40}},
		{"no Spec", []int{1, 40}, false, 1, []int{1, 40}},
		{"no pid 1", []int{2, 40}, true, 1, []int{2, 40}},
	} {
		if got := outsidePIDs(tc.pids, tc.inSandbox, tc.ppid); !slices.Equal(got, tc.want) {
			t.Errorf("%s: outsidePIDs = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestProbeVM checks that Probe's verdict agrees with whether a sandbox
// starts, on a host set up for the suite or not. On Ubuntu 26.04 without the
// AppArmor profile, bubblewrap starts and AppArmor denies the first stage its
// capabilities, and a trial of bubblewrap alone passed there while no
// sandbox could start. CI runs this test there without the profile too.
func TestProbeVM(t *testing.T) {
	t.Parallel()
	rep, err := Probe()
	startErr := startTrueSandbox(t)
	if (err == nil) != (startErr == nil) {
		for _, c := range rep.Checks {
			t.Logf("%s %v: %s", c.Name, c.Status, c.Detail)
		}
		t.Fatalf("Probe = %v, but a sandbox's start = %v", err, startErr)
	}
	if err != nil {
		last := rep.Checks[len(rep.Checks)-1]
		if last.Status != Fail {
			t.Errorf("Probe failed, and its last check passed: %+v", rep.Checks)
		}
		t.Logf("no sandbox starts here, and Probe says why: %s: %s", last.Name, last.Detail)
		return
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

// startTrueSandbox runs true in a sandbox, apart from Probe, and returns why it
// failed.
func startTrueSandbox(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd, err := Command(ctx, Spec{Command: []string{trueBinary()}, Home: t.TempDir()})
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

// TestProbeWithoutStage plays a program that never called Stage. Probe must
// say so, and start no sandbox, since the sandbox's first stage would run
// the program's own main. A bubblewrap of the test's own on PATH logs how
// it was run, so a trial that started shows.
func TestProbeWithoutStage(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	script := "#!/bin/sh\necho \"$1\" >>" + log + "\n[ \"$1\" = --version ] && echo 'bubblewrap 0.11.1'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "bwrap"), []byte(script), 0o700); err != nil { //nolint:gosec // G306: the file is a program the test runs, which needs its owner to execute it.
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	staged.Store(false)
	t.Cleanup(func() { staged.Store(true) })

	rep, err := Probe()
	if err == nil || len(rep.Checks) == 0 {
		t.Fatalf("Probe = %+v, %v", rep, err)
	}
	last := rep.Checks[len(rep.Checks)-1]
	if last.Name != "probe.stage" || last.Status != Fail || !strings.Contains(last.Detail, "sandbox.Stage") {
		t.Errorf("last check = %+v", last)
	}
	b, err := os.ReadFile(log) //nolint:gosec // G304: the test reads a path it made, or one a sandbox must not let it read.
	if err != nil {
		t.Fatal(err)
	}
	if runs := strings.Fields(string(b)); !slices.Equal(runs, []string{"--version"}) {
		t.Errorf("bubblewrap ran with %q, want only --version", runs)
	}
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
	t.Parallel()
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
