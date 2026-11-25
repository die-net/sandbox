package sandbox

import (
	"strings"
	"syscall"
	"testing"
)

func TestParseVersion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in           string
		major, minor int
		ok           bool
	}{
		{"bubblewrap 0.12.0\n", 0, 12, true},
		{"bubblewrap 0.8.0", 0, 8, true},
		{"bubblewrap 0.4.1", 0, 4, true},
		{"bubblewrap 1.0", 1, 0, true},
		{"", 0, 0, false},
		{"bubblewrap", 0, 0, false},
	} {
		major, minor, ok := parseVersion(tc.in)
		if major != tc.major || minor != tc.minor || ok != tc.ok {
			t.Errorf("parseVersion(%q) = %d, %d, %v, want %d, %d, %v", tc.in, major, minor, ok, tc.major, tc.minor, tc.ok)
		}
	}
}

// goodFacts is a host where the trial sandbox starts.
func goodFacts() probeFacts {
	return probeFacts{
		Bwrap:   "/usr/bin/bwrap",
		Version: "bubblewrap 0.12.0\n",
		Kernels: map[Kernel]Kernel{KernelStrict: KernelStrict},
		Self:    "/opt/app/server",
	}
}

func lastCheck(t *testing.T, f probeFacts) Result {
	t.Helper()
	res := diagnose(f)
	if len(res) == 0 {
		t.Fatal("no findings")
	}
	return res[len(res)-1]
}

func TestDiagnose(t *testing.T) {
	t.Parallel()
	ok := goodFacts()
	res := diagnose(ok)
	for _, r := range res {
		if r.Status != Pass {
			t.Errorf("good host: %+v", r)
		}
	}
	if got := res[len(res)-1].Name; got != "probe.userns" {
		t.Errorf("good host ends at %s, want probe.userns", got)
	}

	// The first blocker wins, and the table is in 6.3's order.
	mod := func(f func(*probeFacts)) probeFacts {
		p := goodFacts()
		p.TryErr = "bwrap: No permissions to create new namespace"
		p.Sysctl = map[string]string{}
		f(&p)
		return p
	}
	proc := []mount{{point: "/proc"}, {point: "/proc/kcore"}}
	for _, tc := range []struct {
		name  string
		facts probeFacts
		want  string
		fix   string // text the fix must have
	}{
		{"missing", mod(func(f *probeFacts) { f.Bwrap = "" }), "probe.bubblewrap", "apt install bubblewrap"},
		{"setuid", mod(func(f *probeFacts) { f.Setuid = true }), "probe.bubblewrap", "setuid"},
		{"old", mod(func(f *probeFacts) { f.Version = "bubblewrap 0.4.1" }), "probe.bubblewrap", "older than 0.8"},
		{"no version", mod(func(f *probeFacts) { f.Version = "" }), "probe.bubblewrap", "no version"},
		{"no filter", mod(func(f *probeFacts) { f.Kernels = nil }), "probe.seccomp", "architecture"},
		// A trial that couldn't be built is not blamed on AppArmor.
		{"trial not built", mod(func(f *probeFacts) {
			f.TrialErr = "make its home: no space left on device"
			f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1"
		}), "probe.trial", "no space left"},
		{"apparmor", mod(func(f *probeFacts) { f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1" }), "probe.apparmor-userns", "  userns,"},
		{"apparmor names this binary", mod(func(f *probeFacts) { f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1" }), "probe.apparmor-userns", "profile sandbox-opt-app-server /opt/app/server flags=(unconfined)"},
		{"sysctl clone", mod(func(f *probeFacts) { f.Sysctl["kernel.unprivileged_userns_clone"] = "0" }), "probe.userns-sysctl", "unprivileged_userns_clone=1"},
		{"sysctl max", mod(func(f *probeFacts) { f.Sysctl["user.max_user_namespaces"] = "0" }), "probe.userns-sysctl", "max_user_namespaces="},
		{"docker seccomp", mod(func(f *probeFacts) {
			f.Seccomp, f.Container, f.UnshareErr = 2, "docker", &fakeErr{syscall.EPERM}
		}), "probe.container-seccomp", "Never seccomp=unconfined"},
		{"seccomp without container", mod(func(f *probeFacts) { f.Seccomp, f.UnshareErr = 2, &fakeErr{syscall.EPERM} }), "probe.userns", "no known cause"},
		{"seccomp with other error", mod(func(f *probeFacts) {
			f.Seccomp, f.Container, f.UnshareErr = 2, "docker", &fakeErr{syscall.EINVAL}
		}), "probe.userns", "no known cause"},
		{"docker apparmor", mod(func(f *probeFacts) { f.Container, f.AppArmor = "docker", "docker-default (enforce)" }), "probe.docker-apparmor", "apparmor=unconfined"},
		{"masked proc", mod(func(f *probeFacts) { f.Mounts = proc }), "probe.masked-proc", "systempaths=unconfined"},
		{"systemd unit", mod(func(f *probeFacts) { f.Container = "systemd-unit" }), "probe.systemd-unit", "RestrictNamespaces="},
		{"unknown", mod(func(*probeFacts) {}), "probe.userns", "No permissions"},
		// Order: AppArmor before sysctl before container seccomp.
		{"apparmor first", mod(func(f *probeFacts) {
			f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1"
			f.Sysctl["user.max_user_namespaces"] = "0"
			f.Mounts = proc
		}), "probe.apparmor-userns", ""},
		{"sysctl before masked", mod(func(f *probeFacts) {
			f.Sysctl["user.max_user_namespaces"] = "0"
			f.Mounts = proc
		}), "probe.userns-sysctl", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := lastCheck(t, tc.facts)
			if r.Name != tc.want || r.Status != Fail {
				t.Fatalf("last finding = %s %v, want a failed %s: %s", r.Name, r.Status, tc.want, r.Detail)
			}
			if !strings.Contains(r.Detail, tc.fix) {
				t.Errorf("detail %q lacks %q", r.Detail, tc.fix)
			}
		})
	}
}

// fakeErr wraps an errno as exec's fork error does.
type fakeErr struct{ error }

func (e *fakeErr) Unwrap() error { return e.error }

func TestMasked(t *testing.T) {
	t.Parallel()
	// The mounts Docker makes around /proc.
	const mi = `1 0 0:1 / / rw - overlay overlay rw
2 1 0:5 / /proc rw - proc proc rw
3 2 0:5 /sys /proc/sys ro - proc proc rw
4 2 0:6 /null /proc/kcore rw - tmpfs tmpfs rw
`
	mounts, err := parseMountinfo(strings.NewReader(mi))
	if err != nil {
		t.Fatal(err)
	}
	if !masked(mounts) {
		t.Error("overmounts under /proc not seen")
	}
	if masked(mounts[:2]) {
		t.Error("a plain /proc was called masked")
	}
}

func TestApparmorProfile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		enforce bool
		want    string
		grant   string // the one rule that grants user namespaces
	}{
		{false, "profile sandbox-opt-app-server /opt/app/server flags=(unconfined) {\n  userns,\n}", "userns,"},
		{true, "profile sandbox-opt-app-server /opt/app/server flags=(attach_disconnected) {\n  allow all,\n}", "allow all,"},
	} {
		p, name, err := apparmorProfile("/opt/app/server", tc.enforce)
		if err != nil {
			t.Fatal(err)
		}
		if name != "sandbox-opt-app-server" {
			t.Errorf("name = %q", name)
		}
		for _, s := range []string{"abi <abi/4.0>,", tc.want} {
			if !strings.Contains(p, s) {
				t.Errorf("enforce=%v: profile lacks %q:\n%s", tc.enforce, s, p)
			}
		}
		// The one grant is in the one profile, which is for this binary and
		// not for bubblewrap.
		if strings.Count(p, tc.grant) != 1 || strings.Count(p, "\nprofile ") != 1 || strings.Contains(p, "bwrap") {
			t.Errorf("enforce=%v: want one profile, for this binary, with one %q rule:\n%s", tc.enforce, tc.grant, p)
		}
	}
	for _, bad := range []string{"", "relative", "/opt/my app/x", "/bad\"path", "/bad\nname"} {
		if _, _, err := apparmorProfile(bad, false); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// TestDiagnoseApparmor checks which profile the AppArmor finding prints, by
// the label bubblewrap gets, and that a binary already under its own profile
// is not told to load it again.
func TestDiagnoseApparmor(t *testing.T) {
	t.Parallel()
	const (
		ours     = "sandbox-opt-app-server"
		unconf   = "flags=(unconfined) {\n  userns,"
		enforce  = "flags=(attach_disconnected) {\n  allow all,"
		restrict = "kernel.apparmor_restrict_unprivileged_userns"
	)
	for _, tc := range []struct {
		name        string
		self, bwrap string // this process's label and bubblewrap's
		want        string // "probe.apparmor-userns" with the profile, or the next finding
		profile     string
	}{
		{"no profile attaches to bwrap (Ubuntu 24.04)", "unconfined", "unconfined", "probe.apparmor-userns", unconf},
		{"bwrap-userns-restrict loaded (Ubuntu 26.04)", "unconfined", "bwrap (enforce)", "probe.apparmor-userns", enforce},
		{"bwrap's label unknown", "unconfined", "", "probe.apparmor-userns", unconf},
		{"the unconfined-mode profile is loaded but bwrap leaves it", ours + " (unconfined)", "bwrap (enforce)", "probe.apparmor-userns", enforce},
		{"the unconfined-mode profile is loaded and keeps bwrap", ours + " (unconfined)", ours + " (unconfined)", "probe.userns", ""},
		{"the enforce-mode profile is loaded and keeps bwrap", ours + " (enforce)", ours + " (enforce)", "probe.userns", ""},
		// Under another program's profile, a profile for this binary would not
		// attach, so the finding is a later one.
		{"another enforce-mode profile keeps bwrap", "other (enforce)", "other (enforce)", "probe.userns", ""},
		{"docker-default keeps bwrap", "docker-default (enforce)", "docker-default (enforce)", "probe.docker-apparmor", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := goodFacts()
			if strings.HasPrefix(tc.self, "docker-default") {
				f.Container = "docker"
			}
			f.TryErr = "sandbox: copy the view into a mount namespace of its own: operation not permitted"
			f.Sysctl = map[string]string{restrict: "1"}
			f.AppArmor, f.BwrapLabel = tc.self, tc.bwrap
			r := lastCheck(t, f)
			if r.Name != tc.want || r.Status != Fail {
				t.Fatalf("last finding = %s %v, want a failed %s: %s", r.Name, r.Status, tc.want, r.Detail)
			}
			if tc.profile != "" && !strings.Contains(r.Detail, tc.profile) {
				t.Errorf("detail lacks %q:\n%s", tc.profile, r.Detail)
			}
			if tc.profile == enforce && !strings.Contains(r.Detail, tc.bwrap) {
				t.Errorf("detail does not name bubblewrap's label %q:\n%s", tc.bwrap, r.Detail)
			}
		})
	}
}

func TestDetectContainer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		f    containerFacts
		want string
	}{
		{"none", containerFacts{Cgroup: "0::/user.slice/session-3.scope\n"}, ""},
		{"kubernetes", containerFacts{KubernetesEnv: true, Dockerenv: true}, "kubernetes"},
		{"kubepods", containerFacts{Cgroup: "0::/kubepods/burstable/pod1/abc\n"}, "kubernetes"},
		{"podman", containerFacts{Containerenv: true}, "podman"},
		{"docker", containerFacts{Dockerenv: true}, "docker"},
		{"docker cgroup", containerFacts{Cgroup: "0::/system.slice/docker-abc.scope\n"}, "docker"},
		{"lxc", containerFacts{Virt: "lxc"}, "lxc"},
		{"virt only", containerFacts{Virt: "systemd-nspawn"}, "systemd-nspawn"},
		{"virt none", containerFacts{Virt: "none"}, ""},
		{"unit", containerFacts{InvocationID: true, Cgroup: "0::/system.slice/render.service\n"}, "systemd-unit"},
		{"scope with invocation", containerFacts{InvocationID: true, Cgroup: "0::/user.slice/session-3.scope\n"}, ""},
		{"service without invocation", containerFacts{Cgroup: "0::/system.slice/render.service\n"}, ""},
	} {
		if got := detectContainer(tc.f); got != tc.want {
			t.Errorf("%s: detectContainer = %q, want %q", tc.name, got, tc.want)
		}
	}
}
