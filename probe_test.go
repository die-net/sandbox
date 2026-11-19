package sandbox

import (
	"strings"
	"syscall"
	"testing"
)

func TestParseVersion(t *testing.T) {
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
		{"apparmor", mod(func(f *probeFacts) { f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1" }), "probe.apparmor-userns", `profile sandbox-usr-bin-bwrap "/usr/bin/bwrap" flags=(unconfined)`},
		{"apparmor names this binary", mod(func(f *probeFacts) { f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1" }), "probe.apparmor-userns", `"/opt/app/server"`},
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
	p := apparmorProfile("/usr/bin/bwrap", "/usr/bin/bwrap", "/opt/my app/bin", "/bad\"path", "relative")
	if strings.Count(p, "profile ") != 2 {
		t.Errorf("want two profiles (one deduplicated, one with a space, two refused):\n%s", p)
	}
	for _, s := range []string{"abi <abi/4.0>,", "userns,", `"/opt/my app/bin"`, "profile sandbox-opt-my-app-bin "} {
		if !strings.Contains(p, s) {
			t.Errorf("profile lacks %q:\n%s", s, p)
		}
	}
}

func TestDetectContainer(t *testing.T) {
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
