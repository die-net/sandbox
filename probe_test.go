package sandbox

import (
	"os"
	"path/filepath"
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
		Staged:  true,
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
		{"root", mod(func(f *probeFacts) { f.Root = true }), "probe.root", "switch to the sandbox's own uid"},
		{"no stage", mod(func(f *probeFacts) { f.Staged = false }), "probe.stage", "call sandbox.Stage first in main"},
		{"root before stage", mod(func(f *probeFacts) { f.Root, f.Staged = true, false }), "probe.root", ""},
		{"apparmor", mod(func(f *probeFacts) { f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1" }), "probe.apparmor-userns", "  allow all,"},
		{"apparmor names this binary", mod(func(f *probeFacts) { f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1" }), "probe.apparmor-userns", "profile sandbox-opt-app-server /opt/app/server flags=(attach_disconnected,mediate_deleted)"},
		// Ubuntu 26.04: bubblewrap's profile, whatever the sysctl.
		{"bwrap profile", mod(func(f *probeFacts) {
			f.AppArmor, f.BwrapLabel = "unconfined", "bwrap (enforce)"
		}), "probe.apparmor-bwrap", "profile sandbox-opt-app-server /opt/app/server flags=(attach_disconnected,mediate_deleted)"},
		{"bwrap profile names the label", mod(func(f *probeFacts) {
			f.AppArmor, f.BwrapLabel = "sandbox-opt-app-server (unconfined)", "bwrap (enforce)"
		}), "probe.apparmor-bwrap", `label "bwrap (enforce)"`},
		{"bwrap profile before sysctl", mod(func(f *probeFacts) {
			f.AppArmor, f.BwrapLabel = "unconfined", "bwrap (enforce)"
			f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1"
		}), "probe.apparmor-bwrap", ""},
		// A trial that couldn't be built is not blamed on AppArmor.
		{"trial not built", mod(func(f *probeFacts) {
			f.TrialErr = "make its home: no space left on device"
			f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1"
			f.AppArmor, f.BwrapLabel = "unconfined", "bwrap (enforce)"
		}), "probe.trial", "no space left"},
		// Under its own profile, loaded in enforce mode, loading it again
		// would change nothing, so the failure is someone else's.
		{"own profile in force", mod(func(f *probeFacts) {
			f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1"
			f.AppArmor, f.BwrapLabel = "sandbox-opt-app-server (enforce)", "bwrap (enforce)"
		}), "probe.userns", "no known cause"},
		// v0.1.0's profile, in unconfined mode, is replaced.
		{"old own profile", mod(func(f *probeFacts) {
			f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1"
			f.AppArmor, f.BwrapLabel = "sandbox-opt-app-server (unconfined)", "sandbox-opt-app-server (unconfined)"
		}), "probe.apparmor-userns", "  allow all,"},
		// Under another program's profile, a profile for this binary would
		// not attach, so a later finding explains it.
		{"another profile", mod(func(f *probeFacts) {
			f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1"
			f.AppArmor, f.BwrapLabel = "other (enforce)", "bwrap (enforce)"
		}), "probe.userns", "no known cause"},
		{"docker-default", mod(func(f *probeFacts) {
			f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] = "1"
			f.Container, f.AppArmor, f.BwrapLabel = "docker", "docker-default (enforce)", "bwrap (enforce)"
		}), "probe.docker-apparmor", "apparmor=unconfined"},
		{"same label is no cause", mod(func(f *probeFacts) {
			f.AppArmor, f.BwrapLabel = "sandbox-opt-app-server (enforce)", "sandbox-opt-app-server (enforce)"
		}), "probe.userns", "no known cause"},
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
	p, name, err := apparmorProfile("/opt/app/server")
	if err != nil {
		t.Fatal(err)
	}
	if name != "sandbox-opt-app-server" {
		t.Errorf("name = %q", name)
	}
	for _, s := range []string{
		"abi <abi/4.0>,",
		"profile sandbox-opt-app-server /opt/app/server flags=(attach_disconnected,mediate_deleted) {\n  allow all,\n  allow mount,\n  allow umount,\n  allow pivot_root,\n  allow network,\n  allow unix,\n}",
	} {
		if !strings.Contains(p, s) {
			t.Errorf("profile lacks %q:\n%s", s, p)
		}
	}
	// The one profile is for this binary and not for bubblewrap, and it is
	// in enforce mode, since an unconfined-mode profile lets Ubuntu 26.04's
	// bwrap profile attach to bubblewrap.
	if strings.Count(p, "\nprofile ") != 1 || strings.Contains(p, "bwrap") || strings.Contains(p, "unconfined") {
		t.Errorf("want one profile, for this binary, in enforce mode:\n%s", p)
	}
	for _, bad := range []string{"", "relative", "/opt/my app/x", "/bad\"path", "/bad\nname"} {
		if _, _, err := apparmorProfile(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
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

// TestWriteApparmorProfile writes this test binary's AppArmor profile into
// the directory named by SBX_APPARMOR_OUT, under the name to load it by.
// scripts/apparmor.sh uses it, so the profile the suite runs under is the
// one the library prints.
func TestWriteApparmorProfile(t *testing.T) {
	t.Parallel()
	dir := os.Getenv("SBX_APPARMOR_OUT")
	if dir == "" {
		t.Skip("SBX_APPARMOR_OUT is not set")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	p, name, err := apparmorProfile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(p), 0o600); err != nil { //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
		t.Fatal(err)
	}
}
