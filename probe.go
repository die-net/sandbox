package sandbox

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// Report says what this host's sandbox backend can do, and when it can't
// start, why. The caller logs it once at startup. The library never logs.
type Report struct {
	// Backend is "bubblewrap" or "seatbelt".
	Backend string
	// Kernel maps each requested level to the level given, never a lower
	// one. A level this host can't meet is absent.
	Kernel map[Kernel]Kernel
	// TreeKill is true when killing the sandbox kills every descendant. On
	// macOS it means every process it can find under the sandbox's profile: a
	// process that forks faster than the teardown's scan can outlast it, and
	// Wait then returns an error saying so (the probe.gap.tree-kill finding).
	TreeKill bool
	// PrivateLoopback is true when loopback and abstract sockets are
	// private to the sandbox.
	PrivateLoopback bool
	// Unsupported lists Spec fields this backend can't honor, so Command
	// refuses a Spec that sets them.
	Unsupported []string
	// Ignored lists Spec fields this backend accepts and does nothing
	// with, such as "Hostname" on macOS.
	Ignored []string
	// Container is the container the process runs in, best effort:
	// "docker", "podman", "lxc", "kubernetes", "systemd-unit", or "".
	Container string
	// Checks holds one finding per prerequisite, in order, ending at the
	// first that blocks the sandbox, with its fix in Detail.
	Checks []Result
}

// probeFacts is everything the diagnosis reads, so tests can supply it.
type probeFacts struct {
	Bwrap   string            // path to bubblewrap, "" when not found
	Setuid  bool              // bubblewrap is setuid
	Version string            // output of bwrap --version
	Kernels map[Kernel]Kernel // levels the seccomp filter can be built for
	TryErr  string            // why the trial sandbox failed, "" when it started

	Sysctl     map[string]string // by dotted name, absent when unreadable
	Seccomp    int               // Seccomp: in /proc/self/status
	Container  string            // detectContainer's answer
	UnshareErr error             // clone(CLONE_NEWUSER) as an ordinary process
	AppArmor   string            // /proc/self/attr/current
	Mounts     []mount           // this process's mount table
	Self       string            // this binary's path
}

var versionRE = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// parseVersion returns the major and minor of a "bubblewrap 0.8.0" line.
func parseVersion(s string) (major, minor int, ok bool) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, false
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return major, minor, true
}

// diagnose turns facts into the findings: a pass for each prerequisite up to
// the first that blocks the sandbox, then that one with its fix. The order is
// 6.3's.
func diagnose(f probeFacts) []Result {
	var res []Result
	if f.Bwrap == "" {
		return append(res, fail("probe.bubblewrap", "bubblewrap is not on PATH. Install your distro's package: apt install bubblewrap, dnf install bubblewrap, or pacman -S bubblewrap"))
	}
	if f.Setuid {
		return append(res, fail("probe.bubblewrap", "%s is setuid, which the sandbox refuses. Install the distro's package, which is not setuid, or chmod u-s it", f.Bwrap))
	}
	if major, minor, ok := parseVersion(f.Version); !ok {
		return append(res, fail("probe.bubblewrap", "%s --version printed %q, which has no version. Install the distro's current package", f.Bwrap, f.Version))
	} else if major == 0 && minor < 8 {
		return append(res, fail("probe.bubblewrap", "%s is version %d.%d, older than 0.8. Install the distro's current package", f.Bwrap, major, minor))
	}
	res = append(res, pass("probe.bubblewrap", "%s, %s", f.Bwrap, strings.TrimSpace(f.Version)))
	if len(f.Kernels) == 0 {
		return append(res, fail("probe.seccomp", "no system call filter can be built for this architecture, so no kernel level can be met"))
	}
	res = append(res, pass("probe.seccomp", "a system call filter exists for %d kernel levels", len(f.Kernels)))
	if f.TryErr == "" {
		return append(res, pass("probe.userns", "bubblewrap started a sandbox in a new user namespace and mounted proc, dev and tmpfs"))
	}
	return append(res, firstBlock(f))
}

// firstBlock returns the first setting in 6.3's order that explains the
// failed trial sandbox.
func firstBlock(f probeFacts) Result {
	container := f.Container != "" && f.Container != "systemd-unit"
	switch {
	case f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] == "1":
		profile, name, err := apparmorProfile(f.Self)
		if err != nil {
			return fail("probe.apparmor-userns", "AppArmor restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns=1), and bubblewrap failed: %s\n"+
				"No profile can be generated: %v", f.TryErr, err)
		}
		return fail("probe.apparmor-userns", "AppArmor restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns=1), and bubblewrap failed: %s\n"+
			"Fix: save this as /etc/apparmor.d/%s, then run: sudo apparmor_parser -r /etc/apparmor.d/%s\n"+
			"It grants user namespaces to %s and the processes it starts, and to no other program.\n\n%s",
			f.TryErr, name, name, f.Self, profile)
	case f.Sysctl["kernel.unprivileged_userns_clone"] == "0":
		return fail("probe.userns-sysctl", "kernel.unprivileged_userns_clone is 0, which turns user namespaces off for ordinary users. Fix: sudo sysctl -w kernel.unprivileged_userns_clone=1, and put it in /etc/sysctl.d/ to keep it")
	case f.Sysctl["user.max_user_namespaces"] == "0":
		return fail("probe.userns-sysctl", "user.max_user_namespaces is 0, which turns user namespaces off. Fix: sudo sysctl -w user.max_user_namespaces=15000, and put it in /etc/sysctl.d/ to keep it")
	case f.Seccomp == 2 && container && errors.Is(f.UnshareErr, syscall.EPERM):
		return fail("probe.container-seccomp", "the %s container's seccomp profile refuses unshare(CLONE_NEWUSER) with EPERM, because it grants the namespace calls only with CAP_SYS_ADMIN. "+
			"Fix: run the container with a seccomp profile that is the runtime's default plus clone with the namespace flags, unshare, mount, umount2, pivot_root and the new mount API (open_tree, move_mount, fsopen, fsmount, fsconfig, mount_setattr). Never seccomp=unconfined", f.Container)
	case container && strings.HasPrefix(f.AppArmor, "docker-default"):
		return fail("probe.docker-apparmor", "the container runs under Docker's docker-default AppArmor profile, which denies mount. Fix: a profile that allows mount, or --security-opt apparmor=unconfined for this container only")
	case masked(f.Mounts):
		return fail("probe.masked-proc", "paths under /proc are overmounted, and the kernel refuses a new procfs while the existing one is partly hidden. Fix: Docker --security-opt systempaths=unconfined, or Podman --security-opt unmask=ALL")
	case f.Container == "systemd-unit":
		return fail("probe.systemd-unit", "this runs in a systemd service whose restrictions refuse namespaces or mounts. Fix, for this unit only: relax RestrictNamespaces=, and a SystemCallFilter= that lacks @mount, keeping the rest")
	}
	return fail("probe.userns", "bubblewrap could not start a sandbox, and no known cause matched: %s", f.TryErr)
}

// masked reports whether anything is mounted on a path under /proc.
func masked(mounts []mount) bool {
	for _, m := range mounts {
		if strings.HasPrefix(m.point, "/proc/") {
			return true
		}
	}
	return false
}

// apparmorProfile writes an AppArmor profile for the binary at self that
// allows it, and so bubblewrap when it runs it, to create user namespaces,
// and returns it with the name to save it under. Ubuntu 24.04 and later need
// it. No other program gets user namespaces. A profile on bubblewrap's own
// path would give them to every process on the host that runs it.
//
// The profile is flags=(unconfined), so it confines nothing else: the kernel
// still lets the program do everything it could without a profile, and
// mediates only the user namespace. A child profile for bubblewrap, entered
// by a cx rule, would grant less, but the kernel ignores exec rules in an
// unconfined-mode profile and leaves bubblewrap in the parent's label, where
// it is refused (tried on Ubuntu 24.04, kernel 6.8, and an enforcing parent
// would deny every class of access it did not list). Loaded with
// apparmor_parser -r and exercised by the full test suite on that system.
func apparmorProfile(self string) (profile, name string, err error) {
	if !filepath.IsAbs(self) || strings.ContainsAny(self, "\"\\\n{}[]?*^,;@$ ") {
		return "", "", fmt.Errorf("the path %q is empty, relative, or has a character a profile would need escaped", self)
	}
	name = "sandbox-" + strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, strings.Trim(self, "/"))
	return fmt.Sprintf(`abi <abi/4.0>,
include <tunables/global>

profile %[1]s %[2]s flags=(unconfined) {
  userns,
}
`, name, self), name, nil
}

// containerFacts is what detectContainer reads.
type containerFacts struct {
	KubernetesEnv bool   // KUBERNETES_SERVICE_HOST is set
	Containerenv  bool   // /run/.containerenv exists
	Dockerenv     bool   // /.dockerenv exists
	Cgroup        string // /proc/self/cgroup
	Virt          string // systemd-detect-virt -c, "" or "none" when absent
	InvocationID  bool   // INVOCATION_ID is set
}

// detectContainer names the container, best effort.
func detectContainer(f containerFacts) string {
	switch {
	case f.KubernetesEnv || strings.Contains(f.Cgroup, "kubepods"):
		return "kubernetes"
	case f.Containerenv || strings.Contains(f.Cgroup, "libpod") || f.Virt == "podman":
		return "podman"
	case f.Dockerenv || strings.Contains(f.Cgroup, "docker") || f.Virt == "docker":
		return "docker"
	case f.Virt == "lxc" || f.Virt == "lxc-libvirt" || strings.Contains(f.Cgroup, "/lxc/") || strings.Contains(f.Cgroup, "/lxc.payload"):
		return "lxc"
	case f.Virt != "" && f.Virt != "none":
		return f.Virt
	}
	if f.InvocationID {
		for _, line := range strings.Split(f.Cgroup, "\n") {
			if p, ok := strings.CutPrefix(line, "0::"); ok && strings.HasSuffix(strings.TrimSpace(p), ".service") {
				return "systemd-unit"
			}
		}
	}
	return ""
}
