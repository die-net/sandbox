package sandbox

import (
	"errors"
	"fmt"
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
	Root    bool              // this process runs as root, which Command refuses
	Staged  bool              // this process called Stage, so Start can run
	TryErr  string            // why the trial sandbox failed, "" when it started
	// TrialErr is why the trial sandbox could not be built at all, before
	// bubblewrap ran, such as a home that can't be made or a descriptor
	// limit.
	TrialErr string

	Sysctl     map[string]string // by dotted name, absent when unreadable
	Seccomp    int               // Seccomp: in /proc/self/status
	Container  string            // detectContainer's answer
	UnshareErr error             // clone(CLONE_NEWUSER) as an ordinary process
	AppArmor   string            // this process's AppArmor label, from attr/apparmor/current or attr/current
	BwrapLabel string            // the label bubblewrap gets when this process runs it, "" when unknown
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
	if f.Root {
		return append(res, fail("probe.root", "this program runs as root, and the sandbox refuses root, since it opens paths and writes the sandbox's passwd in this process. Fix: switch to the sandbox's own uid before Probe and Command"))
	}
	if !f.Staged {
		return append(res, fail("probe.stage", "this program did not call sandbox.Stage, so Probe started no sandbox. Start runs this binary again inside the sandbox, and without Stage that run would be the program's own main. "+
			"Fix: call sandbox.Stage first in main, and exit with its code when it reports true"))
	}
	res = append(res, pass("probe.stage", "this program called Stage"))
	if f.TrialErr != "" {
		return append(res, fail("probe.trial", "the trial sandbox could not be built, so nothing was tried: %s", f.TrialErr))
	}
	if f.TryErr == "" {
		return append(res, pass("probe.userns", "a trial sandbox started, set itself up and ran its command"))
	}
	return append(res, firstBlock(f))
}

// firstBlock returns the first setting in 6.3's order that explains the
// failed trial sandbox.
func firstBlock(f probeFacts) Result {
	container := f.Container != "" && f.Container != "systemd-unit"
	switch {
	case apparmorApplies(f) && !apparmorInForce(f) && ubuntuBwrap(f.BwrapLabel) && f.BwrapLabel != f.AppArmor:
		profile, name, err := AppArmorProfile(f.Self)
		if err != nil {
			return fail("probe.apparmor-bwrap", "bubblewrap gets the AppArmor label %q when this program runs it, not this program's own %q, and the sandbox failed: %s\n"+
				"No profile can be generated: %v", f.BwrapLabel, f.AppArmor, f.TryErr, err)
		}
		return fail("probe.apparmor-bwrap", "bubblewrap gets the AppArmor label %q when this program runs it, not this program's own %q, and the sandbox failed: %s\n"+
			"Ubuntu 26.04's bwrap profile does this, and runs what bubblewrap starts stacked with its unpriv_bwrap profile, which denies the capabilities the sandbox's first stage needs, whatever kernel.apparmor_restrict_unprivileged_userns says.\n"+
			"Fix: save this as /etc/apparmor.d/%s, then run: sudo apparmor_parser -r /etc/apparmor.d/%s\n"+
			"%s\n\n%s",
			f.BwrapLabel, f.AppArmor, f.TryErr, name, name, profileGrant(f.Self), profile)
	case apparmorApplies(f) && !apparmorInForce(f) && f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] == "1":
		profile, name, err := AppArmorProfile(f.Self)
		if err != nil {
			return fail("probe.apparmor-userns", "AppArmor restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns=1), and bubblewrap failed: %s\n"+
				"No profile can be generated: %v", f.TryErr, err)
		}
		return fail("probe.apparmor-userns", "AppArmor restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns=1), and bubblewrap failed: %s\n"+
			"Fix: save this as /etc/apparmor.d/%s, then run: sudo apparmor_parser -r /etc/apparmor.d/%s\n"+
			"%s\n\n%s",
			f.TryErr, name, name, profileGrant(f.Self), profile)
	case f.Sysctl["kernel.unprivileged_userns_clone"] == "0":
		return fail("probe.userns-sysctl", "kernel.unprivileged_userns_clone is 0, which turns user namespaces off for ordinary users. Fix: sudo sysctl -w kernel.unprivileged_userns_clone=1, and put it in /etc/sysctl.d/ to keep it")
	case f.Sysctl["user.max_user_namespaces"] == "0":
		return fail("probe.userns-sysctl", "user.max_user_namespaces is 0, which turns user namespaces off. Fix: sudo sysctl -w user.max_user_namespaces=15000, and put it in /etc/sysctl.d/ to keep it")
	case f.Seccomp == 2 && container && errors.Is(f.UnshareErr, syscall.EPERM):
		return fail("probe.container-seccomp", "the %s container's seccomp profile refuses unshare(CLONE_NEWUSER) with EPERM, because it grants the namespace calls only with CAP_SYS_ADMIN. "+
			"Fix: run the container with a seccomp profile that is the runtime's default plus clone with the namespace flags, unshare, mount, umount2, pivot_root and the new mount API (open_tree, move_mount, fsopen, fsmount, fsconfig, mount_setattr). Never seccomp=unconfined", f.Container)
	case container && strings.HasPrefix(f.AppArmor, "docker-default"):
		return fail("probe.docker-apparmor", "the container runs under Docker's docker-default AppArmor profile, which denies mount. Fix: a profile that allows mount, or --security-opt apparmor=unconfined for this container only")
	case container && masked(f.Mounts):
		return fail("probe.masked-proc", "paths under /proc are overmounted, and the kernel refuses a new procfs while the existing one is partly hidden. Fix: Docker --security-opt systempaths=unconfined, or Podman --security-opt unmask=ALL")
	case f.Container == "systemd-unit" && masked(f.Mounts):
		return fail("probe.masked-proc", "paths under /proc are overmounted in this systemd service, and the kernel refuses a new procfs while the existing one is partly hidden. Fix, for this unit only: relax ProtectKernelTunables=, ProtectKernelLogs= and ProtectProc=, which mount over parts of /proc")
	case f.Container == "systemd-unit":
		return fail("probe.systemd-unit", "this runs in a systemd service whose restrictions refuse namespaces or mounts. Fix, for this unit only: relax RestrictNamespaces=, and a SystemCallFilter= that lacks @mount, keeping the rest")
	}
	return fail("probe.userns", "bubblewrap could not start a sandbox, and no known cause matched: %s", f.TryErr)
}

// ubuntuBwrap reports whether label is that of the bwrap profile, which
// Ubuntu's bwrap-userns-restrict attaches to /usr/bin/bwrap. bubblewrap's
// own label reads "bwrap (enforce)" there (TestBwrapLabel on Ubuntu 26.04),
// and what it starts is stacked with unpriv_bwrap. Another profile on
// bubblewrap, such as one an operator wrote, is not blamed for the failure.
func ubuntuBwrap(label string) bool {
	return strings.HasPrefix(label, "bwrap (")
}

// masked reports whether anything is mounted on a path under /proc, as a
// container runtime does to hide parts of it. binfmt_misc is left out:
// systemd mounts it, with an autofs under it, at /proc/sys/fs/binfmt_misc on
// every stock host, and a new procfs starts with it there (Debian 13 and
// Ubuntu 26.04, where sandboxes start).
func masked(mounts []mount) bool {
	for _, m := range mounts {
		if strings.HasPrefix(m.point, "/proc/") && m.point != "/proc/sys/fs/binfmt_misc" {
			return true
		}
	}
	return false
}

// apparmorOwn reports whether this process runs under the profile
// AppArmorProfile names for it, in whatever mode.
func apparmorOwn(f probeFacts) bool {
	_, name, err := AppArmorProfile(f.Self)
	return err == nil && strings.HasPrefix(f.AppArmor, name+" (")
}

// apparmorApplies reports whether a profile for this binary can be what the
// trial needs: the process runs unconfined, under its own profile, or under
// a label Probe couldn't read. Under another profile, such as
// docker-default, the exec rule of whatever started it decides its label,
// and a profile for its path would not attach, so a later finding explains
// the failure.
func apparmorApplies(f probeFacts) bool {
	return f.AppArmor == "" || f.AppArmor == "unconfined" || apparmorOwn(f)
}

// apparmorInForce reports whether this process already runs under the
// profile AppArmorProfile returns, which is in enforce mode, so loading it
// again would change nothing and the trial failed for another reason. Under
// the unconfined-mode profile of v0.1.0 it is not, and the fix is to replace
// it.
func apparmorInForce(f probeFacts) bool {
	return apparmorOwn(f) && strings.HasSuffix(f.AppArmor, " (enforce)")
}

// AppArmorProfile returns the AppArmor profile that Ubuntu 24.04 and later
// need before a sandbox can start from the binary at path, with the name to
// save it under in /etc/apparmor.d. It is the profile Probe prints in its fix.
// path must be the binary's absolute path with symbolic links resolved, since
// AppArmor attaches a profile by the path the kernel execs. A program loads the
// profile at install time, and a test loads it for its own test binary before
// running it. The error says why a path can't have a profile: it is empty or
// relative, or holds a character other than an ASCII letter, a digit, or one
// of / . _ + -. The profile is plain
// text, so it is the same on every platform.
//
// The profile applies to that binary and to every process it starts,
// bubblewrap and the sandbox included, and to no other program. A profile on
// bubblewrap's own path would give user namespaces to every process on the
// host that runs it.
//
// The profile allows everything, user namespaces and capabilities in them
// included. It is in enforce mode, with an all rule, so that exec inherits
// it. Ubuntu 26.04 attaches a profile to /usr/bin/bwrap (bwrap-userns-restrict
// in the apparmor package) that runs whatever bubblewrap starts stacked with
// unpriv_bwrap, which denies every capability. The first stage then can't
// make its mount namespace. An unconfined-mode profile, as this was before,
// looks up the attached profile on exec, and the kernel ignores its exec
// rules, so it can't keep bubblewrap out of that profile (tried on Ubuntu
// 26.04, kernel 7.0). The cost is that no program this binary starts moves
// into a profile of its own, outside the sandbox too.
//
// attach_disconnected lets bubblewrap write /proc/<pid>/uid_map, whose path
// AppArmor can't name from inside the new namespaces, and mediate_deleted is
// there as in Ubuntu's own bwrap profile. The explicit rules
// repeat what all grants on AppArmor 5, because the 4.0 parser of Ubuntu
// 24.04 leaves out of all a mount with MS_SILENT, which bubblewrap's first
// mount sets, and the creation of sockets (tried on Ubuntu 24.04, kernel
// 6.8). Loaded with apparmor_parser -r and exercised by the full test suite
// on both systems.
func AppArmorProfile(path string) (profile, name string, err error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsFunc(path, func(r rune) bool { return !profilePathRune(r) }) {
		return "", "", fmt.Errorf("the path %q is empty, relative, or has a character other than a letter, a digit, or one of /._+-", path)
	}
	name = "sandbox-" + strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, strings.Trim(path, "/"))
	return fmt.Sprintf(`abi <abi/4.0>,
include <tunables/global>

profile %[1]s %[2]s flags=(attach_disconnected,mediate_deleted) {
  allow all,
  allow mount,
  allow umount,
  allow pivot_root,
  allow network,
  allow unix,
}
`, name, path), name, nil
}

// profilePathRune reports whether r may appear in a path that AppArmorProfile
// writes into a profile unquoted. It is an allow list, since AppArmor's lexer
// ends a token at whitespace and at characters such as ! and , (ID_CHARS in
// parser/parser_lex.l), and treats others as glob characters, so a deny list
// that missed one would give a profile that attaches to another path.
func profilePathRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._+-", r)
}

// profileGrant says what AppArmorProfile's profile grants, for the fix.
func profileGrant(self string) string {
	return fmt.Sprintf("It lets %s and every process it starts, bubblewrap and the sandbox included, make user namespaces and use capabilities in them, and it grants nothing to any other program. "+
		"Those processes stay in this profile, so none of them moves into a stricter profile of its own.", self)
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
