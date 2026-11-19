package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Probe tries the Linux backend for real: bubblewrap, its version, a user
// namespace it can mount in, and the seccomp filters this architecture has.
// An error means no sandbox can start, and Report.Checks says why and how to
// fix it. The Report is filled in either way.
func Probe() (Report, error) {
	rep := Report{
		Backend:         "bubblewrap",
		Kernel:          map[Kernel]Kernel{},
		TreeKill:        true,
		PrivateLoopback: true,
		Ignored:         []string{"Services", "BroadLoopback"},
	}
	f := probeFacts{Kernels: rep.Kernel}
	for _, k := range []Kernel{KernelStrict, KernelNested, KernelOpen} {
		if _, err := filterProgram(k); err == nil {
			rep.Kernel[k] = k
		}
	}
	if path, err := exec.LookPath("bwrap"); err == nil {
		f.Bwrap = path
		if fi, err := os.Stat(path); err == nil {
			f.Setuid = fi.Mode()&fs.ModeSetuid != 0
		}
		f.Version = runOutput(path, "--version")
	}
	if exe, err := os.Executable(); err == nil {
		f.Self, _ = filepath.EvalSymlinks(exe)
	}
	rep.Container = gatherContainer()
	f.Container = rep.Container
	// The trial needs a working bubblewrap, and is skipped when diagnose
	// would stop earlier anyway.
	if f.Bwrap != "" && !f.Setuid && len(f.Kernels) > 0 {
		f.TryErr = tryBubblewrap(f.Bwrap)
	}
	if f.TryErr != "" {
		gatherFailureFacts(&f)
	}
	rep.Checks = diagnose(f)
	for _, c := range rep.Checks {
		if c.Status == Fail {
			return rep, fmt.Errorf("the sandbox cannot start: %s: %s", c.Name, firstLine(c.Detail))
		}
	}
	return rep, nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// runOutput returns what a command prints, or "" if it fails.
func runOutput(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// trueBinary finds a program that does nothing and succeeds.
func trueBinary() string {
	for _, n := range []string{"true", "/bin/true", "/usr/bin/true"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// tryBubblewrap starts a sandbox that makes the mounts a real one does, and
// returns bubblewrap's complaint, or "" if it ran.
func tryBubblewrap(bwrap string) string {
	tr := trueBinary()
	if tr == "" {
		return "" // nothing to run in it; the trial proves nothing
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bwrap, "--unshare-user", "--unshare-pid", "--die-with-parent",
		"--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--", tr)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return msg
	}
	return ""
}

// gatherContainer reads the markers detectContainer looks at.
func gatherContainer() string {
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	cg, _ := os.ReadFile("/proc/self/cgroup")
	f := containerFacts{
		KubernetesEnv: os.Getenv("KUBERNETES_SERVICE_HOST") != "",
		Containerenv:  exists("/run/.containerenv"),
		Dockerenv:     exists("/.dockerenv"),
		Cgroup:        string(cg),
		InvocationID:  os.Getenv("INVOCATION_ID") != "",
	}
	if p, err := exec.LookPath("systemd-detect-virt"); err == nil {
		f.Virt = strings.TrimSpace(runOutput(p, "-c"))
	}
	return detectContainer(f)
}

// gatherFailureFacts reads what only the diagnosis of a failed trial needs.
func gatherFailureFacts(f *probeFacts) {
	f.Sysctl = map[string]string{}
	for _, name := range []string{"kernel.apparmor_restrict_unprivileged_userns", "kernel.unprivileged_userns_clone", "user.max_user_namespaces"} {
		if b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(name, ".", "/")); err == nil {
			f.Sysctl[name] = strings.TrimSpace(string(b))
		}
	}
	if st, err := os.Open("/proc/self/status"); err == nil {
		s, _ := parseStatus(st)
		st.Close()
		f.Seccomp = s.Seccomp
	}
	if b, err := os.ReadFile("/proc/self/attr/current"); err == nil {
		f.AppArmor = strings.TrimRight(string(b), "\x00\n")
	}
	if mi, err := os.Open("/proc/self/mountinfo"); err == nil {
		f.Mounts, _ = parseMountinfo(mi)
		mi.Close()
	}
	// An ordinary process asks for a user namespace, with nothing else to
	// go wrong, so EPERM here comes from a filter.
	if tr := trueBinary(); tr != "" {
		cmd := exec.Command(tr)
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
		f.UnshareErr = cmd.Run()
		var ee *exec.ExitError
		if errors.As(f.UnshareErr, &ee) {
			f.UnshareErr = nil
		}
	}
}
