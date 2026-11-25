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

// Probe tries the Linux backend for real: bubblewrap, its version, the
// seccomp filters this architecture has, and a trial sandbox that it starts
// as Start does. So, like Command, it refuses root, and it needs Stage first
// in main: in a program that never called Stage it starts no sandbox, since
// the sandbox's first stage would run the program's own main, and its
// probe.stage check fails. An error means no sandbox can start, and
// Report.Checks says why and how to fix it. The Report is filled in either
// way.
func Probe() (Report, error) {
	rep := Report{
		Backend:         "bubblewrap",
		Kernel:          map[Kernel]Kernel{},
		TreeKill:        true,
		PrivateLoopback: true,
		Ignored:         []string{"Services", "BroadLoopback"},
	}
	f := probeFacts{Kernels: rep.Kernel, Root: os.Geteuid() == 0, Staged: staged.Load()}
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
	// would stop earlier anyway. Without Stage, the trial's first stage
	// would run this program's own main, so it never starts then.
	if f.Bwrap != "" && !f.Setuid && len(f.Kernels) > 0 && !f.Root && f.Staged {
		f.TryErr = trySandbox(f.Kernels)
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
	out, err := exec.CommandContext(ctx, name, args...).Output() //nolint:gosec // G204: Probe runs the tools it reports on, by the names its own code gives.
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

// trySandbox starts a sandbox the way Start does, at the strictest kernel level
// the host can give, running a program that does nothing, and returns why it
// failed, or "" if it ran. A trial of bubblewrap alone isn't enough: on
// Ubuntu 26.04 bubblewrap starts, and AppArmor denies the first stage the
// capabilities it needs.
func trySandbox(kernels map[Kernel]Kernel) string {
	tr := trueBinary()
	if tr == "" {
		return "" // nothing to run in it; the trial proves nothing
	}
	var level Kernel
	for _, k := range []Kernel{KernelStrict, KernelNested, KernelOpen} {
		if _, ok := kernels[k]; ok {
			level = k
			break
		}
	}
	home, err := os.MkdirTemp("", "sandbox-probe-")
	if err != nil {
		return fmt.Sprintf("make the trial sandbox's home: %v", err)
	}
	msg := runTrial(Spec{Command: []string{tr}, Home: home, Kernel: level})
	if err := os.Remove(home); err != nil && msg == "" {
		return fmt.Sprintf("remove the trial sandbox's home: %v", err)
	}
	return msg
}

// runTrial runs the trial sandbox and returns why it failed, or "".
func runTrial(spec Spec) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd, err := Command(ctx, spec)
	if err != nil {
		return err.Error()
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Start()
	if err == nil {
		err = cmd.Wait()
	}
	if err == nil {
		return ""
	}
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		return msg
	}
	return err.Error()
}

// bwrapLabel returns the AppArmor label of a program bubblewrap starts, or ""
// when there is none or bubblewrap fails.
func bwrapLabel(bwrap string) string {
	cat, err := exec.LookPath("cat")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bwrap, "--unshare-user", "--ro-bind", "/", "/", "--", cat, "/proc/self/attr/apparmor/current").Output() //nolint:gosec // G204: bwrap is the bubblewrap Probe found, run with a fixed command.
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(out), "\x00\n")
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
		st.Close() //nolint:gosec // G104: a read-only descriptor, and nothing can be done about a failed close.
		f.Seccomp = s.Seccomp
	}
	// attr/apparmor/current is AppArmor's own, since Linux 5.8, where
	// attr/current is whichever major LSM the kernel runs.
	b, err := os.ReadFile("/proc/self/attr/apparmor/current")
	if err != nil {
		b, err = os.ReadFile("/proc/self/attr/current")
	}
	if err == nil {
		f.AppArmor = strings.TrimRight(string(b), "\x00\n")
	}
	f.BwrapLabel = bwrapLabel(f.Bwrap)
	if mi, err := os.Open("/proc/self/mountinfo"); err == nil {
		f.Mounts, _ = parseMountinfo(mi)
		mi.Close() //nolint:gosec // G104: a read-only descriptor, and nothing can be done about a failed close.
	}
	// An ordinary process asks for a user namespace, with nothing else to
	// go wrong, so EPERM here comes from a filter.
	if tr := trueBinary(); tr != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, tr) //nolint:gosec // G204: tr is a true binary Probe found, run to see whether a user namespace can be made.
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
		f.UnshareErr = cmd.Run()
		var ee *exec.ExitError
		if errors.As(f.UnshareErr, &ee) {
			f.UnshareErr = nil
		}
	}
}
