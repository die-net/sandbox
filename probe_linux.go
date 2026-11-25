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
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Probe tries the Linux backend for real: bubblewrap, its version, the
// seccomp filters this architecture has, and a trial sandbox that Command
// builds, whose first stage must get its capabilities and whose command must
// run. The trial's command is this binary, so the program must call Stage
// first in main, as it must for Command and Check. An error means no sandbox
// can start, and Report.Checks says why and how to fix it. The Report is
// filled in either way.
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
		f.TryErr, f.TrialErr = trySandbox()
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

// trySandbox starts a sandbox through Command, as a caller does, and returns
// why it failed, or "" if its command ran and exited 0. The command is this
// binary's check child in its no-op mode, which needs nothing from the host,
// so the trial fails only where the backend does, such as a first stage
// that AppArmor denies its capabilities. The home is a directory of its own,
// removed after. built is set instead when the trial could not be made at
// all, so its failure is not blamed on the host's sandboxing.
func trySandbox() (failed, built string) {
	home, err := os.MkdirTemp("", "sandbox-probe-")
	if err != nil {
		return "", fmt.Sprintf("make its home: %v", err)
	}
	// Nothing can be done about a home that won't go, and it holds nothing.
	defer func() { _ = os.RemoveAll(home) }()
	// Start refuses a home path with a link in it, which a temporary
	// directory may have, such as a TMPDIR under a link. Probe made this
	// directory just now, so the real path names the same one.
	if resolved, err := filepath.EvalSymlinks(home); err == nil {
		home = resolved
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd, err := Command(ctx, Spec{Command: []string{SelfPath, checkArg, modeNoop}, Home: home})
	if err != nil {
		return "", err.Error()
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Start()
	if err == nil {
		err = cmd.Wait()
	}
	if err == nil {
		return "", ""
	}
	// The stages write why they failed to stderr, which says more than the
	// error Start sees once the stage has exited.
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		return fmt.Sprintf("%s (%v)", msg, err), ""
	}
	return err.Error(), ""
}

// bwrapLabel returns the AppArmor label bubblewrap gets when this process
// runs it, or "" when it can't be read. bubblewrap reads its --args
// descriptor to the end while it parses its arguments (parse_args_recurse in
// bubblewrap.c), which main does before it makes any namespace, so it waits
// there while the pipe's write end is open. The label is read then, and closing
// the pipe ends bubblewrap, which finds no command.
func bwrapLabel(bwrap string) string {
	r, w, err := os.Pipe()
	if err != nil {
		return ""
	}
	defer func() { _ = w.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bwrap, "--args", "3")
	cmd.ExtraFiles = []*os.File{r}
	err = cmd.Start()
	_ = r.Close() // bubblewrap holds its own copy.
	if err != nil {
		return ""
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/attr/current")
	_ = w.Close()  // Ends bubblewrap's read. The deferred close is then a no-op.
	_ = cmd.Wait() // bubblewrap exits 1 for want of a command, which is expected.
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(b), "\x00\n")
}

// gatherAppArmor reads this process's AppArmor label, and the one bubblewrap
// gets when this process runs it, which choose the profile Probe prints.
func gatherAppArmor(f *probeFacts) {
	if b, err := os.ReadFile("/proc/self/attr/current"); err == nil {
		f.AppArmor = strings.TrimRight(string(b), "\x00\n")
	}
	if f.Bwrap != "" {
		f.BwrapLabel = bwrapLabel(f.Bwrap)
	}
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
	if f.Sysctl["kernel.apparmor_restrict_unprivileged_userns"] == "1" {
		gatherAppArmor(f)
	} else if b, err := os.ReadFile("/proc/self/attr/current"); err == nil {
		f.AppArmor = strings.TrimRight(string(b), "\x00\n")
	}
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
