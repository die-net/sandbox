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
		f.TryErr, f.TrialErr = trySandbox(f.Kernels)
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

// trySandbox starts a sandbox the way Start does, at the strictest kernel
// level the host can give. It returns why the sandbox failed, or "" if its
// command ran and exited 0, and sets built instead when the trial could not
// be made at all, before bubblewrap ran, so that failure isn't blamed on the
// host's sandboxing. The command is this binary's check child in its no-op
// mode, which needs nothing from the host. A trial of bubblewrap alone isn't
// enough: on Ubuntu 26.04 bubblewrap starts, and AppArmor denies the first
// stage the capabilities it needs.
func trySandbox(kernels map[Kernel]Kernel) (failed, built string) {
	var level Kernel
	for _, k := range []Kernel{KernelStrict, KernelNested, KernelOpen} {
		if _, ok := kernels[k]; ok {
			level = k
			break
		}
	}
	home, err := os.MkdirTemp("", "sandbox-probe-")
	if err != nil {
		return "", fmt.Sprintf("make its home: %v", err)
	}
	// Start refuses a home path with a link in it, which a temporary
	// directory may have, such as a TMPDIR under a link. Probe made this
	// directory just now, so its real path names the same one.
	resolved, err := filepath.EvalSymlinks(home)
	if err == nil {
		failed, built = runTrial(Spec{Command: []string{SelfPath, checkArg, modeNoop}, Home: resolved, Kernel: level})
	} else {
		built = fmt.Sprintf("resolve its home: %v", err)
	}
	if err := os.Remove(home); err != nil && failed == "" && built == "" {
		built = fmt.Sprintf("remove its home: %v", err)
	}
	return failed, built
}

// runTrial runs the trial sandbox, and returns why it failed or why it
// could not be built, as trySandbox does.
func runTrial(spec Spec) (failed, built string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd, err := Command(ctx, spec)
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
	// Once bubblewrap has run, Start and Wait carry its exit status. An
	// error without one came before bubblewrap ran, such as a descriptor
	// limit or a mount table Start couldn't read.
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return "", err.Error()
	}
	// The stages write why they failed to stderr, which says more than the
	// error Start sees once the stage has exited.
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		return fmt.Sprintf("%s (%v)", msg, err), ""
	}
	return err.Error(), ""
}

// labels returns this process's AppArmor label and the one bubblewrap gets
// when this process runs it, as Probe's diagnosis compares them. Either is ""
// when it can't be read.
func labels(bwrap string) (self, bubblewrap string) {
	return readLabel("/proc/self/attr/"), bwrapLabel(bwrap)
}

// procIsOwn reports whether /proc belongs to this process's pid namespace,
// so that the pids this process sees name the same processes there. Under
// another pid namespace's procfs, /proc/self still resolves to this process,
// through that procfs's own namespace (proc_self_get_link in Linux
// fs/proc/self.c), but by another number than os.Getpid.
func procIsOwn() bool {
	link, err := os.Readlink("/proc/self")
	return err == nil && link == strconv.Itoa(os.Getpid())
}

// bwrapLabel returns the AppArmor label bubblewrap gets when this process
// runs it, or "" when it can't be read, as when /proc belongs to another pid
// namespace, where bubblewrap's pid names another process. bubblewrap reads its --args
// descriptor to the end while it parses its arguments (parse_args_recurse in
// bubblewrap.c), which main does before it makes any namespace, so it waits
// there while the pipe's write end is open. The label is read then, and
// closing the pipe ends bubblewrap, which finds no command. Under an
// unconfined-mode profile, as on Ubuntu 26.04 with its bwrap profile, the
// label is bubblewrap's own, and what it starts gets more stacked on it.
func bwrapLabel(bwrap string) string {
	if !procIsOwn() {
		return ""
	}
	r, w, err := os.Pipe()
	if err != nil {
		return ""
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bwrap, "--args", "3")
	cmd.ExtraFiles = []*os.File{r}
	err = cmd.Start()
	r.Close() //nolint:gosec // G104: bubblewrap holds its own copy, and nothing can be done about a failed close.
	if err != nil {
		return ""
	}
	label := readLabel("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/attr/")
	w.Close()      //nolint:gosec // G104: this ends bubblewrap's read, and the deferred close is then a no-op.
	_ = cmd.Wait() // bubblewrap exits 1 for want of a command, which is expected.
	return label
}

// readLabel returns the AppArmor label of the process whose attr directory
// under /proc is dir, from AppArmor's own apparmor/current, which Linux has
// had since 5.8, or before that from current, which is whichever major LSM
// the kernel runs.
func readLabel(dir string) string {
	b, err := os.ReadFile(dir + "apparmor/current") //nolint:gosec // G304: a fixed file of a process's proc directory.
	if err != nil {
		b, err = os.ReadFile(dir + "current") //nolint:gosec // G304: a fixed file of a process's proc directory.
	}
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(b), "\x00\n")
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
	f.AppArmor, f.BwrapLabel = labels(f.Bwrap)
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
