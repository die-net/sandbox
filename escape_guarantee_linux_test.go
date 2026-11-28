package sandbox

// Escape tests: for each Linux guarantee in the guarantee table of
// docs/security-model.md, code runs inside a sandbox, tries the escape, and
// the test asserts it fails. Each test cites the row it checks as "Row: ...",
// by the first words of the Guarantee column.
//
// The code inside the sandbox is this test binary run as "esc <check>", where
// check is a key of escChecks. A check prints what went wrong on stderr and
// exits 1. Tests that need a fake host (homes, links in /etc, a bind of a
// covered directory) run the sandbox from "esc-host", which makes the host
// first in a user and mount namespace of its own, as withFakeHost does.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// removeAtCleanup removes path when the test ends, and fails the test if it
// can't, unless the test already removed it.
func removeAtCleanup(t testing.TB, path string) {
	t.Helper()
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) { //nolint:gosec // G703: the path is one the test made.
			t.Errorf("remove %s: %v", path, err)
		}
	})
}

func registerEscapeModes() {
	childModes["esc"] = escMode
	childModes["esc-host"] = escHostMode
	childModes["esc-parent"] = escParentMode
}

// ---------------------------------------------------------------- harness

// escT collects what an in-sandbox check finds wrong.
type escT struct{ failed bool }

func (e *escT) failf(format string, a ...any) {
	e.failed = true
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

// is records a failure unless got matches one of want, or is nil when want
// is empty.
func (e *escT) is(name string, got error, want ...error) {
	if len(want) == 0 {
		if got != nil {
			e.failf("%s: %v, want success", name, got)
		}
		return
	}
	for _, w := range want {
		if errors.Is(got, w) {
			return
		}
	}
	e.failf("%s: %v, want one of %v", name, got, want)
}

// escMode runs the check args[0] with the rest of args.
func escMode(args []string) int {
	if len(args) == 0 || escChecks[args[0]] == nil {
		fmt.Fprintln(os.Stderr, "no such check", args)
		return 2
	}
	e := &escT{}
	escChecks[args[0]](e, args[1:])
	if e.failed {
		return 1
	}
	return 0
}

// escChecks are the checks the test binary runs inside a sandbox.
var escChecks = map[string]func(e *escT, args []string){
	"view":          escView,
	"procs":         escProcs,
	"ns":            escNamespaces,
	"seccomp":       escSeccomp,
	"clone-ns":      escCloneNamespaces,
	"net":           escNet,
	"nested":        escNestedStart,
	"nested-inner":  escNestedInner,
	"fds":           escFds,
	"scratch":       escScratch,
	"passwd":        escPasswd,
	"nnp":           escNoNewPrivs,
	"groups":        escGroups,
	"rlimit-fsize":  escRlimitFsize,
	"rlimit-nofile": escRlimitNofile,
	"rlimit-as":     escRlimitAs,
	"rlimit-cpu":    func(*escT, []string) { spin() },
	"rlimit-nproc":  escRlimitNproc,
	"hold":          holdCheck,
	"daemon":        daemonCheck,
	"daemon-child":  daemonChild,
	"daemon-grand":  daemonGrand,
	"peer":          peerCheck,
	"plant-link":    plantLink,
	"exit":          func(_ *escT, a []string) { n, _ := strconv.Atoi(a[0]); os.Exit(n) }, //nolint:revive // deep-exit: the check exists to end the sandbox's command with a chosen status.
	"selfkill":      selfKill,
	"cat":           func(*escT, []string) { _, _ = io.Copy(os.Stdout, os.Stdin) },
	"both":          func(*escT, []string) { fmt.Print("to stdout"); fmt.Fprint(os.Stderr, "to stderr") },
	"env":           func(*escT, []string) { fmt.Println(strings.Join(os.Environ(), "\n")) },
	"bind-hold":     bindHold,
	"read-fds":      readFds,
	"killcanary":    killCanary,
}

// escBinary returns this test binary's path and the directory to bind
// read-only so the sandbox can run it, since it is built under the host's
// covered /tmp.
func escBinary(t testing.TB) (exe, dir string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe, filepath.Dir(exe)
}

// escCmd returns a Cmd, made by Command, that runs this binary in a sandbox
// from spec as `mode args...`. An empty Home is a fresh directory.
func escCmd(ctx context.Context, t *testing.T, spec Spec, mode string, args ...string) (*Cmd, *syncBuffer, *syncBuffer) {
	t.Helper()
	exe, dir := escBinary(t)
	if spec.Home == "" {
		spec.Home = t.TempDir()
	}
	spec.Command = append([]string{exe, mode}, args...)
	spec.Read = append(slices.Clone(spec.Read), dir)
	c, err := Command(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	c.Stdout, c.Stderr = stdout, stderr
	return c, stdout, stderr
}

// escRun runs the check in a sandbox from spec, fails the test if it does not
// exit 0, and returns its stdout.
func escRun(t *testing.T, spec Spec, check string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c, stdout, stderr := escCmd(ctx, t, spec, "esc", append([]string{check}, args...)...)
	if err := c.Start(); err != nil {
		t.Fatalf("%s: start: %v", check, err)
	}
	if err := escWait(t, c, cancel, stdout, stderr, escName(spec, check, args)); err != nil {
		t.Fatalf("%s: %v\n%s", check, err, stderr)
	}
	return stdout.String()
}

// escWithin is how long a check may run before escWait ends it. A check
// takes about a second or less. The bound only keeps one that hangs from
// holding the suite until go test's own timeout, which doesn't say which.
const escWithin = time.Minute

// escWait waits for c, which runs with cancel's context. If c runs past
// escWithin, it ends the sandbox and fails the test with the check's name,
// what it wrote, and how it ended.
func escWait(t *testing.T, c *Cmd, cancel context.CancelFunc, stdout, stderr *syncBuffer, name string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(escWithin):
		cancel()
		err := <-done
		t.Fatalf("%s: still running after %v, then ended: %v\nstdout:\n%s\nstderr:\n%s", name, escWithin, err, stdout, stderr)
		return nil
	}
}

// escName names a check run for a failure: the check, its arguments, and
// the Spec's levels, which tell the runs of one check apart.
func escName(spec Spec, check string, args []string) string {
	return fmt.Sprintf("%s %q under Kernel %q and Network %s", check, args, spec.Kernel, &spec.Network)
}

// jsonArg returns v as the one JSON argument a check takes.
func jsonArg(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// escHostScenario is a fake host, which esc-host makes before it starts a
// sandbox. between runs after Command and before Start.
type escHostScenario struct {
	setup   func() error
	between func() error
}

// hostSecretDir holds, in the fake host, a directory of secrets that a link
// leads to from /etc/skel.
const (
	hostSecretDir = "/mnt/dir" //nolint:gosec // G101: a path in the test's fake host, not a credential.
	etcDirLink    = "/etc/skel/dirlink"
	hostAlias     = "/srv/alias"
	hostAppLink   = "/srv/applink"
	hostPub       = "/srv/users/alice/pub"
)

var escHostScenarios = map[string]escHostScenario{
	"fake": {setup: setupFakeHost},
	"bind": {setup: setupBindHost},
	"swap": {setup: setupFakeHost, between: swapCover},
}

// setupFakeHost is withFakeHost plus a public file under a covered home, a
// link from /etc to a covered directory, and a link to the app's directory.
func setupFakeHost() error {
	if err := withFakeHost(); err != nil {
		return err
	}
	if err := os.MkdirAll(hostPub, 0o755); err != nil { //nolint:gosec // G301: the fixture stands for a file or directory that other users can read by its mode, which only the cover hides.
		return err
	}
	if err := os.WriteFile(hostPub+"/readme", []byte("public"), 0o644); err != nil { //nolint:gosec // G306: the fixture stands for a file or directory that other users can read by its mode, which only the cover hides.
		return err
	}
	if err := os.Mkdir(hostSecretDir, 0o755); err != nil { //nolint:gosec // G301: the fixture stands for a file or directory that other users can read by its mode, which only the cover hides.
		return err
	}
	if err := os.WriteFile(hostSecretDir+"/f", []byte("secret"), 0o644); err != nil { //nolint:gosec // G306: the fixture stands for a file or directory that other users can read by its mode, which only the cover hides.
		return err
	}
	if err := os.Symlink(hostSecretDir, etcDirLink); err != nil {
		return err
	}
	return os.Symlink(appDir, hostAppLink)
}

// setupBindHost is setupFakeHost plus a second mount of appDir, as a bind
// mount or a ZFS snapshot is.
func setupBindHost() error {
	if err := setupFakeHost(); err != nil {
		return err
	}
	if err := os.Mkdir(hostAlias, 0o755); err != nil { //nolint:gosec // G301: the fixture stands for a file or directory that other users can read by its mode, which only the cover hides.
		return err
	}
	if err := unix.Mount(appDir, hostAlias, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s: %w", hostAlias, err)
	}
	if _, err := os.ReadFile(hostAlias + "/app.db"); err != nil {
		return fmt.Errorf("the host's own alias is not readable: %w", err)
	}
	return nil
}

// swapCover replaces appDir, which the sandbox covers, with a link to
// alice's home, as someone with write access to /srv could between
// Command and Start.
func swapCover() error {
	if err := os.Rename(appDir, appDir+".moved"); err != nil {
		return err
	}
	return os.Symlink(fakeHomes[0][:strings.LastIndex(fakeHomes[0], "/")], appDir)
}

// escStartRefused is the status esc-host exits with when Start refuses.
const escStartRefused = 98

// escHostMode makes the fake host args[0], starts the sandbox args[1] (a Spec
// in JSON) with Command and Start, and returns the command's status.
func escHostMode(args []string) int {
	sc, ok := escHostScenarios[args[0]]
	if !ok {
		fmt.Fprintln(os.Stderr, "no scenario", args[0])
		return 2
	}
	var spec Spec
	if err := json.Unmarshal([]byte(args[1]), &spec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := sc.setup(); err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		return 2
	}
	// bubblewrap refuses to run with capabilities unless it is setuid, and
	// would get them from the ambient set. Capabilities belong to a thread.
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	c, err := Command(context.Background(), spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "command:", err)
		return 2
	}
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if sc.between != nil {
		if err := sc.between(); err != nil {
			fmt.Fprintln(os.Stderr, "between:", err)
			return 2
		}
	}
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start refused:", err)
		return escStartRefused
	}
	code, err := exitStatus(c.Wait())
	if err != nil {
		fmt.Fprintln(os.Stderr, "wait:", err)
		return 2
	}
	return code
}

// escHost runs check in a sandbox from spec on the fake host scenario, and
// returns esc-host's exit status and combined output.
func escHost(t *testing.T, scenario string, spec Spec, check string, args ...string) (int, string) {
	t.Helper()
	exe, dir := escBinary(t)
	if spec.Home == "" {
		spec.Home = t.TempDir()
	}
	spec.Command = append([]string{exe, "esc", check}, args...)
	spec.Read = append(slices.Clone(spec.Read), dir)
	cmd := exec.CommandContext(t.Context(), "/proc/self/exe", "esc-host", scenario, jsonArg(t, spec)) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	cmd.Dir = spec.Home
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN},
	}
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

// escHostOK runs check on the fake host and fails the test unless it
// passes.
func escHostOK(t *testing.T, scenario string, spec Spec, check string, args ...string) {
	t.Helper()
	if code, out := escHost(t, scenario, spec, check, args...); code != 0 {
		t.Fatalf("%s on %s: exit %d:\n%s", check, scenario, code, out)
	}
}

// nsLink returns where /proc/<pid>/ns/<name> leads.
func nsLink(pid, name string) string {
	l, _ := os.Readlink("/proc/" + pid + "/ns/" + name)
	return l
}

// nsMembers returns the host pids of the processes whose pid namespace is
// link, as /proc/<pid>/ns/pid reads.
func nsMembers(link string) []int {
	ents, _ := os.ReadDir("/proc")
	var pids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if nsLink(e.Name(), "pid") == link {
			pids = append(pids, pid)
		}
	}
	return pids
}

// waitNoMembers waits up to 5 seconds for no process to be left in the pid
// namespace link, and returns what is.
func waitNoMembers(link string) []int {
	var left []int
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if left = nsMembers(link); len(left) == 0 {
			return nil
		}
	}
	return left
}

// lineWith returns the first line of s that has the prefix, with the prefix
// cut, or "" if none does.
func lineWith(s, prefix string) string {
	for l := range strings.Lines(s) {
		if v, ok := strings.CutPrefix(l, prefix); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ------------------------------------------------------- in-sandbox checks

// viewSpec says what escView expects of paths in the view.
type viewSpec struct {
	// Absent paths do not exist.
	Absent []string `json:"absent,omitempty"`
	// Hidden paths must show no secret: nothing readable that contains
	// "secret", and no entry named so.
	Hidden []string `json:"hidden,omitempty"`
	// Empty directories list nothing.
	Empty []string `json:"empty,omitempty"`
	// Readable files read, with content.
	Readable []string `json:"readable,omitempty"`
	// ReadOnly paths cannot be written.
	ReadOnly []string `json:"read_only,omitempty"`
	// Writable paths can be, and a directory takes a new file.
	Writable []string `json:"writable,omitempty"`
}

func escView(e *escT, args []string) {
	var v viewSpec
	if err := json.Unmarshal([]byte(args[0]), &v); err != nil {
		e.failf("%v", err)
		return
	}
	for _, p := range v.Hidden {
		if what := leaks(p); what != "" {
			e.failf("hidden path %s shows %s", p, what)
		}
	}
	for _, p := range v.Absent {
		if _, err := os.Lstat(p); !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR) {
			e.failf("%s exists: %v", p, err)
		}
	}
	for _, p := range v.Empty {
		if ents, err := os.ReadDir(p); err == nil && len(ents) > 0 {
			e.failf("%s is not empty: %v", p, ents[0].Name())
		}
	}
	for _, p := range v.Readable {
		if data, err := readFile(p); err != nil || len(data) == 0 {
			e.failf("%s is not readable: %q, %v", p, data, err)
		}
	}
	for _, p := range v.ReadOnly {
		// ETXTBSY is the running stage, which no one may open for writing.
		e.is("write "+p, writeProbe(p), unix.EROFS, unix.EACCES, unix.EPERM, unix.ETXTBSY)
	}
	for _, p := range v.Writable {
		e.is("write "+p, writeProbe(p))
	}
}

// leaks returns what of a secret path shows: a regular file under it, to a
// depth of four, whose content holds "secret", or an entry named so. It
// is empty when path is absent or shows nothing.
func leaks(path string) string {
	found := ""
	root := strings.Count(path, "/")
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if strings.Count(p, "/")-root > 4 && d.IsDir() {
			return filepath.SkipDir
		}
		if p != path && strings.Contains(strings.ToLower(d.Name()), "secret") {
			found = "an entry named " + p
			return nil
		}
		if d.Type().IsRegular() {
			if data, err := readFile(p); err == nil && strings.Contains(strings.ToLower(string(data)), "secret") {
				found = "the content of " + p
			}
		}
		return nil
	})
	return found
}

// writeProbe tries to write p: a new file in it when it is a directory,
// and otherwise p itself, created if it is missing. It leaves nothing
// behind.
func writeProbe(p string) error {
	fi, err := os.Stat(p)
	switch {
	case err == nil && fi.IsDir():
		f := filepath.Join(p, "probe")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			return err
		}
		return os.Remove(f)
	case err == nil:
		f, err := openFileFlags(p, os.O_WRONLY|os.O_APPEND, 0)
		if err == nil {
			err = f.Close()
		}
		return err
	default:
		f, err := openFileFlags(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_ = f.Close()
		return os.Remove(p)
	}
}

// procTargets are what escProcs tries to reach.
type procTargets struct {
	ParentPid int `json:"parent_pid"`
	Canary    int `json:"canary"`
	// Secret is in the parent's environment.
	Secret string `json:"secret"`
	ShmKey int    `json:"shm_key"`
}

func escProcs(e *escT, args []string) {
	var tg procTargets
	if err := json.Unmarshal([]byte(args[0]), &tg); err != nil {
		e.failf("%v", err)
		return
	}
	pid := strconv.Itoa(tg.ParentPid)
	e.is("signal the parent", unix.Kill(tg.ParentPid, 0), unix.ESRCH)
	e.is("signal a host process", unix.Kill(tg.Canary, unix.SIGKILL), unix.ESRCH)
	_, err := os.Stat("/proc/" + pid)
	e.is("stat the parent in /proc", err, unix.ENOENT)
	_, err = readFile("/proc/" + pid + "/environ")
	e.is("read the parent's environ", err, unix.ENOENT)
	_, err = unix.PidfdOpen(tg.ParentPid, 0)
	e.is("pidfd_open the parent", err, unix.ESRCH, unix.ENOSYS)
	e.is("ptrace the parent", unix.PtraceAttach(tg.ParentPid), unix.ESRCH, unix.ENOSYS)
	var local, remote [2]unix.Iovec
	buf := make([]byte, 8)
	local[0].Base, local[0].Len = &buf[0], 8
	remote[0].Base, remote[0].Len = &buf[0], 8
	_, _, errno := unix.Syscall6(unix.SYS_PROCESS_VM_READV, uintptr(tg.ParentPid), uintptr(unsafe.Pointer(&local[0])), 1, uintptr(unsafe.Pointer(&remote[0])), 1, 0) //nolint:gosec // G103: the kernel reads or writes the buffer during the call, which keeps it valid.
	if errno != unix.ESRCH && errno != unix.ENOSYS {
		e.failf("process_vm_readv the parent: %v", errno)
	}
	// SysV shared memory is per IPC namespace.
	if _, _, errno := unix.Syscall(unix.SYS_SHMGET, uintptr(tg.ShmKey), 0, 0); errno != unix.ENOENT {
		e.failf("shmget the host's segment: %v, want ENOENT", errno)
	}

	ents, _ := os.ReadDir("/proc")
	n := 0
	for _, ent := range ents {
		if _, err := strconv.Atoi(ent.Name()); err != nil {
			continue
		}
		n++
		if data, err := os.ReadFile("/proc/" + ent.Name() + "/environ"); err == nil && strings.Contains(string(data), tg.Secret) {
			e.failf("/proc/%s/environ holds the parent's secret", ent.Name())
		}
	}
	if n > 12 {
		e.failf("/proc lists %d processes, more than the sandbox's own", n)
	}
	if os.Getpid() == 1 {
		e.failf("the command is pid 1")
	}
	// Pid 1 is the reaper, which the command cannot open: its argv is the
	// stages' name alone, and the checks below find it undumpable, which the
	// first stage isn't.
	if cmdline, err := os.ReadFile("/proc/1/cmdline"); err != nil || string(cmdline) != stagePath+"\x00" {
		e.failf("pid 1's command line is %q, %v, want %q alone", cmdline, err, stagePath)
	}
	_, err = os.ReadFile("/proc/1/environ")
	e.is("read pid 1's environ", err, unix.EACCES)
	_, err = os.Open("/proc/1/mem")
	e.is("open pid 1's memory", err, unix.EACCES)
	_, err = os.Readlink("/proc/1/root")
	e.is("read pid 1's root", err, unix.EACCES)
	_, err = os.Readlink("/proc/1/exe")
	e.is("read pid 1's exe", err, unix.EACCES)
	_, err = os.ReadDir("/proc/1/fd")
	e.is("list pid 1's descriptors", err, unix.EACCES)
	_, err = os.Open("/proc/1/ns/mnt")
	e.is("open pid 1's mount namespace", err, unix.EACCES)
}

// escNamespaces compares this process's namespaces with the host's, which
// args[0] gives as JSON: {"user": "user:[...]", ...}, and args[1] is the host's
// uid. args[2] is "host" when the sandbox shares the host's network.
func escNamespaces(e *escT, args []string) {
	var host map[string]string
	if err := json.Unmarshal([]byte(args[0]), &host); err != nil {
		e.failf("%v", err)
		return
	}
	for name, link := range host {
		got, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil {
			e.failf("read ns %s: %v", name, err)
			continue
		}
		shared := name == "net" && len(args) > 2 && args[2] == "host"
		if (got == link) != shared {
			e.failf("%s namespace is %s, the host's is %s (shared: %v)", name, got, link, shared)
		}
	}
	uid, _ := strconv.Atoi(args[1])
	if os.Getuid() != uid || os.Geteuid() != uid {
		e.failf("uid is %d/%d, want the host's %d", os.Getuid(), os.Geteuid(), uid)
	}
	// One id is mapped, to whatever the namespace the file is read in calls
	// it.
	if m, _ := os.ReadFile("/proc/self/uid_map"); len(strings.Fields(string(m))) != 3 || strings.Fields(string(m))[2] != "1" {
		e.failf("uid_map = %q, want one id mapped", m)
	}
	if hn, _ := os.Hostname(); hn != "sandbox" {
		e.failf("hostname %q", hn)
	}
}

// sc makes a raw system call and returns its errno, or nil.
func sc(nr uintptr, a ...uintptr) error {
	var x [6]uintptr
	copy(x[:], a)
	_, _, errno := unix.Syscall6(nr, x[0], x[1], x[2], x[3], x[4], x[5])
	if errno == 0 {
		return nil
	}
	return errno
}

// escSeccomp makes the calls the filter at level args[0] refuses. A test runs
// it under a level that allows some of them, to show the check then fails, so
// a call that gets through must leave the process as it was. The calls run on
// a thread of their own, which then takes a signal, as Go's preemption sends
// one. A thread a call left traced would stop there for good. Its tracer is
// pid 1, whose wait4 reports the stop under the thread's own id
// (eligible_child in kernel/exit.c reports a tracee whatever the flags), and
// pid 1 skips it as an orphan's and never resumes it. The check would hang
// instead of failing. The thread isn't the process's first, whose stop pid 1
// would take for the command's exit.
func escSeccomp(e *escT, args []string) {
	onOtherThread(func() {
		seccompCalls(e, Kernel(args[0]))
		e.is("a signal after the calls", unix.Tgkill(unix.Getpid(), unix.Gettid(), unix.SIGURG))
	})
}

// onOtherThread runs f on a thread locked to it that isn't the process's
// first, and waits for it.
func onOtherThread(f func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Never unlocked, so the thread ends with the goroutine, and
		// whatever f did to it goes with it.
		runtime.LockOSThread()
		if unix.Gettid() == unix.Getpid() {
			// This goroutine holds the first thread, so the next one
			// gets another.
			onOtherThread(f)
			return
		}
		f()
	}()
	<-done
}

// seccompCalls makes the calls the filter at level refuses.
func seccompCalls(e *escT, level Kernel) {
	// The terminal ioctls are refused at every level, as is another ABI.
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		e.failf("open /dev/ptmx: %v", err)
		return
	}
	defer ptmx.Close()
	fd := ptmx.Fd()
	ch := byte('x')
	// On 32-bit, uintptr drops the high bit and these repeat the plain calls.
	high := uintptr(uint64(1) << 32 & uint64(^uintptr(0)))
	e.is("TIOCSTI", sc(unix.SYS_IOCTL, fd, unix.TIOCSTI, uintptr(unsafe.Pointer(&ch))), unix.EPERM)                      //nolint:gosec // G103: the kernel reads or writes the buffer during the call, which keeps it valid.
	e.is("TIOCSTI with a high bit", sc(unix.SYS_IOCTL, fd, high|unix.TIOCSTI, uintptr(unsafe.Pointer(&ch))), unix.EPERM) //nolint:gosec // G103: the kernel reads or writes the buffer during the call, which keeps it valid.
	sub := [4]byte{2}
	e.is("TIOCLINUX", sc(unix.SYS_IOCTL, fd, unix.TIOCLINUX, uintptr(unsafe.Pointer(&sub[0]))), unix.EPERM)                      //nolint:gosec // G103: the kernel reads or writes the buffer during the call, which keeps it valid.
	e.is("TIOCLINUX with a high bit", sc(unix.SYS_IOCTL, fd, high|unix.TIOCLINUX, uintptr(unsafe.Pointer(&sub[0]))), unix.EPERM) //nolint:gosec // G103: the kernel reads or writes the buffer during the call, which keeps it valid.
	// A TIOCSTI on the controlling terminal's own descriptor 0, whatever
	// it is, is refused by the filter before the device sees it.
	e.is("TIOCSTI on fd 0", sc(unix.SYS_IOCTL, 0, unix.TIOCSTI, uintptr(unsafe.Pointer(&ch))), unix.EPERM) //nolint:gosec // G103: the kernel reads or writes the buffer during the call, which keeps it valid.
	if x32Bit != 0 {
		e.is("an x32 call", sc(unix.SYS_GETPID|x32Bit), unix.ENOSYS)
	}
	if level == KernelOpen {
		return
	}

	// Everything not listed answers ENOSYS, so a program falls back. Each is
	// the call's number and its arguments. They are zeros, except ptrace's:
	// its request 0 is PTRACE_TRACEME, which needs no target and makes the
	// parent the calling thread's tracer (ptrace_traceme in kernel/ptrace.c),
	// so it asks to attach to pid 0, which is no process.
	refused := map[string][]uintptr{
		"bpf": {unix.SYS_BPF}, "io_uring_setup": {unix.SYS_IO_URING_SETUP},
		"io_uring_enter": {unix.SYS_IO_URING_ENTER}, "io_uring_register": {unix.SYS_IO_URING_REGISTER},
		"perf_event_open": {unix.SYS_PERF_EVENT_OPEN}, "userfaultfd": {unix.SYS_USERFAULTFD},
		"keyctl": {unix.SYS_KEYCTL}, "add_key": {unix.SYS_ADD_KEY}, "request_key": {unix.SYS_REQUEST_KEY},
		"init_module": {unix.SYS_INIT_MODULE}, "finit_module": {unix.SYS_FINIT_MODULE},
		"delete_module": {unix.SYS_DELETE_MODULE}, "kexec_load": {unix.SYS_KEXEC_LOAD},
		"ptrace": {unix.SYS_PTRACE, unix.PTRACE_ATTACH, 0}, "setns": {unix.SYS_SETNS}, "clone3": {unix.SYS_CLONE3},
		"process_vm_readv": {unix.SYS_PROCESS_VM_READV}, "process_vm_writev": {unix.SYS_PROCESS_VM_WRITEV},
		"open_by_handle_at": {unix.SYS_OPEN_BY_HANDLE_AT}, "reboot": {unix.SYS_REBOOT},
		"swapon": {unix.SYS_SWAPON}, "acct": {unix.SYS_ACCT},
	}
	if level == KernelStrict {
		for name, call := range map[string][]uintptr{
			"unshare": {unix.SYS_UNSHARE}, "mount": {unix.SYS_MOUNT}, "umount2": {unix.SYS_UMOUNT2},
			"pivot_root": {unix.SYS_PIVOT_ROOT}, "chroot": {unix.SYS_CHROOT}, "fsopen": {unix.SYS_FSOPEN},
			"fsmount": {unix.SYS_FSMOUNT}, "fsconfig": {unix.SYS_FSCONFIG}, "fspick": {unix.SYS_FSPICK},
			"open_tree": {unix.SYS_OPEN_TREE}, "move_mount": {unix.SYS_MOVE_MOUNT}, "mount_setattr": {unix.SYS_MOUNT_SETATTR},
		} {
			refused[name] = call
		}
	}
	for name, call := range refused {
		e.is(name, sc(call[0], call[1:]...), unix.ENOSYS)
	}
	// With real arguments, as a program would call them.
	e.is("unshare(CLONE_NEWUSER)", func() error {
		if level == KernelStrict {
			return unix.Unshare(unix.CLONE_NEWUSER)
		}
		return unix.ENOSYS
	}(), unix.ENOSYS)
	if level == KernelStrict {
		e.is("mount a tmpfs", unix.Mount("none", "/tmp", "tmpfs", 0, ""), unix.ENOSYS)
		e.is("unmount /dev", unix.Unmount("/dev", unix.MNT_DETACH), unix.ENOSYS)
		e.is("chroot", unix.Chroot("/"), unix.ENOSYS)
		e.is("remount / writable", unix.Mount("", "/", "", unix.MS_REMOUNT|unix.MS_BIND, ""), unix.ENOSYS)
	}

	// Sockets: only Unix and IP stream and datagram.
	sock := func(domain, typ, proto int) error {
		fd, err := unix.Socket(domain, typ, proto)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}
	e.is("netlink socket", sock(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE), unix.EAFNOSUPPORT)
	e.is("netlink netfilter socket", sock(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER), unix.EAFNOSUPPORT)
	e.is("packet socket", sock(unix.AF_PACKET, unix.SOCK_RAW, 0), unix.EAFNOSUPPORT)
	e.is("vsock socket", sock(unix.AF_VSOCK, unix.SOCK_STREAM, 0), unix.EAFNOSUPPORT)
	e.is("alg socket", sock(unix.AF_ALG, unix.SOCK_SEQPACKET, 0), unix.EAFNOSUPPORT)
	e.is("bluetooth socket", sock(unix.AF_BLUETOOTH, unix.SOCK_STREAM, 0), unix.EAFNOSUPPORT)
	e.is("key socket", sock(unix.AF_KEY, unix.SOCK_RAW, 2), unix.EAFNOSUPPORT)
	e.is("raw IP socket", sock(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW), unix.EPERM)
	e.is("SOCK_PACKET socket", sock(unix.AF_INET, unix.SOCK_PACKET, 0), unix.EPERM)
	e.is("SCTP socket", sock(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP), unix.EPROTONOSUPPORT)
	e.is("MPTCP socket", sock(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), unix.EPROTONOSUPPORT)
	e.is("sequenced-packet IP socket", sock(unix.AF_INET, unix.SOCK_SEQPACKET, 0), unix.ESOCKTNOSUPPORT)
	e.is("DCCP socket", sock(unix.AF_INET, unix.SOCK_DCCP, 0), unix.ESOCKTNOSUPPORT)
	e.is("a socket pair in the IP family", func() error {
		_, err := unix.Socketpair(unix.AF_INET, unix.SOCK_STREAM, 0)
		return err
	}(), unix.EAFNOSUPPORT)
	e.is("a Unix socket", sock(unix.AF_UNIX, unix.SOCK_STREAM, 0))
	e.is("a TCP socket", sock(unix.AF_INET, unix.SOCK_STREAM, 0))
	e.is("a UDP socket", sock(unix.AF_INET, unix.SOCK_DGRAM, 0))

	// The legacy netfilter options, which need CAP_NET_ADMIN, which a
	// process in a namespace of its own has under nested.
	for _, fam := range []struct {
		name         string
		domain, lvl  int
		set, get, ok []int
	}{
		{"IPv4", unix.AF_INET, unix.IPPROTO_IP, []int{64, 65, 66, 128, 200}, []int{64, 65, 66, 96, 97}, []int{unix.IP_TOS}},
		{"IPv6", unix.AF_INET6, unix.IPPROTO_IPV6, []int{64, 65}, []int{68, 69}, []int{unix.IPV6_TCLASS}},
	} {
		s, err := unix.Socket(fam.domain, unix.SOCK_STREAM, 0)
		if err != nil {
			continue // no IPv6 on this host
		}
		for _, opt := range fam.set {
			e.is(fmt.Sprintf("%s setsockopt %d", fam.name, opt), unix.SetsockoptString(s, fam.lvl, opt, string(make([]byte, 128))), unix.EPERM)
		}
		for _, opt := range fam.get {
			_, err := unix.GetsockoptString(s, fam.lvl, opt)
			e.is(fmt.Sprintf("%s getsockopt %d", fam.name, opt), err, unix.EPERM)
		}
		// An ordinary option still gets to the kernel.
		if err := unix.SetsockoptInt(s, fam.lvl, fam.ok[0], 0); errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSYS) {
			e.failf("%s ordinary option %d: %v", fam.name, fam.ok[0], err)
		}
		_ = unix.Close(s)
	}
	e.is("personality READ_IMPLIES_EXEC", sc(unix.SYS_PERSONALITY, 0x0400000), unix.EPERM)
	e.is("personality BSD", sc(unix.SYS_PERSONALITY, 6), unix.EPERM)
	e.is("personality query", sc(unix.SYS_PERSONALITY, 0xffffffff))
}

// escCloneNamespaces starts a process in each kind of new namespace and
// expects the filter to refuse it under strict (args[0] "refused") and not
// under nested ("allowed").
func escCloneNamespaces(e *escT, args []string) {
	for name, flag := range map[string]uintptr{
		"user": unix.CLONE_NEWUSER, "mount": unix.CLONE_NEWNS, "net": unix.CLONE_NEWNET,
		"pid": unix.CLONE_NEWPID, "ipc": unix.CLONE_NEWIPC, "uts": unix.CLONE_NEWUTS,
		"cgroup": unix.CLONE_NEWCGROUP,
	} {
		cmd := exec.CommandContext(context.Background(), "/bin/true")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: flag}
		err := cmd.Run()
		if args[0] == "refused" {
			e.is("start in a new "+name+" namespace", err, unix.EPERM)
		} else if name == "user" {
			e.is("start in a new user namespace", err)
		}
	}
}

// netTargets are what escNet tries to reach.
type netTargets struct {
	// Loop is a TCP listener on the host's loopback.
	Loop string `json:"loop"`
	// Abstract is an abstract Unix socket of the host, starting with "@".
	Abstract string `json:"abstract"`
	// Unix is a Unix socket file on the host in a covered directory.
	Unix string `json:"unix"`
	// Host is true when the sandbox shares the host's network.
	Host bool `json:"host"`
}

func escNet(e *escT, args []string) {
	var tg netTargets
	if err := json.Unmarshal([]byte(args[0]), &tg); err != nil {
		e.failf("%v", err)
		return
	}
	dial := func(addr string) error {
		c, err := dialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			_ = c.Close()
		}
		return err
	}
	if tg.Host {
		e.is("dial the host's loopback", dial(tg.Loop))
		e.is("connect to the host's abstract socket", connectUnix(tg.Abstract))
		return
	}
	e.is("dial the host's loopback", dial(tg.Loop), unix.ECONNREFUSED)
	e.is("dial the host's loopback by name", dial(strings.Replace(tg.Loop, "127.0.0.1", "localhost", 1)), unix.ECONNREFUSED)
	e.is("connect to the host's abstract socket", connectUnix(tg.Abstract), unix.ECONNREFUSED)
	// Hidden, or covered by /dev/null, which refuses.
	e.is("connect to a host socket file", connectUnix(tg.Unix), unix.ENOENT, unix.ECONNREFUSED)
	e.is("dial out", dial("192.0.2.1:9"), unix.ENETUNREACH)
	e.is("dial out over IPv6", dial("[2001:db8::1]:9"), unix.ENETUNREACH, unix.EADDRNOTAVAIL, unix.EAFNOSUPPORT)
	// The only interface is a loopback, which cannot be reconfigured.
	if dev, err := os.ReadFile("/proc/net/dev"); err == nil {
		for l := range strings.Lines(string(dev)) {
			if name, _, ok := strings.Cut(l, ":"); ok {
				if n := strings.TrimSpace(name); n != "lo" && n != "" && !strings.Contains(n, "|") {
					e.failf("interface %q besides lo", n)
				}
			}
		}
	}
	// Nothing listens on the sandbox's own loopback unless it started it, so
	// the host's port is not here even though the address is.
	ln, err := listenLocal()
	if err != nil {
		e.failf("listen on its own loopback: %v", err)
		return
	}
	defer ln.Close()
	e.is("its own loopback works", dial(ln.Addr().String()))
}

// nestedTargets2 are the paths escNestedStart and escNestedInner use.
type nestedTargets2 struct {
	// ReadOnly is a directory bound read-only into the sandbox.
	ReadOnly string `json:"read_only"`
	// Host is a path under /home that the sandbox covers.
	HostHome string `json:"host_home"`
}

const nestedVar = "SANDBOX_TEST_ESC_NESTED"

// escNestedStart starts escNestedInner in a user, mount and network
// namespace of its own, as software with a sandbox of its own would under
// nested, holding the capabilities there.
func escNestedStart(e *escT, args []string) {
	cmd := exec.CommandContext(context.Background(), "/proc/self/exe", "esc", "nested-inner")
	cmd.Env = append(os.Environ(), nestedVar+"="+args[0])
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_NET_ADMIN, unix.CAP_SYS_CHROOT},
	}
	if err := cmd.Run(); err != nil {
		e.failf("inner: %v", err)
	}
}

func escNestedInner(e *escT, _ []string) {
	var tg nestedTargets2
	if err := json.Unmarshal([]byte(os.Getenv(nestedVar)), &tg); err != nil {
		e.failf("%v", err)
		return
	}
	// The mounts here were copied from the sandbox's, so the kernel locks
	// them.
	for _, p := range []string{"/dev", "/proc", "/home", "/tmp", "/etc/passwd", tg.ReadOnly} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		e.is("unmount "+p, unix.Unmount(p, unix.MNT_DETACH), unix.EINVAL, unix.EPERM)
	}
	e.is("remount / writable", unix.Mount("", "/", "", unix.MS_REMOUNT|unix.MS_BIND, ""), unix.EPERM, unix.EINVAL)
	e.is("remount the read-only bind writable", unix.Mount("", tg.ReadOnly, "", unix.MS_REMOUNT|unix.MS_BIND, ""), unix.EPERM, unix.EINVAL)
	e.is("write /escape after", writeProbe("/escape"), unix.EROFS, unix.EACCES)
	e.is("write in the read-only bind after", writeProbe(tg.ReadOnly), unix.EROFS, unix.EACCES)
	// A bind of the root without its children would show what the covers
	// hide. The kernel refuses it, and the recursive one keeps the covers.
	if err := os.Mkdir("peek", 0o700); err != nil {
		e.failf("%v", err)
		return
	}
	e.is("bind / without its mounts", unix.Mount("/", "peek", "", unix.MS_BIND, ""), unix.EINVAL)
	if err := unix.Mount("/", "peek", "", unix.MS_BIND|unix.MS_REC, ""); err == nil {
		if ents, _ := os.ReadDir("peek/home"); len(ents) > 0 {
			e.failf("peek/home shows %d entries, the cover is gone", len(ents))
		}
		if what := leaks("peek" + tg.HostHome); what != "" {
			e.failf("peek shows %s", what)
		}
	}
	// The sandbox's namespaces belong to a user namespace this one is not
	// the owner of, so pid 1's cannot be joined.
	_, err := os.Open("/proc/1/ns/mnt")
	e.is("open pid 1's mount namespace", err, unix.EACCES)
	e.is("write the hostname of the host's namespace", func() error {
		return os.WriteFile("/proc/sys/kernel/hostname", []byte("x"), 0o600)
	}(), unix.EACCES, unix.EROFS, unix.EPERM)
	// The classic chroot escape, a descriptor of the old root and a walk up
	// from a new one, only returns to the same view.
	oldRoot, err := os.Open("/")
	if err != nil {
		e.failf("%v", err)
		return
	}
	defer oldRoot.Close()
	if err := os.Mkdir("jail", 0o700); err != nil {
		e.failf("%v", err)
		return
	}
	if err := unix.Chroot("jail"); err != nil {
		e.failf("chroot: %v", err)
		return
	}
	if err := unix.Fchdir(int(oldRoot.Fd())); err != nil {
		e.failf("fchdir: %v", err)
		return
	}
	for range 10 {
		_ = os.Chdir("..")
	}
	if err := unix.Chroot("."); err != nil {
		e.failf("chroot back: %v", err)
		return
	}
	if ents, _ := os.ReadDir("/home"); len(ents) > 0 {
		e.failf("/home shows %d entries after the chroot walk", len(ents))
	}
	if what := leaks(tg.HostHome); what != "" {
		e.failf("after the chroot walk, %s", what)
	}
	if _, err := os.Stat("/dev/sandbox-stage"); err != nil {
		e.failf("the walk did not end at the sandbox's own root: %v", err)
	}
}

// escFds looks for the setup descriptors in every way open to the
// command.
func escFds(e *escT, _ []string) {
	for fd, target := range openFds() {
		e.failf("holds descriptor %d to %s", fd, target)
	}
	// pid 1 holds the control socket until setup ends, and the lifeline's
	// read end after, but its descriptors are closed to the command.
	for fd := fdArgs; fd <= fdFiles; fd++ {
		_, err := os.Open("/proc/1/fd/" + strconv.Itoa(fd))
		e.is(fmt.Sprintf("open pid 1's descriptor %d", fd), err, unix.EACCES)
		_, err = os.Readlink("/proc/1/fd/" + strconv.Itoa(fd))
		e.is(fmt.Sprintf("read pid 1's descriptor %d", fd), err, unix.EACCES)
	}
	// Nothing at the numbers the stages use answers a write.
	for fd := fdArgs; fd <= fdFiles; fd++ {
		if _, err := unix.Write(fd, []byte("{}")); !errors.Is(err, unix.EBADF) {
			e.failf("write to descriptor %d: %v, want EBADF", fd, err)
		}
	}
	// Every process in the sandbox the command can see holds none either.
	ents, _ := os.ReadDir("/proc")
	for _, ent := range ents {
		if _, err := strconv.Atoi(ent.Name()); err != nil || ent.Name() == "1" {
			continue
		}
		fds, err := os.ReadDir("/proc/" + ent.Name() + "/fd")
		if err != nil {
			continue
		}
		for _, f := range fds {
			if target, err := os.Readlink("/proc/" + ent.Name() + "/fd/" + f.Name()); err == nil && (strings.HasPrefix(target, "socket:") || strings.HasPrefix(target, "pipe:")) && f.Name() > "2" {
				e.failf("process %s holds %s on descriptor %s", ent.Name(), target, f.Name())
			}
		}
	}
}

func escScratch(e *escT, args []string) {
	const tmpfsMagic = 0x01021994
	for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		var st unix.Statfs_t
		if err := unix.Statfs(d, &st); err != nil {
			e.failf("statfs %s: %v", d, err)
			continue
		}
		if st.Type != tmpfsMagic {
			e.failf("%s is filesystem %#x, want tmpfs", d, st.Type)
		}
		if size := fsBytes(st.Blocks, st.Bsize); size == 0 || size > 1<<30 {
			e.failf("%s holds %d bytes, want at most 1 GiB", d, size)
		}
		f := filepath.Join(d, "sandbox-test-"+args[0])
		e.is("write "+f, os.WriteFile(f, []byte("hello"), 0o600)) //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
	}
	// The host's own files in them are not here.
	for _, p := range args[1:] {
		if _, err := os.Stat(p); !errors.Is(err, unix.ENOENT) { //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
			e.failf("host file %s: %v, want ENOENT", p, err)
		}
	}
}

func escPasswd(e *escT, args []string) {
	name, home := args[0], args[1]
	uid, gid := os.Getuid(), os.Getgid()
	pw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		e.failf("%v", err)
		return
	}
	if want := fmt.Sprintf("%s:x:%d:%d::%s:/bin/sh\n", name, uid, gid, home); string(pw) != want {
		e.failf("/etc/passwd = %q, want %q", pw, want)
	}
	gr, _ := os.ReadFile("/etc/group")
	if strings.Count(string(gr), "\n") != 1 || !strings.Contains(string(gr), fmt.Sprintf(":x:%d:", gid)) {
		e.failf("/etc/group = %q, want one entry for gid %d", gr, gid)
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil || u.Username != name || u.HomeDir != home {
		e.failf("LookupId = %+v, %v", u, err)
	}
	for _, other := range []string{"root", "daemon", "nobody"} {
		// With cgo the lookup goes through NSS, and nss-systemd (on hosts
		// whose nsswitch.conf lists it, such as Debian with systemd's
		// libnss-systemd) makes up root and nobody even when /etc/passwd
		// does not list them. That is not a host listing leaking in.
		if cgoBuild && (other == "root" || other == "nobody") {
			continue
		}
		if _, err := user.Lookup(other); err == nil {
			e.failf("user %s is listed", other)
		}
	}
	e.is("write /etc/passwd", func() error { return os.WriteFile("/etc/passwd", []byte("root::0:0::/:/bin/sh\n"), 0o600) }(), unix.EROFS, unix.EACCES)
	e.is("append to /etc/group", func() error {
		f, err := os.OpenFile("/etc/group", os.O_WRONLY|os.O_APPEND, 0)
		if err == nil {
			_ = f.Close()
		}
		return err
	}(), unix.EROFS, unix.EACCES)
}

func escNoNewPrivs(e *escT, _ []string) {
	status, _ := os.ReadFile("/proc/self/status")
	if v := lineWith(string(status), "NoNewPrivs:"); v != "1" {
		e.failf("NoNewPrivs = %q, want 1", v)
	}
	if v := lineWith(string(status), "Seccomp:"); v != "2" {
		e.failf("Seccomp = %q, want a filter (2)", v)
	}
	for _, n := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if v := lineWith(string(status), n+":"); strings.Trim(v, "0") != "" {
			e.failf("%s = %s, want none", n, v)
		}
	}
	// A real setuid-root program stays an ordinary one: its effective uid
	// after the exec is the account's own. This checks the outcome, not
	// which mechanism gives it. The kernel ignores the setuid bit on a nosuid
	// mount, under no_new_privs, and when the file's owner has no mapping in
	// the user namespace (bprm_fill_uid in Linux's fs/exec.c). bubblewrap's
	// binds are nosuid (bind_mount in its bind-mount.c), and the host's uid 0
	// is not mapped, so the loop would pass without no_new_privs. The
	// NoNewPrivs line above is the check of that. passwd, su and mount are
	// setuid root on every Debian and Ubuntu install, the minimal ones too,
	// since their packages are required. The status is read before Wait, so
	// a program that has already exited is a zombie, whose status still
	// shows its uids.
	checked := 0
	for _, p := range []string{"/usr/bin/passwd", "/usr/bin/su", "/usr/bin/mount"} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode()&os.ModeSetuid == 0 {
			continue
		}
		cmd := exec.CommandContext(context.Background(), p, "--help") //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		cmd.Stdin = nil
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Start(); err != nil {
			e.failf("start %s: %v", p, err)
			continue
		}
		st, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/status")
		f := strings.Fields(lineWith(string(st), "Uid:"))
		switch {
		case err != nil || len(f) < 2:
			e.failf("the uids of %s: %q, %v", p, st, err)
		case f[1] != strconv.Itoa(os.Getuid()):
			e.failf("%s runs with euid %s", p, f[1])
		}
		checked++
		_ = cmd.Wait()
	}
	if checked == 0 {
		e.failf("no setuid passwd, su or mount in the sandbox, so no real setuid program was tried")
	}
}

func escGroups(e *escT, _ []string) {
	got, err := unix.Getgroups()
	if err != nil {
		e.failf("%v", err)
		return
	}
	fmt.Println(got)
}

// spin burns CPU until it is killed.
func spin() {
	for {
		_ = strings.Repeat("x", 1000)
	}
}

func escRlimitFsize(e *escT, args []string) {
	// The signal for a write past the limit would end the process.
	signal.Ignore(unix.SIGXFSZ)
	f, err := os.Create(filepath.Join(args[0], "big")) //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
	if err != nil {
		e.failf("%v", err)
		return
	}
	defer f.Close()
	chunk := make([]byte, 1<<16)
	var written int64
	var werr error
	for range 64 { // 4 MiB
		var n int
		n, werr = f.Write(chunk)
		written += int64(n)
		if werr != nil {
			break
		}
	}
	e.is("write past RLIMIT_FSIZE", werr, unix.EFBIG)
	if limit, _ := strconv.ParseInt(args[1], 10, 64); written > limit {
		e.failf("wrote %d bytes, past the limit %d", written, limit)
	}
	e.is("truncate past RLIMIT_FSIZE", f.Truncate(8<<20), unix.EFBIG)
}

func escRlimitNofile(e *escT, args []string) {
	limit, _ := strconv.Atoi(args[0])
	var files []*os.File
	var err error
	for len(files) <= limit+10 {
		var f *os.File
		if f, err = os.Open("/dev/null"); err != nil {
			break
		}
		files = append(files, f)
	}
	e.is("open past RLIMIT_NOFILE", err, unix.EMFILE)
	if len(files) > limit {
		e.failf("opened %d files with a limit of %d", len(files), limit)
	}
}

func escRlimitAs(e *escT, args []string) {
	limit, _ := strconv.Atoi(args[0])
	_, err := unix.Mmap(-1, 0, limit*2, unix.PROT_NONE, unix.MAP_ANON|unix.MAP_PRIVATE)
	e.is("map twice RLIMIT_AS", err, unix.ENOMEM)
}

// escRlimitNproc starts sleeping children until the kernel refuses, and
// expects it before args[0] of them.
func escRlimitNproc(e *escT, args []string) {
	most, _ := strconv.Atoi(args[0])
	var kids []*exec.Cmd
	defer func() {
		for _, k := range kids {
			_ = k.Process.Kill()
			_ = k.Wait()
		}
	}()
	var err error
	for len(kids) < most {
		cmd := exec.CommandContext(context.Background(), "/bin/sleep", "300")
		if err = cmd.Start(); err != nil {
			break
		}
		kids = append(kids, cmd)
	}
	e.is("fork past RLIMIT_NPROC", err, unix.EAGAIN)
}

// holdCheck prints the sandbox's pid namespace, then waits to be killed.
func holdCheck(*escT, []string) {
	fmt.Println("ns", nsLink("self", "pid"))
	time.Sleep(time.Minute)
}

// daemonCheck prints its pid namespace and starts a daemon that setsid's
// and double-forks, then exits (args[1] "exit") or waits (args[1] "hang") once
// the daemon is running. args[0] is a file the daemon writes.
func daemonCheck(e *escT, args []string) {
	fmt.Println("ns", nsLink("self", "pid"))
	cmd := exec.CommandContext(context.Background(), "/proc/self/exe", "esc", "daemon-child", args[0]) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Run(); err != nil {
		e.failf("daemon-child: %v", err)
		return
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(args[0]); err == nil { //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
			break
		}
		if time.Now().After(deadline) {
			e.failf("the daemon never started")
			return
		}
	}
	fmt.Println("ready")
	if args[1] == "hang" {
		time.Sleep(time.Minute)
	}
}

// daemonChild starts the daemon in a session of its own and exits, so the
// daemon is reparented to pid 1.
func daemonChild(e *escT, args []string) {
	cmd := exec.CommandContext(context.Background(), "/proc/self/exe", "esc", "daemon-grand", args[0]) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		e.failf("daemon-grand: %v", err)
	}
}

func daemonGrand(_ *escT, args []string) {
	_ = os.WriteFile(args[0], nil, 0o600) //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
	time.Sleep(time.Minute)
}

// peerCheck connects to the Unix socket args[0] and says its pid namespace.
// With args[1] "setsid" it leaves its session first.
func peerCheck(e *escT, args []string) {
	if len(args) > 1 && args[1] == "setsid" {
		if _, err := unix.Setsid(); err != nil {
			// A process group leader cannot setsid, and a fresh Go process
			// is not one unless it was started as one.
			e.failf("setsid: %v", err)
			return
		}
	}
	c, err := dialTimeout("unix", args[0], 5*time.Second)
	if err != nil {
		e.failf("%v", err)
		return
	}
	defer c.Close()
	if _, err := fmt.Fprintf(c, "ns %s\n", nsLink("self", "pid")); err != nil {
		e.failf("send the namespace: %v", err)
		return
	}
	_, _ = io.Copy(io.Discard, c)
}

// plantLink replaces the directory args[0] with a link to args[1], as a
// sandbox that can write the directory's parent can.
func plantLink(e *escT, args []string) {
	if err := os.RemoveAll(args[0]); err != nil { //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
		e.failf("%v", err)
		return
	}
	e.is("plant a link", os.Symlink(args[1], args[0]))
}

func selfKill(_ *escT, args []string) {
	n, _ := strconv.Atoi(args[0])
	_ = unix.Kill(os.Getpid(), syscall.Signal(n))
	time.Sleep(time.Minute)
}

// bindHold listens on the address args[0], says so, and waits.
func bindHold(e *escT, args []string) {
	ln, err := listenTCP(args[0])
	if err != nil {
		e.failf("%v", err)
		return
	}
	defer ln.Close()
	fmt.Println("listening")
	time.Sleep(2 * time.Second)
}

// readFds prints, for descriptors 3 to args[0], what each holds.
func readFds(e *escT, args []string) {
	n, _ := strconv.Atoi(args[0])
	for fd := 3; fd < 3+n; fd++ {
		buf := make([]byte, 64)
		k, err := unix.Pread(fd, buf, 0)
		if err != nil {
			e.failf("read fd %d: %v", fd, err)
			continue
		}
		fmt.Printf("%d:%s\n", fd, buf[:k])
	}
}

// killCanary tries to kill the pid args[0] and says what happened.
func killCanary(e *escT, args []string) {
	n, _ := strconv.Atoi(args[0])
	e.is("kill a host process", unix.Kill(n, unix.SIGKILL), unix.ESRCH)
	e.is("kill a host process group", unix.Kill(-n, unix.SIGKILL), unix.ESRCH)
}

// escParentMode starts a sandbox from the Spec in args[0], passes its output
// on, prints "pid <host pid of pid 1>", and waits to be killed without
// waiting for the sandbox.
func escParentMode(args []string) int {
	var spec Spec
	if err := json.Unmarshal([]byte(args[0]), &spec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c, err := Command(context.Background(), spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("pid", c.Pid())
	time.Sleep(time.Minute)
	return 0
}

// ------------------------------------------------------------------ tests

// hostNamespaces returns the links of the host's own namespaces.
func hostNamespaces() map[string]string {
	m := map[string]string{}
	for _, n := range []string{"user", "pid", "ipc", "uts", "mnt", "net"} {
		m[n] = nsLink("self", n)
	}
	return m
}

// Row: "User/pid/ipc/uts namespaces, uid mapped to itself, --die-with-parent,
// --as-pid-1".
func TestEscapeNamespaces(t *testing.T) {
	t.Parallel()
	for _, network := range []Network{NetworkNone, NetworkHost} {
		t.Run(network.String(), func(t *testing.T) {
			t.Parallel()
			escRun(t, Spec{Home: t.TempDir(), Network: network}, "ns", jsonArg(t, hostNamespaces()), strconv.Itoa(os.Getuid()), network.String())
		})
	}
}

// Row: "User/pid/ipc/uts namespaces ...": the host's processes, its parent,
// and its environment are out of reach, at every kernel level and network.
//
//nolint:paralleltest // uses t.Setenv, which t.Parallel forbids, so its subtests, which share what it sets, are serial too.
func TestEscapeHostProcesses(t *testing.T) {
	secret := fmt.Sprintf("host-env-secret-%d", os.Getpid())
	t.Setenv("SANDBOX_TEST_HOST_SECRET", secret)
	canary := exec.CommandContext(t.Context(), "sleep", "300")
	if err := canary.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = canary.Process.Kill(); _ = canary.Wait() }()
	// A SysV segment on the host, which the sandbox's IPC namespace hides.
	key := 0x5a5a0000 + os.Getpid()&0xffff
	shm, _, errno := unix.Syscall(unix.SYS_SHMGET, uintptr(key), 4096, 0o600|unix.IPC_CREAT)
	if errno != 0 {
		t.Fatalf("shmget: %v", errno)
	}
	defer func() { _, _, _ = unix.Syscall(unix.SYS_SHMCTL, shm, unix.IPC_RMID, 0) }()
	for _, level := range []Kernel{KernelStrict, KernelNested, KernelOpen} {
		for _, network := range []Network{NetworkNone, NetworkHost} {
			t.Run(string(level)+"/"+network.String(), func(t *testing.T) {
				if !kernelFilterBuilds && level != KernelOpen {
					t.Skip("no system call list on " + runtime.GOARCH)
				}
				// The command's own environment is not the host's: the secret
				// is in this process's, not in Env.
				escRun(t, Spec{Home: t.TempDir(), Kernel: level, Network: network}, "procs",
					jsonArg(t, procTargets{ParentPid: os.Getpid(), Canary: canary.Process.Pid, Secret: secret, ShmKey: key}))
			})
		}
	}
	if err := canary.Process.Signal(syscall.Signal(0)); err != nil {
		t.Errorf("the host's process did not survive the sandbox: %v", err)
	}
	t.Run("kill a host process and group", func(t *testing.T) {
		escRun(t, Spec{Home: t.TempDir()}, "killcanary", strconv.Itoa(canary.Process.Pid))
		if err := canary.Process.Signal(syscall.Signal(0)); err != nil {
			t.Errorf("the host's process was signaled: %v", err)
		}
	})
}

// Row: "Bridge check by pid namespace (--info-fd)": a peer on a socket in
// Write is in the pid namespace of Pid(), as the bridge check needs, also
// after it calls setsid, and is a descendant of Pid().
func TestEscapePidNamespacePeer(t *testing.T) {
	t.Parallel()
	type peerInfo struct {
		pid      int
		says     string
		link     string
		descends bool
		pid1Link string
		err      string
	}
	for _, mode := range []string{"", "setsid"} {
		t.Run("peer "+mode, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			sock := filepath.Join(dir, "bridge.sock")
			var lc net.ListenConfig
			ln, err := lc.Listen(t.Context(), "unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			c, _, stderr := escCmd(t.Context(), t, Spec{Write: []string{dir}}, "esc", "peer", sock, mode)
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			pid1 := c.Pid()
			peer := make(chan peerInfo, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					peer <- peerInfo{err: "accept: " + err.Error()}
					return
				}
				defer conn.Close()
				raw, _ := conn.(*net.UnixConn).SyscallConn()
				var cred *unix.Ucred
				var cerr error
				_ = raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
				if cerr != nil {
					peer <- peerInfo{err: "cred: " + cerr.Error()}
					return
				}
				line, _ := bufio.NewReader(conn).ReadString('\n')
				// The peer is blocked until this side closes, so its /proc
				// entries can be read.
				info := peerInfo{pid: int(cred.Pid), says: strings.TrimPrefix(strings.TrimSpace(line), "ns ")}
				info.link = nsLink(strconv.Itoa(int(cred.Pid)), "pid")
				info.pid1Link = nsLink(strconv.Itoa(pid1), "pid")
				for p := int(cred.Pid); p > 1; {
					if p == pid1 {
						info.descends = true
						break
					}
					st, err := os.ReadFile("/proc/" + strconv.Itoa(p) + "/stat")
					if err != nil {
						break
					}
					// The parent is after the command's name, whose
					// parentheses may hold anything.
					f := strings.Fields(string(st[bytes.LastIndexByte(st, ')')+2:]))
					if len(f) < 2 {
						break
					}
					p, _ = strconv.Atoi(f[1])
				}
				peer <- info
			}()
			got := <-peer
			if err := c.Wait(); err != nil {
				t.Fatalf("%v: %s", err, stderr)
			}
			if got.err != "" {
				t.Fatal(got.err)
			}
			if got.says == "" || got.says == nsLink("self", "pid") {
				t.Errorf("the peer says its pid namespace is %q, the host's is %q", got.says, nsLink("self", "pid"))
			}
			// The bridge's check: SO_PEERCRED's pid is in the sandbox's pid
			// namespace, the one Pid() is pid 1 of, and descends from it.
			if got.link != got.says {
				t.Errorf("SO_PEERCRED pid %d is in %q, the peer says %q", got.pid, got.link, got.says)
			}
			if got.pid1Link != "" && got.pid1Link != got.link {
				t.Errorf("Pid() %d is in %q, the peer in %q", pid1, got.pid1Link, got.link)
			}
			if !got.descends {
				t.Errorf("SO_PEERCRED pid %d is not a descendant of Pid() %d", got.pid, pid1)
			}
		})
	}
}

// Row: "User/pid/ipc/uts namespaces ... --die-with-parent": a SIGKILLed
// parent takes everything with it, including a process that setsid'd and
// double-forked, with OwnSession as without.
func TestEscapeParentKilled(t *testing.T) {
	t.Parallel()
	for _, own := range []bool{false, true} {
		name := "caller's session"
		if own {
			name = "own session"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			ready := filepath.Join(home, "ready")
			exe, dir := escBinary(t)
			spec := Spec{Home: home, Command: []string{exe, "esc", "daemon", ready, "hang"}, Read: []string{dir}, OwnSession: own}
			parent := exec.CommandContext(t.Context(), "/proc/self/exe", "esc-parent", jsonArg(t, spec)) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
			out, err := parent.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			parent.Stderr = &stderr
			if err := parent.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = parent.Wait() }()
			rd := bufio.NewReader(out)
			var ns string
			var pid1 int
			var lines []string
			for {
				line, err := rd.ReadString('\n')
				if err != nil {
					// The parent's stderr is whole, and no longer written,
					// only once it has been waited for.
					_ = parent.Process.Kill()
					_ = parent.Wait()
					t.Fatalf("before ready: %v, after the lines %q; stderr: %s", err, lines, &stderr)
				}
				lines = append(lines, line)
				line = strings.TrimSpace(line)
				if v, ok := strings.CutPrefix(line, "pid "); ok {
					pid1, _ = strconv.Atoi(v)
				}
				if v, ok := strings.CutPrefix(line, "ns "); ok {
					ns = v
				}
				if line == "ready" {
					break
				}
			}
			members := nsMembers(ns)
			if len(members) < 2 {
				t.Fatalf("expected the command, the daemon and pid 1 in %s, found %v", ns, members)
			}
			// The daemon is in a session of its own, away from pid 1's.
			var daemons int
			for _, m := range members {
				if st, err := os.ReadFile("/proc/" + strconv.Itoa(m) + "/stat"); err == nil {
					f := strings.Fields(string(st[bytes.LastIndexByte(st, ')')+2:]))
					if len(f) > 4 && f[3] != strconv.Itoa(mySid()) {
						daemons++
					}
				}
			}
			if err := parent.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if left := waitNoMembers(ns); len(left) > 0 {
				t.Errorf("processes %v of the sandbox outlived the parent (%d were in a session of their own)", left, daemons)
			}
			if !gone(pid1) {
				t.Errorf("pid 1 (%d) outlived the parent", pid1)
			}
		})
	}
}

// Row: "User/pid/ipc/uts namespaces ... --as-pid-1": when the command exits,
// a process left running that setsid'd and double-forked dies with the
// sandbox.
func TestEscapeDaemonDiesWithCommand(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	c, stdout, stderr := escCmd(t.Context(), t, Spec{Home: home}, "esc", "daemon", filepath.Join(home, "ready"), "exit")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("%v: %s", err, stderr)
	}
	ns := lineWith(stdout.String(), "ns ")
	if ns == "" {
		t.Fatalf("no namespace in %q", stdout)
	}
	if left := waitNoMembers(ns); len(left) > 0 {
		t.Errorf("processes %v outlived the command", left)
	}
}

// Row: "caller's session kept": every process in the sandbox stays in the
// caller's session, so the sandbox has not made one that could hold a
// terminal, and the filter refuses TIOCSTI and TIOCLINUX. Every process is in
// one process group, which is not the caller's.
func TestEscapeSessionKept(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c, stdout, _ := escCmd(ctx, t, Spec{}, "esc", "hold")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = c.Wait() }()
	var ns string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if ns = lineWith(stdout.String(), "ns "); ns != "" {
			break
		}
	}
	if ns == "" {
		t.Fatal("the command never started")
	}
	sid, pgid := mySid(), strconv.Itoa(c.run.cmd.Process.Pid)
	members := nsMembers(ns)
	if len(members) == 0 {
		t.Fatal("no members found")
	}
	for _, m := range members {
		st, err := os.ReadFile("/proc/" + strconv.Itoa(m) + "/stat")
		if err != nil {
			continue
		}
		f := strings.Fields(string(st[bytes.LastIndexByte(st, ')')+2:]))
		if f[3] != strconv.Itoa(sid) {
			t.Errorf("process %d is in session %s, the caller's is %d", m, f[3], sid)
		}
		if f[2] != pgid {
			t.Errorf("process %d is in process group %s, want the sandbox's own, %s", m, f[2], pgid)
		}
	}
}

// Row: "Filter: allowlist, arg checks, ENOSYS default ..." and "Caller's
// session kept, TIOCSTI/TIOCLINUX refused": the refusals, at each level.
func TestEscapeSeccomp(t *testing.T) {
	t.Parallel()
	for _, level := range []Kernel{KernelStrict, KernelNested, KernelOpen} {
		t.Run(string(level), func(t *testing.T) {
			t.Parallel()
			if !kernelFilterBuilds && level != KernelOpen {
				t.Skip("no system call list on " + runtime.GOARCH)
			}
			escRun(t, Spec{Home: t.TempDir(), Kernel: level}, "seccomp", string(level))
		})
	}
	t.Run("foreign ABI", func(t *testing.T) {
		t.Parallel()
		if x32Bit == 0 {
			t.Skip("arm64 has no x32 ABI, and the 32-bit compat ABI needs assembly or a 32-bit binary to call, so no foreign ABI can be reached from Go here; the filter's arch check is covered offline by TestSeccompFilter")
		}
	})
	t.Run("namespaces by clone", func(t *testing.T) {
		t.Parallel()
		if !kernelFilterBuilds {
			t.Skip("no system call list on " + runtime.GOARCH)
		}
		escRun(t, Spec{Home: t.TempDir(), Kernel: KernelStrict}, "clone-ns", "refused")
		escRun(t, Spec{Home: t.TempDir(), Kernel: KernelNested}, "clone-ns", "allowed")
	})
}

// Row: "Filter ... TSYNC result check" is TestSeccompUnsyncedThread. Row:
// "First stage: ... no_new_privs": the command has it, and a setuid-root
// program does not gain privilege.
func TestEscapeNoNewPrivs(t *testing.T) {
	t.Parallel()
	for _, level := range []Kernel{KernelStrict, KernelNested, KernelOpen} {
		t.Run(string(level), func(t *testing.T) {
			t.Parallel()
			if !kernelFilterBuilds && level != KernelOpen {
				t.Skip("no system call list on " + runtime.GOARCH)
			}
			escRun(t, Spec{Home: t.TempDir(), Kernel: level}, "nnp")
		})
	}
}

// Row: "First stage: ... caps dropped": the command's capability sets are
// empty in the sandbox of a root-mapped namespace too, covered by
// TestIsolation's thread check. The supplementary-groups caveat from
// docs/linux.md (The view: "It holds only while the account has no
// supplementary groups"): the groups pass through into the sandbox, which is why the
// guarantee needs none.
func TestEscapeSupplementaryGroups(t *testing.T) {
	t.Parallel()
	groups, err := unix.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	out := escRun(t, Spec{Home: t.TempDir()}, "groups")
	inside := strings.Fields(strings.Trim(out, "[]\n"))
	if len(inside) != len(groups) {
		t.Errorf("the sandbox has groups %v, the caller has %v: the count should match, since the kernel keeps them", inside, groups)
	}
	if len(groups) > 0 {
		t.Logf("this account has supplementary groups %v, shown in the sandbox as %v: they still count for file modes, so the read-only root is not a guarantee here, as docs/linux.md says", groups, inside)
	}
}

// Row: "Read-only root; covers; default covers; people's homes; the account's
// own home": the default covers are empty, and so are the account's home and
// the host's other files in /tmp, /var and /run.
func TestEscapeDefaultCovers(t *testing.T) {
	t.Parallel()
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A file of the host in /dev/shm and /var/tmp is out of the sandbox's own.
	// Its name is not escScratch's, whose file TestEscapeScratch checks never
	// shows on the host while this test may run beside it.
	shm := fmt.Sprintf("/dev/shm/sandbox-cover-%d", os.Getpid())
	if err := os.WriteFile(shm, []byte("secret"), 0o600); err != nil {
		t.Skip("cannot write /dev/shm on this host: " + err.Error())
	}
	removeAtCleanup(t, shm)
	view := viewSpec{
		// /run and /var hold the files links in /etc lead to, so they are
		// not empty, but nothing else of the host's is there.
		Empty:  []string{"/home", "/root", "/mnt", "/media", "/.snapshots", "/sysroot"},
		Absent: []string{"/var/log", "/var/lib/dpkg", "/var/lib/systemd", "/var/cache", "/var/spool", "/var/mail", "/run/user", "/run/dbus", "/run/systemd/journal", "/run/lock", "/run/credentials", "/run/utmp"},
		Hidden: []string{"/home", "/root", "/run", "/var", "/mnt", "/media", other, shm, filepath.Dir(other)},
	}
	if h, err := os.UserHomeDir(); err == nil {
		view.Hidden = append(view.Hidden, h)
		if u, err := user.Current(); err == nil {
			view.Hidden = append(view.Hidden, u.HomeDir)
		}
	}
	escRun(t, Spec{Home: t.TempDir()}, "view", jsonArg(t, view))
}

// Row: "Read-only root": nothing outside Home and Write can be written, and
// Read is read-only.
func TestEscapeWriteOutside(t *testing.T) {
	t.Parallel()
	read, write, other := t.TempDir(), t.TempDir(), t.TempDir()
	home := t.TempDir()
	view := viewSpec{
		ReadOnly: []string{"/", "/etc", "/etc/hostname", "/usr", "/usr/bin", "/bin", "/lib", "/opt", "/sys", "/proc/sys/kernel/hostname", "/dev/sandbox-stage", read},
		Writable: []string{home, write, "/tmp", "/dev/shm"},
		Hidden:   []string{other},
	}
	escRun(t, Spec{Home: home, Write: []string{write}, Read: []string{read}}, "view", jsonArg(t, view))
	// What the sandbox wrote shows on the host, and what it could not write does not.
	if err := os.WriteFile(filepath.Join(home, "after"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Row: "Read-only root; covers; ... Legwork's config, state, and other
// sandboxes' directories covered": Cover hides directories, files and sockets
// the caller names, however they are named, and Read brings back a path under
// a covered one without its neighbors.
func TestEscapeCover(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		spec  Spec
		view  viewSpec
		wants func(t *testing.T, code int, out string)
	}{
		{
			"a directory",
			Spec{Cover: []string{appDir}},
			viewSpec{Hidden: []string{appDir, appDB}, Empty: []string{appDir}, ReadOnly: []string{appDir}},
			nil,
		},
		{
			"a file",
			Spec{Cover: []string{appDB}},
			viewSpec{Hidden: []string{appDB}, ReadOnly: []string{appDB}},
			nil,
		},
		{
			"a socket",
			Spec{Cover: []string{coveredSock}},
			viewSpec{ReadOnly: []string{coveredSock}},
			nil,
		},
		{
			"a path that is a link",
			Spec{Cover: []string{hostAppLink}},
			viewSpec{Hidden: []string{appDir, hostAppLink}},
			nil,
		},
		{
			"the homes in /etc/passwd and the directory they share",
			Spec{},
			viewSpec{Hidden: append([]string{"/srv/users"}, fakeHomes...), Empty: []string{"/srv/users"}},
			nil,
		},
		{
			"a Read path under a covered home, and its neighbors",
			Spec{Read: []string{hostPub}},
			viewSpec{Readable: []string{hostPub + "/readme"}, ReadOnly: []string{hostPub, hostPub + "/readme"}, Hidden: fakeHomes},
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.spec.Home = t.TempDir()
			escHostOK(t, "fake", tc.spec, "view", jsonArg(t, tc.view))
		})
	}
	t.Run("a covered socket cannot be connected to", func(t *testing.T) {
		// A socket covered by /dev/null refuses connections, and the real
		// one, which the fake host listens on, is not reachable.
		escHostOK(t, "fake", Spec{Cover: []string{coveredSock}}, "net", jsonArg(t, netTargets{Loop: "127.0.0.1:1", Abstract: "@none", Unix: coveredSock}))
	})
}

// Row: "Mount-table covers (.zfs, other mounts of a covered fs)": a second
// mount of a covered directory is hidden too.
func TestEscapeMountTableCovers(t *testing.T) {
	t.Parallel()
	t.Run("a bind mount of a covered directory", func(t *testing.T) {
		t.Parallel()
		view := viewSpec{Hidden: []string{appDir, hostAlias, hostAlias + "/app.db"}, Empty: []string{hostAlias, appDir}}
		escHostOK(t, "bind", Spec{Cover: []string{appDir}}, "view", jsonArg(t, view))
	})
	t.Run(".zfs snapshot directory", func(t *testing.T) {
		t.Parallel()
		t.Skip("the VM has no ZFS dataset, and mounting one needs root, so the .zfs/snapshot cover cannot be built here; the bind mount above stands in for it, and TestMountCovers checks the .zfs rule on a fake mount table")
	})
}

// Row: "/etc links into covered dirs rebound": a link from /etc to a file
// under a default cover reads, read-only, and one to a private path or to a
// directory does not.
func TestEscapeEtcLinks(t *testing.T) {
	t.Parallel()
	view := viewSpec{
		Readable: []string{sharedLink},
		ReadOnly: []string{sharedLink},
		Hidden:   []string{privateLink, etcDirLink, etcDirLink + "/f", fakeHomes[0]},
	}
	escHostOK(t, "fake", Spec{}, "view", jsonArg(t, view))
}

// Row: "Bind sources by fd with RESOLVE_NO_SYMLINKS; a cover that became a
// link aborts": a cover replaced by a link to another cover between Command
// and Start leaves both hidden, or stops the sandbox.
func TestEscapeCoverSwappedForLink(t *testing.T) {
	t.Parallel()
	view := viewSpec{Hidden: []string{appDir, "/srv/users/alice", fakeHomes[0]}}
	code, out := escHost(t, "swap", Spec{Cover: []string{appDir}}, "view", jsonArg(t, view))
	switch code {
	case 0, escStartRefused:
	default:
		t.Fatalf("exit %d:\n%s", code, out)
	}
	t.Logf("exit %d: %s", code, strings.TrimSpace(out))
}

// Row: "Bind sources by fd with RESOLVE_NO_SYMLINKS ...": the race itself, between
// prepare and the bind, cannot be hit through the API, so the two places
// that guard it are driven directly.
func TestEscapeBindSourcesRefuseLinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	secret := filepath.Join(root, "secret")
	for _, d := range []string{realDir, secret} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openNoLinks(realDir); err != nil {
		t.Errorf("a plain directory: %v", err)
	} else {
		_ = f.Close()
	}
	if f, err := openNoLinks(link); err == nil {
		_ = f.Close()
		t.Error("openNoLinks followed a link")
	}
	if f, err := openNoLinks(filepath.Join(link, "x")); err == nil {
		_ = f.Close()
		t.Error("openNoLinks followed a link in the middle of a path")
	}
	// A component swapped for a link after the check.
	if err := os.Rename(realDir, realDir+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, realDir); err != nil {
		t.Fatal(err)
	}
	if f, err := openNoLinks(realDir); err == nil {
		_ = f.Close()
		t.Error("openNoLinks followed a link swapped in after the check")
	}
	// A cover that has become a link since it was resolved stops newLaunch.
	home := t.TempDir()
	l, err := newLaunch(Spec{Home: home, Dir: home, Cover: []string{link}, Kernel: KernelStrict}, account{"u", "g"}, nil)
	if err == nil {
		l.close()
		t.Fatal("newLaunch bound a cover that is a link")
	}
	if !strings.Contains(err.Error(), "link") {
		t.Errorf("error %q does not say it is a link", err)
	}
	// And a home that has become one.
	l, err = newLaunch(Spec{Home: link, Dir: link, Kernel: KernelStrict}, account{"u", "g"}, nil)
	if err == nil {
		l.close()
		t.Error("newLaunch bound a home that is a link")
	}
}

// Row: "Path and link rules: no link in home or write; a link followed only
// outside writable dirs; a missing cover inside a writable dir aborts; no
// mount inside a writable dir; cwd must be shown": Start refuses each layout.
func TestEscapeStartRefusesLayouts(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	if err := os.MkdirAll(secret, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "f"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	mk := func(parts ...string) string {
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(p, 0o750); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := func(name string) string {
		p := filepath.Join(root, name)
		if err := os.Symlink(secret, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	home := mk("home")
	mk("secret", "x")
	for _, tc := range []struct {
		name string
		spec Spec
		want string
	}{
		{"Home is a link", Spec{Home: link("homelink")}, "link"},
		{"a link in the middle of Home", Spec{Home: filepath.Join(link("midlink"), "x")}, "link"},
		{"Write is a link", Spec{Home: home, Write: []string{link("wlink")}}, "link"},
		{"a link in the middle of Write", Spec{Home: home, Write: []string{filepath.Join(link("wmid"), "x")}}, "link"},
		{"a cover inside Home", Spec{Home: home, Cover: []string{mk("home", "state")}}, "inside"},
		{"a Read path inside Home", Spec{Home: home, Read: []string{mk("home", "ro")}}, "inside"},
		{"a Write path inside Home", Spec{Home: home, Write: []string{mk("home", "rw")}}, "inside"},
		{"a cover that went missing inside Home", Spec{Home: home, Cover: []string{filepath.Join(home, "gone")}}, "missing"},
		{"Dir through a link", Spec{Home: home, Dir: filepath.Join(home, "x")}, ""},
		{"Dir not absolute", Spec{Home: home, Dir: "relative"}, "absolute"},
		{"Dir under a cover", Spec{Home: home, Dir: "/home"}, "covered"},
		{"Dir that does not exist", Spec{Home: home, Dir: filepath.Join(root, "nope")}, ""},
		{"Home that does not exist", Spec{Home: filepath.Join(root, "nope")}, "does not exist"},
		{"no Home", Spec{}, "home"},
		{"a relative Home", Spec{Home: "relative"}, "absolute"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.name == "Dir through a link" {
				// A link inside Home, which Dir may not follow.
				if err := os.Symlink(secret, filepath.Join(home, "x")); err != nil {
					t.Fatal(err)
				}
				removeAtCleanup(t, filepath.Join(home, "x"))
			}
			tc.spec.Command = []string{"/bin/true"}
			c, err := Command(t.Context(), tc.spec)
			if err != nil {
				t.Fatalf("Command: %v", err)
			}
			err = c.Start()
			if err == nil {
				_ = c.run.lifeline.Close()
				_ = c.Wait()
				t.Fatal("Start succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Start = %v, want it to mention %q", err, tc.want)
			}
			if c.Pid() != 0 {
				t.Errorf("Pid = %d after a refused Start", c.Pid())
			}
		})
	}
}

// Row: same: the layout changes between Command and Start. A Home, Write
// path or cover that became a link in between is refused.
func TestEscapeSwappedBetweenCommandAndStart(t *testing.T) {
	t.Parallel()
	secret := t.TempDir()
	if err := os.WriteFile(filepath.Join(secret, "f"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	swap := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Rename(dir, dir+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(secret, dir); err != nil {
			t.Fatal(err)
		}
	}
	for _, which := range []string{"home", "write", "read"} {
		t.Run(which, func(t *testing.T) {
			t.Parallel()
			home, write, read := t.TempDir(), t.TempDir(), t.TempDir()
			c, _, _ := escCmd(t.Context(), t, Spec{Home: home, Write: []string{write}, Read: []string{read}}, "esc", "env")
			swap(t, map[string]string{"home": home, "write": write, "read": read}[which])
			err := c.Start()
			if which == "read" {
				// A Read path that is a link outside every writable path is
				// followed, which the rules allow, so only the sandbox that
				// started must not show the secret's parent.
				if err != nil {
					return
				}
				_ = c.run.lifeline.Close()
				_ = c.Wait()
				return
			}
			if err == nil {
				_ = c.run.lifeline.Close()
				_ = c.Wait()
				t.Fatalf("Start followed a %s that became a link", which)
			}
		})
	}
}

// Row: "Path and link rules ...": a link one sandbox plants in the directory
// another sandbox is given as Write is refused when the second starts,
// and the link, read through the first sandbox's own view, reaches nothing.
func TestEscapePlantedLink(t *testing.T) {
	t.Parallel()
	parent := t.TempDir() // the first sandbox's Home
	victim := filepath.Join(parent, "work")
	if err := os.Mkdir(victim, 0o750); err != nil {
		t.Fatal(err)
	}
	secret := t.TempDir() // the caller's data
	if err := os.WriteFile(filepath.Join(secret, "db"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(secret, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	escRun(t, Spec{Home: parent}, "plant-link", victim, secret)
	if fi, err := os.Lstat(victim); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was not planted: %v", err)
	}
	// The second sandbox, which is given the planted path.
	for _, tc := range []struct {
		name string
		spec Spec
	}{
		{"as Home", Spec{Home: victim}},
		{"as Write", Spec{Home: t.TempDir(), Write: []string{victim}}},
		{"under Write", Spec{Home: t.TempDir(), Write: []string{filepath.Join(victim, "sub")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.spec.Command = []string{"/bin/true"}
			c, err := Command(t.Context(), tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Start(); err == nil {
				_ = c.run.lifeline.Close()
				_ = c.Wait()
				t.Fatal("Start accepted the planted link")
			}
		})
	}
	// The sandbox that planted it sees the data through it as nothing.
	escRun(t, Spec{Home: parent}, "view", jsonArg(t, viewSpec{Hidden: []string{victim, secret}}))
}

// Row: "Network" and the Limits in docs/security-model.md for NetworkHost: under NetworkNone the host's loopback,
// abstract sockets and socket files are out of reach, and the network is
// only a loopback. Under NetworkHost, which must be asked for, they are
// shared, as documented.
func TestEscapeNetwork(t *testing.T) {
	t.Parallel()
	var lc net.ListenConfig
	tcp, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	abstract := fmt.Sprintf("@sandbox-esc-%d", os.Getpid())
	ab, err := lc.Listen(t.Context(), "unix", abstract)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ab.Close() })
	sock := filepath.Join(t.TempDir(), "host.sock")
	us, err := lc.Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = us.Close() })
	for _, level := range []Kernel{KernelStrict, KernelOpen} {
		for _, host := range []bool{false, true} {
			n := NetworkNone
			if host {
				n = NetworkHost
			}
			t.Run(string(level)+"/"+n.String(), func(t *testing.T) {
				t.Parallel()
				if !kernelFilterBuilds && level != KernelOpen {
					t.Skip("no system call list on " + runtime.GOARCH)
				}
				escRun(t, Spec{Home: t.TempDir(), Kernel: level, Network: n}, "net",
					jsonArg(t, netTargets{Loop: tcp.Addr().String(), Abstract: abstract, Unix: sock, Host: host}))
			})
		}
	}
}

// Row: "Network namespace ...": two sandboxes with a Loopback port each bind
// the same port, since each loopback is private.
func TestEscapeLoopbackIsPrivate(t *testing.T) {
	t.Parallel()
	cmds := make([]*Cmd, 0, 2)
	outs := make([]*syncBuffer, 0, 2)
	for range 2 {
		c, stdout, _ := escCmd(t.Context(), t, Spec{Loopback: 1}, "esc", "bind-hold", "127.0.0.1:4444")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, c)
		outs = append(outs, stdout)
	}
	for i, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Errorf("sandbox %d: %v", i, err)
		}
		if !strings.Contains(outs[i].String(), "listening") {
			t.Errorf("sandbox %d output %q", i, outs[i])
		}
	}
}

// Row: "Options on a descriptor, not in pid 1's argv": nothing the spec names
// appears in the command line of pid 1 or of bubblewrap, which any process
// can read. Both are fixed: the command goes in the settings, and the stages
// are found by roleVar.
func TestEscapeOptionsNotInArgv(t *testing.T) {
	t.Parallel()
	home, write, read, cover := t.TempDir(), t.TempDir(), t.TempDir(), "/srv/app-cover-marker"
	c, _, _ := escCmd(t.Context(), t, Spec{Home: home, Write: []string{write}, Read: []string{read}, Cover: []string{cover}}, "esc", "hold")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.run.lifeline.Close(); _ = c.Wait() }()
	read1 := func(pid int, file string) string {
		b, _ := readFile("/proc/" + strconv.Itoa(pid) + "/" + file)
		return string(b)
	}
	for _, p := range []struct {
		name string
		pid  int
		want []string
	}{
		{"bubblewrap", c.run.cmd.Process.Pid, []string{"bwrap", "--args", strconv.Itoa(fdArgs), "--", stagePath}},
		{"pid 1", c.Pid(), []string{stagePath}},
	} {
		argv := read1(p.pid, "cmdline")
		if argv == "" {
			t.Fatalf("%s: no command line", p.name)
		}
		if want := strings.Join(p.want, "\x00") + "\x00"; argv != want {
			t.Errorf("%s's command line is %q, want %q", p.name, argv, want)
		}
		for _, secret := range []string{home, write, read, cover} {
			if strings.Contains(argv, secret) {
				t.Errorf("%s's command line shows %s: %q", p.name, secret, argv)
			}
		}
		for _, flag := range []string{"--bind", "--ro-bind", "--tmpfs", "--cap-add"} {
			if strings.Contains(argv, flag) {
				t.Errorf("%s's command line holds %s: %q", p.name, flag, argv)
			}
		}
	}
	// And the environment of bubblewrap, which holds only the command's.
	if env := read1(c.run.cmd.Process.Pid, "environ"); strings.Contains(env, "SANDBOX_TEST_SPEC") {
		t.Errorf("bubblewrap's environment has the spec: %q", env)
	}
}

// Row: "Root launcher ... refuses euid 0": Command and Run refuse to run as
// uid 0, here a user namespace's root.
func TestEscapeRefusesEuid0(t *testing.T) {
	t.Parallel()
	// existing: TestCommandRefusesRoot. Run is the second entry point.
	runAsNamespaceRoot(t, "esc-root")
}

func registerEscRoot() {
	childModes["esc-root"] = func([]string) int {
		spec := Spec{Command: []string{"/bin/true"}, Home: os.TempDir()}
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "not root")
			return 1
		}
		code := 0
		if _, err := Command(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "root") {
			fmt.Fprintf(os.Stderr, "Command: %v\n", err)
			code = 1
		}
		if _, err := Run(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "root") {
			fmt.Fprintf(os.Stderr, "Run: %v\n", err)
			code = 1
		}
		return code
	}
}

// Row: "First stage: private mounts, caps dropped, no_new_privs, pid 1 re-exec,
// undumpable": a command under nested, which has CAP_SYS_ADMIN in a user
// namespace of its own, cannot undo the view: unmount a cover, remount a
// read-only bind writable, or bind the root without its covers.
func TestEscapeNestedCannotUndoView(t *testing.T) {
	t.Parallel()
	if !kernelFilterBuilds {
		t.Skip("no system call list on " + runtime.GOARCH)
	}
	exe, dir := escBinary(t)
	_ = exe
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/home"
	}
	escRun(t, Spec{Home: t.TempDir(), Kernel: KernelNested}, "nested", jsonArg(t, nestedTargets2{ReadOnly: dir, HostHome: home}))
}

// Row: "Reaper starts the command with only fds 0-2" (and the control
// socket, lifeline and info fd): the command holds none, and cannot open them
// through pid 1.
func TestEscapeSetupDescriptors(t *testing.T) {
	t.Parallel()
	for _, level := range []Kernel{KernelStrict, KernelOpen} {
		t.Run(string(level), func(t *testing.T) {
			t.Parallel()
			escRun(t, Spec{Home: t.TempDir(), Kernel: level}, "fds")
		})
	}
	// With Files, the command holds those and nothing more.
	f1, f2 := t.TempDir()+"/a", t.TempDir()+"/b"
	for i, p := range []string{f1, f2} {
		if err := os.WriteFile(p, []byte(fmt.Sprintf("file %d", i)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := openFile(f1)
	b, _ := openFile(f2)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	c, stdout, stderr := escCmd(t.Context(), t, Spec{Files: []*os.File{a, b}}, "esc", "read-fds", "2")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("%v: %s", err, stderr)
	}
	if want := "3:file 0\n4:file 1\n"; stdout.String() != want {
		t.Errorf("descriptors read %q, want %q", stdout, want)
	}
}

// Row: "Scratch tmpfs 1 GiB": /tmp, /var/tmp and /dev/shm are the sandbox's own
// tmpfs, writable, no larger than 1 GiB, and the host's files in them are out
// of reach. What the sandbox writes there does not reach the host.
func TestEscapeScratch(t *testing.T) {
	t.Parallel()
	id := strconv.Itoa(os.Getpid())
	hostFiles := []string{"/var/tmp/sandbox-esc-" + id, "/dev/shm/sandbox-esc-" + id, os.TempDir() + "/sandbox-esc-" + id}
	var present []string
	for _, p := range hostFiles {
		if err := os.WriteFile(p, []byte("secret"), 0o600); err == nil {
			present = append(present, p)
			removeAtCleanup(t, p)
		}
	}
	args := append([]string{id}, present...)
	escRun(t, Spec{Home: t.TempDir()}, "scratch", args...)
	for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if _, err := os.Stat(d + "/sandbox-test-" + id); err == nil {
			t.Errorf("the sandbox's write in %s reached the host", d)
		}
	}
}

// Row: "One-entry passwd/group": the sandbox's /etc/passwd lists only its own
// account, with its own home, and cannot be written.
func TestEscapePasswd(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	name := "sandbox"
	if u, err := user.LookupId(strconv.Itoa(os.Getuid())); err == nil {
		name = u.Username
	}
	escRun(t, Spec{Home: home}, "passwd", name, home)
}

// Row: "Rlimits": the limits are enforced, not only set.
func TestEscapeRlimitsEnforced(t *testing.T) {
	t.Parallel()
	t.Run("file size", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		const limit = 1 << 20
		escRun(t, Spec{Home: home, Rlimits: []Rlimit{{ResourceFileSize, limit, limit}}}, "rlimit-fsize", home, strconv.Itoa(limit))
		if fi, err := os.Stat(filepath.Join(home, "big")); err != nil || fi.Size() > limit {
			t.Errorf("file on the host: %v, %v", fi, err)
		}
	})
	t.Run("open files", func(t *testing.T) {
		t.Parallel()
		escRun(t, Spec{Rlimits: []Rlimit{{ResourceOpenFiles, 40, 40}}}, "rlimit-nofile", "40")
	})
	t.Run("address space", func(t *testing.T) {
		t.Parallel()
		const limit = 8 << 30
		escRun(t, Spec{Rlimits: []Rlimit{{ResourceAddressSpace, limit, limit}}}, "rlimit-as", strconv.FormatUint(limit, 10))
	})
	t.Run("processes", func(t *testing.T) {
		t.Parallel()
		// RLIMIT_NPROC counts every process of the uid. In a user
		// namespace of its own, which the sandbox is, that is the
		// sandbox's own.
		c, _, stderr := escCmd(t.Context(), t, Spec{Rlimits: []Rlimit{{ResourceProcesses, 50, 50}}}, "esc", "rlimit-nproc", "200")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, stderr)
		}
	})
	t.Run("cpu time", func(t *testing.T) {
		t.Parallel()
		start := time.Now()
		c, _, _ := escCmd(t.Context(), t, Spec{Rlimits: []Rlimit{{ResourceCPU, 1, 3}}}, "esc", "rlimit-cpu")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		err := c.Wait()
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("Wait = %v, want the command killed", err)
		}
		if d := time.Since(start); d > 15*time.Second {
			t.Errorf("took %v to stop a 1 second CPU limit", d)
		}
		// The soft limit sends SIGXCPU, which a Go program ignores, and the
		// hard limit SIGKILL.
		if code := ee.ExitCode(); code != 128+int(unix.SIGXCPU) && code != 128+int(unix.SIGKILL) {
			t.Errorf("exit code %d, want SIGXCPU's or SIGKILL's", code)
		}
	})
}

// Row: "First stage ... no_new_privs" and "Filter": the kernel levels are
// never lowered: the level a Cmd was given is the one that runs. Strict
// refuses what nested allows, and a Spec with no level is strict.
func TestEscapeKernelNeverLowered(t *testing.T) {
	t.Parallel()
	if !kernelFilterBuilds {
		t.Skip("no system call list on " + runtime.GOARCH)
	}
	for _, level := range []Kernel{"", KernelStrict} {
		escRun(t, Spec{Home: t.TempDir(), Kernel: level}, "clone-ns", "refused")
	}
	escRun(t, Spec{Home: t.TempDir(), Kernel: KernelNested}, "clone-ns", "allowed")
}

// mySid returns this process's session id.
func mySid() int {
	sid, err := unix.Getsid(0)
	if err != nil {
		return -1
	}
	return sid
}

// escTry runs the check in a sandbox from spec and returns whether it
// passed.
func escTry(t *testing.T, spec Spec, check string, args ...string) bool {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c, stdout, stderr := escCmd(ctx, t, spec, "esc", append([]string{check}, args...)...)
	if err := c.Start(); err != nil {
		t.Fatalf("%s: start: %v", check, err)
	}
	return escWait(t, c, cancel, stdout, stderr, escName(spec, check, args)) == nil
}

// The checks above are only worth their passes if they fail when an escape
// works. Each of these runs one against a sandbox that has the hole: a secret
// in the sandbox's own home, a level that allows what another refuses, and
// the host's network.
func TestEscapeChecksCatchEscapes(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "token"), []byte("a secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if escTry(t, Spec{Home: home}, "view", jsonArg(t, viewSpec{Hidden: []string{filepath.Join(home, "token")}})) {
		t.Error("view: a readable secret was reported hidden")
	}
	if escTry(t, Spec{Home: home}, "view", jsonArg(t, viewSpec{Hidden: []string{home}})) {
		t.Error("view: a readable directory of secrets was reported hidden")
	}
	if escTry(t, Spec{Home: home}, "view", jsonArg(t, viewSpec{ReadOnly: []string{home}})) {
		t.Error("view: a writable directory was reported read-only")
	}
	if escTry(t, Spec{Home: home}, "view", jsonArg(t, viewSpec{Writable: []string{"/etc"}})) {
		t.Error("view: /etc was reported writable")
	}
	if kernelFilterBuilds {
		if escTry(t, Spec{Home: home, Kernel: KernelOpen}, "seccomp", string(KernelStrict)) {
			t.Error("seccomp: the open level passed the strict refusals")
		}
		if escTry(t, Spec{Home: home, Kernel: KernelNested}, "clone-ns", "refused") {
			t.Error("clone-ns: nested passed the strict refusals")
		}
	}
	tcp, err := listenLocal()
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	targets := netTargets{Loop: tcp.Addr().String(), Abstract: "@none", Unix: "/nonexistent"}
	if escTry(t, Spec{Home: home, Network: NetworkHost}, "net", jsonArg(t, targets)) {
		t.Error("net: the host's loopback was reported unreachable under NetworkHost")
	}
	if escTry(t, Spec{Home: home, Network: NetworkHost}, "ns", jsonArg(t, hostNamespaces()), strconv.Itoa(os.Getuid()), "none") {
		t.Error("ns: the host's network namespace was reported private under NetworkHost")
	}
}
