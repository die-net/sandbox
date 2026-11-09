package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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

	"golang.org/x/sys/unix"
)

// stageArg is the first argument of the run of this binary that bubblewrap
// starts inside the sandbox ahead of the command, and reaperArg that of the
// run the first stage execs. stagePath is where the binary is bound in. /dev
// is a tmpfs bubblewrap makes, so the bind lands in no directory a sandbox
// writes.
const (
	stageArg  = "--legwork-sandbox-stage"
	reaperArg = "--legwork-sandbox-reaper"
	stagePath = "/dev/legwork-sandbox"
)

// failed is the exit status of a sandbox whose stages could not set up, as
// distinct from the command's own.
const failed = 125

// Stage runs one of the sandbox's stages if this process was started as it,
// and reports false otherwise. A program that uses this package calls it
// first in main, before it reads its arguments.
func Stage() (int, bool) {
	if len(os.Args) < 5 || (os.Args[1] != stageArg && os.Args[1] != reaperArg) || os.Args[3] != "--" {
		return 0, false
	}
	var level Kernel
	err := level.Set(os.Args[2])
	code := failed
	if err == nil && os.Args[1] == stageArg {
		err = firstStage()
	} else if err == nil {
		code, err = reaperStage(level, os.Args[4:])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: %v\n", err)
		return failed, true
	}
	return code, true
}

// firstStage runs inside the sandbox as pid 1, which bubblewrap starts with
// --as-pid-1, holding CAP_SYS_ADMIN and CAP_SETPCAP in the sandbox's user
// namespace, before anything untrusted runs. bubblewrap leaves the view a
// slave of the host's mounts, so a mount made on the host later, such as a
// bind of a covered path, would appear inside. Run unprivileged, bubblewrap
// puts pid 1 in a user namespace nested in the one that owns the view's
// mounts, so the capabilities cannot change those. This copies the view
// into a mount namespace of its own and makes every mount in it private.
// unshare moves only the calling thread, so it then execs this binary again
// as the reaper, which leaves the whole of pid 1 in the new namespace and
// none in bubblewrap's.
//
// It also gives up every capability and sets no_new_privs before that exec.
// Both belong to a thread, not a process, and bubblewrap raised the
// capabilities as ambient ones before it started this binary, so every
// thread the Go runtime made holds them. Dropping them on any thread but the
// one that execs would leave the others holding them, and the command could
// be forked from one of those. execve carries only this locked thread's
// empty sets into the new image, which starts with that one thread, so every
// thread of the reaper, and the command, starts with none.
func firstStage() error {
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("copy the view into a mount namespace of its own: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	if err := dropCapabilities(); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	args := slices.Concat([]string{os.Args[0], reaperArg}, os.Args[2:])
	return syscall.Exec("/proc/self/exe", args, os.Environ()) //nolint:gosec // This is the sandbox's own binary, not a shell.
}

// reaperStage runs as pid 1 in the sandbox's own mount namespace, with no
// capabilities and no_new_privs set, which the first stage left it. It makes
// itself undumpable, so the command cannot read its memory or descriptors
// through /proc, installs the filter on all its threads, and starts the
// command. Then it relays signals to the command,
// reaps every orphan in the namespace, and exits with the command's status,
// which also kills whatever is left. The filter goes on here rather than
// through bubblewrap, since it refuses the calls the first stage makes.
func reaperStage(level Kernel, command []string) (int, error) {
	// Undumpable belongs to the process, and execve resets it, so it is
	// set here rather than in the first stage.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return 0, fmt.Errorf("make pid 1 undumpable: %w", err)
	}
	// bubblewrap gave the stages the command's environment, so its PATH is
	// the one to look the command up on.
	path, err := exec.LookPath(command[0])
	if err != nil {
		return 0, err
	}
	if err := installSeccomp(level); err != nil {
		return 0, err
	}
	child, err := os.StartProcess(path, command, &os.ProcAttr{ //nolint:gosec // Running the configured command is the sandbox's job, and it is not a shell.
		Env:   os.Environ(),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		return 0, fmt.Errorf("start command: %w", err)
	}
	stop := relaySignals(child)
	defer stop()
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("wait: %w", err)
		}
		if pid != child.Pid {
			continue
		}
		if ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return ws.ExitStatus(), nil
	}
}

// dropCapabilities empties the calling thread's bounding set and clears all
// its other sets. The calls act on that thread alone, so the caller must be
// locked to it and exec from it. What it then runs holds none, even as uid 0
// inside, and the empty bounding set is inherited by everything that starts.
func dropCapabilities() error {
	for c := 0; ; c++ {
		err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
		if errors.Is(err, unix.EINVAL) {
			break
		}
		if err != nil {
			return fmt.Errorf("drop capability %d from the bounding set: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("clear capabilities: %w", err)
	}
	return nil
}

// Run runs spec's command in a sandbox that bubblewrap builds, and returns
// its exit status. A status from a signal is 128 plus the signal's number,
// as a shell reports it.
func Run(ctx context.Context, spec Spec) (int, error) {
	bwrap, err := findBwrap()
	if err != nil {
		return 0, err
	}
	homes, err := hostHomes()
	if err != nil {
		return 0, err
	}
	// The account Legwork runs as may come from a directory service that
	// /etc/passwd does not list.
	if home, err := os.UserHomeDir(); err == nil {
		homes = append(homes, home)
	}
	if spec.Dir == "" {
		if spec.Dir, err = os.Getwd(); err != nil {
			return 0, fmt.Errorf("find working directory: %w", err)
		}
	}
	mounts, err := hostMounts()
	if err != nil {
		return 0, err
	}
	spec, err = prepare(spec, homes, os.DirFS("/"), mounts)
	if err != nil {
		return 0, err
	}
	// pid 1 builds the filter again to install it, but a filter that
	// cannot be built is refused here, before bubblewrap builds the view.
	if _, err := filterProgram(spec.Kernel); err != nil {
		return 0, err
	}
	l, err := newLaunch(spec, lookupAccount())
	if err != nil {
		return 0, err
	}
	defer l.close()

	// The options go on a descriptor so that pid 1's command line, which
	// any process inside can read, does not list them. bubblewrap takes the
	// command only from its own arguments, and the command is the first
	// stage, with the real one after it.
	args := append([]string{"--args", "3", "--", stagePath, stageArg, string(spec.Kernel), "--"}, spec.Command...)
	cmd := exec.CommandContext(ctx, bwrap, args...) //nolint:gosec // Running the configured command in the sandbox is its job, and bubblewrap is not a shell.
	cmd.Args[0] = "bwrap"
	cmd.Env = commandEnv(os.Environ(), spec)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = l.inherit
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start bubblewrap: %w", err)
	}
	sent := l.send()
	// bubblewrap's outer process does not pass signals on, so a SIGTERM
	// or SIGHUP relayed to it ends it, and --die-with-parent then kills
	// everything inside with SIGKILL. Relaying rather than dying lets Run
	// still wait for it and return its status.
	stop := relaySignals(cmd.Process)
	defer stop()
	code, err := exitStatus(cmd.Wait())
	// A write fails only when bubblewrap exited before it read everything,
	// which its status already says.
	if serr := <-sent; serr != nil && err == nil && code == 0 {
		err = serr
	}
	return code, err
}

// findBwrap finds bubblewrap on the PATH. It refuses a setuid copy, since
// bubblewrap's serious past flaws were in its setuid mode, and the sandbox
// needs nothing that mode adds.
func findBwrap() (string, error) {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return "", fmt.Errorf("find bubblewrap, which the sandbox needs on Linux: %w", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("find bubblewrap: %w", err)
	}
	if fi.Mode()&fs.ModeSetuid != 0 {
		return "", fmt.Errorf("%s is setuid, which the sandbox refuses", path)
	}
	return path, nil
}

// hostHomes returns the homes to cover for the accounts in /etc/passwd. It
// reads the file itself, since without cgo Go cannot list a directory
// service's accounts either.
func hostHomes() ([]string, error) {
	passwd, err := os.ReadFile("/etc/passwd")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read /etc/passwd: %w", err)
	}
	return accountHomes(passwd, ownerOf), nil
}

// hostMounts reads the host's mount table, as this process sees it.
func hostMounts() ([]mount, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("read mount table: %w", err)
	}
	defer f.Close()
	return parseMountinfo(f)
}

// ownerOf returns the uid that owns path, following symlinks.
func ownerOf(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat %s: no owner", path)
	}
	return uint64(st.Uid), nil
}

// launch is what Run hands bubblewrap: its options, which it reads from the
// first inherited descriptor, and the descriptors they name.
type launch struct {
	// inherit are bubblewrap's descriptors from 3 on.
	inherit []*os.File
	// writes are the pipes whose other ends are in inherit, with what to
	// send on each once bubblewrap is running.
	writes []pendingWrite
}

// pendingWrite is a pipe to fill and close once bubblewrap has started.
type pendingWrite struct {
	w    *os.File
	body []byte
}

// Mount kinds, which order mounts at the same path.
const (
	coverMount = iota
	scratchMount
	bindMount
)

// mountOp is one of bubblewrap's mount options, at path.
type mountOp struct {
	path string
	kind int
	args []string
}

// scratchDirs are the covered paths that get a writable tmpfs of the
// sandbox's own rather than an empty, read-only one: temporary files and
// shared memory.
var scratchDirs = []string{"/tmp", "/var/tmp", "/dev/shm"}

// scratchSize is the most each of scratchDirs holds. A tmpfs is otherwise as
// large as the host's memory, so one sandbox could fill it, and only a
// delegated cgroup's memory limit would stop it.
const scratchSize = 1 << 30

// newLaunch builds bubblewrap's options for spec. Each bind source is opened
// here without following links and passed as a descriptor, so nothing
// changed between prepare and bubblewrap's setup can redirect it. Mounts go
// parent first, since bubblewrap makes them in the order given.
func newLaunch(spec Spec, acct account) (*launch, error) {
	l := &launch{}
	ok := false
	defer func() {
		if !ok {
			l.close()
		}
	}()
	argsPipe, err := l.pipe()
	if err != nil {
		return nil, err
	}
	args := []string{
		"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
		"--die-with-parent", "--hostname", "legwork",
		// The first stage is pid 1 and the reaper, so bubblewrap's own
		// does not stay in the mount namespace the stage leaves.
		"--as-pid-1",
		// For the first stage alone, which drops them before the command.
		"--cap-add", "CAP_SYS_ADMIN", "--cap-add", "CAP_SETPCAP",
		// No --new-session: the hub checks that a bridge is in the session
		// of the CLI the runner started, and the filter refuses TIOCSTI,
		// which a new session would otherwise guard against.
		"--ro-bind", "/", "/",
	}
	var ops []mountOp
	var readOnly []string
	for _, c := range spec.Cover {
		if slices.Contains(scratchDirs, c) {
			continue
		}
		fi, err := os.Lstat(c)
		if err != nil {
			return nil, fmt.Errorf("cover %s: %w", c, err)
		}
		// A directory gets an empty tmpfs. Anything else, a socket or a
		// pipe as much as a file, gets /dev/null, which nothing can connect
		// to or read anything from. A link here was made since prepare
		// resolved the path, and bubblewrap would follow it.
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			return nil, fmt.Errorf("cover %s: it has become a link since it was resolved", c)
		case fi.IsDir():
			ops = append(ops, mountOp{c, coverMount, []string{"--perms", "0755", "--tmpfs", c}})
			readOnly = append(readOnly, c)
		default:
			ops = append(ops, mountOp{c, coverMount, []string{"--ro-bind", "/dev/null", c}})
		}
	}
	for _, d := range scratchDirs {
		if fi, err := os.Stat(filepath.Dir(d)); err == nil && fi.IsDir() {
			ops = append(ops, mountOp{d, scratchMount, []string{"--perms", "01777", "--size", strconv.Itoa(scratchSize), "--tmpfs", d}})
		}
	}
	self, err := unix.Open("/proc/self/exe", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open this binary for the first stage: %w", err)
	}
	ops = append(ops,
		mountOp{"/proc", bindMount, []string{"--proc", "/proc"}},
		mountOp{"/dev", bindMount, []string{"--dev", "/dev"}},
		mountOp{stagePath, bindMount, []string{"--ro-bind-fd", l.fd(os.NewFile(uintptr(self), "legwork")), stagePath}},
	)
	for _, b := range []struct {
		paths []string
		flag  string
	}{
		{append([]string{spec.Home}, spec.Write...), "--bind-fd"},
		{spec.Read, "--ro-bind-fd"},
	} {
		for _, p := range b.paths {
			f, err := openNoLinks(p)
			if err != nil {
				return nil, err
			}
			ops = append(ops, mountOp{p, bindMount, []string{b.flag, l.fd(f), p}})
		}
	}
	slices.SortStableFunc(ops, func(a, b mountOp) int {
		if d := strings.Count(a.path, "/") - strings.Count(b.path, "/"); d != 0 {
			return d
		}
		return a.kind - b.kind
	})
	for _, op := range ops {
		args = append(args, op.args...)
	}

	// Only the sandbox's uid and gid are mapped, so the host's entries for
	// anyone else would show ids that do not exist inside, and programs
	// that look themselves up fail without an entry.
	uid, gid := os.Getuid(), os.Getgid()
	for _, f := range []struct{ path, body string }{
		{"/etc/passwd", fmt.Sprintf("%s:x:%d:%d::%s:/bin/sh\n", acct.user, uid, gid, spec.Home)},
		{"/etc/group", fmt.Sprintf("%s:x:%d:\n", acct.group, gid)},
	} {
		fd, err := l.data([]byte(f.body))
		if err != nil {
			return nil, err
		}
		args = append(args, "--perms", "0444", "--ro-bind-data", fd, f.path)
	}
	for _, c := range readOnly {
		args = append(args, "--remount-ro", c)
	}
	args = append(args, "--chdir", spec.Dir)

	var body []byte
	for _, a := range args {
		body = append(append(body, a...), 0)
	}
	l.writes[argsPipe].body = body
	ok = true
	return l, nil
}

// openNoLinks opens path, which prepare resolved, for bubblewrap to bind
// from, refusing a link anywhere in it. A link found here was put there
// since prepare looked, and following it could bind Legwork's data in the
// place of what was meant.
func openNoLinks(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("open %s without following links: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

// fd adds f to bubblewrap's descriptors and returns the number it will have
// there.
func (l *launch) fd(f *os.File) string {
	l.inherit = append(l.inherit, f)
	return strconv.Itoa(2 + len(l.inherit))
}

// pipe adds a pipe for bubblewrap to read, and returns its index in writes.
func (l *launch) pipe() (int, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return 0, fmt.Errorf("make pipe for bubblewrap: %w", err)
	}
	l.fd(r)
	l.writes = append(l.writes, pendingWrite{w: w})
	return len(l.writes) - 1, nil
}

// data adds a pipe that will carry body, and returns its descriptor's
// number in bubblewrap.
func (l *launch) data(body []byte) (string, error) {
	i, err := l.pipe()
	if err != nil {
		return "", err
	}
	l.writes[i].body = body
	return strconv.Itoa(2 + len(l.inherit)), nil
}

// send closes this process's copies of bubblewrap's descriptors, which
// bubblewrap now holds, and fills each pipe in the background, since
// bubblewrap reads them in turn. It sends the result on the channel when
// all are done.
func (l *launch) send() <-chan error {
	var errs []error
	for _, f := range l.inherit {
		errs = append(errs, f.Close())
	}
	l.inherit = nil
	writes := l.writes
	l.writes = nil
	done := make(chan error, 1)
	go func() {
		for _, pw := range writes {
			_, err := pw.w.Write(pw.body)
			errs = append(errs, err, pw.w.Close())
		}
		done <- errors.Join(errs...)
	}()
	return done
}

// close closes every descriptor the launch still holds.
func (l *launch) close() {
	for _, f := range l.inherit {
		_ = f.Close()
	}
	for _, pw := range l.writes {
		_ = pw.w.Close()
	}
	l.inherit, l.writes = nil, nil
}

// account is the user and group name the sandbox's passwd and group give
// its uid and gid.
type account struct {
	user, group string
}

// lookupAccount finds this process's user and group names in the host's
// files.
func lookupAccount() account {
	acct := account{user: "legwork", group: "legwork"}
	if u, err := user.LookupId(strconv.Itoa(os.Getuid())); err == nil {
		acct.user = u.Username
	}
	if g, err := user.LookupGroupId(strconv.Itoa(os.Getgid())); err == nil {
		acct.group = g.Name
	}
	return acct
}

// commandEnv returns env with the sandbox's home and its own temporary
// directory in the variables programs read them from.
func commandEnv(env []string, spec Spec) []string {
	set := map[string]string{
		"HOME":            spec.Home,
		"TMPDIR":          "/tmp",
		"XDG_CONFIG_HOME": filepath.Join(spec.Home, ".config"),
		"XDG_CACHE_HOME":  filepath.Join(spec.Home, ".cache"),
		"XDG_DATA_HOME":   filepath.Join(spec.Home, ".local", "share"),
		"XDG_STATE_HOME":  filepath.Join(spec.Home, ".local", "state"),
	}
	out := slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		_, ok := set[name]
		return ok
	})
	for name, value := range set {
		out = append(out, name+"="+value)
	}
	return out
}

// relaySignals passes the signals a supervisor sends on to p, and returns a
// function that stops. An interrupt from a terminal already reaches the
// whole process group, so it is not relayed.
func relaySignals(p *os.Process) func() {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				_ = p.Signal(s)
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(sigs)
		close(done)
	}
}

// exitStatus turns the error from waiting on bubblewrap into its exit
// status, which is the command's.
func exitStatus(err error) (int, error) {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return 0, err
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return ee.ExitCode(), nil
}
