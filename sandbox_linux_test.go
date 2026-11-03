package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/die-net/legwork/internal/peer"
)

// testSpecVar carries a Spec, as JSON, to a run of the test binary that
// starts a sandbox from it, so that withFakeHost can change the host for
// that run alone first.
const testSpecVar = "LEGWORK_SANDBOX_TEST_SPEC"

// fakeHostVar tells that run to make the host withFakeHost describes before
// it starts the sandbox.
const fakeHostVar = "LEGWORK_SANDBOX_TEST_FAKE_HOST"

// fakeHomes are the secrets withFakeHost puts in each home. carol has no
// passwd entry, as an account from a directory service would not.
var fakeHomes = []string{"/srv/users/alice/secret", "/srv/users/bob/secret", "/srv/users/carol/secret"}

const (
	// sharedLink leads from /etc to a file under a default cover, as
	// Ubuntu's /etc/resolv.conf leads into /run.
	sharedLink = "/etc/skel/shared"
	// privateLink leads from /etc to alice's secret.
	privateLink = "/etc/skel/private"
	// legworkDir stands for a directory the config names, such as
	// Legwork's state, outside every default cover.
	legworkDir = "/srv/legwork"
	// legworkDB stands for the database in it.
	legworkDB = legworkDir + "/legwork.db"
	// outsidePath is where a sandbox tries to write outside its own
	// directories, in a directory whose mode lets its account write.
	outsidePath = "/srv/planted"
	// lateMount is where TestLateMounts binds legworkDir once a sandbox is
	// running, and lateDone is the file it writes when it has.
	lateMount = "/srv/late"
	lateDone  = "/srv/late-done"
)

// iptSoSetReplace is IPT_SO_SET_REPLACE from linux/netfilter_ipv4/ip_tables.h,
// which x/sys/unix does not carry: the setsockopt that replaces an iptables
// table, which needs CAP_NET_ADMIN.
const iptSoSetReplace = 64

// TestMain lets the test binary be each part of a sandbox: the process that
// starts it, its first stage, and the command inside it.
func TestMain(m *testing.M) {
	if code, ok := Stage(); ok {
		os.Exit(code)
	}
	if body, ok := os.LookupEnv(testSpecVar); ok {
		os.Exit(runFromEnv(body))
	}
	if len(os.Args) == 2 && os.Args[1] == "rename" {
		os.Exit(renameBetweenDirs())
	}
	if len(os.Args) == 2 && os.Args[1] == "homes" {
		os.Exit(homesUnreadable())
	}
	if len(os.Args) == 2 && os.Args[1] == "links" {
		os.Exit(followLinks())
	}
	if len(os.Args) == 3 && os.Args[1] == "kernel" {
		os.Exit(kernelChecks(Kernel(os.Args[2])))
	}
	if len(os.Args) == 3 && os.Args[1] == "dial" {
		os.Exit(dial(os.Args[2]))
	}
	if len(os.Args) == 2 && os.Args[1] == "late" {
		os.Exit(lateMountHidden())
	}
	if len(os.Args) == 3 && os.Args[1] == "isolation" {
		os.Exit(isolationChecks(os.Args[2]))
	}
	if len(os.Args) == 3 && os.Args[1] == "nested" {
		os.Exit(startNested(os.Args[2]))
	}
	if len(os.Args) == 2 && os.Args[1] == "nested-mounts" {
		os.Exit(nestedMounts())
	}
	os.Exit(m.Run())
}

// runFromEnv starts a sandbox from a Spec in JSON and returns its status.
func runFromEnv(body string) int {
	// The command inherits this environment, and must not start a
	// sandbox of its own.
	if err := os.Unsetenv(testSpecVar); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return failed
	}
	var spec Spec
	if err := json.Unmarshal([]byte(body), &spec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return failed
	}
	if _, ok := os.LookupEnv(fakeHostVar); ok {
		if err := withFakeHost(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return failed
		}
		go bindWhenStarted(spec.Home)
		// bubblewrap refuses to run with capabilities unless it is setuid,
		// as it would get them here through the ambient set. Capabilities
		// belong to a thread, so clearing them on the one that starts it
		// leaves the others able to make bindWhenStarted's mount.
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return failed
		}
	}
	code, err := Run(context.Background(), spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return failed
	}
	return code
}

// withFakeHost runs in a user and mount namespace of its own, as the
// account's own uid with CAP_SYS_ADMIN there, since only that can add
// accounts and links to the host. Keeping the account's uid means bubblewrap
// runs unprivileged, as it does in a deployment, rather than taking its
// path for root. It mounts a tmpfs on /srv with three homes under
// /srv/users, each holding a secret, and binds a passwd over the host's that
// lists alice and bob, so that two homes with one prefix make /srv/users a
// directory of homes. Only one uid is mapped, so every account is the
// account's own uid, which owns the homes. /srv also holds legworkDB,
// and its own mode lets that account write outsidePath. It also mounts a
// tmpfs on /mnt, which every sandbox covers, with a shared file, and one on
// /etc/skel with sharedLink to that file and privateLink to alice's secret.
func withFakeHost() error {
	if err := os.Unsetenv(fakeHostVar); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	if err := unix.Mount("homes", "/srv", "tmpfs", 0, "mode=0755"); err != nil {
		return fmt.Errorf("mount /srv: %w", err)
	}
	// Shared, so a mount made under it later reaches a sandbox's copy of
	// it unless the sandbox stops it.
	if err := unix.Mount("", "/srv", "", unix.MS_SHARED, ""); err != nil {
		return fmt.Errorf("share /srv: %w", err)
	}
	if err := os.Mkdir(lateMount, 0o750); err != nil {
		return err
	}
	for _, p := range append(slices.Clone(fakeHomes), legworkDB) {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte("secret"), 0o600); err != nil {
			return err
		}
	}
	uid := os.Getuid()
	entries := fmt.Sprintf("root:x:0:0::/root:/bin/sh\nalice:x:%d:%d::/srv/users/alice:/bin/sh\nbob:x:%d:%d::/srv/users/bob:/bin/sh\n", uid, uid, uid, uid)
	if err := os.WriteFile("/srv/passwd", []byte(entries), 0o600); err != nil {
		return err
	}
	if err := unix.Mount("/srv/passwd", "/etc/passwd", "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind passwd: %w", err)
	}
	for _, d := range []string{"/mnt", "/etc/skel"} {
		if err := unix.Mount("host", d, "tmpfs", 0, "mode=0755"); err != nil {
			return fmt.Errorf("mount %s: %w", d, err)
		}
	}
	if err := os.WriteFile("/mnt/shared", []byte("shared"), 0o600); err != nil {
		return err
	}
	if err := os.Symlink("/mnt/shared", sharedLink); err != nil {
		return err
	}
	return os.Symlink(fakeHomes[0], privateLink)
}

// followLinks reports, as its exit status, whether sharedLink cannot be read
// or privateLink can.
func followLinks() int {
	code := 0
	if _, err := os.ReadFile(sharedLink); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	if _, err := os.ReadFile(privateLink); err == nil {
		fmt.Fprintln(os.Stderr, "readable:", privateLink)
		code = 1
	}
	return code
}

// kernelChecks makes system calls that the filter for level decides, and
// reports, as its exit status, whether any had a result other than the one
// level should give. A refusal the filter makes differs from the kernel's
// own where it can, as ENOSYS from an unlisted call does from the EPERM a
// caller without capabilities gets.
func kernelChecks(level Kernel) int {
	strict := level == KernelStrict
	// filtered is want under strict and nested, and otherwise the kernel's
	// own result.
	filtered := func(want, open error) error {
		if level == KernelOpen {
			return open
		}
		return want
	}
	pick := func(strictWant, otherWant error) error {
		if strict {
			return strictWant
		}
		return otherWant
	}
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer ptmx.Close()
	checks := []struct {
		name string
		want error
		call func() error
	}{
		{"io_uring_setup", filtered(unix.ENOSYS, unix.EFAULT), func() error {
			_, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, 0, 0)
			if errno != 0 {
				return errno
			}
			return nil
		}},
		{"unshare", pick(unix.ENOSYS, unix.EPERM), func() error { return unix.Unshare(unix.CLONE_NEWUTS) }},
		{"mount", pick(unix.ENOSYS, unix.EPERM), func() error { return unix.Mount("none", "/tmp", "tmpfs", 0, "") }},
		{"netlink socket", filtered(unix.EAFNOSUPPORT, nil), func() error { return socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE) }},
		{"tcp socket", nil, func() error { return socket(unix.AF_INET, unix.SOCK_STREAM, 0) }},
		{"raw socket", unix.EPERM, func() error { return socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP) }},
		{"TIOCSTI", unix.EPERM, func() error { return unix.IoctlSetInt(int(ptmx.Fd()), unix.TIOCSTI, 0) }},
		{"start a process", nil, func() error { return startTrue(0) }},
		{"start a process in a user namespace", pick(unix.EPERM, nil), func() error { return startTrue(unix.CLONE_NEWUSER) }},
	}
	code := 0
	for _, c := range checks {
		if err := c.call(); !errors.Is(err, c.want) {
			fmt.Fprintf(os.Stderr, "%s: %v, want %v\n", c.name, err, c.want)
			code = 1
		}
	}
	return code
}

// socket opens and closes a socket.
func socket(domain, typ, proto int) error {
	fd, err := unix.Socket(domain, typ, proto)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// startTrue runs /bin/true, cloned with flags.
func startTrue(flags uintptr) error {
	cmd := exec.CommandContext(context.Background(), "/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: flags}
	return cmd.Run()
}

// dial connects to the unix socket at path, as the bridge connects to
// mcp.sock, and waits for the other end to close it.
func dial(path string) int {
	var dialer net.Dialer
	conn, err := dialer.DialContext(context.Background(), "unix", path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer conn.Close()
	if _, err := io.Copy(io.Discard, conn); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// bindWhenStarted waits until a sandbox with home has written started there,
// then binds legworkDir, which the sandbox covers, at lateMount, as someone
// on the host might while a long-lived sandbox runs, and writes lateDone. A
// sandbox that is not waiting for it never writes started.
func bindWhenStarted(home string) {
	for {
		if _, err := os.Stat(filepath.Join(home, "started")); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := unix.Mount(legworkDir, lateMount, "", unix.MS_BIND, ""); err != nil {
		fmt.Fprintln(os.Stderr, "bind late:", err)
		return
	}
	if err := os.WriteFile(lateDone, nil, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// lateMountHidden writes started in its working directory, which is its
// home, waits for bindWhenStarted to bind legworkDir at lateMount, and
// reports, as its exit status, whether the database shows there.
func lateMountHidden() int {
	if err := os.WriteFile("started", nil, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(lateDone); err == nil {
			break
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "the late bind never happened")
			return 1
		}
	}
	code := 0
	if _, err := os.ReadFile(filepath.Join(lateMount, filepath.Base(legworkDB))); !errors.Is(err, unix.ENOENT) {
		fmt.Fprintf(os.Stderr, "read the late bind: %v, want %v\n", err, unix.ENOENT)
		code = 1
	}
	// pid 1's view of the files, which every process inside can try.
	if _, err := os.ReadFile("/proc/1/root" + lateMount + "/" + filepath.Base(legworkDB)); err == nil {
		fmt.Fprintln(os.Stderr, "read the late bind through pid 1's root")
		code = 1
	}
	return code
}

// isolationTargets are what isolationChecks tries to reach from inside a
// sandbox, and how that sandbox was built.
type isolationTargets struct {
	// OtherSandbox is a file in another sandbox's directory.
	OtherSandbox string `json:"other_sandbox"`
	// Socket is a socket file, under a covered path, that is not in Write.
	Socket string `json:"socket"`
	// Abstract is an abstract socket a process outside listens on.
	Abstract string `json:"abstract"`
	// Pid is a process outside, which stands for serve.
	Pid    int    `json:"pid"`
	Kernel Kernel `json:"kernel"`
}

// isolationChecks tries each way out of the sandbox in body, an
// isolationTargets in JSON, and reports, as its exit status, whether any had
// a result other than the one its sandbox should give. A gap the doc lists
// is expected to be open, so closing it shows up here too.
func isolationChecks(body string) int {
	var tg isolationTargets
	if err := json.Unmarshal([]byte(body), &tg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// The filter refuses ptrace under strict and nested, before the pid
	// namespace hides the process.
	traced := unix.ESRCH
	if tg.Kernel != KernelOpen {
		traced = unix.ENOSYS
	}
	checks := []struct {
		name string
		want error
		call func() error
	}{
		{"write and read its own home", nil, func() error {
			if err := os.WriteFile("own", []byte("own"), 0o600); err != nil {
				return err
			}
			_, err := os.ReadFile("own")
			return err
		}},
		{"read a path the config names", unix.ENOENT, func() error {
			_, err := os.ReadFile(legworkDB)
			return err
		}},
		{"read another sandbox's directory", unix.ENOENT, func() error {
			_, err := os.ReadFile(tg.OtherSandbox)
			return err
		}},
		{"write outside its own directories", unix.EROFS, func() error {
			return os.WriteFile(outsidePath, nil, 0o600)
		}},
		{"connect to a socket not in write", unix.ENOENT, func() error {
			return connectUnix(tg.Socket)
		}},
		// Abstract sockets belong to a network namespace, and the sandbox
		// shares the host's until the egress proxy brings one of its own,
		// so for now this is a gap the doc lists.
		{"connect to an abstract socket outside", nil, func() error {
			return connectUnix(tg.Abstract)
		}},
		{"signal a process outside", unix.ESRCH, func() error {
			return unix.Kill(tg.Pid, 0)
		}},
		{"trace a process outside", traced, func() error {
			if err := unix.PtraceAttach(tg.Pid); err != nil {
				return err
			}
			// Let the process outside run on, so the failure is reported
			// rather than hanging the test.
			return unix.PtraceDetach(tg.Pid)
		}},
		// pid 1 is the reaper, which any process in the sandbox can read
		// through /proc, so neither its command line, its environment, nor
		// its descriptors may name the paths the sandbox hides.
		{"find the spec in pid 1", nil, func() error {
			cmdline, err := os.ReadFile("/proc/1/cmdline")
			if err != nil {
				return err
			}
			// pid 1 is undumpable, so its environment and descriptors may
			// be closed to the command altogether.
			environ, err := os.ReadFile("/proc/1/environ")
			if err != nil && !errors.Is(err, unix.EACCES) {
				return err
			}
			if strings.Contains(string(cmdline)+string(environ), legworkDir) {
				return fmt.Errorf("pid 1's command line or environment names %s", legworkDir)
			}
			fds, err := os.ReadDir("/proc/1/fd")
			if errors.Is(err, unix.EACCES) {
				return nil
			}
			if err != nil {
				return err
			}
			for _, fd := range fds {
				if target, err := os.Readlink("/proc/1/fd/" + fd.Name()); err == nil && within(target, legworkDir) {
					return fmt.Errorf("pid 1 holds %s", target)
				}
			}
			return nil
		}},
		{"replace an iptables table", unix.EPERM, replaceIPTable},
	}
	code := 0
	for _, c := range checks {
		if err := c.call(); !errors.Is(err, c.want) {
			fmt.Fprintf(os.Stderr, "%s: %v, want %v\n", c.name, err, c.want)
			code = 1
		}
	}
	return code
}

// nestedTargets are the paths nestedMounts tries to reach.
type nestedTargets struct {
	// Other is a file under the host's /tmp, which every sandbox covers.
	Other string `json:"other"`
	// ReadOnly is a directory bound read-only into the sandbox, which its
	// account owns.
	ReadOnly string `json:"read_only"`
}

// nestedTargetsVar carries a nestedTargets, as JSON, from startNested to
// nestedMounts.
const nestedTargetsVar = "LEGWORK_SANDBOX_TEST_NESTED"

// startNested starts nestedMounts in a user and mount namespace of its own,
// as software with a sandbox of its own would under kernel nested, and
// returns its status. Like such software, it maps its own uid there. Mapping
// uid 0 would need CAP_SETFCAP, which the sandbox does not leave, so the
// child keeps CAP_SYS_ADMIN and CAP_NET_ADMIN across its exec as ambient
// capabilities, and it has a network namespace of its own to hold the
// second in. body is a nestedTargets in JSON.
func startNested(body string) int {
	cmd := exec.CommandContext(context.Background(), "/proc/self/exe", "nested-mounts")
	cmd.Env = append(os.Environ(), nestedTargetsVar+"="+body)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_NET_ADMIN},
	}
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "mounts in a user namespace of its own:", err)
		return 1
	}
	return 0
}

// nestedMounts tries, with CAP_SYS_ADMIN in a user and mount namespace
// inside a sandbox, to undo the sandbox's view, and reports, as its exit
// status, whether any result differs from the one expected. The kernel locks
// the mounts it copied into a namespace the code made, so a covered path
// cannot be unmounted, a read-only bind cannot be made writable, and a mount
// with covers under it cannot be bound elsewhere without them. A mount of
// its own, such as a tmpfs, still works, which is what nested is for.
func nestedMounts() int {
	var tg nestedTargets
	if err := json.Unmarshal([]byte(os.Getenv(nestedTargetsVar)), &tg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.Mkdir("peek", 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	planted := filepath.Join(tg.ReadOnly, "planted")
	checks := []struct {
		name string
		want error
		call func() error
	}{
		{"unmount a covered path", unix.EINVAL, func() error {
			return unix.Unmount("/tmp", unix.MNT_DETACH)
		}},
		{"read the covered path after", unix.ENOENT, func() error {
			_, err := os.ReadFile(tg.Other)
			return err
		}},
		{"remount a read-only bind writable", unix.EPERM, func() error {
			return unix.Mount("", tg.ReadOnly, "", unix.MS_REMOUNT|unix.MS_BIND, "")
		}},
		{"write the read-only bind after", unix.EROFS, func() error {
			return os.WriteFile(planted, nil, 0o600)
		}},
		{"bind the root without its covers", unix.EINVAL, func() error {
			return unix.Mount("/", "peek", "", unix.MS_BIND, "")
		}},
		{"read under the bind", unix.ENOENT, func() error {
			_, err := os.ReadFile(filepath.Join("peek", tg.Other))
			return err
		}},
		{"mount a tmpfs", nil, func() error {
			return unix.Mount("none", "peek", "tmpfs", 0, "")
		}},
		// The kernel would answer EINVAL for the empty table, having
		// reached the code; the filter answers first.
		{"replace an iptables table in its own network namespace", unix.EPERM, replaceIPTable},
	}
	code := 0
	for _, c := range checks {
		if err := c.call(); !errors.Is(err, c.want) {
			fmt.Fprintf(os.Stderr, "%s: %v, want %v\n", c.name, err, c.want)
			code = 1
		}
	}
	return code
}

// replaceIPTable tries to replace an iptables table with an empty one.
func replaceIPTable() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	setErr := unix.SetsockoptString(fd, unix.IPPROTO_IP, iptSoSetReplace, string(make([]byte, 128)))
	if err := unix.Close(fd); err != nil && setErr == nil {
		return err
	}
	return setErr
}

// connectUnix connects a new socket to the unix socket at path, which is
// abstract when it starts with "@", and closes it.
func connectUnix(path string) error {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	connErr := unix.Connect(fd, &unix.SockaddrUnix{Name: path})
	if err := unix.Close(fd); err != nil && connErr == nil {
		return err
	}
	return connErr
}

// homesUnreadable reports, as its exit status, whether any of fakeHomes can
// be read.
func homesUnreadable() int {
	code := 0
	for _, p := range fakeHomes {
		if _, err := os.ReadFile(p); err == nil { //nolint:gosec // The paths are the test's own, and reading them is the check.
			fmt.Fprintln(os.Stderr, "readable:", p)
			code = 1
		}
	}
	return code
}

// renameBetweenDirs moves a file from one new directory to another in the
// working directory, as uv does when it fills its cache.
func renameBetweenDirs() int {
	for _, d := range []string{"a", "b"} {
		if err := os.Mkdir(d, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	if err := os.WriteFile(filepath.Join("a", "f"), nil, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.Rename(filepath.Join("a", "f"), filepath.Join("b", "f")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// runSandbox runs the test binary inside a sandbox built from spec, with
// args, and returns its exit status and output. With fakeHost, the sandbox is
// started in a user and mount namespace with withFakeHost's changes.
func runSandbox(t *testing.T, spec Spec, fakeHost bool, args ...string) (int, string) {
	t.Helper()
	out, err := sandboxCmd(t, spec, fakeHost, args...).CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

// sandboxCmd returns the command runSandbox runs. It starts in spec's home,
// which the sandbox keeps as the command's working directory, as the runner
// starts the CLI in its scratch directory.
func sandboxCmd(t *testing.T, spec Spec, fakeHost bool, args ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	spec.Command = append([]string{exe}, args...)
	// The test binary is built under the host's /tmp, which is covered.
	spec.Read = append(spec.Read, filepath.Dir(exe))
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "/proc/self/exe")
	cmd.Dir = spec.Home
	cmd.Env = append(os.Environ(), testSpecVar+"="+string(body))
	if fakeHost {
		cmd.Env = append(cmd.Env, fakeHostVar+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
			AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN},
		}
	}
	return cmd
}

func TestRenameBetweenDirs(t *testing.T) {
	code, out := runSandbox(t, Spec{Home: t.TempDir()}, false, "rename")
	if code != 0 {
		t.Fatalf("rename in the sandbox's home exited %d: %s", code, out)
	}
}

func TestCoverHomes(t *testing.T) {
	// withFakeHost writes the secrets as the account that then starts the
	// sandbox, so a pass means the sandbox hid them.
	if code, out := runSandbox(t, Spec{Home: t.TempDir()}, true, "homes"); code != 0 {
		t.Fatalf("a home was readable in the sandbox, exit %d: %s", code, out)
	}
}

func TestEtcLinks(t *testing.T) {
	if code, out := runSandbox(t, Spec{Home: t.TempDir()}, true, "links"); code != 0 {
		t.Fatalf("links from /etc in the sandbox, exit %d: %s", code, out)
	}
}

func TestKernelLevels(t *testing.T) {
	for _, level := range []Kernel{KernelStrict, KernelNested, KernelOpen} {
		t.Run(string(level), func(t *testing.T) {
			spec := Spec{Home: t.TempDir(), Kernel: level}
			if code, out := runSandbox(t, spec, false, "kernel", string(level)); code != 0 {
				t.Fatalf("system calls under kernel %s, exit %d: %s", level, code, out)
			}
		})
	}
}

// TestBridgePeer checks that a process in a sandbox passes the hub's check
// on the bridge: it reaches a socket under a covered path when the socket is
// in Write, and it is in the session of the process the runner started.
func TestBridgePeer(t *testing.T) {
	// The test's temporary directory is under /tmp, which every sandbox
	// covers, as /run covers mcp.sock.
	sock := filepath.Join(t.TempDir(), "mcp.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	spec := Spec{Home: t.TempDir(), Write: []string{sock}}
	cmd := sandboxCmd(t, spec, false, "dial", sock)
	// The runner starts the CLI as the leader of a new session.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	leader, err := peer.Of(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	conns := make(chan net.Conn, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			conns <- conn
		}
	}()
	select {
	case conn := <-conns:
		if err := peer.Check(conn, leader); err != nil {
			t.Errorf("peer check: %v", err)
		}
		// Closing it ends the dialer.
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	case err := <-done:
		t.Fatalf("the sandbox exited before connecting: %v: %s", err, out.String())
	}
	if err := <-done; err != nil {
		t.Fatalf("sandbox: %v: %s", err, out.String())
	}
}

// TestIsolation runs, under the strict and open kernel levels, the checks
// from the doc's list that need no egress proxy: a path the config names,
// another sandbox's directory, writing outside, a socket file and an
// abstract socket outside, and signaling and tracing the process that
// stands for serve. The open level shows what the namespaces refuse without
// the filter in front of them.
func TestIsolation(t *testing.T) {
	for _, level := range []Kernel{KernelStrict, KernelOpen} {
		t.Run(string(level), func(t *testing.T) {
			other := filepath.Join(t.TempDir(), "f")
			if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
				t.Fatal(err)
			}
			var lc net.ListenConfig
			// The test's temporary directory is under /tmp, which every
			// sandbox covers.
			sock := filepath.Join(t.TempDir(), "other.sock")
			abstract := fmt.Sprintf("@legwork-sandbox-test-%d-%s", os.Getpid(), strings.ReplaceAll(t.Name(), "/", "-"))
			for _, addr := range []string{sock, abstract} {
				ln, err := lc.Listen(t.Context(), "unix", addr)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := ln.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			body, err := json.Marshal(isolationTargets{
				OtherSandbox: other,
				Socket:       sock,
				Abstract:     abstract,
				Pid:          os.Getpid(),
				Kernel:       level,
			})
			if err != nil {
				t.Fatal(err)
			}
			spec := Spec{Home: t.TempDir(), Cover: []string{legworkDir}, Kernel: level}
			if code, out := runSandbox(t, spec, true, "isolation", string(body)); code != 0 {
				t.Fatalf("a way out of the sandbox, exit %d: %s", code, out)
			}
		})
	}
}

// TestNestedMounts checks that code under kernel nested that makes a user
// and mount namespace of its own cannot use it to undo the sandbox's view.
func TestNestedMounts(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	// sandboxCmd binds the test binary's directory back read-only.
	body, err := json.Marshal(nestedTargets{Other: other, ReadOnly: filepath.Dir(exe)})
	if err != nil {
		t.Fatal(err)
	}
	spec := Spec{Home: t.TempDir(), Kernel: KernelNested}
	if code, out := runSandbox(t, spec, false, "nested", string(body)); code != 0 {
		t.Fatalf("undoing the view under kernel nested, exit %d: %s", code, out)
	}
}

// sessionStore makes the CLI's session store in a fake home, with a saved
// session for threads a and b, and returns the store.
func sessionStore(t *testing.T, home string) string {
	t.Helper()
	store := filepath.Join(home, ".claude", "projects")
	for _, thread := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(store, thread), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(store, thread, "session.jsonl"), []byte(thread), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

// TestRefusedLayouts checks that a sandbox refuses to start when a sandbox
// that shares its home has planted a link in it or moved a covered path
// away, and when anything would be mounted inside its home at all, which a
// sandbox could have prepared for bubblewrap to follow.
func TestRefusedLayouts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, store string)
	}{
		{"a cover and a bind inside the home", func(*testing.T, string) {}},
		{"a write path made a link to Legwork's state", func(t *testing.T, store string) {
			state := t.TempDir()
			if err := os.WriteFile(filepath.Join(state, "legwork.db"), []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(filepath.Join(store, "a")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(state, filepath.Join(store, "a")); err != nil {
				t.Fatal(err)
			}
		}},
		{"the covered store moved away", func(t *testing.T, store string) {
			if err := os.Rename(store, store+"-moved"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			store := sessionStore(t, home)
			tc.plant(t, store)
			spec := Spec{Home: home, Cover: []string{store}, Write: []string{filepath.Join(store, "a")}}
			code, out := runSandbox(t, spec, false, "rename")
			if code != failed {
				t.Fatalf("the sandbox started, exit %d: %s", code, out)
			}
		})
	}
}

// TestLateMounts checks that a mount made on the host after a sandbox has
// started, here a bind of a covered directory to a path the sandbox can
// see, does not appear inside it.
func TestLateMounts(t *testing.T) {
	home := t.TempDir()
	spec := Spec{Home: home, Cover: []string{legworkDir}}
	if code, out := runSandbox(t, spec, true, "late"); code != 0 {
		t.Fatalf("a later mount reached the sandbox, exit %d: %s", code, out)
	}
}
