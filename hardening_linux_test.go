package sandbox

// Regression tests for the findings of the security review of the Linux
// backend: the sandbox's own process group, a read-only /dev, descriptors
// handed in, and the caller's session keyring. Each runs code inside a
// sandbox as escape_guarantee_linux_test.go does, and was checked to fail with
// its fix taken out.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func init() {
	childModes["esc-tty"] = escTTYMode
	childModes["esc-keys"] = escKeysMode
	escChecks["sig-group"] = escSigGroup
	escChecks["dev-ro"] = escDevReadOnly
	escChecks["keys"] = escKeys
	escChecks["reopen"] = escReopen
}

// ------------------------------------------------- 1. the process group

// escSigGroup is what a sandbox may try against the caller's process group.
func escSigGroup(e *escT, args []string) {
	switch args[0] {
	case "kill0":
		// Ends the sandbox's own group, bubblewrap included.
		_ = unix.Kill(0, unix.SIGTERM)
		time.Sleep(10 * time.Second)
		e.fail("kill(0) did not end the sandbox's group")
	case "killall":
		// Every process in the namespace but pid 1 and this one, which is
		// nothing outside.
		e.is("kill(-1)", unix.Kill(-1, unix.SIGTERM), nil, unix.ESRCH)
	case "nice":
		e.is("setpriority(PRIO_PGRP, 0)", unix.Setpriority(unix.PRIO_PGRP, 0, 19))
		e.is("setpriority(PRIO_PROCESS, 0)", unix.Setpriority(unix.PRIO_PROCESS, 0, 19))
	case "nice-user":
		// Its own uid is the caller's. The kernel skips the processes the
		// caller's pid namespace cannot see.
		e.is("setpriority(PRIO_USER, 0)", unix.Setpriority(unix.PRIO_USER, 0, 19), nil, unix.EPERM)
	}
}

// Row: "process group": a sandbox's kill(0), kill(-1) and setpriority reach
// nothing outside it. The caller's group holds a sibling, which stays alive
// and at its priority, and the caller gets no signal.
func TestEscapeSignalsStayInside(t *testing.T) {
	canary := exec.Command("sleep", "120") // in this process's group
	if err := canary.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = canary.Process.Kill(); _ = canary.Wait() }()
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGUSR1, unix.SIGHUP, unix.SIGINT)
	defer signal.Stop(sigs)
	prio := func(pid int) int {
		p, err := unix.Getpriority(unix.PRIO_PROCESS, pid)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if self := prio(0); self <= 1 {
		t.Skip("the test's own priority is already the lowest")
	}
	for _, mode := range []string{"kill0", "killall", "nice", "nice-user"} {
		t.Run(mode, func(t *testing.T) {
			selfBefore, canaryBefore := prio(0), prio(canary.Process.Pid)
			c, _, stderr := escCmd(t, t.Context(), Spec{}, "esc", "sig-group", mode)
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			err := c.Wait()
			if mode == "kill0" && err == nil {
				t.Error("kill(0) from inside did not end the sandbox, so it signalled nothing")
			} else if mode != "kill0" && err != nil {
				t.Fatalf("%v: %s", err, stderr)
			}
			time.Sleep(200 * time.Millisecond)
			select {
			case s := <-sigs:
				t.Errorf("the caller was sent %v from inside", s)
			default:
			}
			if err := canary.Process.Signal(syscall.Signal(0)); err != nil {
				t.Errorf("a process in the caller's group: %v", err)
			}
			st, _ := os.ReadFile("/proc/" + strconv.Itoa(canary.Process.Pid) + "/stat")
			if !bytes.Contains(st, []byte(") S ")) && !bytes.Contains(st, []byte(") R ")) {
				t.Errorf("the caller's sibling is not running: %s", st)
			}
			if got := prio(0); got != selfBefore {
				t.Errorf("the caller's priority changed from %d to %d", selfBefore, got)
			}
			if got := prio(canary.Process.Pid); got != canaryBefore {
				t.Errorf("a sibling's priority changed from %d to %d", canaryBefore, got)
			}
		})
	}
}

// escTTYMode is a process that has a terminal for its standard input, as a
// shell's job has. It runs the Spec in args[0] with that terminal, and says
// whose the terminal's foreground is while the sandbox runs and after.
func escTTYMode(args []string) int {
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
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fg, _ := unix.IoctlGetInt(0, unix.TIOCGPGRP)
	fmt.Println("sandbox-foreground", fg == c.run.cmd.Process.Pid && fg != unix.Getpgrp())
	if err := c.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fg, _ = unix.IoctlGetInt(0, unix.TIOCGPGRP)
	fmt.Println("caller-foreground-again", fg == unix.Getpgrp())
	return 0
}

// Row: "process group": a sandbox in its own group still reads its caller's
// terminal, which is why it takes the foreground, and the caller gets the
// foreground back when it is done. Without it the read stops the sandbox on
// SIGTTIN.
func TestEscapeTerminalForeground(t *testing.T) {
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skip("no /dev/ptmx: " + err.Error())
	}
	master := os.NewFile(uintptr(mfd), "ptmx")
	defer master.Close()
	if err := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(mfd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()

	// A shell, which stops on SIGTTIN where a Go program, which handles the
	// signal, does not.
	spec := Spec{Home: t.TempDir(), Command: []string{"/bin/sh", "-c", `read line; printf 'got %s\n' "$line"`}}
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	exe, _ := escBinary(t)
	cmd := exec.CommandContext(ctx, exe, "esc-tty", string(body))
	var stdout, stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, &stdout, &stderr
	// A session of its own whose controlling terminal is the pty, with its
	// group in the foreground, as a shell's job.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := master.WriteString("ping\n"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("%v (a sandbox in the background group stops on its read)\nstdout: %s\nstderr: %s", err, &stdout, &stderr)
	}
	for _, want := range []string{"got ping", "sandbox-foreground true", "caller-foreground-again true"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("output lacks %q: %s", want, &stdout)
		}
	}
}

// ------------------------------------------------------- 2. /dev read-only

// escDevReadOnly checks that nothing in /dev but /dev/shm is writable, that
// every writable tmpfs the sandbox made holds at most args[0] bytes, and that
// the devices a program needs still work. The rest of args are directories
// the caller bound in, which are its own to size.
func escDevReadOnly(e *escT, args []string) {
	limit, _ := strconv.ParseUint(args[0], 10, 64)
	fd, err := unix.Open("/dev/big", unix.O_CREAT|unix.O_WRONLY, 0o600)
	if err == nil {
		_ = unix.Close(fd)
	}
	e.is("create /dev/big", err, unix.EROFS)
	e.is("mkdir /dev/dir", unix.Mkdir("/dev/dir", 0o700), unix.EROFS)
	e.is("symlink in /dev", unix.Symlink("/etc", "/dev/link"), unix.EROFS)
	e.is("unlink /dev/fd", unix.Unlink("/dev/fd"), unix.EROFS)
	// Writing into a file already there, such as the stage's binary, is no
	// room either.
	e.is("write /dev/sandbox-stage", func() error {
		fd, err := unix.Open("/dev/sandbox-stage", unix.O_WRONLY, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}(), unix.EROFS, unix.EACCES, unix.ETXTBSY)

	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		e.fail("read mountinfo: %v", err)
		return
	}
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(mi)), "\n") {
		f := strings.Fields(line)
		sep := 0
		for i, s := range f {
			if s == "-" {
				sep = i
				break
			}
		}
		if sep == 0 || len(f) < sep+4 {
			continue
		}
		mp, opts, fstype, super := f[4], strings.Split(f[5], ","), f[sep+1], strings.Split(f[sep+3], ",")
		if fstype != "tmpfs" && fstype != "ramfs" && fstype != "devtmpfs" {
			continue
		}
		if contains(args[1:], mp) {
			continue
		}
		var st unix.Stat_t
		if unix.Stat(mp, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue // a device node bound from the host
		}
		var sf unix.Statfs_t
		if err := unix.Statfs(mp, &sf); err != nil {
			e.fail("statfs %s: %v", mp, err)
			continue
		}
		writable := !contains(opts, "ro") && !contains(super, "ro")
		size := sf.Blocks * uint64(sf.Bsize)
		if writable && (fstype != "tmpfs" || size > limit) {
			e.fail("%s is a writable %s of %d bytes, want at most %d", mp, fstype, size, limit)
		}
		checked++
	}
	if checked == 0 {
		e.fail("no tmpfs found in the mount table")
	}

	// What programs use from /dev.
	for _, p := range []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"} {
		fd, err := unix.Open(p, unix.O_RDWR, 0)
		e.is("open "+p, err)
		if err == nil {
			_ = unix.Close(fd)
		}
	}
	var buf [16]byte
	for _, p := range []string{"/dev/zero", "/dev/urandom"} {
		fd, err := unix.Open(p, unix.O_RDONLY, 0)
		if err == nil {
			n, rerr := unix.Read(fd, buf[:])
			if rerr != nil || n != len(buf) {
				e.fail("read %s: %d, %v", p, n, rerr)
			}
			_ = unix.Close(fd)
		}
	}
	// There may be no controlling terminal to open.
	if fd, err := unix.Open("/dev/tty", unix.O_RDWR, 0); err == nil {
		_ = unix.Close(fd)
	} else {
		e.is("open /dev/tty", err, unix.ENXIO)
	}
	// A new pseudoterminal through /dev/ptmx and /dev/pts.
	if mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0); err != nil {
		e.fail("open /dev/ptmx: %v", err)
	} else {
		e.is("unlock the pty", unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0))
		n, err := unix.IoctlGetInt(mfd, unix.TIOCGPTN)
		e.is("pty number", err)
		if sfd, err := unix.Open("/dev/pts/"+strconv.Itoa(n), unix.O_RDWR|unix.O_NOCTTY, 0); err != nil {
			e.fail("open the pty's slave: %v", err)
		} else {
			_ = unix.Close(sfd)
		}
		_ = unix.Close(mfd)
	}
	// /dev/fd and the standard stream links lead to the descriptors.
	if target, err := os.Readlink("/dev/fd"); err != nil || target != "/proc/self/fd" {
		e.fail("/dev/fd is %q, %v", target, err)
	}
	if fd, err := unix.Open("/dev/fd/0", unix.O_RDONLY, 0); err != nil {
		e.fail("open /dev/fd/0: %v", err)
	} else {
		_ = unix.Close(fd)
	}
	for _, l := range []string{"/dev/stdin", "/dev/stdout", "/dev/stderr"} {
		if _, err := os.Readlink(l); err != nil {
			e.fail("%s: %v", l, err)
		}
	}
	// /dev/shm is the one place in /dev to write, and it is capped.
	e.is("write /dev/shm", os.WriteFile("/dev/shm/ok", []byte("ok"), 0o600))
	var sf unix.Statfs_t
	if err := unix.Statfs("/dev/shm", &sf); err != nil || sf.Blocks*uint64(sf.Bsize) > limit {
		e.fail("/dev/shm holds %d bytes, %v, want at most %d", sf.Blocks*uint64(sf.Bsize), err, limit)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Row: "Scratch tmpfs 1 GiB": with a small ScratchSize, nothing in /dev can be
// written but /dev/shm, every writable tmpfs in the sandbox holds no more than
// that, and the devices still work.
func TestEscapeDevReadOnly(t *testing.T) {
	const size = 16 << 20
	home := t.TempDir() // may itself be a tmpfs on the host, and is the caller's
	escRun(t, Spec{Home: home, ScratchSize: size}, "dev-ro", strconv.Itoa(size), home)
	escRun(t, Spec{Home: home}, "dev-ro", strconv.Itoa(scratchSize), home)
}

// ----------------------------------------- 3. descriptors handed in

// escReopen tries to reopen descriptor 3 through /proc/self/fd/3 for writing
// and for reading, and says what became of each on stdout. args[0] is the
// bytes it writes through the descriptor it reopened, if it did.
func escReopen(e *escT, args []string) {
	target, _ := os.Readlink("/proc/self/fd/3")
	fmt.Println("target", target)
	for _, m := range []struct {
		name string
		flag int
	}{{"write", unix.O_WRONLY}, {"read", unix.O_RDONLY}} {
		fd, err := unix.Open("/proc/self/fd/3", m.flag, 0)
		if err != nil {
			fmt.Printf("%s %v\n", m.name, err)
			continue
		}
		fmt.Printf("%s ok\n", m.name)
		if m.name == "write" {
			_, _ = unix.Write(fd, []byte(args[0]))
		}
		_ = unix.Close(fd)
	}
}

// Row: "descriptors handed in" (documented, not prevented): a file passed in
// is reopened with more access than the caller opened it with and past its
// cover, since Linux lets /proc/self/fd reopen a file by its inode. A socket
// and a pipe lead nowhere on the file system, so reopening one gives the
// sandbox no more than the descriptor already did.
func TestEscapeReopenDescriptor(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		dir := t.TempDir()
		covered := filepath.Join(dir, "covered")
		if err := os.Mkdir(covered, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(covered, "ro.txt")
		if err := os.WriteFile(path, []byte("config"), 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path) // read-only
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		c, stdout, stderr := escCmd(t, t.Context(), Spec{Cover: []string{covered}, Files: []*os.File{f}}, "esc", "reopen", "REWRITTEN")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, stderr)
		}
		t.Logf("reopened: %s", stdout)
		if !strings.Contains(stdout.String(), "write ok") {
			t.Errorf("the read-only file was not reopened for writing: %s", stdout)
		}
		got, _ := os.ReadFile(path)
		if !bytes.HasPrefix(got, []byte("REWRITTEN")) {
			t.Errorf("the file reads %q, so the documented reopening no longer works, and the docs need to change", got)
		}
	})
	t.Run("socket", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		a, b := os.NewFile(uintptr(fds[0]), "a"), os.NewFile(uintptr(fds[1]), "b")
		defer a.Close()
		defer b.Close()
		c, stdout, stderr := escCmd(t, t.Context(), Spec{Files: []*os.File{a}}, "esc", "reopen", "x")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, stderr)
		}
		if !strings.Contains(stdout.String(), "write no such device or address") || !strings.Contains(stdout.String(), "read no such device or address") {
			t.Errorf("a socket was reopened: %s", stdout)
		}
	})
	t.Run("pipe", func(t *testing.T) {
		// A pipe's read end can be reopened as another end of the same pipe,
		// which is the pipe the caller passed and nothing else: what it
		// writes comes out of the pipe the caller holds.
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		c, stdout, stderr := escCmd(t, t.Context(), Spec{Files: []*os.File{r}}, "esc", "reopen", "via-the-pipe")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatalf("%v: %s", err, stderr)
		}
		_ = w.Close()
		t.Logf("reopened: %s", stdout)
		if !strings.Contains(stdout.String(), "target pipe:[") {
			t.Fatalf("descriptor 3 is not a pipe: %s", stdout)
		}
		// What it wrote is in the pipe the caller holds, and that is all.
		var buf [64]byte
		n, _ := r.Read(buf[:])
		if got := string(buf[:n]); got != "via-the-pipe" {
			t.Errorf("the pipe holds %q, want what the sandbox wrote through its reopened end", got)
		}
	})
}

// ------------------------------------------------- 4. the session keyring

// escKeysMode puts a key in a new session keyring of its own, as a login
// does, and runs the Spec in args[0] from it at KernelOpen, which allows keyctl.
// args[1] is the key's description.
func escKeysMode(args []string) int {
	var spec Spec
	if err := json.Unmarshal([]byte(args[0]), &spec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := unix.KeyctlJoinSessionKeyring("test-caller"); err != nil {
		fmt.Fprintln(os.Stderr, "join a session keyring:", err)
		return 1
	}
	secret := []byte("hunter2-kerberos-ticket")
	typ, _ := unix.BytePtrFromString("user")
	desc, _ := unix.BytePtrFromString(args[1])
	for _, ring := range []int{unix.KEY_SPEC_SESSION_KEYRING, unix.KEY_SPEC_USER_KEYRING} {
		if _, _, errno := unix.Syscall6(unix.SYS_ADD_KEY, uintptr(unsafe.Pointer(typ)), uintptr(unsafe.Pointer(desc)), uintptr(unsafe.Pointer(&secret[0])), uintptr(len(secret)), uintptr(ring), 0); errno != 0 {
			fmt.Fprintln(os.Stderr, "add a key:", errno)
			return 1
		}
	}
	// The control: the key is there for this process.
	if _, err := unix.KeyctlSearch(unix.KEY_SPEC_SESSION_KEYRING, "user", args[1], 0); err != nil {
		fmt.Fprintln(os.Stderr, "the caller cannot find its own key:", err)
		return 1
	}
	ring, _ := unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, false)
	spec.Command = append(spec.Command, strconv.Itoa(ring), args[1])
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
	if err := c.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// escKeys looks for the caller's key, whose description is args[1], in every
// keyring it has, and checks that its session keyring is not the caller's,
// args[0].
func escKeys(e *escT, args []string) {
	for _, r := range []struct {
		name string
		id   int
	}{
		{"thread", unix.KEY_SPEC_THREAD_KEYRING}, {"process", unix.KEY_SPEC_PROCESS_KEYRING},
		{"session", unix.KEY_SPEC_SESSION_KEYRING}, {"user", unix.KEY_SPEC_USER_KEYRING},
		{"user session", unix.KEY_SPEC_USER_SESSION_KEYRING},
	} {
		if id, err := unix.KeyctlSearch(r.id, "user", args[1], 0); err == nil {
			e.fail("found the caller's key %d in the %s keyring", id, r.name)
		}
	}
	// The caller's session keyring by its id.
	if id, err := unix.KeyctlSearch(atoi(args[0]), "user", args[1], 0); err == nil {
		e.fail("found the caller's key %d in its session keyring by id", id)
	}
	if ring, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, false); err == nil && strconv.Itoa(ring) == args[0] {
		e.fail("the session keyring is the caller's, %d", ring)
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// Row: "session keyring": under KernelOpen, which allows keyctl, a sandbox
// does not share its caller's session keyring, and so cannot find or read a
// key in it.
func TestEscapeSessionKeyring(t *testing.T) {
	if _, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, true); err != nil {
		t.Skip("no key support: " + err.Error())
	}
	exe, dir := escBinary(t)
	spec := Spec{Home: t.TempDir(), Read: []string{dir}, Kernel: KernelOpen, Command: []string{exe, "esc", "keys"}}
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(exe, "esc-keys", string(body), fmt.Sprintf("sbx-secret-%d", os.Getpid())).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}
