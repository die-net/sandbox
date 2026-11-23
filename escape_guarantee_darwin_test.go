package sandbox

// Escape tests for the macOS backend: for each guarantee in the macOS column
// of docs/security-model.md's guarantee table, code runs inside a sandbox,
// tries the escape, and the test asserts it fails. Each test cites the row it
// checks as "Row: ...", by the first words of the Guarantee column. A guarantee the platform cannot give has a test named TestGap...
// that shows the gap, and fails when the gap closes, so that the docs get
// changed with it.
//
// The code inside the sandbox is this test binary run as "esc <check>", where
// check is a key of escChecks, or /bin/sh. A check prints what went wrong on
// stderr and exits 1.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func registerEscapeChecks() {
	childModes["canary"] = canaryMode
	escChecks["denied"] = escDenied
	escChecks["allowed"] = escAllowed
	escChecks["unreadable"] = escUnreadable
	escChecks["writes-denied"] = escWritesDenied
	escChecks["writes-allowed"] = escWritesAllowed
	escChecks["exec-denied"] = escExecDenied
	escChecks["signals"] = escSignals
	escChecks["procinfo"] = escProcInfo
	escChecks["dial-denied"] = escDialDenied
	escChecks["dial-ok"] = escDialOK
	escChecks["bind-ok"] = escBindOK
	escChecks["bind-denied"] = escBindDenied
	escChecks["loopback"] = escLoopback
	escChecks["unix-connect"] = escUnixConnect
	escChecks["tty"] = escTTY
	escChecks["plant-link"] = escPlantLink
	escChecks["wait-file"] = escWaitFile
	escChecks["procargs"] = escProcArgs
	escChecks["setsid-connect"] = escSetsidConnect
	escChecks["daemon"] = escDaemon
	escChecks["reopen"] = escReopen
	// udp-ok binds a UDP socket on loopback and sends a datagram to it.
	escChecks["udp-ok"] = func(e *escT, _ []string) {
		c, err := listenPacket("udp", "127.0.0.1:0")
		if err != nil {
			e.failf("udp bind: %v", err)
			return
		}
		defer c.Close()
		d, err := dialTimeout("udp", c.LocalAddr().String(), time.Second)
		if err != nil {
			e.failf("udp dial: %v", err)
			return
		}
		defer d.Close()
		if _, err := d.Write([]byte("x")); err != nil {
			e.failf("udp send: %v", err)
		}
	}
}

// ---------------------------------------------------------------- helpers

// canaryMode is a process that records the signals it gets, in the directory
// args[0], and otherwise sleeps. It writes "ready" when it is listening.
func canaryMode(args []string) int {
	dir := args[0]
	sigs := make(chan os.Signal, 8)
	signalNotifyAll(sigs)
	_ = os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600) //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
	for s := range sigs {
		f, err := openFileFlags(filepath.Join(dir, "got"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			if _, err := fmt.Fprintln(f, s); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
			_ = f.Close()
		}
	}
	return 0
}

// canary starts a canary in a process group of its own, or in the caller's if
// own is false, and returns its pid and the directory it records signals in.
// It is ended with the test.
func canary(t *testing.T, own bool) (pid int, dir string) {
	t.Helper()
	dir = realTemp(t)
	cmd := exec.CommandContext(t.Context(), self(t), "canary", dir) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: own}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	eventually(t, 10*time.Second, "the canary did not start", func() bool { _, err := os.Stat(filepath.Join(dir, "ready")); return err == nil })
	return cmd.Process.Pid, dir
}

// gotSignals returns what a canary recorded.
func gotSignals(dir string) string {
	b, _ := readFile(filepath.Join(dir, "got"))
	return strings.TrimSpace(string(b))
}

// lanAddr returns an address of this host that is not loopback, or "" if
// there is none.
func lanAddr() string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() && !ip.IP.IsLinkLocalUnicast() {
			return ip.IP.String()
		}
	}
	return ""
}

// listenAny starts a TCP listener on all addresses of the host, which a
// connection to 127.0.0.1, ::1 and the LAN address each reach, that accepts
// and closes. It returns the port.
func listenAny(t testing.TB) int {
	t.Helper()
	l, err := listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// openPerm reports whether err is a refusal by the profile: EPERM.
func isPerm(err error) bool { return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) }

// ---------------------------------------------------------------- checks in the sandbox

// escDenied fails for each path in args that can be opened, listed, or
// statted.
func escDenied(e *escT, args []string) {
	for _, p := range args {
		if f, err := openFile(p); err == nil {
			_, rerr := f.Readdirnames(1)
			_ = f.Close()
			if rerr == nil || errors.Is(rerr, io.EOF) {
				e.failf("open %s: worked", p)
			}
		} else if !isPerm(err) {
			e.failf("open %s: %v, want a refusal by the profile", p, err)
		}
		if _, err := os.Stat(p); err == nil { //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
			e.failf("stat %s: worked", p)
		}
		if _, err := readFile(p); err == nil {
			e.failf("read %s: worked", p)
		}
	}
}

// escUnreadable fails for each path in args that can be opened. Unlike
// escDenied it takes any error, since a path under a link that now leads
// elsewhere may not exist there.
func escUnreadable(e *escT, args []string) {
	for _, p := range args {
		if f, err := openFile(p); err == nil {
			e.failf("open %s: worked", p)
			_ = f.Close()
		}
		if _, err := readFile(p); err == nil {
			e.failf("read %s: worked", p)
		}
		if _, err := os.ReadDir(p); err == nil {
			e.failf("list %s: worked", p)
		}
	}
}

// escAllowed fails for each path in args that cannot be read.
func escAllowed(e *escT, args []string) {
	for _, p := range args {
		fi, err := os.Stat(p) //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
		if err != nil {
			e.failf("stat %s: %v", p, err)
			continue
		}
		if fi.IsDir() {
			if _, err := os.ReadDir(p); err != nil {
				e.failf("list %s: %v", p, err)
			}
		} else if fi.Mode().IsRegular() {
			if _, err := readFile(p); err != nil {
				e.failf("read %s: %v", p, err)
			}
		} else if f, err := openFile(p); err != nil {
			e.failf("open %s: %v", p, err)
		} else {
			_ = f.Close()
		}
	}
}

// escWritesDenied fails for each path in args, a directory, in which a file
// can be made, written, or removed, or a directory made, or an existing entry
// renamed.
func escWritesDenied(e *escT, args []string) {
	for _, d := range args {
		name := filepath.Join(d, ".esc-write")
		if err := os.WriteFile(name, []byte("x"), 0o600); err == nil { //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
			e.failf("create %s: worked", name)
			_ = os.Remove(name) //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
		} else if !isPerm(err) && !errors.Is(err, syscall.EROFS) {
			e.failf("create %s: %v, want a refusal", name, err)
		}
		if err := os.Mkdir(name, 0o750); err == nil { //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
			e.failf("mkdir %s: worked", name)
			_ = os.Remove(name) //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
		}
		if err := os.Symlink("/etc/hosts", name); err == nil {
			e.failf("symlink %s: worked", name)
			_ = os.Remove(name) //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
		}
	}
}

// escWritesAllowed fails for each directory in args that cannot be written.
func escWritesAllowed(e *escT, args []string) {
	for _, d := range args {
		name := filepath.Join(d, ".esc-write")
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil { //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
			e.failf("create %s: %v", name, err)
			continue
		}
		if err := os.Remove(name); err != nil { //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
			e.failf("remove %s: %v", name, err)
		}
	}
}

// escExecDenied fails for each path in args that can be run.
func escExecDenied(e *escT, args []string) {
	for _, p := range args {
		cmd := exec.CommandContext(context.Background(), p) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		if err := cmd.Run(); err == nil {
			e.failf("run %s: worked", p)
		} else if !isPerm(err) {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				e.failf("run %s: it ran, and exited %d", p, ee.ExitCode())
			}
		}
	}
}

// escSignals tries every way to signal processes outside: the pids in args
// by number, the caller's process group, every process, and this group. It
// fails for a signal that was delivered to a pid in args. args are the pids
// of the stage, its parent, and canaries.
//
// It never sends a signal that can hurt anything. If the profile fails
// open, a deadly signal kills whatever it reaches, and a broadcast reaches
// every process the user owns: SIGUSR1 here ended the user's desktop
// session three times. Seatbelt checks signal 0 like any other, and kill
// with it reports the check without delivering anything, so the pids and the
// group are tried with 0. A broadcast succeeds whenever any one process may
// be signaled, and the sandbox may always signal its own, so its result
// says nothing: it sends SIGWINCH, whose default action is to ignore it,
// and the canaries record whether it reached them. (Go's runtime sends
// SIGURG to itself for preemption, so the canaries would record that one
// with no one else sending it.)
func escSignals(e *escT, args []string) {
	for _, a := range args {
		pid, _ := strconv.Atoi(a)
		if err := syscall.Kill(pid, 0); err == nil {
			e.failf("kill(%d, 0) worked", pid)
		} else if !isPerm(err) && !errors.Is(err, syscall.ESRCH) {
			e.failf("kill(%d, 0): %v", pid, err)
		}
		pgid, err := syscall.Getpgid(pid)
		// A group of 1 is init's, and killpg(1) is kill(-1), a broadcast.
		if err == nil && pgid > 1 {
			if err := syscall.Kill(-pgid, 0); err == nil {
				e.failf("killpg(%d) worked", pgid)
			}
		}
		for _, which := range []int{unix.PRIO_PROCESS, unix.PRIO_PGRP} {
			target := pid
			if which == unix.PRIO_PGRP {
				target = pgid
			}
			if target <= 1 {
				continue
			}
			// Set it to what it is, so that a profile that fails open changes nothing.
			cur, gerr := unix.Getpriority(which, target)
			if gerr != nil {
				continue
			}
			if err := unix.Setpriority(which, target, cur); err == nil {
				e.failf("setpriority(%d, %d) worked", which, target)
			}
		}
	}
	// A broadcast reaches only what the sandbox may signal, and its own group.
	signalIgnore(syscall.SIGWINCH)
	_ = syscall.Kill(-1, syscall.SIGWINCH)
	_ = syscall.Kill(0, syscall.SIGWINCH)
	// Nice 0 changes nothing even if allowed: processes already at 0 stay
	// there, and an unprivileged caller cannot lower a higher one. Without
	// the sandbox it returns nil, or EACCES for those it could not lower.
	if err := unix.Setpriority(unix.PRIO_USER, os.Getuid(), 0); !errors.Is(err, syscall.EPERM) {
		e.failf("setpriority(PRIO_USER) = %v, want EPERM", err)
	}
}

// escProcInfo fails for each pid in args whose proc_pidinfo works.
func escProcInfo(e *escT, args []string) {
	const procPidTBSDInfo = 3
	for _, a := range args {
		pid, _ := strconv.Atoi(a)
		var buf [256]byte
		_, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, 2 /* PIDINFO */, uintptr(pid), procPidTBSDInfo, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) //nolint:gosec,staticcheck // G103: the kernel reads or writes the buffer during the call, which keeps it valid. SA1019: Syscall6 passes the number to libc's syscall(2), and libproc has no binding without cgo.
		if errno == 0 {
			e.failf("proc_pidinfo(%d) worked", pid)
		}
		// Footprints are process-info too.
		_, _, errno = unix.Syscall6(unix.SYS_PROC_INFO, 9 /* PIDRUSAGE */, uintptr(pid), 0, 0, uintptr(unsafe.Pointer(&buf[0])), 96) //nolint:gosec,staticcheck // G103: the kernel reads or writes the buffer during the call, which keeps it valid. SA1019: Syscall6 passes the number to libc's syscall(2), and libproc has no binding without cgo.
		if errno == 0 {
			e.failf("proc_pid_rusage(%d) worked", pid)
		}
	}
	// Its own is fine.
	var buf [256]byte
	if _, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, 2, uintptr(os.Getpid()), procPidTBSDInfo, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); errno != 0 { //nolint:gosec,staticcheck // G103: the kernel reads or writes the buffer during the call, which keeps it valid. SA1019: Syscall6 passes the number to libc's syscall(2), and libproc has no binding without cgo.
		e.failf("proc_pidinfo(self): %v", errno)
	}
}

// escDialDenied fails for each address in args, as "network:host:port", that
// can be reached. A refusal by the profile is EPERM.
func escDialDenied(e *escT, args []string) {
	for _, a := range args {
		network, addr, _ := strings.Cut(a, ":")
		c, err := dialTimeout(network, addr, 3*time.Second)
		if err == nil {
			e.failf("dial %s: connected", a)
			_ = c.Close()
			continue
		}
		if !isPerm(err) {
			e.failf("dial %s: %v, want a refusal by the profile", a, err)
		}
	}
}

// escDialOK fails for each address in args that cannot be reached.
func escDialOK(e *escT, args []string) {
	for _, a := range args {
		network, addr, _ := strings.Cut(a, ":")
		c, err := dialTimeout(network, addr, 3*time.Second)
		if err != nil {
			e.failf("dial %s: %v", a, err)
			continue
		}
		_ = c.Close()
	}
}

// escBindOK fails for each address in args that cannot be listened on, and
// dialed from the same sandbox.
func escBindOK(e *escT, args []string) {
	for _, a := range args {
		l, err := listen("tcp", a)
		if err != nil {
			e.failf("listen %s: %v", a, err)
			continue
		}
		go func() {
			c, err := l.Accept()
			if err == nil {
				_ = c.Close()
			}
		}()
		c, err := dialTimeout("tcp", l.Addr().String(), 3*time.Second)
		if err != nil {
			e.failf("dial own %s: %v", a, err)
		} else {
			_ = c.Close()
		}
		_ = l.Close()
	}
}

// escBindDenied fails for each address in args that can be listened on.
func escBindDenied(e *escT, args []string) {
	for _, a := range args {
		l, err := listen("tcp", a)
		if err == nil {
			e.failf("listen %s: worked", a)
			_ = l.Close()
		} else if !isPerm(err) {
			e.failf("listen %s: %v, want a refusal by the profile", a, err)
		}
	}
}

// escLoopback listens on each of the ports in args and dials it, and also
// tries ports nobody gave it, on every kind of address, which must be refused:
// the ports on either side of the given ones, and a port well away.
func escLoopback(e *escT, args []string) {
	for _, p := range args {
		escBindOK(e, []string{"127.0.0.1:" + p})
	}
	ports := make([]int, 0, 2*len(args)+2)
	for _, a := range args {
		n, _ := strconv.Atoi(a)
		ports = append(ports, n-1, n+1)
	}
	ports = append(ports, 80, 8080)
	lan := lanAddr()
	for _, n := range ports {
		if slices.Contains(args, strconv.Itoa(n)) {
			continue
		}
		p := strconv.Itoa(n)
		escBindDenied(e, []string{"127.0.0.1:" + p, "0.0.0.0:" + p, "[::1]:" + p, "[::]:" + p})
		if lan != "" {
			escBindDenied(e, []string{lan + ":" + p})
		}
	}
}

// escUnixConnect fails for each socket path in args prefixed "ok:" that cannot
// be connected to, and each prefixed "no:" that can.
func escUnixConnect(e *escT, args []string) {
	for _, a := range args {
		want, path, _ := strings.Cut(a, ":")
		c, err := dialTimeout("unix", path, 3*time.Second)
		switch {
		case want == "ok" && err != nil:
			e.failf("connect %s: %v", path, err)
		case want == "no" && err == nil:
			e.failf("connect %s: worked", path)
		case want == "no" && !isPerm(err):
			e.failf("connect %s: %v, want a refusal by the profile", path, err)
		}
		if c != nil {
			_ = c.Close()
		}
	}
}

// escTTY tries what a process can do to a terminal it was not handed: open
// each device in args, and type into the one on standard input.
func escTTY(e *escT, args []string) {
	// For reading as well as writing: reading another terminal's input
	// steals what its user types, and file-read of / shows it.
	for _, p := range args {
		for _, flags := range []int{os.O_RDWR, os.O_RDONLY | syscall.O_NONBLOCK} {
			f, err := openFileFlags(p, flags, 0)
			if err == nil {
				e.failf("open %s (flags %#x): worked", p, flags)
				_ = f.Close()
			} else if !isPerm(err) {
				e.failf("open %s: %v, want a refusal", p, err)
			}
		}
	}
	// TIOCSTI on the inherited descriptor, if it is a terminal.
	for _, b := range []byte("echo injected\n") {
		if err := ioctlPtr(0, unix.TIOCSTI, unsafe.Pointer(&b)); err == nil { //nolint:gosec // G103: the kernel reads or writes the buffer during the call, which keeps it valid.
			e.failf("TIOCSTI on standard input worked")
			return
		}
	}
}

// ioctlPtr is ioctl with a pointer argument.
func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)) //nolint:staticcheck // SA1019: Syscall passes the number to libc's syscall(2), and the test needs the raw ioctl that x/sys/unix has no typed wrapper for.
	if errno != 0 {
		return errno
	}
	return nil
}

// escPlantLink plants a link to args[0] at args[1], and then tries to read
// and write through it.
func escPlantLink(e *escT, args []string) {
	target, link := args[0], args[1]
	if err := os.Symlink(target, link); err != nil {
		e.failf("symlink: %v", err)
		return
	}
	escDenied(e, []string{filepath.Join(link, "secret"), link})
	escWritesDenied(e, []string{link})
}

// escWaitFile waits for args[0] to exist, then runs the check named by
// args[1] with the rest.
func escWaitFile(e *escT, args []string) {
	for range 600 {
		if _, err := os.Stat(args[0]); err == nil { //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if escChecks[args[1]] == nil {
		e.failf("no check %s", args[1])
		return
	}
	escChecks[args[1]](e, args[2:])
}

// escProcArgs fails unless it can read the environment of the pid in args[0],
// which the profile cannot prevent.
func escProcArgs(e *escT, args []string) {
	pid, _ := strconv.Atoi(args[0])
	b, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		e.failf("KERN_PROCARGS2: %v", err)
		return
	}
	if !bytes.Contains(b, []byte(args[1])) {
		e.failf("KERN_PROCARGS2 did not return %q", args[1])
	}
}

// escSetsidConnect starts a child that makes a session of its own, which the
// command, as the leader of its process group, cannot do itself, and dials the
// address in args[0]. It prints the session the command is in and the one the
// child is.
func escSetsidConnect(e *escT, args []string) {
	before, _ := unix.Getsid(0)
	cmd := exec.CommandContext(context.Background(), self1(), "esc", "dial-in-session", args[0]) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, os.Stderr
	if err := cmd.Run(); err != nil {
		e.failf("the child that made a session and dialed: %v", err)
		return
	}
	fmt.Println(before, strings.TrimSpace(out.String()))
}

func registerDialInSession() {
	escChecks["dial-in-session"] = func(e *escT, args []string) {
		sid, _ := unix.Getsid(0)
		network, addr := "tcp", args[0]
		if p, ok := strings.CutPrefix(addr, "unix-"); ok {
			network, addr = "unix", p
		}
		c, err := dialTimeout(network, addr, 3*time.Second)
		if err != nil {
			e.failf("dial after setsid: %v", err)
			return
		}
		// Hold the connection while the caller asks who is on the other end.
		time.Sleep(300 * time.Millisecond)
		_ = c.Close()
		fmt.Println(sid)
	}
}

// escDaemon starts a process that makes its own session and so leaves the
// command's process group, and tells the caller its pid and where it records
// what it can reach. args are the log file and the paths to try to read.
func escDaemon(e *escT, args []string) {
	cmd := exec.CommandContext(context.Background(), self1(), append([]string{"esc", "daemon-child"}, args...)...) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		e.failf("start the daemon: %v", err)
		return
	}
	fmt.Println(cmd.Process.Pid)
}

func self1() string { exe, _ := os.Executable(); return exe }

func registerDaemonChild() {
	escChecks["daemon-child"] = func(_ *escT, args []string) {
		log, paths := args[0], args[1:]
		for i := 0; ; i++ {
			var worked []string
			for _, p := range paths {
				if _, err := readFile(p); err == nil {
					worked = append(worked, p)
				}
			}
			if c, err := dialTimeout("tcp", "1.1.1.1:443", 200*time.Millisecond); err == nil {
				worked = append(worked, "net")
				_ = c.Close()
			}
			f, err := openFileFlags(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err == nil {
				if _, err := fmt.Fprintf(f, "%d pid=%d worked=%v\n", i, os.Getpid(), worked); err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
				_ = f.Close()
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// escReopen reopens the descriptor in fd 3 through /dev/fd, for writing, and
// writes to the descriptor in fd 4 directly. It reports which worked.
func escReopen(_ *escT, _ []string) {
	f, err := os.OpenFile("/dev/fd/3", os.O_WRONLY|os.O_TRUNC, 0)
	if err == nil {
		fmt.Println("reopen: worked")
		_ = f.Close()
	} else {
		fmt.Println("reopen:", err)
	}
	w := os.NewFile(4, "out")
	if _, err := w.WriteString("direct\n"); err == nil {
		fmt.Println("direct: worked")
	} else {
		fmt.Println("direct:", err)
	}
}

// ---------------------------------------------------------------- the view

// userHomeOnData makes a directory under the account's real home, which is
// under /Users, with a secret in it, and returns the secret's path. The
// directory is removed at the end of the test.
func userHomeSecret(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	if home, err = filepath.EvalSymlinks(home); err != nil || !strings.HasPrefix(home, "/Users/") {
		t.Skipf("the home %q is not under /Users", home)
	}
	dir, err := os.MkdirTemp(home, ".sandbox-escape-test-")
	if err != nil {
		t.Skipf("cannot write in the home: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return writeFile(t, "top secret\n", dir, "secret")
}

// Row: "Read-only root; covers; default covers; people's homes; the account's
// own home". Every default cover hides what is under it, whatever name the
// path is reached by: through the /var and /tmp links, and through
// /System/Volumes/Data, which is the same files under another name.
func TestEscapeDefaultCovers(t *testing.T) {
	t.Parallel()
	inHome := userHomeSecret(t)
	inVar := hostSecret(t) // under /private/var/folders
	tmpDir, err := os.MkdirTemp("/private/tmp", "sandbox-escape-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	inTmp := writeFile(t, "top secret\n", tmpDir, "secret")

	var paths []string
	add := func(p string) { paths = append(paths, p) }
	for _, p := range []string{inHome, inVar, inTmp} {
		add(p)
		add(filepath.Dir(p))
		// The data volume's own name for each of these.
		add("/System/Volumes/Data" + p)
	}
	add(strings.Replace(inVar, "/private/var", "/var", 1))
	add(strings.Replace(inTmp, "/private/tmp", "/tmp", 1))
	// The directories themselves, which a listing would show.
	for _, d := range []string{"/Users", "/Volumes", "/private/var", "/private/tmp", "/var", "/tmp", "/private/var/folders", "/Users/Shared"} {
		if _, err := os.Stat(d); err == nil {
			add(d)
		}
	}
	// And the same, through the data volume.
	add("/System/Volumes/Data/Users")
	add("/System/Volumes/Data/private/var/db")
	// Outside the sandbox every one of them is there.
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("setup: %s is not there outside the sandbox: %v", p, err)
		}
	}
	escRun(t, Spec{}, "denied", paths...)
}

// Row: "Read-only root". What a program needs of the host is readable, and the
// few paths under a default cover that it needs are shown: /bin/sh finds its
// shell by /private/var/select, and /etc/localtime leads into
// /private/var/db/timezone.
func TestEscapeViewShowsHost(t *testing.T) {
	t.Parallel()
	escRun(t, Spec{}, "allowed", "/usr/bin/true", "/bin/sh", "/System/Library", "/usr/lib", "/etc/hosts", "/etc/localtime",
		"/private/etc/hosts", "/private/var/select", "/private/var/db/timezone", "/Applications", "/dev/urandom", "/usr/share")
	// A shell script runs, which needs /private/var/select.
	if out := shOK(t, Spec{}, "echo ok"); out != "ok\n" {
		t.Errorf("echo = %q", out)
	}
	// And so does an interpreter's #! line, since process-exec-interpreter
	// is allowed with the rest.
	home := realTemp(t)
	script := filepath.Join(home, "s")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho from script\n"), 0o700); err != nil { //nolint:gosec // G306: the file is a program the test runs, which needs its owner to execute it.
		t.Fatal(err)
	}
	if out := shOK(t, Spec{Home: home}, script); out != "from script\n" {
		t.Errorf("script = %q", out)
	}
}

// Row: "Legwork's config, state, and other sandboxes' directories covered" and the
// Cover field: each cover hides what is under it, and a Read path and a Cover
// inside it behave as nested binds do: the nearest rule above a path decides.
func TestEscapeCover(t *testing.T) {
	t.Parallel()
	// A cover outside every default cover.
	spec := Spec{Cover: []string{"/usr/share/man"}}
	if _, err := os.Stat("/usr/share/man"); err != nil {
		t.Skip("no /usr/share/man to cover")
	}
	escRun(t, spec, "denied", "/usr/share/man", "/usr/share/man/man1")
	escRun(t, Spec{}, "allowed", "/usr/share/man")

	// Nested: a Read path shows a directory under the covered temporary
	// directory, a Cover inside it hides a part, a Read inside that shows a
	// part again, and a sibling of each stays hidden or shown by the rule above.
	root := realTemp(t)
	tool := mkdirs(t, root, "tool")
	secrets := mkdirs(t, tool, "secrets")
	pub := mkdirs(t, secrets, "public")
	mkdirs(t, root, "sibling")
	for _, p := range []string{filepath.Join(tool, "bin"), filepath.Join(secrets, "key"), filepath.Join(pub, "readme"), filepath.Join(root, "sibling", "f")} {
		writeFile(t, "x", p)
	}
	nested := Spec{Read: []string{tool, pub}, Cover: []string{secrets}}
	escRun(t, nested, "allowed", filepath.Join(tool, "bin"), filepath.Join(pub, "readme"), pub)
	escRun(t, nested, "denied", filepath.Join(secrets, "key"), secrets, filepath.Join(root, "sibling", "f"))
	// A cover at the same path as a read path shows it, as a bind shows
	// what a cover would have hidden.
	same := Spec{Read: []string{tool}, Cover: []string{tool}}
	escRun(t, same, "allowed", filepath.Join(tool, "bin"))
}

// Row: "Path and link rules": Read shows a path under a cover; a link in it
// is followed by the kernel, and the profile decides by where it leads.
func TestEscapeReadFollowsLinksOut(t *testing.T) {
	t.Parallel()
	root := realTemp(t)
	shown := mkdirs(t, root, "shown")
	hidden := mkdirs(t, root, "hidden")
	writeFile(t, "secret", hidden, "secret")
	if err := os.Symlink(hidden, filepath.Join(shown, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(hidden, "secret"), filepath.Join(shown, "file")); err != nil {
		t.Fatal(err)
	}
	escRun(t, Spec{Read: []string{shown}}, "denied", filepath.Join(shown, "out", "secret"), filepath.Join(shown, "out"), filepath.Join(shown, "file"))
}

// Row: "Read-only root" and "Write outside Home": nothing outside Home and the
// Write paths can be written, whatever the path.
func TestEscapeWriteOutside(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	write := mkdirs(t, realTemp(t), "w")
	read := mkdirs(t, realTemp(t), "r")
	sub := mkdirs(t, home, "sub")
	cwd, _ := os.Getwd()
	denied := []string{
		"/", "/usr", "/usr/local", "/usr/bin", "/Library", "/private/etc", "/etc", "/Applications", "/private/tmp", "/tmp",
		"/private/var/tmp", filepath.Dir(home), read, filepath.Dir(write), "/System/Volumes/Data" + filepath.Dir(home),
	}
	if userHome, err := os.UserHomeDir(); err == nil {
		denied = append(denied, userHome)
	}
	denied = append(denied, cwd)
	spec := Spec{Home: home, Write: []string{write}, Read: []string{read}}
	escRun(t, spec, "writes-denied", denied...)
	escRun(t, spec, "writes-allowed", home, sub, write)
	// The home's own name through the data volume is the same place.
	escRun(t, spec, "writes-allowed", "/System/Volumes/Data"+home)
}

// Row: "Path and link rules ... a link inside it pointing out": a link the
// sandbox plants in its home, to a directory under a cover, leads nowhere
// the profile does not already show, so nothing is read or written through
// it. The next run's Start refuses a home with such a link in its path.
func TestEscapePlantedLink(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	secret := hostSecret(t)
	target := filepath.Dir(secret)
	escRun(t, Spec{Home: home}, "plant-link", target, filepath.Join(home, "planted"))
	// The link is there for the next run, whose Home may not go through it,
	// and whose Write path may not either.
	c, err := Command(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: filepath.Join(home, "planted")})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err == nil || !strings.Contains(err.Error(), "link") {
		t.Errorf("Start with a home through the planted link = %v", err)
	}
	c, err = Command(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: realTemp(t), Write: []string{filepath.Join(home, "planted")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err == nil || !strings.Contains(err.Error(), "link") {
		t.Errorf("Start with a write path through the planted link = %v", err)
	}
}

// Row: "Bind sources by fd with RESOLVE_NO_SYMLINKS; a cover that became a
// link aborts": there are no fds on macOS, and Seatbelt matches the path a
// file has when it is opened. A Write directory that another process swaps for
// a link after the profile is written gives the sandbox nothing: its path now
// leads elsewhere, to a place the rule does not name. This is the host doing
// the swap. The sandbox doing it to its own Home or Write path, which is the
// other half, is TestEscapeRootsCannotBeSwapped.
func TestEscapeSwappedAfterStart(t *testing.T) {
	t.Parallel()
	root := realTemp(t)
	write := mkdirs(t, root, "w")
	secrets := mkdirs(t, root, "secrets")
	writeFile(t, "secret", secrets, "secret")
	writeFile(t, "inside", write, "inside")
	home := realTemp(t)
	gate := filepath.Join(home, "go")
	// Once the swap is made, the sandbox tries to read the secret by the
	// Write path, to write by it, and to list it.
	c := escCmd(t.Context(), t, Spec{Home: home, Write: []string{write}}, "wait-file", gate, "unreadable", filepath.Join(write, "secret"), filepath.Join(write, "inside"), write)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	// Swap: the directory becomes a link to the secrets.
	if err := os.Rename(write, write+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secrets, write); err != nil {
		t.Fatal(err)
	}
	writeFile(t, "", gate)
	if err := c.Wait(); err != nil {
		t.Errorf("the sandbox reached something through the swapped link: %v\n%s", err, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(secrets, ".esc-write")); err == nil {
		t.Error("the sandbox wrote through the swapped link")
	}
}

// Row: "Path and link rules ... a missing cover inside a writable dir aborts;
// no mount inside a writable dir; cwd must be shown": Start refuses these
// layouts, as the Linux backend does, since the rules are the shared ones.
func TestEscapeStartRefusesLayouts(t *testing.T) {
	t.Parallel()
	root := realTemp(t)
	home := mkdirs(t, root, "home")
	state := mkdirs(t, home, "state")
	mkdirs(t, root, "other")
	for _, tc := range []struct {
		name string
		spec Spec
		want string
	}{
		{"a cover inside the home", Spec{Home: home, Cover: []string{state}}, "inside"},
		{"a cover that moved away from the home", Spec{Home: home, Cover: []string{filepath.Join(home, "gone")}}, "missing"},
		{"a write path inside the home", Spec{Home: home, Write: []string{state}}, "inside"},
		{"a read path inside the home", Spec{Home: home, Read: []string{state}}, "inside"},
		{"a dir under a cover", Spec{Home: home, Dir: "/Users"}, "covered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.spec.Command = []string{"/usr/bin/true"}
			c, err := Command(t.Context(), tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Start(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Start = %v, want an error with %q", err, tc.want)
			}
		})
	}
}

// Row: "/etc links into covered dirs rebound": /etc is a link to /private/etc,
// and /etc/localtime leads under a cover. Both read.
func TestEscapeEtcLinks(t *testing.T) {
	t.Parallel()
	want, err := os.ReadFile("/etc/localtime")
	if err != nil {
		t.Skip("no /etc/localtime")
	}
	got := shOK(t, Spec{}, "cat /etc/localtime")
	if got != string(want) {
		t.Errorf("/etc/localtime inside is %d bytes, outside %d", len(got), len(want))
	}
	if shOK(t, Spec{}, "cat /etc/hosts") == "" {
		t.Error("/etc/hosts is empty")
	}
}

// Row: "Mount-table covers": there is no .zfs, and other volumes are under
// /Volumes, which is covered. The data volume's own name for the covered
// places is covered too, which TestEscapeDefaultCovers checks. Mounting an
// APFS snapshot needs root, so that case is not tried.
func TestEscapeOtherVolumes(t *testing.T) {
	t.Parallel()
	ents, err := os.ReadDir("/Volumes")
	if err != nil || len(ents) == 0 {
		t.Skip("no volume to try")
	}
	paths := make([]string, 0, len(ents)+1)
	for _, e := range ents {
		paths = append(paths, "/Volumes/"+e.Name())
	}
	escRun(t, Spec{}, "denied", append(paths, "/Volumes")...)
}

// Row: "Scratch tmpfs ...: none. TMPDIR is in Home": TMPDIR is a directory in
// the home, and there is no size cap on it beyond RLIMIT_FSIZE per file. A
// Spec.ScratchSize does not bound it.
func TestGapScratchUnbounded(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	out := shOK(t, Spec{Home: home, ScratchSize: 1 << 20}, `dd if=/dev/zero of="$TMPDIR/big" bs=1048576 count=8 2>/dev/null; wc -c < "$TMPDIR/big"`)
	if n, _ := strconv.Atoi(strings.TrimSpace(out)); n != 8<<20 {
		t.Errorf("wrote %q bytes under a ScratchSize of 1 MiB, want 8 MiB: the gap closed", out)
	}
}

// Row: "Path and link rules": a Home or Write path with a character a profile
// cannot hold is refused, and the ones it can are escaped, so a name with a
// quote, a backslash, parentheses, a semicolon, a space or non-ASCII holds
// exactly that directory, and a sibling that shares a prefix is not shown.
func TestEscapeProfileQuoting(t *testing.T) {
	t.Parallel()
	root := realTemp(t)
	for _, name := range []string{`a"b`, `a\b`, `a (b)`, `a;b`, `a b`, `a#b`, `héllo ☃`, `a"); (allow default`, `\"`} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := mkdirs(t, root, name)
			sibling := mkdirs(t, root, name+"2")
			prefix := mkdirs(t, root, strings.TrimRight(name, `"\`)) // may equal dir
			_ = prefix
			spec := Spec{Home: dir, Read: []string{sibling}}
			escRun(t, spec, "writes-allowed", dir)
			// The sibling is readable only as a Read path, so its files
			// are not writable, and a directory that shares the prefix
			// but was not named is covered like the rest of /private/var.
			other := mkdirs(t, root, name+"-unnamed")
			escRun(t, spec, "writes-denied", sibling, other)
			escRun(t, spec, "denied", other)
		})
	}
	// A control character cannot be named in a profile, and a path with one
	// is refused rather than guessed at.
	bad := root + "/new\nline"
	if err := os.Mkdir(bad, 0o750); err != nil {
		t.Fatal(err)
	}
	// A Cover is not tried: it lies under /private/var, which is covered, so
	// the profile never names it.
	for _, spec := range []Spec{{Home: bad}, {Home: realTemp(t), Read: []string{bad}}, {Home: realTemp(t), Write: []string{bad}}} {
		spec.Command = []string{"/usr/bin/true"}
		c, err := Command(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Start(); err == nil || !strings.Contains(err.Error(), "control character") {
			t.Errorf("Start with a newline in a path = %v", err)
		}
	}
}

// Row: "Seatbelt profile: deny default, covers as denies after the broad allow":
// code under a cover cannot run, and code in the home can.
func TestEscapeExec(t *testing.T) {
	t.Parallel()
	secret := hostSecret(t)
	hidden := filepath.Join(filepath.Dir(secret), "true")
	copyFile(t, "/usr/bin/true", hidden)
	home := realTemp(t)
	inHome := filepath.Join(home, "true")
	copyFile(t, "/usr/bin/true", inHome)
	escRun(t, Spec{Home: home}, "exec-denied", hidden)
	if r := sh(t, Spec{Home: home}, inHome); r.code != 0 {
		t.Errorf("a program the sandbox owns does not run: %s", r)
	}
	if r := sh(t, Spec{Home: home, Read: []string{filepath.Dir(hidden)}}, hidden); r.code != 0 {
		t.Errorf("a program under a Read path does not run: %s", r)
	}
}

// copyFile copies src to dst, executable.
func copyFile(t testing.TB, src, dst string) {
	t.Helper()
	b, err := readFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o700); err != nil { //nolint:gosec // G306: the file is a program the test runs, which needs its owner to execute it.
		t.Fatal(err)
	}
}

// Row: "First stage: no capabilities to drop. Test that a setuid binary can't
// escape the profile, such as sudo": a setuid program cannot be run inside a
// profile at all, so one cannot be used to act as root.
func TestEscapeSetuid(t *testing.T) {
	t.Parallel()
	var setuid []string
	for _, p := range []string{"/usr/bin/sudo", "/bin/ps", "/usr/bin/su", "/usr/bin/login", "/usr/bin/crontab", "/usr/bin/top"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSetuid != 0 {
			setuid = append(setuid, p)
		}
	}
	if len(setuid) == 0 {
		t.Skip("no setuid program found")
	}
	// Outside the sandbox at least one of them runs.
	if err := exec.CommandContext(context.Background(), "/bin/ps", "-p", "1").Run(); err != nil {
		t.Skipf("ps does not run outside the sandbox: %v", err)
	}
	escRun(t, Spec{}, "exec-denied", setuid...)
	r := sh(t, Spec{}, "/usr/bin/sudo -n true; echo status $?")
	if strings.Contains(r.stdout, "status 0") {
		t.Errorf("sudo ran in the sandbox: %s", r)
	}
}

// ---------------------------------------------------------------- processes

// Row: "No pid namespace ... Deny process-info* and signal outside the
// sandbox, and test KERN_PROCARGS2 and kill on the parent" and "Own process
// group...no signals or priority changes reach the caller's group": nothing
// outside can be signaled, reniced, or asked about, whether by pid, by group,
// by broadcast or by user. The caller, its parent, the stage that supervises
// the sandbox, init, a canary in the caller's group and one in another all
// stay untouched.
func TestEscapeSignalsStayInside(t *testing.T) {
	t.Parallel()
	inGroup, dirA := canary(t, false)
	otherGroup, dirB := canary(t, true)
	home := realTemp(t)
	gate := filepath.Join(home, "go")
	// The stage's pid is known only after Start, so the check reads its
	// targets from a file the test writes then.
	cmd, err := Command(t.Context(), Spec{Home: home, Command: []string{self(t), "esc", "wait-file", gate, "signals-from-file", filepath.Join(home, "pids")}})
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = []string{}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, fmt.Sprintf("%d\n%d\n%d\n%d\n%d\n1\n", cmd.Pid(), os.Getpid(), os.Getppid(), inGroup, otherGroup), home, "pids")
	writeFile(t, "", gate)
	if err := cmd.Wait(); err != nil {
		t.Errorf("a signal got out, or a priority changed, or process-info worked: %v\n%s", err, stderr.String())
	}
	time.Sleep(200 * time.Millisecond)
	for name, dir := range map[string]string{"the canary in the caller's group": dirA, "the canary in another group": dirB} {
		if got := gotSignals(dir); got != "" {
			t.Errorf("%s was signaled: %s", name, got)
		}
	}
	if !alive(inGroup) || !alive(otherGroup) {
		t.Error("a canary died")
	}
}

func registerSignalsFromFile() {
	escChecks["signals-from-file"] = func(e *escT, args []string) {
		b, err := os.ReadFile(args[0]) //nolint:gosec // G703: the path is an argument the test passed to this child, whose job is to try it.
		if err != nil {
			e.failf("read pids: %v", err)
			return
		}
		escSignals(e, strings.Fields(string(b)))
		escProcInfo(e, strings.Fields(string(b)))
	}
}

// Row: "No pid namespace ... process-info": proc_pidinfo and proc_pid_rusage
// of a process outside are refused, though they work on the sandbox's own.
func TestEscapeProcessInfo(t *testing.T) {
	t.Parallel()
	pid, _ := canary(t, false)
	escRun(t, Spec{}, "procinfo", strconv.Itoa(pid), strconv.Itoa(os.Getpid()), strconv.Itoa(os.Getppid()), "1")
	// Outside, the same calls work, so the refusal is the profile's.
	var buf [256]byte
	if _, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, 2, uintptr(pid), 3, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); errno != 0 { //nolint:gosec,staticcheck // G103: the kernel reads or writes the buffer during the call, which keeps it valid. SA1019: Syscall6 passes the number to libc's syscall(2), and libproc has no binding without cgo.
		t.Fatalf("proc_pidinfo outside: %v", errno)
	}
}

// Row: "No pid namespace": processes of the same uid are visible, and Seatbelt
// cannot deny KERN_PROCARGS2, so a sandbox reads another process's environment.
// This documents the gap, and fails when it closes.
func TestGapProcessEnvironment(t *testing.T) {
	t.Parallel()
	dir := realTemp(t)
	cmd := exec.CommandContext(t.Context(), self(t), "canary", dir) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	cmd.Env = []string{"SANDBOX_GAP_SECRET=hunter2-gap"}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	eventually(t, 10*time.Second, "the canary did not start", func() bool { _, err := os.Stat(filepath.Join(dir, "ready")); return err == nil })
	pid, secret := strconv.Itoa(cmd.Process.Pid), "SANDBOX_GAP_SECRET=hunter2-gap" //nolint:gosec // G101: a made-up value for the test to hide, not a credential.
	escRun(t, Spec{}, "procargs", pid, secret)
	// A profile that denies the sysctl by name and every process-info
	// operation makes no difference, which is why this is a gap and not a rule.
	profile := "(version 1)\n(allow default)\n(deny process-info*)\n(deny sysctl-read (sysctl-name \"kern.procargs2\"))\n"
	out, err := exec.CommandContext(t.Context(), sandboxExec, "-p", profile, self(t), "esc", "procargs", pid, secret).CombinedOutput() //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	if err != nil {
		t.Errorf("a profile that denies it stopped it, so the gap closed: %v\n%s", err, out)
	}
}

// Row: "Teardown: pid 1 dies, all die" is the process group and the profile's
// marker on macOS: when the command exits, everything left in its group is
// ended, as a background process the command forked and forgot. Those that left
// the group are TestEscapeSetpgidAndJobControl's.
func TestEscapeTeardownEndsGroup(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	marker := filepath.Join(home, "pid")
	r := sh(t, Spec{Home: home}, `/bin/sleep 300 & echo $! > "$1"; exit 0`, marker)
	if r.code != 0 {
		t.Fatal(r)
	}
	b, _ := readFile(marker)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid == 0 {
		t.Fatal("no pid")
	}
	eventually(t, 5*time.Second, "a background process outlived its command", func() bool { return !alive(pid) })
}

// Row: "Teardown ... on parent death": when the caller dies, however it dies,
// the stage reads EOF on the lifeline and ends the sandbox. The caller here
// is a process of its own that starts a sandbox and is then killed with
// SIGKILL.
func TestEscapeParentKilled(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	marker := filepath.Join(home, "pid")
	body := jsonArg(t, Spec{Home: home, Command: []string{self(t), "esc", "hold", marker}})
	parent := exec.CommandContext(t.Context(), self(t), "esc-parent", body) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	var stderr syncBuffer
	parent.Stderr = &stderr
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "the sandbox did not start", func() bool { _, err := os.Stat(marker); return err == nil })
	b, _ := readFile(marker)
	inner, _ := strconv.Atoi(string(b))
	if !alive(inner) {
		t.Fatal("the command is not running")
	}
	_ = parent.Process.Signal(syscall.SIGKILL)
	_ = parent.Wait()
	eventually(t, 10*time.Second, "the command outlived its caller", func() bool { return !alive(inner) })
}

func registerEscParent() {
	// esc-parent starts a sandbox from the Spec in args[0] and waits for it.
	childModes["esc-parent"] = func(args []string) int {
		var spec Spec
		if err := jsonUnmarshal(args[0], &spec); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 98
		}
		c, err := Command(context.Background(), spec)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 99
		}
		c.Env = []string{}
		if err := c.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 99
		}
		_ = c.Wait()
		return 0
	}
}

// Row: the same for a stage that is itself killed: Wait then ends the group,
// which the stage could not.
func TestEscapeStageKilled(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	marker := filepath.Join(home, "pid")
	c := escCmd(t.Context(), t, Spec{Home: home}, "hold", marker)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "no start", func() bool { _, err := os.Stat(marker); return err == nil })
	b, _ := readFile(marker)
	inner, _ := strconv.Atoi(string(b))
	_ = syscall.Kill(c.Pid(), syscall.SIGKILL)
	err := c.Wait()
	if err == nil {
		t.Error("Wait after the stage was killed returned nil")
	}
	eventually(t, 5*time.Second, "the command outlived its killed stage", func() bool { return !alive(inner) })
}

// ---------------------------------------------------------------- network

// Row: "Network namespace, proxy listener handed out": with NetworkNone the
// sandbox reaches no address: a public one, a local listener on 127.0.0.1,
// ::1 or the host's LAN address, a UDP resolver. It cannot resolve names or
// connect to the sockets of system services.
func TestEscapeNetworkNone(t *testing.T) {
	t.Parallel()
	port := listenAny(t)
	targets := []string{
		"tcp:1.1.1.1:443", "tcp:127.0.0.1:" + strconv.Itoa(port), "tcp:[::1]:" + strconv.Itoa(port),
		"udp:9.9.9.9:53", "tcp:169.254.169.254:80",
	}
	if lan := lanAddr(); lan != "" {
		targets = append(targets, "tcp:"+lan+":"+strconv.Itoa(port))
	}
	escRun(t, Spec{}, "dial-denied", targets...)
	// Names do not resolve: the resolver needs the network.
	if r := sh(t, Spec{}, "/usr/bin/curl -sS -m 5 -o /dev/null https://example.com; echo status $?"); strings.Contains(r.stdout, "status 0") {
		t.Errorf("curl reached the internet with NetworkNone: %s", r)
	}
	// The sockets of system services, which are covered paths, and the ones
	// that are not.
	escRun(t, Spec{}, "unix-connect", "no:/private/var/run/mDNSResponder", "no:/var/run/mDNSResponder", "no:/var/run/syslog")
}

// Row: "parent-bound port allowed by number ... Test that other ports
// refuse": the Listen ports and nothing else, on 127.0.0.1 and ::1 alike.
func TestEscapeListenPortsOnly(t *testing.T) {
	t.Parallel()
	other := listenAny(t)
	c := escCmd(t.Context(), t, Spec{Listen: 2}, "dial-each")
	addrs := c.ListenAddrs()
	c.spec.Command = append([]string{self(t), "esc", "dial-each"}, addrs...)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	drain(c.Listeners())
	if err := c.Wait(); err != nil {
		t.Fatalf("the Listen ports are not reachable: %v", err)
	}
	// Other ports, including the neighbors of the allowed ones.
	denied := make([]string, 0, 3*len(addrs)+2)
	for _, a := range addrs {
		_, p, _ := net.SplitHostPort(a)
		n, _ := strconv.Atoi(p)
		for _, d := range []int{-1, 1} {
			denied = append(denied, "tcp:127.0.0.1:"+strconv.Itoa(n+d))
		}
		denied = append(denied, "tcp:[::1]:"+p)
	}
	denied = append(denied, "tcp:127.0.0.1:"+strconv.Itoa(other), "tcp:[::1]:"+strconv.Itoa(other))
	c2 := escCmd(t.Context(), t, Spec{Listen: 1}, "dial-denied", denied...)
	if err := c2.Start(); err != nil {
		t.Fatal(err)
	}
	drain(c2.Listeners())
	var errb bytes.Buffer
	c2.Stderr = &errb
	if err := c2.Wait(); err != nil {
		t.Errorf("another port was reachable: %v\n%s", err, errb.String())
	}
}

// drain accepts and closes connections on each listener until it is closed.
func drain(ls []net.Listener) {
	for _, l := range ls {
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
}

// Row: "Network namespace ... Loopback": the Loopback ports can be bound and
// dialed from inside, and no other port can be bound, on 127.0.0.1, ::1, the
// wildcard or the LAN address (TestEscapeLoopbackPortsAllAddresses adds UDP and
// a connection from outside, and TestGapLoopbackBindsLANAddress the gap that
// the given ports themselves bind on all of them).
func TestEscapeLoopbackPorts(t *testing.T) {
	t.Parallel()
	c := escCmd(t.Context(), t, Spec{Loopback: 2}, "loopback")
	ports := c.LoopbackPorts()
	c.spec.Command = []string{self(t), "esc", "loopback", strconv.Itoa(ports[0]), strconv.Itoa(ports[1])}
	var errb bytes.Buffer
	c.Stderr = &errb
	if r := execute(t, c); r.code != 0 {
		t.Errorf("%s", r)
	}
}

// Row: "Network: BroadLoopback only by opt-in": without it a sandbox reaches no
// local listener, with it, it reaches every one on any of the host's own
// addresses. That is the reported gap (docs/macos.md, M1): the test documents it,
// and fails if a per-port deny ever becomes reliable.
func TestGapBroadLoopback(t *testing.T) {
	t.Parallel()
	port := listenAny(t)
	p := strconv.Itoa(port)
	targets := []string{"tcp:127.0.0.1:" + p, "tcp:[::1]:" + p}
	if lan := lanAddr(); lan != "" {
		targets = append(targets, "tcp:"+lan+":"+p)
	}
	escRun(t, Spec{}, "dial-denied", targets...)
	escRun(t, Spec{BroadLoopback: true}, "dial-ok", targets...)
	escRun(t, Spec{BroadLoopback: true, Network: NetworkHost}, "dial-ok", targets...)
	// A sandbox with it can listen too, which Loopback does for named ports.
	escRun(t, Spec{BroadLoopback: true}, "bind-ok", "127.0.0.1:0")
	escRun(t, Spec{}, "bind-denied", "127.0.0.1:0")
	// It is wider than the dial: bind and accept on every address and any port,
	// the wildcard and the LAN address too, and UDP as well as TCP.
	bind := []string{"0.0.0.0:0", "[::]:0"}
	if lan := lanAddr(); lan != "" {
		bind = append(bind, lan+":0")
	}
	escRun(t, Spec{BroadLoopback: true}, "bind-ok", bind...)
	escRun(t, Spec{BroadLoopback: true}, "udp-ok")
	escRun(t, Spec{}, "bind-denied", bind...)
}

// Row: "Network: NetworkHost (asked for explicitly): allow outbound, deny
// localhost": the sandbox reaches the internet and no local listener, over
// 127.0.0.1, ::1 and the LAN address, and for every one of a run of ports,
// since a per-port rule after a broad allow is what failed in M1.
func TestEscapeNetworkHost(t *testing.T) {
	t.Parallel()
	conn, err := dialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	if err != nil {
		t.Skipf("no internet to reach outside the sandbox: %v", err)
	}
	_ = conn.Close()
	spec := Spec{Network: NetworkHost}
	escRun(t, spec, "dial-ok", "tcp:1.1.1.1:443")
	// Names resolve, through the system resolver.
	if r := sh(t, spec, "/usr/bin/curl -sS -m 10 -o /dev/null -w '%{http_code}' https://example.com"); r.code != 0 || !strings.HasPrefix(r.stdout, "2") && !strings.HasPrefix(r.stdout, "3") {
		t.Errorf("curl with NetworkHost: %s", r)
	}
	var targets []string
	lan := lanAddr()
	for range 40 {
		l, err := listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		p := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
		targets = append(targets, "tcp:127.0.0.1:"+p, "tcp:[::1]:"+p)
		if lan != "" {
			targets = append(targets, "tcp:"+lan+":"+p)
		}
	}
	escRun(t, spec, "dial-denied", targets...)
	// A sandbox cannot listen either.
	escRun(t, spec, "bind-denied", "127.0.0.1:0", "0.0.0.0:0")
	// UDP to localhost is refused too.
	udp, err := listenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	escRun(t, spec, "dial-denied", "udp:127.0.0.1:"+strconv.Itoa(udp.LocalAddr().(*net.UDPAddr).Port))
}

// Row: "Seatbelt profile: ... mcp.sock by path": a unix socket in Write connects
// only when it is itself a Write path. Another socket in a Write directory,
// the home, or anywhere under a cover does not, and a sandbox cannot bind a
// socket of its own.
func TestEscapeUnixSockets(t *testing.T) {
	t.Parallel()
	dir := realTemp(t)
	listen := func(path string) {
		l, err := listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	// Socket paths are short on macOS, so these live in a short directory.
	short, err := os.MkdirTemp("/private/tmp", "sbx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	mcp, other, covered := filepath.Join(short, "mcp.sock"), filepath.Join(short, "other.sock"), filepath.Join(dir, "c.sock")
	listen(mcp)
	listen(other)
	listen(covered)
	wdir := mkdirs(t, short, "w")
	inDir := filepath.Join(wdir, "in.sock")
	listen(inDir)
	home := realTemp(t)
	inHome := filepath.Join(home, "h.sock")
	listen(inHome)
	spec := Spec{Home: home, Write: []string{mcp, wdir}}
	escRun(t, spec, "unix-connect", "ok:"+mcp, "no:"+other, "no:"+covered, "no:"+inDir, "no:"+inHome)
	// Under NetworkHost too.
	spec.Network = NetworkHost
	escRun(t, spec, "unix-connect", "ok:"+mcp, "no:"+other, "no:"+covered, "no:"+inDir, "no:"+inHome)
	// Binding a socket is refused.
	r := sh(t, spec, `/usr/bin/nc -l -U "$1/new.sock" 2>&1 & sleep 1; kill $! 2>/dev/null; ls "$1" 2>&1`, home)
	if strings.Contains(r.stdout, "new.sock") {
		t.Errorf("the sandbox bound a unix socket: %s", r)
	}
}

// ---------------------------------------------------------------- mach services and launch services

// Row: "Seatbelt profile: ... mach services" and "no kernel keyrings. The
// keychain is the equivalent. Test that it is unreachable": a lookup of a
// service outside the requested groups fails. Each of these tools works
// outside the sandbox and needs a service: Directory Services answers the
// first, and the keychain's search list and its items come from securityd and
// the user's cfprefs, which hold the login keychain's path.
func TestEscapeMachLookups(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, cmd string
		leak      string // what the answer must not hold inside
	}{
		{"Directory Services", "/usr/bin/dscl . -read /Users/root UniqueID", "UniqueID: 0"},
		{"keychain search list", "/usr/bin/security list-keychains", "keychain"},
		{"keychain item", "/usr/bin/security find-generic-password -s sandbox-test-no-such-item", "SecKeychainSearchCreateFromAttributes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			outside, err := exec.CommandContext(t.Context(), "/bin/sh", "-c", tc.cmd+" 2>&1").Output() //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
			if err != nil && tc.name == "Directory Services" {
				t.Skipf("does not work outside the sandbox: %v", err)
			}
			r := sh(t, Spec{}, tc.cmd+" 2>&1")
			if r.stdout == string(outside) {
				t.Errorf("the same answer inside the sandbox as outside:\n%s", r.stdout)
			}
			if tc.name != "keychain item" && strings.Contains(r.stdout, tc.leak) {
				t.Errorf("the sandbox got %q: %s", tc.leak, r.stdout)
			}
		})
	}
}

// Row: "no kernel keyrings. The keychain is the equivalent": the user's login
// keychain is a file under the covered home, and a sandbox cannot read it.
func TestEscapeKeychainFiles(t *testing.T) {
	t.Parallel()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home")
	}
	var paths []string
	for _, p := range []string{"Library/Keychains", "Library/Keychains/login.keychain-db", "Library/Application Support/com.apple.TCC"} {
		full := filepath.Join(home, p)
		if _, err := os.Stat(full); err == nil {
			paths = append(paths, full)
		}
	}
	if len(paths) == 0 {
		t.Skip("no keychain files under the home")
	}
	escRun(t, Spec{}, "denied", paths...)
}

// Row: "Seatbelt profile: ... never lsopen" and M3: opening an app or a URL
// through LaunchServices fails under every Services group, even one that
// allows the lookup of launchservicesd, and starts nothing outside the
// profile: no app is launched, and the default browser does not fetch.
func TestEscapeLaunchServices(t *testing.T) {
	t.Parallel()
	beacon := make(chan string, 16)
	ln, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadString('\n')
			beacon <- line
			_ = c.Close()
		}
	}()
	url := "http://" + ln.Addr().String() + "/sandbox-lsopen-beacon"
	// Anything that is running already is not this test's, and anything this
	// test starts is ended with it, so a miscount cannot carry to a later run.
	before := calculators(t)
	t.Cleanup(func() {
		for pid := range calculators(t) {
			if _, old := before[pid]; !old {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	for _, services := range [][]Service{nil, {ServiceFirefox}, {ServiceFirefox, ServiceDirectory}} {
		spec := Spec{Services: services, BroadLoopback: true}
		for _, cmd := range []string{
			"/usr/bin/open -g /System/Applications/Calculator.app",
			"/usr/bin/open -g " + url,
			`/usr/bin/osascript -e 'tell application "Calculator" to launch'`,
			`/usr/bin/open -g -a Calculator`,
		} {
			r := sh(t, spec, cmd+"; echo status $?")
			if strings.Contains(r.stdout, "status 0") {
				t.Errorf("services %v: %q succeeded: %s", services, cmd, r)
			}
			// An app starts a moment after it is asked to, so look for it
			// after each attempt, and say which attempt it followed.
			time.Sleep(300 * time.Millisecond)
			for pid, comm := range calculators(t) {
				if _, old := before[pid]; !old {
					t.Errorf("services %v: %q launched an app outside the profile: pid %d, %s", services, cmd, pid, comm)
					_ = syscall.Kill(pid, syscall.SIGKILL)
					before[pid] = comm
				}
			}
		}
	}
	time.Sleep(500 * time.Millisecond)
	select {
	case line := <-beacon:
		t.Errorf("a URL opened from inside the sandbox reached the beacon: %q", line)
	default:
	}
}

// calculators returns the pids of running Calculator apps, by the path of the
// executable and not by a substring of any command line, since the commands
// this test runs name the app themselves.
func calculators(t testing.TB) map[int]string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "/bin/ps", "-axww", "-o", "pid=,comm=").Output()
	if err != nil {
		t.Fatal(err)
	}
	found := map[int]string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		pidStr, comm, ok := strings.Cut(line, " ")
		if !ok || !strings.HasSuffix(strings.TrimSpace(comm), "/Calculator.app/Contents/MacOS/Calculator") {
			continue
		}
		var pid int
		if _, err := fmt.Sscan(pidStr, &pid); err == nil {
			found[pid] = strings.TrimSpace(comm)
		}
	}
	return found
}

// ---------------------------------------------------------------- terminals

// Row: "Caller's session kept, TIOCSTI/TIOCLINUX refused: TIOCSTI is open ...
// Deny opening /dev/ttys* and /dev/ptmx beyond inherited descriptors ...
// Test injecting into another terminal of the same user": a sandbox cannot
// open another terminal, a new pty, its own controlling terminal, packet
// capture or a disk, and TIOCSTI on a terminal it was handed types nothing.
func TestEscapeTerminals(t *testing.T) {
	t.Parallel()
	master, slaveName := openPty(t)
	slave, err := openFileFlags(slaveName, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	// Control: outside the sandbox, TIOCSTI on the same terminal types, if the
	// kernel allows it, so that a refusal inside is the profile's.
	typed := byte('Z')
	control := ioctlPtr(int(slave.Fd()), unix.TIOCSTI, unsafe.Pointer(&typed)) == nil //nolint:gosec // G103: the kernel reads or writes the buffer during the call, which keeps it valid.
	if !control {
		t.Log("TIOCSTI is refused outside the sandbox too: the kernel here already refuses it")
	}
	// The devices a sandbox might open.
	devs := []string{slaveName, "/dev/ptmx", "/dev/tty", "/dev/bpf0", "/dev/disk0", "/dev/rdisk0"}
	c := escCmd(t.Context(), t, Spec{}, "tty", devs...)
	c.Stdin = slave
	var errb bytes.Buffer
	c.Stderr = &errb
	c.Stdout = io.Discard
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Errorf("a terminal or device was reachable: %v\n%s", err, errb.String())
	}
	// Nothing was typed into the terminal. A pty master has no read deadline,
	// so the read runs on its own and is ended by closing the master.
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := master.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case s := <-got:
		if control && s != "Z" && strings.Contains(s, "Z") {
			s = strings.Replace(s, "Z", "", 1)
		}
		if strings.Contains(s, "injected") {
			t.Errorf("TIOCSTI injected %q", s)
		}
	case <-time.After(500 * time.Millisecond):
	}
	_ = master.Close()
}

// openPty opens a pseudoterminal pair, and returns its master and the slave's
// path.
func openPty(t *testing.T) (*os.File, string) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	fd := int(master.Fd())
	const tiocptygrant, tiocptyunlk, tiocptygname = 0x20007454, 0x20007452, 0x40807453
	if err := ioctlPtr(fd, tiocptygrant, nil); err != nil {
		t.Skipf("grant: %v", err)
	}
	if err := ioctlPtr(fd, tiocptyunlk, nil); err != nil {
		t.Skipf("unlock: %v", err)
	}
	var name [128]byte
	if err := ioctlPtr(fd, tiocptygname, unsafe.Pointer(&name[0])); err != nil { //nolint:gosec // G103: the kernel reads or writes the buffer during the call, which keeps it valid.
		t.Skipf("name: %v", err)
	}
	return master, string(name[:bytes.IndexByte(name[:], 0)])
}

// ---------------------------------------------------------------- bridge and session

// Row: "Bridge check by pid namespace ..., by session on macOS ... Test a
// sandboxed process calling setsid and connecting": a process in the sandbox
// can call setsid, and then it connects from a session of its own, so a check
// that keys on the session of the peer sees a session that is neither the
// sandbox's start nor the caller's. This documents what a bridge check may
// rely on: the peer is the sandbox's process, and nothing says which session
// it is in. It fails if setsid stops working.
func TestGapSetsidConnect(t *testing.T) {
	t.Parallel()
	short, err := os.MkdirTemp("/private/tmp", "sbx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	sock := filepath.Join(short, "bridge.sock")
	l, err := listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var peerPid, peerSid, peerPgid int
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		raw, _ := conn.(*net.UnixConn).SyscallConn()
		_ = raw.Control(func(fd uintptr) {
			// LOCAL_PEERPID, which is for unix sockets, as a bridge's is.
			peerPid, _ = unix.GetsockoptInt(int(fd), 0 /* SOL_LOCAL */, 0x002 /* LOCAL_PEERPID */)
		})
		if peerPid > 0 {
			peerSid, _ = unix.Getsid(peerPid)
			peerPgid, _ = unix.Getpgid(peerPid)
		}
		// Hold the connection until the command is done.
		_, _ = io.Copy(io.Discard, conn)
	}()
	c := escCmd(t.Context(), t, Spec{Write: []string{sock}}, "setsid-connect", "unix-"+sock)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("the sandboxed process could not make a session of its own and connect: %v\n%s", err, errb.String())
	}
	<-done
	mySid, _ := unix.Getsid(0)
	f := strings.Fields(out.String())
	if len(f) != 2 {
		t.Fatalf("output %q", out.String())
	}
	if peerPid == 0 {
		t.Fatal("no peer pid")
	}
	if f[1] == strconv.Itoa(mySid) {
		t.Errorf("the process is in the caller's session %d after setsid", mySid)
	}
	// What a bridge check can learn from the connection: the peer's pid,
	// which is a process of the sandbox, in a session that is neither the
	// command's nor the caller's, and in a process group of its own. The
	// peer has exited by now, so its session is read while it held the
	// connection.
	if peerSid == 0 || strconv.Itoa(peerSid) == f[0] || peerSid == mySid {
		t.Errorf("the peer %d is in session %d, which is the command's %s or the caller's %d: a check by session would have seen a sandbox process", peerPid, peerSid, f[0], mySid)
	}
	t.Logf("peer pid %d, session %d, group %d; the command's session is %s", peerPid, peerSid, peerPgid, f[0])
}

// ---------------------------------------------------------------- the profile and its start

// Row: "Options on a descriptor, not in pid 1's argv": the profile goes to
// sandbox-exec on a pipe, so no command line names it, and the paths it covers
// are not in any argv. The command holds the pipe's read end, which is at end
// of file and holds nothing.
func TestEscapeProfileNotInArgv(t *testing.T) {
	t.Parallel()
	covered := filepath.Join(realTemp(t), "very-secret-cover-name-xyzzy")
	if err := os.Mkdir(covered, 0o750); err != nil {
		t.Fatal(err)
	}
	home := realTemp(t)
	marker := filepath.Join(home, "pid")
	c := escCmd(t.Context(), t, Spec{Home: home, Cover: []string{covered}}, "hold", marker)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { c.stop(); _ = c.Wait() }()
	eventually(t, 10*time.Second, "no start", func() bool { _, err := os.Stat(marker); return err == nil })
	// Only this sandbox's own processes are looked at: the stage, the command
	// and whatever it started. Other programs on a machine run sandbox-exec
	// with a profile in argv, and a check of every process would find theirs.
	members := tree(t, c.Pid())
	if len(members) < 2 {
		t.Fatalf("the sandbox's processes are %v", members)
	}
	args := strings.Join(args(t, members), "\n")
	for _, s := range []string{"deny default", "(version 1)", "very-secret-cover-name-xyzzy", "sandbox-exec", "subpath", "(allow"} {
		if strings.Contains(args, s) {
			t.Errorf("a command line of the sandbox's processes shows %q:\n%s", s, args)
		}
	}
	// Nor is it in the environment the command's neighbors can read.
	b, _ := unix.SysctlRaw("kern.procargs2", c.Pid())
	if bytes.Contains(b, []byte("very-secret-cover-name-xyzzy")) {
		t.Error("the stage's arguments or environment name a cover")
	}
	// The command holds no descriptor that has the profile: the one pipe left is
	// at end of file.
	r := escResult(t, Spec{Cover: []string{covered}}, "fds")
	for fd, kind := range fdKinds(r.stdout) {
		if fd > 2 && kind != "fifo" {
			t.Errorf("descriptor %d is a %s", fd, kind)
		}
	}
	out2 := shOK(t, Spec{Cover: []string{covered}}, `cat <&3; echo end`)
	if out2 != "end\n" {
		t.Errorf("descriptor 3, the profile's pipe, held %q", out2)
	}
}

// Row: "/usr/bin/sandbox-exec by absolute path, never from PATH": a program
// named sandbox-exec first on the caller's PATH is not run.
func TestEscapeSandboxExecAbsolute(t *testing.T) {
	bin := realTemp(t)
	marker := filepath.Join(bin, "ran")
	script := "#!/bin/sh\necho ran > " + marker + "\nexit 99\n"
	if err := os.WriteFile(filepath.Join(bin, "sandbox-exec"), []byte(script), 0o700); err != nil { //nolint:gosec // G306: the file is a program the test runs, which needs its owner to execute it.
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	if r := sh(t, Spec{}, "echo through the real one"); r.code != 0 || r.stdout != "through the real one\n" {
		t.Errorf("%s", r)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a sandbox-exec found on PATH was run")
	}
}

// Row: "Kernel level per child ... one profile for every level, never weaker
// than asked": every Kernel level gets the same view, and Probe says so.
func TestEscapeKernelLevels(t *testing.T) {
	t.Parallel()
	secret := hostSecret(t)
	for _, k := range []Kernel{"", KernelStrict, KernelNested, KernelOpen} {
		escRun(t, Spec{Kernel: k}, "denied", secret, filepath.Dir(secret))
		escRun(t, Spec{Kernel: k}, "dial-denied", "tcp:1.1.1.1:443")
	}
	rep, err := Probe()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []Kernel{KernelStrict, KernelNested, KernelOpen} {
		if rep.Kernel[k] != KernelStrict {
			t.Errorf("Probe says %s gets %q, want strict", k, rep.Kernel[k])
		}
	}
}

// Row: "Seatbelt profile ... never lsopen": whatever Spec made it, a profile
// does not name lsopen, iokit, or a Mach service outside its groups, and it
// confines signals and process info to the sandbox.
func TestEscapeProfileNeverAllows(t *testing.T) {
	t.Parallel()
	for _, in := range []profileInput{
		{Home: "/h"},
		{Home: "/h", Network: NetworkHost, Services: []Service{ServiceFirefox, ServiceDirectory}},
		{Home: "/h", BroadLoopback: true, Listen: []int{1, 2}, Loopback: []int{3}, Write: []string{"/w"}, Read: []string{"/r"}, Cover: []string{"/c"}, Sockets: []string{"/w/s"}, Marker: marker{In: "com.die-net.sandbox.in.x", Out: "com.die-net.sandbox.out.x"}},
	} {
		p, err := profile(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"lsopen", "iokit", "(allow default)", "(allow mach-lookup)", "(allow signal)", "(allow process-info*)", "(allow network*)", "(allow file-write*)\n", "mach-priv", "system-fsctl"} {
			if strings.Contains(p, bad) {
				t.Errorf("a profile contains %q:\n%s", bad, p)
			}
		}
		for _, line := range strings.Split(p, "\n") {
			if strings.HasPrefix(line, "(allow mach-lookup") || strings.HasPrefix(line, "(allow mach-register") {
				known := false
				for _, rules := range serviceRules {
					known = known || slices.Contains(rules, line)
				}
				if !known && !strings.Contains(line, "configd") && !strings.Contains(line, "dnssd") && !strings.Contains(line, "TrustEvaluationAgent") && !strings.Contains(line, "com.die-net.sandbox.in.") {
					t.Errorf("a Mach service outside a group: %s", line)
				}
			}
		}
		if !strings.Contains(p, "(deny default)") || !strings.Contains(p, "(target same-sandbox)") {
			t.Errorf("a profile lacks its basics:\n%s", p)
		}
	}
}

// Row: "Escape tests ... same suite": a profile of a Spec that names every field
// starts a sandbox, so that a rule written wrongly fails here and not at an
// adopter's.
func TestEscapeEveryFieldStarts(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	root := realTemp(t)
	sock := filepath.Join(os.TempDir(), "x.sock")
	_ = sock
	spec := Spec{
		Home: home, Dir: home, Write: []string{mkdirs(t, root, "w")}, Read: []string{mkdirs(t, root, "r")}, Cover: []string{mkdirs(t, root, "c")},
		Kernel: KernelNested, Network: NetworkNone, BroadLoopback: true, Services: []Service{ServiceFirefox, ServiceDirectory},
		Listen: 1, Loopback: 1, Rlimits: []Rlimit{{ResourceCore, 0, 0}}, Hostname: "x", ScratchSize: 10,
	}
	spec.Command = []string{"/usr/bin/true"}
	c, err := Command(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	r := execute(t, c)
	if r.code != 0 {
		t.Errorf("%s", r)
	}
	for _, l := range c.Listeners() {
		_ = l.Close()
	}
}

// ---------------------------------------------------------------- descriptors

// Row: "Descriptors handed in" (docs/linux.md): a descriptor grants what its
// object does. On Linux the command reopens a read-only file under a cover
// through /proc/self/fd for writing. On macOS /dev/fd/N is the file's path,
// and the profile decides by that path, so the reopen is refused under a
// cover, though a write to a descriptor opened for writing is not.
func TestEscapeDescriptorsHandedIn(t *testing.T) {
	t.Parallel()
	secret := hostSecret(t)
	ro, err := openFile(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	dir := realTemp(t)
	rw, err := openFileFlags(filepath.Join(dir, "out"), os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	out := escRun(t, Spec{Files: []*os.File{ro, rw}}, "reopen")
	if !strings.Contains(out, "reopen: ") || strings.Contains(out, "reopen: worked") {
		t.Errorf("the read-only descriptor was reopened for writing:\n%s", out)
	}
	if !strings.Contains(out, "direct: worked") {
		t.Errorf("a write to a descriptor opened for writing failed:\n%s", out)
	}
	if b, _ := readFile(secret); string(b) != "top secret\n" {
		t.Errorf("the secret was changed: %q", b)
	}
	if b, _ := readFile(filepath.Join(dir, "out")); string(b) != "direct\n" {
		t.Errorf("out = %q", b)
	}
}

// Row: "Root launcher ... Test the euid-0 refusal": a Command made as root is
// refused, checked by making the check think it is root.
func TestEscapeRefusesEuid0(t *testing.T) {
	t.Parallel()
	if _, err := commandAs(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: realTemp(t)}, 0); err == nil {
		t.Error("Command as root succeeded")
	}
	if _, err := runAs(t.Context(), Spec{Command: []string{"/usr/bin/true"}, Home: realTemp(t)}, 0); err == nil {
		t.Error("Run as root succeeded")
	}
}

// Row: "Supplementary groups, host secrets readable by mode": the account's
// groups usually include staff and admin, which Seatbelt does not take away.
// What admin can write, such as /Library and /usr/local, is still refused,
// since the profile allows writes only in the home and the Write paths.
func TestEscapeAdminGroupWrites(t *testing.T) {
	t.Parallel()
	var admin bool
	gs, _ := os.Getgroups()
	for _, g := range gs {
		if g == 80 {
			admin = true
		}
	}
	if !admin {
		t.Skip("the account is not in the admin group")
	}
	var writable []string
	for _, d := range []string{"/Library", "/usr/local", "/Applications", "/opt/homebrew", "/Library/Application Support"} {
		if unix.Access(d, unix.W_OK) == nil {
			writable = append(writable, d)
		}
	}
	if len(writable) == 0 {
		t.Skip("admin can write nowhere interesting here")
	}
	escRun(t, Spec{}, "writes-denied", writable...)
}

var _ = sync.Mutex{}

// rawXPCSource is a client that talks to launchservicesd without the
// LaunchServices API, as a hand-written one would, so that no check in the
// API's own code stands in the way. It connects, sends a message the shape of
// a request to open something, and prints the reply's description.
const rawXPCSource = `
#include <xpc/xpc.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  xpc_connection_t c = xpc_connection_create_mach_service("com.apple.coreservices.launchservicesd", NULL, 0);
  if (!c) { printf("no connection\n"); return 2; }
  xpc_connection_set_event_handler(c, ^(xpc_object_t e) { });
  xpc_connection_resume(c);
  xpc_object_t m = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_string(m, "op", "open");
  xpc_dictionary_set_string(m, "url", argv[1]);
  xpc_object_t r = xpc_connection_send_message_with_reply_sync(c, m);
  char *d = xpc_copy_description(r);
  printf("reply: %s\n", d);
  free(d);
  return 0;
}
`

// Row: "Launching apps and URLs" (docs/macos.md, M3), the raw-XPC case that
// M3 left open: a client that talks to launchservicesd directly. With the
// Firefox group, which allows the lookup, the connection is made, where
// without it the sandbox refuses the lookup. Our message is rejected as it is
// outside the sandbox too, since the real request is private to
// LaunchServices, so this shows the lookup and that nothing opens from it, not
// that lsd checks lsopen itself: a replay of a real open request was not
// possible, and that stays untested.
func TestEscapeLaunchServicesRawXPC(t *testing.T) {
	t.Parallel()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	dir := realTemp(t)
	src := writeFile(t, rawXPCSource, dir, "rawxpc.c")
	bin := filepath.Join(dir, "rawxpc")
	if out, err := exec.CommandContext(t.Context(), cc, "-o", bin, src).CombinedOutput(); err != nil { //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
		t.Skipf("cannot build the client: %v\n%s", err, out)
	}
	beacon := make(chan struct{}, 1)
	ln, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			beacon <- struct{}{}
			_ = c.Close()
		}
	}()
	url := "http://" + ln.Addr().String() + "/raw-xpc-beacon"
	before := calculators(t)
	t.Cleanup(func() {
		for pid := range calculators(t) {
			if _, old := before[pid]; !old {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	without := sh(t, Spec{Home: dir, Read: []string{dir}}, bin+" "+url+" 2>&1")
	with := sh(t, Spec{Home: dir, Read: []string{dir}, Services: []Service{ServiceFirefox}, BroadLoopback: true}, bin+" "+url+" 2>&1")
	if !strings.Contains(without.stdout, "Connection invalid") {
		t.Errorf("without the group the lookup of launchservicesd was not refused:\n%s", without.stdout)
	}
	if !strings.Contains(with.stdout, "reply:") || strings.Contains(with.stdout, "Connection invalid") {
		t.Errorf("with the Firefox group the connection was not made:\n%s", with.stdout)
	}
	time.Sleep(500 * time.Millisecond)
	select {
	case <-beacon:
		t.Error("a raw message to launchservicesd made the default browser fetch a URL")
	default:
	}
	for pid, comm := range calculators(t) {
		if _, old := before[pid]; !old {
			t.Errorf("an app was launched outside the profile: pid %d, %s", pid, comm)
		}
	}
}

// Row: "Own process group, foreground of a terminal on Stdin": a command that
// reads the terminal is not stopped by SIGTTIN, though it is in a process group
// of its own, since the stage gives it the foreground, and gives it back when
// it ends. A Run in a session of its own, with a pty as its terminal, runs cat,
// which must echo what is typed, and then see the end of file.
func TestEscapeTerminalForeground(t *testing.T) {
	t.Parallel()
	master, slaveName := openPty(t)
	slave, err := openFileFlags(slaveName, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	home := realTemp(t)
	body := jsonArg(t, Spec{Home: home, Command: []string{"/bin/cat"}})
	cmd := exec.CommandContext(t.Context(), self(t), "esc-run", body) //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	cmd.Dir = home
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	go func() { _, _ = io.Copy(&out, master) }()
	text := func() string { out.mu.Lock(); defer out.mu.Unlock(); return out.buf.String() }
	// Let cat start, then type. Each line comes back twice: the terminal
	// echoes it, and cat writes it.
	time.Sleep(500 * time.Millisecond)
	_, _ = master.WriteString("typed-line\n")
	eventually(t, 10*time.Second, "cat did not read the terminal: the sandbox was in the background\n", func() bool {
		return strings.Count(text(), "typed-line") >= 2
	})
	// The end of file ends cat, and Run returns its status after it has given
	// the foreground back.
	_, _ = master.Write([]byte{4})
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v\n%s", err, text())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("cat did not end on the end of file\n%s", text())
	}
	_ = master.Close()
}
