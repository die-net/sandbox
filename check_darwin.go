package sandbox

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// probeLimit bounds how many outside processes each attempt tries.
const probeLimit = 16

// foreignPIDs returns the pids kern.proc.all lists that are neither this
// process nor its descendants: the parent first, then this account's other
// processes, which only a profile can refuse to signal, then everyone else's,
// which refuse by their uid anyway. A sandbox's own tree is not outside it.
func foreignPIDs() ([]int, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	ppid := map[int]int{}
	mine := map[int]bool{}
	uid := uint32(os.Geteuid())
	for _, p := range procs {
		ppid[int(p.Proc.P_pid)] = int(p.Eproc.Ppid)
		mine[int(p.Proc.P_pid)] = p.Eproc.Ucred.Uid == uid
	}
	self := os.Getpid()
	inTree := func(pid int) bool {
		for range 4096 {
			if pid == self {
				return true
			}
			pp, ok := ppid[pid]
			if !ok || pp <= 0 {
				return false
			}
			pid = pp
		}
		return false
	}
	var out []int
	for pid := range ppid {
		if pid > 0 && !inTree(pid) {
			out = append(out, pid)
		}
	}
	slices.SortFunc(out, func(a, b int) int {
		if mine[a] != mine[b] {
			if mine[a] {
				return -1
			}
			return 1
		}
		return a - b
	})
	if pp := os.Getppid(); slices.Contains(out, pp) {
		out = append([]int{pp}, slices.DeleteFunc(out, func(p int) bool { return p == pp })...)
	}
	return out, nil
}

// procEnvironment reports whether KERN_PROCARGS2 returns the environment of
// pid. The record is an int argc, the executable's path, padding NULs, argc
// arguments, and then the environment, each string NUL-terminated. Apple's own
// binaries are returned with no environment, so a call that works is not
// enough: it has to hold a string after the arguments.
func procEnvironment(pid int) bool {
	b, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(b) < 4 {
		return false
	}
	argc := int(binary.NativeEndian.Uint32(b[:4]))
	rest := b[4:]
	// The path, then the NULs that pad it.
	if i := bytes.IndexByte(rest, 0); i >= 0 {
		rest = rest[i:]
	} else {
		return false
	}
	rest = bytes.TrimLeft(rest, "\x00")
	for range argc {
		i := bytes.IndexByte(rest, 0)
		if i < 0 {
			return false
		}
		rest = rest[i+1:]
	}
	return len(bytes.TrimLeft(rest, "\x00")) > 0
}

// checkProcesses tries what a process of the same uid can do to the ones
// outside this tree. macOS has no pid namespace, so the processes are listed
// and, but for a profile that denies signals, signalable. A profile cannot
// keep KERN_PROCARGS2 from returning another process's environment, which
// TestEscapeProcessEnvironment shows, so that is a known gap and shows up here
// as a failure.
func checkProcesses(*checkEnv) []Result {
	pids, err := foreignPIDs()
	if err != nil {
		return []Result{
			skipped("proc.visible", "%v", err), skipped("proc.signal", "%v", err),
			skipped("proc.trace", "%v", err), skipped("proc.environ", "%v", err),
		}
	}
	if len(pids) == 0 {
		return []Result{
			pass("proc.visible", "no process outside this tree is listed by kern.proc.all"),
			pass("proc.signal", "no outside process to signal"),
			skipped("proc.trace", "task_for_pid needs a signed binary or root, and ptrace would stop its target"),
			pass("proc.environ", "no outside process whose environment to read"),
		}
	}
	res := []Result{fail("proc.visible", "%d processes outside this tree are listed by kern.proc.all, such as pid %d. macOS has no pid namespace", len(pids), pids[0])}
	try := pids[:min(len(pids), probeLimit)]
	for _, a := range []struct {
		name string
		fn   func(pid int) bool
	}{
		{"proc.signal", func(pid int) bool { return syscall.Kill(pid, 0) == nil }},
		{"proc.environ", procEnvironment},
	} {
		var worked []string
		for _, pid := range try {
			if a.fn(pid) {
				worked = append(worked, strconv.Itoa(pid))
			}
		}
		res = append(res, verdict(a.name, fmt.Sprintf("%d outside processes tried", len(try)), worked))
		if a.name == "proc.signal" {
			res = append(res, skipped("proc.trace", "task_for_pid needs a signed binary or root, and ptrace would stop its target"))
		}
	}
	return res
}

// platformHints finds the targets the child cannot name for itself. Under a
// sandbox its HOME is the sandbox's home and its environment is empty, so it
// would look for the user's secrets and sockets in the wrong place. The
// caller's own are used, and a path is kept only if it exists, and a directory
// only if this account can write it (access(2), so nothing is created here), so that a refusal inside is the
// profile's.
func platformHints(spec *Spec) checkHints {
	h := checkHints{Set: true}
	var homes []string
	if home, err := os.UserHomeDir(); err == nil {
		homes = append(homes, home)
	}
	if more, err := hostHomes(); err == nil {
		homes = append(homes, more...)
	}
	slices.Sort(homes)
	homes = slices.Compact(homes)
	var secrets []string
	for _, h := range homes {
		for _, s := range secretFiles {
			secrets = append(secrets, filepath.Join(h, s))
		}
	}
	for _, p := range slices.Concat(secrets, secretPaths) {
		if _, err := os.Lstat(p); err == nil {
			h.Secrets = append(h.Secrets, p)
		}
	}
	for _, p := range socketCandidates() {
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
			h.Sockets = append(h.Sockets, p)
		}
	}
	// Directories a sandbox must not write, which this account can: the parents
	// of its own, the places other programs keep their files, and the account's
	// home.
	dirs := []string{os.TempDir(), "/tmp", "/private/tmp", "/private/var/tmp", "/Users/Shared", "/opt/homebrew", "/usr/local", "/Library/Caches"}
	dirs = append(dirs, homes...)
	if spec != nil {
		dirs = append(dirs, filepath.Dir(spec.Home))
		for _, w := range spec.Write {
			dirs = append(dirs, filepath.Dir(w))
		}
	}
	slices.Sort(dirs)
	for _, d := range slices.Compact(dirs) {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() && unix.Access(d, unix.W_OK) == nil {
			h.WriteTargets = append(h.WriteTargets, d)
		}
	}
	return h
}
