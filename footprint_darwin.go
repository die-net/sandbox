package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unsafe"

	"golang.org/x/sys/unix"
)

// procInfoRusage is proc_info's call number for proc_pid_rusage, and
// rusageOffsetFootprint is where ri_phys_footprint lies in the V0 record that
// the call fills: a 16-byte uuid, then seven 8-byte counters.
const (
	procInfoRusage        = 9
	rusageSize            = 96
	rusageOffsetFootprint = 72
)

// Footprint returns the memory footprint, in bytes, of the processes in the
// sandbox: every process that runs under its profile, wherever it has gone,
// whatever its process group or parent (a command can leave its group with
// setpgid or job control, or outlive its parent), and also the command's
// group and their descendants, which covers the moment before sandbox-exec has
// applied the profile. It is the physical footprint macOS itself charges a
// process (ri_phys_footprint), which counts compressed and swapped pages that a
// resident size leaves out. It is a soft limit for a caller's watchdog to poll:
// it is the sum at one moment, and a process that is gone before it is read is
// left out. An error that says no process is left means the command and
// everything it started have ended.
func (c *Cmd) Footprint() (int64, error) {
	if c.run.cmd == nil {
		return 0, errors.New("sandbox: not started")
	}
	if c.run.waited {
		return 0, errors.New("sandbox: already waited for")
	}
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return 0, fmt.Errorf("list processes: %w", err)
	}
	// The command's group number may be someone else's once the group is
	// empty, so a member counts only if the stage, which is still this process's
	// child and so still has its pid, is among its ancestors. That covers the
	// moment before sandbox-exec has applied the profile.
	ppid := map[int]int{}
	for i := range procs {
		p := &procs[i]
		ppid[int(p.Proc.P_pid)] = int(p.Eproc.Ppid)
	}
	stage := c.run.cmd.Process.Pid
	uid := euid()
	underStage := func(pid int) bool {
		for range 4096 {
			if pid == stage {
				return true
			}
			pp, ok := ppid[pid]
			if !ok || pp <= 1 {
				return false
			}
			pid = pp
		}
		return false
	}
	in := map[int32]bool{}
	for i := range procs {
		p := &procs[i]
		if p.Proc.P_stat == stateZombie {
			continue
		}
		if (int(p.Eproc.Pgid) == c.run.group && underStage(int(p.Proc.P_pid))) || (p.Eproc.Ucred.Uid == uid && c.run.mark.inSandbox(int(p.Proc.P_pid))) {
			in[p.Proc.P_pid] = true
		}
	}
	// Descendants of a member, found until no more are.
	for grew := true; grew; {
		grew = false
		for i := range procs {
			p := &procs[i]
			if !in[p.Proc.P_pid] && in[p.Eproc.Ppid] && p.Proc.P_stat != stateZombie {
				in[p.Proc.P_pid], grew = true, true
			}
		}
	}
	var total int64
	found := false
	for pid := range in {
		if fp, err := physFootprint(int(pid)); err == nil {
			total += fp
			found = true
		}
	}
	if !found {
		return 0, errors.New("sandbox: no process of the sandbox is left")
	}
	return total, nil
}

// physFootprint returns the physical footprint of pid, from proc_info's
// PROC_INFO_CALL_PIDRUSAGE, which libproc's proc_pid_rusage wraps. It is
// called directly, since the package builds without cgo.
func physFootprint(pid int) (int64, error) {
	var buf [rusageSize]byte
	_, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, procInfoRusage, uintptr(pid), 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) //nolint:gosec,staticcheck // G103: the kernel writes the buffer during the call. SA1019: Syscall6 passes the number to libc's syscall(2), and libproc's wrapper has no binding without cgo.
	if errno != 0 {
		return 0, errno
	}
	fp := binary.NativeEndian.Uint64(buf[rusageOffsetFootprint:])
	if fp > math.MaxInt64 { // not a size of memory, so the sum below cannot overflow on it
		fp = math.MaxInt64
	}
	return int64(fp), nil
}
