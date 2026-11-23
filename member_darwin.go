package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Which processes run under a sandbox's profile, whatever their process group,
// session or parent. Seatbelt has no pid namespace, and a command can leave its
// group with setpgid or a shell's job control, so the group alone does not name
// the sandbox. sandbox_check(3) asks the kernel what the profile of a pid
// allows, and a profile of this package can be told apart by a pair of Mach
// names that no other profile treats the way it does: it allows a lookup of one
// random name, and denies a lookup of another.
//
// A process that is not sandboxed allows both. A process under any other
// profile, including another sandbox of this package, has a different pair of
// names, and a profile that denies by default denies both, so only a process
// under this profile allows the first and denies the second. The check is only
// asked of processes by a caller outside the profile, and a process in it
// cannot change its own profile, so it cannot make itself look different.

//go:cgo_import_dynamic libc_sandbox_check sandbox_check "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic _ _ "/usr/lib/libSystem.B.dylib"

//go:linkname syscall_syscall9 syscall.syscall9
func syscall_syscall9(fn, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err syscall.Errno)

// libc_sandbox_check_trampoline_addr is the address of the assembly trampoline.
var libc_sandbox_check_trampoline_addr uintptr

const (
	// filterGlobalName is SANDBOX_FILTER_GLOBAL_NAME, which makes the check
	// take a Mach service name, and noReport is SANDBOX_CHECK_NO_REPORT, which
	// keeps a denial out of the system log.
	filterGlobalName = 2
	noReport         = 0x40000000
	// stateZombie is SZOMB: a process that has exited and not been reaped.
	stateZombie = 5
)

// marker is the pair of names that tell a sandbox's processes from every other
// process. It is random for each sandbox, and only the profile and the caller
// that wrote it know it.
type marker struct {
	// In is a name the profile allows a lookup of, and Out one it denies.
	In  string `json:"in,omitempty"`
	Out string `json:"out,omitempty"`
}

// newMarker returns a marker with a fresh pair of names.
func newMarker() (marker, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return marker{}, fmt.Errorf("make a sandbox marker: %w", err)
	}
	id := hex.EncodeToString(b[:])
	return marker{In: "com.die-net.sandbox.in." + id, Out: "com.die-net.sandbox.out." + id}, nil
}

// lookupAllowed reports whether pid's profile allows a Mach lookup of name.
// ok is false if the kernel would not say, as for a process that is gone.
func lookupAllowed(pid int, name string) (allowed, ok bool) {
	op, err := unix.BytePtrFromString("mach-lookup")
	if err != nil {
		return false, false
	}
	n, err := unix.BytePtrFromString(name)
	if err != nil {
		return false, false
	}
	// sandbox_check is variadic, and its fourth argument is the name. It is
	// passed where either calling convention reads it: the fourth register on
	// amd64, and the first stack slot on arm64, where Apple puts every variadic
	// argument. syscall9 puts its ninth argument there on arm64 and its seventh
	// to ninth on the stack on amd64, which nothing reads.
	r, _, _ := syscall_syscall9(libc_sandbox_check_trampoline_addr,
		uintptr(pid), uintptr(unsafe.Pointer(op)), filterGlobalName|noReport, uintptr(unsafe.Pointer(n)),
		0, 0, 0, 0, uintptr(unsafe.Pointer(n)))
	switch int32(r) {
	case 0:
		return true, true
	case 1:
		return false, true
	}
	return false, false
}

// inSandbox reports whether pid runs under the profile that m belongs to.
func (m marker) inSandbox(pid int) bool {
	if m.In == "" || pid <= 1 {
		return false
	}
	if allowed, ok := lookupAllowed(pid, m.In); !ok || !allowed {
		return false
	}
	allowed, ok := lookupAllowed(pid, m.Out)
	return ok && !allowed
}

// processes returns the pids of every process that runs under m's profile.
func (m marker) processes() ([]int, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}
	var out []int
	for _, p := range procs {
		if p.Proc.P_stat == stateZombie {
			continue
		}
		if pid := int(p.Proc.P_pid); m.inSandbox(pid) {
			out = append(out, pid)
		}
	}
	return out, nil
}

// settleScans is how many scans in a row must find nothing before kill
// believes the sandbox is empty. A process that forks and exits again within
// a millisecond is missing from a scan that listed its parent, so one empty
// scan proves little.
const settleScans = 5

// teardownBudget is how long a teardown keeps scanning for processes that keep
// forking before it gives up and says it could not confirm the sandbox empty.
// It is a variable so that a test can give it none.
var teardownBudget = 5 * time.Second

// sweep scans every process of this account once, and signals each that runs
// under m's profile at the moment it is found, not after the scan, so the time
// between seeing a process and ending it is one check, not a whole scan.
// Only this account's processes are asked, since a sandbox cannot run as
// another uid (a setuid program does not run in a profile), which halves the
// calls. It returns how many it signalled.
func (m marker) sweep() (int, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return 0, fmt.Errorf("list processes: %w", err)
	}
	uid := uint32(os.Geteuid())
	n := 0
	for _, p := range procs {
		if p.Proc.P_stat == stateZombie || p.Eproc.Ucred.Uid != uid {
			continue
		}
		if pid := int(p.Proc.P_pid); m.inSandbox(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			n++
		}
	}
	return n, nil
}

// kill ends every process that runs under m's profile, and keeps scanning until
// settleScans scans in a row find none, or budget has passed. It reports
// whether it saw the sandbox empty. False means a process may still run: one
// that forks again before each signal lands can keep ahead of the scan for as
// long as it likes, and so can a process the kernel will not end. At least one
// scan is made, whatever the budget.
func (m marker) kill(budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for empty := 0; ; {
		n, err := m.sweep()
		switch {
		case err != nil:
			return false
		case n > 0:
			empty = 0
		default:
			if empty++; empty >= settleScans {
				return true
			}
		}
		if !time.Now().Before(deadline) {
			return false
		}
	}
}
