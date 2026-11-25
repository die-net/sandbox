package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

//go:linkname syscallSyscall9 syscall.syscall9
func syscallSyscall9(fn, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err syscall.Errno)

// libcSandboxCheckTrampolineAddr is the address of the assembly trampoline.
var libcSandboxCheckTrampolineAddr uintptr

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
	r, _, _ := syscallSyscall9(libcSandboxCheckTrampolineAddr,
		uintptr(pid), uintptr(unsafe.Pointer(op)), filterGlobalName|noReport, uintptr(unsafe.Pointer(n)), //nolint:gosec // G103: the pointers are converted in the call's own argument list, which keeps them valid until it returns.
		0, 0, 0, 0, uintptr(unsafe.Pointer(n))) //nolint:gosec // G103: as above.
	switch int32(r) { //nolint:gosec // G115: sandbox_check returns a C int, so only the low 32 bits of the register mean anything.
	case 0:
		return true, true
	case 1:
		return false, true
	}
	return false, false
}

// kernelFinds reports whether the kernel still finds pid, which a sandbox_check
// of an operation that does not exist answers: -1 (EINVAL) for a process it
// finds, whether or not it is sandboxed, and 1 for a pid it does not find, such
// as one that has gone, a zombie, or a process that has begun to exit. (The
// answers were measured; Sandbox.kext is not public.) A lookup that answers 1
// answers it for those too, so it cannot tell them from a denial.
func kernelFinds(pid int) bool {
	op, err := unix.BytePtrFromString("no-such-operation")
	if err != nil {
		return false
	}
	r, _, _ := syscallSyscall9(libcSandboxCheckTrampolineAddr,
		uintptr(pid), uintptr(unsafe.Pointer(op)), noReport, 0, //nolint:gosec // G103: the pointer is converted in the call's own argument list, which keeps it valid until it returns.
		0, 0, 0, 0, 0)
	return int32(r) == -1 //nolint:gosec // G115: sandbox_check returns a C int, so only the low 32 bits of the register mean anything.
}

// lookup is what a check of one pid found.
type lookup struct {
	// In is whether the process runs under the profile that the marker belongs to.
	In bool
	// Known is false if the answer cannot be relied on: the kernel would not say,
	// or a 1 came for a pid it no longer finds (kernelFinds), as for a process
	// that is gone, a zombie, or one that is exiting. In is then false too.
	Known bool
	// Free is whether the process was found under no profile: its lookup of the
	// name that the profile denies was allowed. A process in a sandbox, this one
	// or another, is never free, and no process in one can make a free one.
	Free bool
}

// look checks pid against m's profile.
//
// Out is asked first, then In, and a process is a member only for "denied, then
// allowed". sandbox-exec applies its profile to itself in place, so a process
// can be unsandboxed at the first call and under another profile at the second,
// and that profile, any deny-default one, denies both names. Asked In then Out,
// that process answered "allowed, then denied", the member pattern, and a scan
// killed it. Asked Out then In, it answers "allowed" at the first call, which
// is not a member's answer. A process cannot leave a profile or swap it for
// another, so "denied, then allowed" cannot come from a change between the two
// calls, and an allowed answer is only given for a process the kernel found.
func (m marker) look(pid int) lookup {
	if m.In == "" || pid <= 1 {
		return lookup{Known: true}
	}
	out, ok := lookupAllowed(pid, m.Out)
	if !ok {
		return lookup{}
	}
	if out {
		return lookup{Known: true, Free: true}
	}
	in, ok := lookupAllowed(pid, m.In)
	if !ok {
		return lookup{}
	}
	if in {
		return lookup{In: true, Known: true}
	}
	// Denied twice: a process under another profile, or a pid the kernel does
	// not find, which answers the same.
	return lookup{Known: kernelFinds(pid)}
}

// member reports whether pid runs under the profile that m belongs to, and
// whether that answer can be relied on (see lookup).
func (m marker) member(pid int) (in, known bool) {
	l := m.look(pid)
	return l.In, l.Known
}

// inSandbox reports whether pid runs under the profile that m belongs to.
func (m marker) inSandbox(pid int) bool {
	in, _ := m.member(pid)
	return in
}

// processes returns the pids of every process that runs under m's profile.
func (m marker) processes() ([]int, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}
	var out []int
	for i := range procs {
		p := &procs[i]
		if p.Proc.P_stat == stateZombie {
			continue
		}
		if pid := int(p.Proc.P_pid); m.inSandbox(pid) {
			out = append(out, pid)
		}
	}
	return out, nil
}

// prober returns the scan's view of the system for m: the account's pids
// from proc_listpids in one atomic list (procinfo_darwin.go), sandbox_check, and
// the process's bsdinfo.
func (m marker) prober(execPid int) prober {
	uid := euid()
	p := prober{
		execPid: execPid,
		list:    func() ([]int, error) { return listUIDPids(uid) },
		look:    m.look,
		stat:    statPid,
		// This signals a number, after the check that found it. The number would
		// have to leave the process that was checked and be given to another
		// within the microseconds between the two, and forkproc hands pids out in
		// sequence, skipping any in use (see killGroup in stage_darwin.go).
		kill:  func(pid int) { _ = syscall.Kill(pid, syscall.SIGKILL) },
		now:   time.Now,
		sleep: time.Sleep,
	}
	return p
}

// kill ends every process that runs under m's profile and keeps scanning until
// a scan proves the profile empty (scan_darwin.go), or budget has passed.
// execPid is the pid of the sandbox-exec that was started to apply the profile,
// or 0 if the caller does not have it (prober.execPid). It
// returns how many scans it made, and whether it proved the sandbox empty.
// False means a process may still run: one that forks again before each signal
// lands can keep ahead of the scan for as long as it likes, and so can a
// process the kernel will not end. At least one scan is made, whatever the
// budget.
func (m marker) kill(budget time.Duration, execPid int) (scans int, out endKind) {
	return m.prober(execPid).run(budget)
}
