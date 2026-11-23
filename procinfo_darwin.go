package sandbox

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The two proc_info calls that a teardown scan makes, which libproc's
// proc_listpids and proc_pidinfo wrap. They are called directly, as
// physFootprint calls proc_pid_rusage, since the package builds without cgo and
// golang.org/x/sys/unix has no wrapper for either. The numbers are from XNU's
// bsd/sys/proc_info.h and proc_info_private.h.
const (
	procInfoListPids = 0x1 // PROC_INFO_CALL_LISTPIDS
	procInfoPidInfo  = 0x2 // PROC_INFO_CALL_PIDINFO
	procUIDOnly      = 4   // PROC_UID_ONLY
	procPidTBSDInfo  = 3   // PROC_PIDTBSDINFO
	// stateForking is SIDL: a process that fork is still making.
	stateForking = 1
	// flagInExit is PROC_FLAG_INEXIT in pbi_flags: the process has begun to
	// exit (P_LEXIT) and is not yet a zombie.
	flagInExit = 4
)

// bsdInfo is struct proc_bsdinfo, 136 bytes, which PROC_PIDTBSDINFO fills.
type bsdInfo struct {
	Flags, Status, XStatus, Pid, PPid  uint32
	UID, GID, RUID, RGID, SVUID, SVGID uint32
	_                                  uint32
	Comm                               [16]byte
	Name                               [32]byte
	NFiles, PGID, PJobC, ETDev, ETPGID uint32
	Nice                               int32
	StartSec, StartUsec                uint64
}

// listCall is one proc_info(PROC_INFO_CALL_LISTPIDS) call for a uid: with no
// buffer it returns the room the kernel would use for (nprocs+20) pids, in
// bytes, and with one it fills the buffer and returns the bytes it wrote. A test
// supplies its own.
type listCall func(buf []int32) (bytes int, err error)

// listUIDPids returns the pids of every process whose effective uid is uid, in
// one atomic list. proc_listpids (bsd/kern/proc_info.c) builds the list inside
// one hold of proc_list_lock, from allproc and then zombproc, so it holds every
// such process that exists at that moment, whatever its state, zombies
// included. A process that fork is still making is in neither list until
// pinsertchild adds it to allproc, which is after fork_create_child has copied
// the address space (see scan_darwin.go for why the proof does not need it).
func listUIDPids(uid uint32) ([]int, error) {
	return listPids(func(buf []int32) (int, error) {
		var p unsafe.Pointer
		if len(buf) > 0 {
			p = unsafe.Pointer(&buf[0])
		}
		n, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, procInfoListPids, procUIDOnly, uintptr(uid), 0, uintptr(p), uintptr(len(buf)*4))
		if errno != 0 {
			return 0, fmt.Errorf("list processes: %w", errno)
		}
		return int(n), nil
	})
}

// listPids makes the list with call, and asks again while the list may have
// been cut short.
//
// The kernel stops filling the list at min(nprocs+20, the buffer), where
// nprocs is read when the call starts, before it takes the lock. A list that
// reaches that many entries may have been cut. It is cut in list order, which
// is allproc from the newest process to the oldest and then every zombie, so
// the cut would lose the oldest live processes, the sandbox's first ones among
// them, and every zombie, and the scan would then take them for gone. A list
// that is shorter than both limits is whole. The size is asked again after the
// list, and the list must be shorter than the smaller of the two answers, since
// nprocs can fall between the first answer and the call that fills the buffer
// and the cap the kernel used is then below the first answer.
func listPids(call listCall) ([]int, error) {
	for range 5 {
		before, err := call(nil)
		if err != nil {
			return nil, err
		}
		buf := make([]int32, 2*(before/4)+64)
		got, err := call(buf)
		if err != nil {
			return nil, err
		}
		after, err := call(nil)
		if err != nil {
			return nil, err
		}
		n := got / 4
		if n >= min(before, after)/4 || n >= len(buf) {
			continue
		}
		pids := make([]int, n)
		for i, pid := range buf[:n] {
			pids[i] = int(pid)
		}
		return pids, nil
	}
	return nil, errors.New("list processes: the list was cut short each time")
}

// readBSD reads pid's proc_bsdinfo with proc_pidinfo's PROC_PIDTBSDINFO
// (proc_pidbsdinfo in bsd/kern/proc_info.c). Its argument asks for zombies too:
// proc_pidinfo then falls back from proc_find to proc_find_zombref, so a zombie
// is reported, as pbi_status SZOMB. A process that has been reaped, one that
// fork has not finished making (proc_find refuses P_REF_NEW), and one that has
// left proc_find's reach and not yet reached proc_find_zombref, are ESRCH.
func readBSD(pid int) (bsdInfo, error) {
	var b bsdInfo
	n, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, procInfoPidInfo, uintptr(pid), procPidTBSDInfo, 1, uintptr(unsafe.Pointer(&b)), unsafe.Sizeof(b))
	if errno != 0 {
		return bsdInfo{}, errno
	}
	if int(n) != int(unsafe.Sizeof(b)) {
		return bsdInfo{}, fmt.Errorf("proc_pidinfo returned %d bytes, want %d", n, unsafe.Sizeof(b))
	}
	return b, nil
}

// statPid reads what a scan needs of pid from its proc_bsdinfo.
func statPid(pid int) (procStat, error) {
	b, err := readBSD(pid)
	if err != nil {
		return procStat{}, err
	}
	return procStatOf(b), nil
}

// procStatOf is what a scan needs of a proc_bsdinfo.
func procStatOf(b bsdInfo) procStat {
	return procStat{
		Forking: b.Status == stateForking,
		Zombie:  b.Status == stateZombie,
		Exiting: b.Flags&flagInExit != 0,
		Start:   int64(b.StartSec)*1_000_000 + int64(b.StartUsec),
		Comm:    unix.ByteSliceToString(b.Comm[:]),
		PPid:    int(b.PPid),
	}
}
