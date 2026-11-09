package sandbox

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"slices"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Offsets into struct seccomp_data, which the kernel gives the filter. An
// argument is 64 bits, and its low half comes first on both little-endian
// architectures the filter supports.
const (
	offNr   = 0
	offArch = 4
	offArgs = 16
)

// The netfilter socket options, from linux/netfilter_ipv4/ip_tables.h and
// linux/netfilter_ipv6/ip6_tables.h, which x/sys/unix does not carry. On
// IPv4 every netfilter option is netfilterOptMin or more. On IPv6,
// ip6tables has ip6tSetReplace, the option after it, ip6tGetRevisionMatch,
// and the option after that, among ordinary IPv6 options.
const (
	netfilterOptMin      = 64
	ip6tSetReplace       = 64
	ip6tGetRevisionMatch = 68
)

// nsFlags are the clone flags that make namespaces. KernelStrict refuses a
// clone with any of them.
const nsFlags = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
	unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET

// nestedSyscalls are what KernelNested allows beyond KernelStrict: what a
// sandbox of the command's own is built from. Chromium's also chroots into
// an empty directory in its own namespace.
var nestedSyscalls = []uint32{
	unix.SYS_UNSHARE, unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
	unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK,
	unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_MOUNT_SETATTR,
}

// Results the filter returns. A system call it does not list fails with
// ENOSYS, as one the kernel lacks would, so a program falls back as it does
// on an older kernel, and a call added in a later kernel stays refused until
// it is reviewed. A call it refuses for its arguments fails as the kernel
// would refuse it for an unprivileged caller.
var (
	retAllow           = bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}
	retENOSYS          = bpf.RetConstant{Val: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)}
	retEPERM           = bpf.RetConstant{Val: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)}
	retEAFNOSUPPORT    = bpf.RetConstant{Val: unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT)}
	retEPROTO          = bpf.RetConstant{Val: unix.SECCOMP_RET_ERRNO | uint32(unix.EPROTONOSUPPORT)}
	retESOCKTNOSUPPORT = bpf.RetConstant{Val: unix.SECCOMP_RET_ERRNO | uint32(unix.ESOCKTNOSUPPORT)}
)

// arg loads the low 32 bits of system call argument i. Each argument the
// filter checks is an int or unsigned int, or a clone flag the kernel keeps
// only the low 32 bits of, so the kernel ignores the high bits too. Checking
// all 64 would let a caller set a high bit to pass a check the kernel then
// does not see.
func arg(i uint32) bpf.LoadAbsolute {
	return bpf.LoadAbsolute{Off: offArgs + 8*i, Size: 4}
}

// seccompFilter returns the filter for level. Each check that reads an
// argument comes before the plain list, so a call on the list never loads
// one, and the kernel caches its result and skips the filter for it.
//
// KernelOpen gives up the allowlist but keeps the native ABI and the
// terminal checks, which cost a program nothing it needs. The command stays
// in the session of whoever started the sandbox, so without them it could
// type into their terminal. On an architecture with no list, KernelOpen has
// no filter at all.
func seccompFilter(level Kernel) ([]bpf.Instruction, error) {
	if auditArch == 0 {
		if level == KernelOpen {
			return nil, nil
		}
		return nil, fmt.Errorf("no system call list for %s; use kernel open", runtime.GOARCH)
	}
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: offArch, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: auditArch, SkipTrue: 1},
		retENOSYS,
		bpf.LoadAbsolute{Off: offNr, Size: 4},
	}
	if x32Bit != 0 {
		prog = append(prog,
			bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: x32Bit, SkipFalse: 1},
			retENOSYS,
		)
	}

	// TIOCSTI pushes input into a terminal as if typed, and TIOCLINUX
	// pastes a console's selection, so either could run a command in the
	// shell of whoever started the sandbox on their terminal.
	prog = append(prog, syscallIf(unix.SYS_IOCTL,
		arg(1),
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.TIOCSTI, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.TIOCLINUX, SkipTrue: 1},
		retAllow,
		retEPERM,
	)...)
	if level == KernelOpen {
		return append(prog, retAllow), nil
	}

	// Only the Unix and IP families, so netlink, packet, and the rest of
	// the kernel's socket code are out of reach. A program that probes a
	// family, as glibc's resolver does with netlink, gets the error a
	// kernel without it gives and falls back. Raw and packet sockets need
	// a capability the command does not hold, and are refused here too.
	// Within IP, only stream and datagram sockets of TCP, UDP, and ping,
	// so SCTP, DCCP, L2TP, MPTCP, and SMC's code is out of reach too, and
	// Go falls back from MPTCP to TCP. The type is checked as well as the
	// protocol, since protocol 0 means whichever protocol registered the
	// type first, which for a sequenced-packet socket is SCTP.
	prog = append(prog, syscallIf(unix.SYS_SOCKET,
		arg(0),
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.AF_UNIX, SkipTrue: 17},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.AF_INET, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.AF_INET6, SkipTrue: 1},
		retEAFNOSUPPORT,
		arg(1),
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.SOCK_RAW, SkipTrue: 12},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.SOCK_PACKET, SkipTrue: 11},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.SOCK_STREAM, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.SOCK_DGRAM, SkipTrue: 1},
		retESOCKTNOSUPPORT,
		arg(2),
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 5},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_TCP, SkipTrue: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_UDP, SkipTrue: 3},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_ICMP, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_ICMPV6, SkipTrue: 1},
		retEPROTO,
		retAllow,
		retEPERM,
	)...)
	// A socket pair in another family runs that family's code, and loads
	// its module, even though only Unix sockets make pairs.
	prog = append(prog, syscallIf(unix.SYS_SOCKETPAIR,
		arg(0),
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.AF_UNIX, SkipTrue: 1},
		retEAFNOSUPPORT,
		retAllow,
	)...)

	// The legacy netfilter options replace and read iptables, arptables,
	// and ebtables tables, and ipset and IPVS state, on IPv4 sockets from
	// option 64 up, where no ordinary IPv4 option is, and ip6tables' on
	// IPv6 sockets at 64, 65, 68, and 69. They need CAP_NET_ADMIN, which
	// code under nested holds in a network namespace of its own, and they
	// are how CVE-2021-22555 was reached. Netlink, which nftables uses, is
	// refused above.
	for _, nr := range []uint32{unix.SYS_SETSOCKOPT, unix.SYS_GETSOCKOPT} {
		prog = append(prog, syscallIf(nr,
			arg(1),
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_IP, SkipFalse: 3},
			arg(2),
			bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: netfilterOptMin, SkipTrue: 8},
			retAllow,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_IPV6, SkipFalse: 5},
			arg(2),
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: ip6tSetReplace, SkipTrue: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: ip6tSetReplace + 1, SkipTrue: 3},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: ip6tGetRevisionMatch, SkipTrue: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: ip6tGetRevisionMatch + 1, SkipTrue: 1},
			retAllow,
			retEPERM,
		)...)
	}

	// The personalities Docker allows: Linux, 32-bit Linux, a 2.6 version
	// in uname, and asking for the current one. The values are from
	// linux/personality.h, which x/sys/unix does not carry.
	const perLinux, perLinux32, uname26, perQuery = 0, 0x0008, 0x0020000, 0xffffffff
	prog = append(prog, syscallIf(unix.SYS_PERSONALITY,
		arg(0),
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: perLinux, SkipTrue: 5},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: perLinux32, SkipTrue: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uname26, SkipTrue: 3},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uname26 | perLinux32, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: perQuery, SkipTrue: 1},
		retEPERM,
		retAllow,
	)...)

	syscalls := slices.Concat(commonSyscalls, archSyscalls)
	switch level {
	case KernelNested:
		syscalls = append(append(syscalls, nestedSyscalls...), unix.SYS_CLONE)
	default:
		// clone3 passes its flags in memory, which the filter cannot
		// read, so it is not listed, and libc falls back to clone.
		prog = append(prog, syscallIf(unix.SYS_CLONE,
			arg(0),
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: nsFlags, SkipTrue: 1},
			retAllow,
			retEPERM,
		)...)
	}
	for _, nr := range syscalls {
		prog = append(prog,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 1},
			retAllow,
		)
	}
	return append(prog, retENOSYS), nil
}

// syscallIf returns body guarded by a check that the system call is nr, for
// the filter to run after it loads the number. body must end every path in
// a return, since the call is decided there, and must be short enough for a
// conditional jump to skip, which the filter's own checks are.
func syscallIf(nr uint32, body ...bpf.Instruction) []bpf.Instruction {
	// The skip is counted in the type the jump takes, so it cannot wrap.
	var skip uint8
	for range body {
		if skip == math.MaxUint8 {
			panic("system call check too long to jump over")
		}
		skip++
	}
	return append([]bpf.Instruction{bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: skip}}, body...)
}

// filterProgram returns level's filter as the kernel takes it, or nil for no
// filter. Run calls it before it starts bubblewrap, so a filter that cannot
// be built, as on an architecture with no system call list, is refused
// there rather than by pid 1 once the sandbox is up.
func filterProgram(level Kernel) (*unix.SockFprog, error) {
	insts, err := seccompFilter(level)
	if err != nil || insts == nil {
		return nil, err
	}
	raw, err := bpf.Assemble(insts)
	if err != nil {
		return nil, fmt.Errorf("assemble system call filter: %w", err)
	}
	// The length is counted in the type the kernel takes, so it cannot
	// wrap.
	prog := &unix.SockFprog{}
	filter := make([]unix.SockFilter, 0, len(raw))
	for _, r := range raw {
		if prog.Len == unix.BPF_MAXINSNS {
			return nil, errors.New("system call filter is too long")
		}
		filter = append(filter, unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K})
		prog.Len++
	}
	prog.Filter = &filter[0]
	return prog, nil
}

// installSeccomp applies level's filter to every thread of this process, so
// that whichever thread starts the command passes it on. It needs
// no_new_privs.
func installSeccomp(level Kernel) error {
	prog, err := filterProgram(level)
	if err != nil || prog == nil {
		return err
	}
	// x/sys/unix has no seccomp call, and the kernel takes the program by
	// address. It reads it during the call, and KeepAlive holds it until then.
	//
	// With TSYNC, a thread the kernel cannot move to the filter, because it
	// already has one this filter does not descend from, fails the call
	// with that thread's id as its result and no errno, and no thread gets
	// the filter. So any result but 0 is an error. SECCOMP_FILTER_FLAG_TSYNC_ESRCH
	// would turn that into ESRCH, but it needs Linux 5.7, and checking the
	// result works on every kernel that has TSYNC, from 3.17.
	tid, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(prog))) //nolint:gosec // G103: passing a pointer to the kernel needs unsafe, and the call does not keep it.
	runtime.KeepAlive(prog)
	if errno != 0 {
		return fmt.Errorf("install system call filter: %w", errno)
	}
	if tid != 0 {
		return fmt.Errorf("install system call filter: thread %d could not take it", tid)
	}
	return nil
}
