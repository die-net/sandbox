package sandbox

import (
	"encoding/binary"
	"math"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// call is one system call as the filter sees it.
type call struct {
	arch uint32
	nr   uint32
	args [6]uint64
}

// data lays c out as struct seccomp_data for bpf.VM. The VM loads words big
// endian, so each is written that way, at the offset where the filter reads
// it on a little-endian machine: an argument's low half first.
func (c call) data() []byte {
	b := make([]byte, 64)
	binary.BigEndian.PutUint32(b[offNr:], c.nr)
	binary.BigEndian.PutUint32(b[offArch:], c.arch)
	for i, a := range c.args {
		binary.BigEndian.PutUint32(b[offArgs+8*i:], uint32(a&math.MaxUint32))
		binary.BigEndian.PutUint32(b[offArgs+8*i+4:], uint32(a>>32))
	}
	return b
}

func TestSeccompFilter(t *testing.T) {
	const (
		allow       = unix.SECCOMP_RET_ALLOW
		enosys      = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)
		eperm       = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
		eafnosupp   = unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT)
		eproto      = unix.SECCOMP_RET_ERRNO | uint32(unix.EPROTONOSUPPORT)
		esocktno    = unix.SECCOMP_RET_ERRNO | uint32(unix.ESOCKTNOSUPPORT)
		highBit     = 1 << 32
		cloneThread = unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD
	)
	sys := func(nr uint32, args ...uint64) call {
		c := call{arch: auditArch, nr: nr}
		copy(c.args[:], args)
		return c
	}
	type filterCase struct {
		name   string
		call   call
		strict uint32
		nested uint32
	}
	cases := []filterCase{
		{"read", sys(unix.SYS_READ), allow, allow},
		{"execve", sys(unix.SYS_EXECVE), allow, allow},
		{"landlock_restrict_self", sys(unix.SYS_LANDLOCK_RESTRICT_SELF), allow, allow},
		{"another architecture", call{arch: unix.AUDIT_ARCH_I386, nr: unix.SYS_READ}, enosys, enosys},
		{"io_uring_setup", sys(unix.SYS_IO_URING_SETUP), enosys, enosys},
		{"bpf", sys(unix.SYS_BPF), enosys, enosys},
		{"perf_event_open", sys(unix.SYS_PERF_EVENT_OPEN), enosys, enosys},
		{"keyctl", sys(unix.SYS_KEYCTL), enosys, enosys},
		{"ptrace", sys(unix.SYS_PTRACE), enosys, enosys},
		{"setns", sys(unix.SYS_SETNS), enosys, enosys},
		{"unshare", sys(unix.SYS_UNSHARE, unix.CLONE_NEWUSER), enosys, allow},
		{"mount", sys(unix.SYS_MOUNT), enosys, allow},
		{"fsopen", sys(unix.SYS_FSOPEN), enosys, allow},
		{"chroot", sys(unix.SYS_CHROOT), enosys, allow},
		{"clone3", sys(unix.SYS_CLONE3), enosys, enosys},
		{"clone a thread", sys(unix.SYS_CLONE, cloneThread), allow, allow},
		{"clone a process", sys(unix.SYS_CLONE, uint64(unix.SIGCHLD)), allow, allow},
		{"clone a user namespace", sys(unix.SYS_CLONE, unix.CLONE_NEWUSER|uint64(unix.SIGCHLD)), eperm, allow},
		{"clone a network namespace", sys(unix.SYS_CLONE, unix.CLONE_NEWNET), eperm, allow},
		{"clone a namespace with a high bit", sys(unix.SYS_CLONE, highBit|unix.CLONE_NEWNS), eperm, allow},
		{"tcp socket", sys(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC), allow, allow},
		{"tcp socket naming TCP", sys(unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP), allow, allow},
		{"ping socket", sys(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP), allow, allow},
		{"sctp socket", sys(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP), eproto, eproto},
		{"sctp by its type", sys(unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_SEQPACKET, 0), esocktno, esocktno},
		{"dccp by its type", sys(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_DCCP|unix.SOCK_CLOEXEC, 0), esocktno, esocktno},
		{"mptcp socket", sys(unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), eproto, eproto},
		{"unix socket pair", sys(unix.SYS_SOCKETPAIR, unix.AF_UNIX, unix.SOCK_STREAM), allow, allow},
		{"netlink socket pair", sys(unix.SYS_SOCKETPAIR, unix.AF_NETLINK, unix.SOCK_RAW), eafnosupp, eafnosupp},
		{"udp6 socket", sys(unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_DGRAM), allow, allow},
		{"unix socket", sys(unix.SYS_SOCKET, unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK), allow, allow},
		{"inet socket with a high bit", sys(unix.SYS_SOCKET, highBit|unix.AF_INET, unix.SOCK_STREAM), allow, allow},
		{"netlink socket", sys(unix.SYS_SOCKET, unix.AF_NETLINK, unix.SOCK_RAW), eafnosupp, eafnosupp},
		{"packet socket", sys(unix.SYS_SOCKET, unix.AF_PACKET, unix.SOCK_RAW), eafnosupp, eafnosupp},
		{"vsock socket", sys(unix.SYS_SOCKET, unix.AF_VSOCK, unix.SOCK_STREAM), eafnosupp, eafnosupp},
		{"raw inet socket", sys(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC), eperm, eperm},
		{"packet type inet socket", sys(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_PACKET), eperm, eperm},
		{"terminal ioctl", sys(unix.SYS_IOCTL, 0, unix.TCGETS), allow, allow},
		{"TIOCSTI", sys(unix.SYS_IOCTL, 0, unix.TIOCSTI), eperm, eperm},
		{"TIOCSTI with a high bit", sys(unix.SYS_IOCTL, 0, highBit|unix.TIOCSTI), eperm, eperm},
		{"TIOCLINUX", sys(unix.SYS_IOCTL, 0, unix.TIOCLINUX), eperm, eperm},
		{"an IPv4 option", sys(unix.SYS_SETSOCKOPT, 3, unix.IPPROTO_IP, unix.IP_TOS), allow, allow},
		{"replace an iptables table", sys(unix.SYS_SETSOCKOPT, 3, unix.IPPROTO_IP, 64), eperm, eperm},
		{"read an iptables table", sys(unix.SYS_GETSOCKOPT, 3, unix.IPPROTO_IP, 65), eperm, eperm},
		{"an ebtables option", sys(unix.SYS_SETSOCKOPT, 3, unix.IPPROTO_IP, 128), eperm, eperm},
		{"an IPv6 option", sys(unix.SYS_SETSOCKOPT, 3, unix.IPPROTO_IPV6, unix.IPV6_TCLASS), allow, allow},
		{"replace an ip6tables table", sys(unix.SYS_SETSOCKOPT, 3, unix.IPPROTO_IPV6, 64), eperm, eperm},
		{"an ip6tables revision", sys(unix.SYS_GETSOCKOPT, 3, unix.IPPROTO_IPV6, 69), eperm, eperm},
		{"a TCP option", sys(unix.SYS_SETSOCKOPT, 3, unix.IPPROTO_TCP, 64), allow, allow},
		{"personality query", sys(unix.SYS_PERSONALITY, 0xffffffff), allow, allow},
		{"personality linux", sys(unix.SYS_PERSONALITY, 0), allow, allow},
		{"personality bsd", sys(unix.SYS_PERSONALITY, 6), eperm, eperm},
	}
	if x32Bit != 0 {
		cases = append(cases, filterCase{"x32 read", sys(x32Bit | unix.SYS_READ), enosys, enosys})
	}
	// Under open, only other ABIs and the terminal ioctls are refused.
	openRefused := map[string]uint32{
		"another architecture": enosys, "x32 read": enosys,
		"TIOCSTI": eperm, "TIOCSTI with a high bit": eperm, "TIOCLINUX": eperm,
	}
	for _, level := range []Kernel{KernelStrict, KernelNested, KernelOpen} {
		insts, err := seccompFilter(level)
		if err != nil {
			t.Fatal(err)
		}
		if len(insts) > unix.BPF_MAXINSNS {
			t.Fatalf("%s: %d instructions, more than the kernel takes", level, len(insts))
		}
		vm, err := bpf.NewVM(insts)
		if err != nil {
			t.Fatalf("%s: %v", level, err)
		}
		for _, tc := range cases {
			want := tc.strict
			if level == KernelNested {
				want = tc.nested
			}
			if level == KernelOpen {
				want = allow
				if w, ok := openRefused[tc.name]; ok {
					want = w
				}
			}
			got, err := vm.Run(tc.call.data())
			if err != nil {
				t.Fatalf("%s: %s: %v", level, tc.name, err)
			}
			if got != int(want) {
				t.Errorf("%s: %s = %#x, want %#x", level, tc.name, got, want)
			}
		}
	}
}
