package sandbox

import "golang.org/x/sys/unix"

// auditArch is the architecture the filter allows, as seccomp reports it.
// A system call through the 32-bit ABI reports another and is refused.
const auditArch = unix.AUDIT_ARCH_AARCH64

// x32Bit is zero, since arm64 has no x32 ABI.
const x32Bit = 0

// archSyscalls is empty, since commonSyscalls is every call Docker allows on
// arm64.
var archSyscalls []uint32
