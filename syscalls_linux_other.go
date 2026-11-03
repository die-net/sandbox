//go:build !amd64 && !arm64

package sandbox

// auditArch is zero where the filter has no list of system calls, which
// makes KernelStrict and KernelNested refuse to start.
const auditArch = 0

// x32Bit is zero, since only amd64 has an x32 ABI.
const x32Bit = 0

// commonSyscalls and archSyscalls are empty where the filter has no list.
var commonSyscalls, archSyscalls []uint32
