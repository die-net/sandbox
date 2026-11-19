//go:build linux && !amd64 && !arm64

package sandbox

// kernelFilterBuilds is false where the filter has no list of system calls,
// so only KernelOpen starts.
const kernelFilterBuilds = false
