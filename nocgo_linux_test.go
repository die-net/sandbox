//go:build linux && !cgo

package sandbox

// cgoBuild is true when the test binary resolves users through libc and NSS.
const cgoBuild = false
