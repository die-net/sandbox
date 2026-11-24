module github.com/die-net/sandbox

go 1.26.0

// The race detector on darwin crashes the child of a fork before it execs in
// 1.26.0 to 1.26.4 (golang/go#79804, fixed by #79806). CI takes its Go from
// here, and TestRaceDetectorToolchainCanForkOnDarwin checks the one in use.
toolchain go1.26.5

require (
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
)
