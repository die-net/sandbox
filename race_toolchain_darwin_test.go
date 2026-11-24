//go:build race

package sandbox

import (
	"go/version"
	"runtime"
	"testing"
)

// Before Go 1.26.5, a binary built with -race on darwin could crash the child
// of a fork before it execed: rawSyscall was instrumented, and the race
// runtime's state is not valid in the child (golang/go#79804, backported as
// #79806). The parent saw a Start that worked and a Wait that returned "signal:
// segmentation fault", for a program that never ran. Every test here starts
// processes, so with such a toolchain any of them can fail on a crash that no
// sandbox caused, as TestProfileCutShortDoesNotRun did on macos-26 in CI.
func TestRaceDetectorToolchainCanForkOnDarwin(t *testing.T) {
	t.Parallel()
	got := runtime.Version()
	if !version.IsValid(got) {
		t.Skipf("%q is not a release, so its fixes can't be told", got)
	}
	if version.Compare(got, "go1.26.5") < 0 {
		t.Errorf("%s with -race can crash a forked child before it execs (golang/go#79804): use go1.26.5 or later", got)
	}
}
