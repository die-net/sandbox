package sandbox

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
)

// roleVar names, in the environment of a run of this binary that the package
// starts, the part of the sandbox that run plays: its stage, Linux's reaper, or
// the check child. The init below finds those runs by it, so a program that
// imports the package needs no call in main, and its own arguments, whatever
// they are, are never taken for a stage's. Start and Check add it to the
// environment they already build, and replace any copy the caller's Cmd.Env
// holds. The run unsets it before anything else, so nothing it starts inherits
// it, and the command never sees it.
const roleVar = "DIE_NET_SANDBOX_ROLE"

// The parts of the sandbox a run of this binary can play. The stages are in
// stage_linux.go and stage_darwin.go, the check child in check.go, and the
// check child's namespace attempts in check_linux.go.
const (
	roleStage   = "stage"
	roleReaper  = "reaper"
	roleCheck   = "check"
	roleCheckNS = "check-ns"
)

// failed is the exit status of a run of this binary that could not play its
// part, as distinct from the command's own status.
const failed = 125

// stageOpts is what this binary's stage runs with. A program leaves it the
// zero value. A test binary sets it from a package-level initializer in a
// _test.go file, which Go runs before any init, since a stage runs from the
// init below and never reaches TestMain. Nothing a caller sends the stage can
// set it.
var stageOpts stageOptions

// init plays the part roleVar names, if it names one, and exits. Only an init
// keeps the part on the process's first thread: Go runs every init on the main
// goroutine locked to that thread (main in runtime/proc.go), and a call of
// runtime.LockOSThread here keeps it there for good (go doc
// runtime.LockOSThread). Linux's reaper, pid 1 of the sandbox, needs its first
// thread for the calls that act on one thread. The init of every package this
// one imports has run by then, and that of every package that imports it, the
// program's main among them, has not.
//
//nolint:gochecknoinits // The owner approved this one init: a run of this binary as part of the sandbox must be found before main, and on the first thread, which only an init can do.
func init() {
	role, ok := os.LookupEnv(roleVar)
	if !ok {
		return
	}
	runtime.LockOSThread()
	os.Exit(playRole(role))
}

// playRole unsets roleVar and plays role, and returns the exit status.
func playRole(role string) int {
	// At once, so that nothing this run starts inherits it.
	if err := os.Unsetenv(roleVar); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: unset %s: %v\n", roleVar, err)
		return failed
	}
	if role == roleCheck {
		return checkStage()
	}
	if code, ok := platformRole(role, stageOpts); ok {
		return code
	}
	fmt.Fprintf(os.Stderr, "sandbox: %s=%q names no part of the sandbox on %s\n", roleVar, role, runtime.GOOS)
	return failed
}

// withRole returns env without any setting of roleVar, and with roleVar set to
// role at the end unless role is empty, so that no two settings can disagree.
// Which of two would count depends on the path: a Go process takes the first
// (copyenv in syscall/env_unix.go), os/exec keeps the last (dedupEnv in
// os/exec/exec.go), and os.StartProcess and syscall.Exec, which the stages
// use, pass both on.
func withRole(env []string, role string) []string {
	out := slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return name == roleVar
	})
	if role != "" {
		out = append(out, roleVar+"="+role)
	}
	return out
}
