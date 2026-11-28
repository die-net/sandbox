//go:build !linux && !darwin

package sandbox

import (
	"context"
	"errors"
	"net"
	"os"
)

// SelfPath is the path under which a sandbox's command names this binary.
// Here it is a variable, the executable's real path found at start-up, since
// no backend can bind a copy at a fixed path (Linux's SelfPath is a
// constant). It is empty if the path cannot be found. Callers must not
// change it.
var SelfPath = func() string {
	exe, _ := os.Executable()
	return exe
}()

// backend is what a Cmd holds for the platform's implementation, which is
// nothing where there is no backend yet.
type backend struct{}

// Cmd's backend field is for the backends that have state to keep. Naming it
// here keeps the checks for unused code from reporting it, since nothing here
// reads it.
var _ backend = (&Cmd{}).backend

// Command is not supported off Linux yet.
func Command(context.Context, Spec) (*Cmd, error) {
	return nil, errors.ErrUnsupported
}

// Start is not supported off Linux yet.
func (*Cmd) Start() error { return errors.ErrUnsupported }

// Wait is not supported off Linux yet.
func (*Cmd) Wait() error { return errors.ErrUnsupported }

// Pid is zero where there is no backend yet.
func (*Cmd) Pid() int { return 0 }

// ListenAddrs is empty where there is no backend yet.
func (*Cmd) ListenAddrs() []string { return nil }

// LoopbackPorts is empty where there is no backend yet.
func (*Cmd) LoopbackPorts() []int { return nil }

// Listeners is empty where there is no backend yet.
func (*Cmd) Listeners() []net.Listener { return nil }

// Footprint is not supported where there is no backend yet.
func (*Cmd) Footprint() (int64, error) { return 0, errors.ErrUnsupported }

// Run is not supported off Linux yet.
func Run(context.Context, Spec) (int, error) {
	return 0, errors.ErrUnsupported
}

// stageOptions is empty where there is no stage.
type stageOptions struct{}

// platformRole plays no part here, where no backend has a stage, and reports
// false. The check child, which needs none, is played before it is called.
func platformRole(string, stageOptions) (int, bool) { return 0, false }
