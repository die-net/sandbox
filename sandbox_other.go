//go:build !linux

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

// run is what a started Cmd holds, which is nothing where there is no
// backend yet.
type run struct{}

// Command is not supported off Linux yet.
func Command(context.Context, Spec) (*Cmd, error) {
	return nil, errors.ErrUnsupported
}

// Start is not supported off Linux yet.
func (c *Cmd) Start() error { return errors.ErrUnsupported }

// Wait is not supported off Linux yet.
func (c *Cmd) Wait() error { return errors.ErrUnsupported }

// Pid is zero where there is no backend yet.
func (c *Cmd) Pid() int { return 0 }

// ListenAddrs is empty where there is no backend yet.
func (c *Cmd) ListenAddrs() []string { return nil }

// LoopbackPorts is empty where there is no backend yet.
func (c *Cmd) LoopbackPorts() []int { return nil }

// Listeners is empty where there is no backend yet.
func (c *Cmd) Listeners() []net.Listener { return nil }

// Footprint is not supported where there is no backend yet.
func (c *Cmd) Footprint() (int64, error) { return 0, errors.ErrUnsupported }

// Run is not supported off Linux yet.
func Run(context.Context, Spec) (int, error) {
	return 0, errors.ErrUnsupported
}

// Stage reports that this process is not a sandbox stage, since none run off
// Linux yet.
func Stage() (int, bool) {
	if len(os.Args) > 1 && os.Args[1] == checkArg {
		return checkStage(), true
	}
	return 0, false
}
