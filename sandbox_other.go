//go:build !linux

package sandbox

import (
	"context"
	"errors"
)

// Run is not supported off Linux yet.
func Run(context.Context, Spec) (int, error) {
	return 0, errors.ErrUnsupported
}

// Stage reports that this process is not a sandbox stage, since none run off
// Linux yet.
func Stage() (int, bool) {
	return 0, false
}
