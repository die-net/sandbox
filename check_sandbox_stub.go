//go:build !sandbox_cmd

package sandbox

import (
	"context"
	"errors"
	"io"
	"os"
)

// startInSandbox is the one place Check touches Command. Until cmd.go
// lands this is a stub, and check_sandbox.go, tagged sandbox_cmd, is the real
// one. At merge, delete this file and that tag.
func startInSandbox(context.Context, Spec, string, *os.File, io.Writer) (func() error, error) {
	return nil, errors.New("Check with a Spec needs Command, which is not merged yet")
}
