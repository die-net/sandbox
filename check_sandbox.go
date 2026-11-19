package sandbox

import (
	"context"
	"io"
	"os"
)

// startInSandbox starts the check child inside a sandbox built from spec,
// and returns a function that waits for it. The child gets the results
// descriptor and the payload descriptor as 3 and 4, then spec's own Files.
// Its command is SelfPath, so the view needs no path to this binary on
// Linux.
func startInSandbox(ctx context.Context, spec Spec, out, payload *os.File, stderr io.Writer) (func() error, error) {
	spec.Command = []string{SelfPath, checkArg}
	spec.Files = append([]*os.File{out, payload}, spec.Files...)
	cmd, err := Command(ctx, spec)
	if err != nil {
		return nil, err
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	cmd.Env = nil // Start sets HOME, TMPDIR and the rest
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd.Wait, nil
}
