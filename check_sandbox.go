//go:build sandbox_cmd

package sandbox

import (
	"context"
	"io"
	"os"
)

// startInSandbox starts the check child inside a sandbox built from spec,
// with out as its descriptor 3, and returns a function that waits for it.
// It is the one place Check touches Command: it assumes
// Command(ctx, Spec) (*Cmd, error), Cmd.Start, Cmd.Wait, settable
// Cmd.Stdout, Cmd.Stderr and Cmd.Env, Spec.Files for descriptors 3 and up,
// and SelfPath, the binary as the command names it.
func startInSandbox(ctx context.Context, spec Spec, payload string, out *os.File, stderr io.Writer) (func() error, error) {
	spec.Command = []string{SelfPath, checkArg, payload}
	spec.Files = append([]*os.File{out}, spec.Files...) // fd 3
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
