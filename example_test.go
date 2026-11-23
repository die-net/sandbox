package sandbox_test

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/die-net/sandbox"
)

// Example is the program in README.md. It has no Output comment, so go test
// compiles it and doesn't run it. A real program calls Stage first in main.
func Example() {
	if code, ok := sandbox.Stage(); ok {
		os.Exit(code)
	}
	if err := runExample(); err != nil {
		log.Fatal(err)
	}
}

// runExample is the rest of the program in README.md, in a function of its
// own so that its deferred cleanup runs before the program exits on an error.
func runExample() (err error) {
	dir, err := os.MkdirTemp("", "sandbox-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	home, err := filepath.EvalSymlinks(dir) // Home may not contain a link.
	if err != nil {
		return err
	}
	cmd, err := sandbox.Command(context.Background(), sandbox.Spec{
		Command: []string{"/bin/sh", "-c", "echo hello from $HOME"},
		Home:    home,
	})
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}
