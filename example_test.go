package sandbox_test

import (
	"context"
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
	home, err := os.MkdirTemp("", "sandbox-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(home)
	home, err = filepath.EvalSymlinks(home) // Home may not contain a link.
	if err != nil {
		log.Fatal(err)
	}
	cmd, err := sandbox.Command(context.Background(), sandbox.Spec{
		Command: []string{"/bin/sh", "-c", "echo hello from $HOME"},
		Home:    home,
	})
	if err != nil {
		log.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		log.Fatal(err)
	}
}
