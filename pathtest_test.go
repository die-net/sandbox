//go:build linux || darwin

package sandbox

import "os"

// The tests open the paths they name: files they made, and paths that a
// sandbox must refuse, tried from inside it. A variable path is the point of
// each, so these wrappers are where the check for one is silenced.

// readFile is os.ReadFile of a path the test names.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: the test reads a path it made, or one a sandbox must not let it read.
}

// openFile is os.Open of a path the test names.
func openFile(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // G304: the test opens a path it made, or one a sandbox must not let it open.
}

// openFileFlags is os.OpenFile of a path the test names.
func openFileFlags(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm) //nolint:gosec // G304: the test opens a path it made, or one a sandbox must not let it open.
}

// createFile is os.Create of a path the test names.
func createFile(path string) (*os.File, error) {
	return os.Create(path) //nolint:gosec // G304: the test creates a file at a path it made.
}
