//go:build linux || darwin

package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"testing"
)

func registerFdsListed() {
	childModes["fds-listed"] = fdsListedMode
}

// fdsListed is what fdsListedMode reports.
type fdsListed struct {
	Closed int    `json:"closed"`
	Fds    []int  `json:"fds"`
	Error  string `json:"error,omitempty"`
}

// fdsListedMode opens a pipe and the directory that lists this process's
// descriptors, reads the directory's first name, which buffers every entry,
// and closes the pipe's read end, which is one of them. It prints, as JSON,
// that descriptor's number and what listedFds returns for the rest. It runs
// in a process of its own, which holds few enough descriptors that the first
// read buffers them all.
func fdsListedMode([]string) int {
	dir := "/dev/fd"
	if runtime.GOOS == "linux" {
		dir = "/proc/self/fd"
	}
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer w.Close()
	closed := int(r.Fd())
	d, err := os.Open(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer d.Close()
	first, err := d.Readdirnames(1)
	if err != nil || len(first) != 1 || first[0] == strconv.Itoa(closed) {
		fmt.Fprintf(os.Stderr, "the first name of %s is %q (%v), and the pipe is %d\n", dir, first, err, closed)
		return 1
	}
	_ = r.Close()
	var out fdsListed
	out.Closed = closed
	out.Fds, err = listedFds(d)
	if err != nil {
		out.Error = err.Error()
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return 1
	}
	return 0
}

// Row: "Descriptors handed in": the stage lists its descriptors to mark them
// close-on-exec, and one that closes during the listing neither fails it nor
// drops another from it. The descriptor here closes after the directory was
// read and before listedFds goes through the entries, which is where
// os.ReadDir stats each entry of /dev/fd on macOS. There the stat fails with
// EBADF, which Go 1.26 returned as the stage's error (CI on macOS 15 and 26)
// and Go 1.27 drops the entry for. listedFds reads the names alone.
func TestListedFdsKeepsADescriptorThatClosed(t *testing.T) {
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), exe, "fds-listed") //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	var stderr []byte
	out, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		stderr = ee.Stderr
	}
	if err != nil {
		t.Fatalf("fds-listed: %v: %s", err, stderr)
	}
	var got fdsListed
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("fds-listed printed %q: %v", out, err)
	}
	if got.Error != "" {
		t.Errorf("listing the descriptors failed: %s", got.Error)
	}
	if !slices.Contains(got.Fds, got.Closed) {
		t.Errorf("the listing %v lacks descriptor %d, which closed after the directory was read", got.Fds, got.Closed)
	}
}
