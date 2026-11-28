//go:build linux || darwin

package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

// TestOverheadTrue measures what a sandbox costs: Command, Start and Wait for
// /usr/bin/true. It is skipped unless SANDBOX_OVERHEAD names the
// number of runs, since it is a measurement and not a check. It prints the
// median and the 90th percentile after three warm-up runs.
//
//nolint:paralleltest // measures the machine: the start overhead, which other tests' load would change.
func TestOverheadTrue(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("SANDBOX_OVERHEAD"))
	if n <= 0 {
		t.Skip("set SANDBOX_OVERHEAD to a number of runs to measure")
	}
	home, err := filepath.EvalSymlinks(t.TempDir()) // Home may not contain a link.
	if err != nil {
		t.Fatal(err)
	}
	var times []time.Duration
	for i := range n + 3 {
		start := time.Now()
		c, err := Command(t.Context(), Spec{Home: home, Command: []string{"/usr/bin/true"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
		if i >= 3 {
			times = append(times, time.Since(start))
		}
	}
	slices.Sort(times)
	t.Logf("n=%d p50=%v p90=%v min=%v max=%v", n, times[n/2], times[n*9/10], times[0], times[n-1])
}
