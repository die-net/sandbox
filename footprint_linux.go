package sandbox

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Footprint returns the resident memory, in bytes, of the processes in the
// sandbox: every descendant of the bubblewrap process, which includes pid 1
// and everything it reaps. It sums each process's resident set, so a page
// that processes share is counted for each, and it is the sum at one moment.
// It is for a caller's watchdog to poll where there is no cgroup to bound the
// memory, and a process that is gone before it is read is left out.
func (c *Cmd) Footprint() (int64, error) {
	if c.run.cmd == nil {
		return 0, errors.New("sandbox: not started")
	}
	if c.run.waited {
		return 0, errors.New("sandbox: already waited for")
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("list processes: %w", err)
	}
	ppid := map[int]int{}
	for _, d := range ents {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		if b, err := os.ReadFile("/proc/" + d.Name() + "/stat"); err == nil {
			if _, pp, ok := parseStat(string(b)); ok {
				ppid[pid] = pp
			}
		}
	}
	root := c.run.cmd.Process.Pid
	inTree := func(pid int) bool {
		for range 4096 {
			if pid == root {
				return true
			}
			pp, ok := ppid[pid]
			if !ok || pp <= 0 {
				return false
			}
			pid = pp
		}
		return false
	}
	pageSize := int64(os.Getpagesize())
	var total int64
	found := false
	for pid := range ppid {
		if !inTree(pid) {
			continue
		}
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm")
		if err != nil {
			continue
		}
		// size resident shared text lib data dt, in pages.
		if f := strings.Fields(string(b)); len(f) >= 2 {
			if pages, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				total += pages * pageSize
				found = true
			}
		}
	}
	if !found {
		return 0, errors.New("sandbox: no process of the sandbox is left")
	}
	return total, nil
}
