package sandbox

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

// The stage's teardown proves the sandbox empty with one scan, tells the
// caller, and the caller's Wait scans no more. A zombie of this account that
// the test process never reaped, which other tests leave, is excused by its
// parent, which is no member, but one whose parent the scan cannot clear costs
// the stage a second scan, so with one the test accepts two. Another
// process of the account starting during the scan costs one more, and how often
// that happens depends on the load of the machine (a parallel build can make
// half of all scans unclean). So the test goes on until enough runs have made
// the scans expected, up to a limit, and the limit is generous: a stage that
// needs two scans always never gets there. None of the runs may have the
// caller scan, whatever the load, since the stage has its whole budget.
func TestTeardownOneScanInTheStageAndNoneInTheCaller(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	const tries, most = 60, 5
	hits, ran := 0, 0
	for ran < tries && hits < most {
		ran++
		// A zombie whose parent is no process of this account, or that the scan
		// has not cleared yet, costs a second scan.
		zombies := len(foreignZombies(t)) > 0
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
		if n := callerSideScans(c); n != 0 {
			t.Fatalf("the caller made %d scans after the stage reported the sandbox empty", n)
		}
		if n := c.run.stageScans; n == 1 || (n == 2 && zombies) {
			hits++
		} else {
			t.Logf("the stage made %d scans, want 1 (or 2 with a foreign zombie: %v)", c.run.stageScans, zombies)
		}
	}
	if hits < most {
		t.Errorf("the stage made the scans expected in %d of %d runs, want %d", hits, ran, most)
	}
}

// foreignZombies returns the zombies of this account, which include this
// process's own children that other tests left unreaped.
func foreignZombies(t *testing.T) []int {
	t.Helper()
	pids, err := listUIDPids(euid())
	if err != nil {
		t.Fatal(err)
	}
	var out []int
	for _, pid := range pids {
		if st, err := statPid(pid); err == nil && st.Zombie {
			out = append(out, pid)
		}
	}
	return out
}

// A zombie that nothing reaps, as a program might leave, makes the first scan
// unknown and no scan after it: the sandbox is still proved empty, the caller
// does not scan, and Wait neither fails nor stalls.
func TestTeardownLingeringZombie(t *testing.T) {
	t.Parallel()
	z := zombieChild(t)
	c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{"/usr/bin/true"}})
	if err != nil {
		t.Fatal(err)
	}
	// The zombie is a child of this process, which is no member, so a scan would
	// excuse it at once (TestRealScanExcusesAZombieOfANonMember). Its parent is
	// hidden from the stage's scan, to leave what the scan remembers.
	c.Env = []string{shellPath, stageOrphanZombiesEnv + "=1"}
	start := time.Now()
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	err = c.Wait()
	if errors.Is(err, ErrSurvivors) || err != nil {
		t.Errorf("Wait with the zombie %d lingering: %v", z, err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Wait took %v with a zombie lingering", d)
	}
	if n := callerSideScans(c); n != 0 {
		t.Errorf("the caller made %d scans", n)
	}
	// The zombie is new to the first scan, and known to the second. Other
	// processes of the account starting and exiting can add scans, as many as the
	// load makes unclean, so only the least is checked, and the time above bounds
	// the rest.
	if n := c.run.stageScans; n < 2 {
		t.Errorf("the stage made %d scans, want at least 2", n)
	}
}

// A stage that is killed before it can say the sandbox is empty leaves the
// proof to the caller, which ends a chain of processes that is still forking,
// and Wait does not report survivors.
func TestTeardownStageKilledMidTeardown(t *testing.T) {
	t.Parallel()
	delay := 150 * time.Millisecond
	for range 5 {
		c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{"/usr/bin/perl", "-e", reforkScript, "10"}})
		if err != nil {
			t.Fatal(err)
		}
		c.Env = []string{shellPath}
		c.Stdout = &syncBuffer{} // the chain holds it open, so Wait waits for the chain
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		endAtCleanup(t, c)
		// The chain's first process exits at once, which starts the stage's
		// teardown, and the chain keeps forking. The stage is this process's
		// child, so it is ours to kill.
		time.Sleep(delay)
		if err := syscall.Kill(c.Pid(), syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		err = waitWithin(t, c, 9*time.Second)
		if errors.Is(err, ErrSurvivors) {
			t.Fatalf("Wait: %v", err)
		}
		if c.run.stageScans != 0 {
			// The stage had finished before it was killed.
			delay /= 2
			continue
		}
		if n := callerSideScans(c); n < 1 {
			t.Errorf("the caller made %d scans for a stage that never reported", n)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("Wait took %v, with the chain due to stop by itself at 10 s", d)
		}
		if got, err := c.run.mark.processes(); err != nil || len(got) != 0 {
			t.Errorf("processes of the sandbox after Wait: %v, %v", got, err)
		}
		return
	}
	t.Error("the stage always finished before it was killed")
}
