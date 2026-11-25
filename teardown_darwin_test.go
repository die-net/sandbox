package sandbox

import (
	"errors"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// The stage's teardown proves the sandbox empty with as few scans as the
// machine allows, tells the caller, and the caller's Wait scans no more. How
// many scans a teardown takes depends on the rest of the account: a process
// that exits between the list and its read makes a scan unclean, and with a few
// fork loops running most first scans are (docs/macos.md, "Process churn"). So
// each run is measured against a baseline: once Wait has returned, the test
// tears down the same sandbox, now empty, with the same scan from outside, and
// counts its scans. Both see the same churn and the same zombies, and a stage
// that needs one scan more than it should, on every run, stands out by a scan
// a run. The test allows half that. With a few fork loops running, the
// difference of one run has a spread of about two scans, so it takes hundreds
// of runs to tell half a scan a run from noise. The test stops sooner when it
// can: once it has made enough runs that a scan a run more could not hide in
// the noise, it stops as soon as the stage has made no more scans than the
// baseline, which on a quiet machine is at once. None of the runs may have the
// caller scan, whatever the load, since the stage has its whole budget.
func TestTeardownOneScanInTheStageAndNoneInTheCaller(t *testing.T) {
	t.Parallel()
	home := realTemp(t)
	const least, most = 50, 400
	stage, base, runs := 0, 0, 0
	for runs < most && (runs < least || stage > base) {
		runs++
		c, err := Command(t.Context(), Spec{Home: home, Command: []string{"/usr/bin/true"}})
		if err != nil {
			t.Fatal(err)
		}
		// The stage is this test binary, and one built with -race sleeps a second
		// as it exits, for races to be reported, which over 50 runs or more is most
		// of a minute. Other tests' stages keep the sleep.
		c.Env = []string{"GORACE=atexit_sleep_ms=0"}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
		if n := callerSideScans(c); n != 0 {
			t.Fatalf("the caller made %d scans after the stage reported the sandbox empty", n)
		}
		n, end := c.run.mark.kill(c.run.budget, c.run.group)
		if end != endEmpty {
			t.Fatalf("the baseline teardown of the empty sandbox ended with %v after %d scans", end, n)
		}
		stage += c.run.stageScans
		base += n
	}
	t.Logf("%d runs: the stage made %d scans, the baseline %d", runs, stage, base)
	if 2*(stage-base) > runs {
		t.Errorf("the stage made %d scans in %d runs, more than half a scan a run over the baseline's %d", stage, runs, base)
	}
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
	c.Env = []string{shellPath, stageOrphanZombieEnv + "=" + strconv.Itoa(z)}
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
		c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: reforkCommand("chain 10 200")})
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
