package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// churnBackoff sets the waits between scans from SANDBOX_CHURN_BACKOFF, as
// "start,max" in milliseconds (fractions allowed), for trying other waits.
func churnBackoff(t *testing.T) {
	v := os.Getenv("SANDBOX_CHURN_BACKOFF")
	if v == "" {
		return
	}
	a, b, ok := strings.Cut(v, ",")
	x, err1 := strconv.ParseFloat(a, 64)
	y, err2 := strconv.ParseFloat(b, 64)
	if !ok || err1 != nil || err2 != nil {
		t.Fatalf("SANDBOX_CHURN_BACKOFF = %q, want start,max in ms", v)
	}
	oldStart, oldMax := backoffStart, backoffMax
	t.Cleanup(func() { backoffStart, backoffMax = oldStart, oldMax })
	backoffStart, backoffMax = time.Duration(x*float64(time.Millisecond)), time.Duration(y*float64(time.Millisecond))
}

// TestChurnCleanScanRate measures how often a scan of an empty sandbox is clean,
// and how long a teardown takes, while other processes of the account fork and
// exit as fast as they can: n perl loops, each with one child at a time that
// exits at once. It needs a machine with nothing else to do, and takes half a
// minute, so it runs only with SANDBOX_CHURN=1. The figures are in
// docs/macos.md, "Process churn".
func TestChurnCleanScanRate(t *testing.T) {
	if os.Getenv("SANDBOX_CHURN") == "" {
		t.Skip("set SANDBOX_CHURN=1 to measure")
	}
	churnBackoff(t)
	const loop = `use POSIX; my $e = time + $ARGV[0]; my $n = 0; while (time < $e) { my $p = fork(); if (!$p) { POSIX::_exit(0) } waitpid($p, 0); $n++ } print "$n\n";`
	budget := 200 * time.Millisecond
	if v, err := strconv.Atoi(os.Getenv("SANDBOX_CHURN_BUDGET_MS")); err == nil {
		budget = time.Duration(v) * time.Millisecond
	}
	loopCounts := []int{1, 2, 4, 8, 16}
	if v := os.Getenv("SANDBOX_CHURN_LOOPS"); v != "" {
		loopCounts = nil
		for _, f := range strings.Split(v, ",") {
			n, err := strconv.Atoi(f)
			if err != nil {
				t.Fatalf("SANDBOX_CHURN_LOOPS = %q", v)
			}
			loopCounts = append(loopCounts, n)
		}
	}
	// The loops run for as long as the scans and the teardowns do.
	const tries = 20
	secs := 4 + int((tries * budget).Seconds())
	for _, loops := range loopCounts {
		var cmds []*exec.Cmd
		outs := make([]*syncBuffer, loops)
		for i := range loops {
			cmd := exec.Command("/usr/bin/perl", "-e", loop, strconv.Itoa(secs))
			outs[i] = &syncBuffer{}
			cmd.Stdout = outs[i]
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			cmds = append(cmds, cmd)
		}
		time.Sleep(300 * time.Millisecond)
		m, err := newMarker()
		if err != nil {
			t.Fatal(err)
		}
		p := m.prober(0)
		var mem memory
		scans, clean := 0, 0
		begin := time.Now()
		wait := backoffStart
		for time.Since(begin) < 2*time.Second {
			ok, next, err := p.scan(mem)
			if err != nil {
				t.Fatal(err)
			}
			mem = next
			scans++
			if ok {
				clean++
				wait = backoffStart
				continue
			}
			// As a teardown does between scans.
			p.sleep(wait)
			wait = min(2*wait, backoffMax)
		}
		var worst time.Duration
		total, most, gaveUp := 0, 0, 0
		for range tries {
			s := time.Now()
			n, end := m.kill(budget, 0)
			worst = max(worst, time.Since(s))
			total += n
			most = max(most, n)
			if end != endEmpty {
				gaveUp++
			}
		}
		forks := 0
		for i, cmd := range cmds {
			_ = cmd.Wait()
			var n int
			fmt.Sscan(outs[i].buf.String(), &n)
			forks += n
		}
		t.Logf("loops=%d: %d forks/s; scans=%d clean=%d (%.1f%%); %d teardowns with a %v budget: mean %.1f scans, most %d, worst %v, gave up %d",
			loops, forks/secs, scans, clean, 100*float64(clean)/float64(scans), tries, budget, float64(total)/tries, most, worst, gaveUp)
	}
}

// TestChurnNormalTeardownLatency measures how long Wait takes for a command that
// leaves two orphans behind, which the teardown signals in its first scan, on an
// idle machine and with 4 fork loops running. Run it with SANDBOX_CHURN=1.
func TestChurnNormalTeardownLatency(t *testing.T) {
	if os.Getenv("SANDBOX_CHURN") == "" {
		t.Skip("set SANDBOX_CHURN=1 to measure")
	}
	churnBackoff(t)
	const loop = `use POSIX; my $e = time + $ARGV[0]; while (time < $e) { my $p = fork(); if (!$p) { POSIX::_exit(0) } waitpid($p, 0); }`
	for _, loops := range []int{0, 4, 16} {
		var cmds []*exec.Cmd
		for range loops {
			cmd := exec.Command("/usr/bin/perl", "-e", loop, "9")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			cmds = append(cmds, cmd)
		}
		time.Sleep(200 * time.Millisecond)
		var took []time.Duration
		scans, survivors := 0, 0
		for range 20 {
			c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{"/bin/sh", "-c", "/bin/sleep 30 & /bin/sleep 30 & exit 0"}})
			if err != nil {
				t.Fatal(err)
			}
			c.Env = []string{shellPath}
			start := time.Now()
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			if err := c.Wait(); err != nil {
				survivors++
			}
			took = append(took, time.Since(start))
			scans += c.run.stageScans
		}
		for _, cmd := range cmds {
			_ = cmd.Wait()
		}
		slices.Sort(took)
		t.Logf("loops=%d: Start to Wait 20 runs: p50 %v, p90 %v, worst %v; mean stage scans %.1f; %d with ErrSurvivors",
			loops, took[10].Round(100*time.Microsecond), took[18].Round(100*time.Microsecond), took[19].Round(100*time.Microsecond), float64(scans)/20, survivors)
	}
}
