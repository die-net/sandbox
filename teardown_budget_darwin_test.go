package sandbox

import (
	"errors"
	"fmt"
	"slices"
	"syscall"
	"testing"
	"time"
)

// The teardown waits between scans, and spends its time by why scans are unclean:
// members that keep turning up end it early, and noise does not.

// ------------------------------------------------------------------ the waits

func TestRunBackoff(t *testing.T) {
	t.Parallel()
	// A pid that is never settled, so that no scan is clean.
	f := newFake([]int{10, 20})
	f.stat = func(_, pid int) (procStat, error) {
		if pid == 20 {
			return procStat{}, errGone
		}
		return procStat{Start: f.t0.Add(-time.Hour).UnixMicro()}, nil
	}
	scans, out := f.prober().run(200 * time.Millisecond)
	if out != endBudget {
		t.Fatalf("out = %v, want the budget to run out", out)
	}
	if len(f.slept) != scans-1 && len(f.slept) != scans {
		t.Errorf("%d scans and %d waits: want a wait after each scan, the first excepted", scans, len(f.slept))
	}
	want := []time.Duration{1, 2, 4, 8, 16, 25, 25, 25}
	for i, d := range want {
		if i >= len(f.slept) || f.slept[i] != d*time.Millisecond {
			t.Fatalf("waits = %v, want %v and then 25 ms each", f.slept, want)
		}
	}
	var total time.Duration
	for _, d := range f.slept {
		total += d
		if d > backoffMax {
			t.Errorf("a wait of %v, over the cap of %v", d, backoffMax)
		}
	}
	if total > 200*time.Millisecond {
		t.Errorf("waited %v in all, over the budget", total)
	}
}

func TestRunDoesNotWaitBeforeTheFirstScanOrAfterTheLast(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20})
	if scans, out := f.prober().run(time.Second); scans != 1 || out != endEmpty || len(f.slept) != 0 {
		t.Errorf("scans = %d, out = %v, waits = %v; want one scan, clean, no wait", scans, out, f.slept)
	}
	// Unclean once, then clean: one wait, between them, of the shortest.
	f = newFake([]int{10, 20, 30}, []int{10})
	f.members = map[int]bool{30: true}
	if scans, out := f.prober().run(time.Second); scans != 2 || out != endEmpty || !slices.Equal(f.slept, []time.Duration{time.Millisecond}) {
		t.Errorf("scans = %d, out = %v, waits = %v; want two scans and one wait of 1 ms", scans, out, f.slept)
	}
}

// A wait never goes past the deadline.
func TestRunWaitStopsAtTheDeadline(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20})
	f.stat = func(_, pid int) (procStat, error) {
		if pid == 20 {
			return procStat{}, errGone
		}
		return procStat{Start: f.t0.Add(-time.Hour).UnixMicro()}, nil
	}
	f.step = 0
	f.prober().run(5 * time.Millisecond)
	if !slices.Equal(f.slept, []time.Duration{time.Millisecond, 2 * time.Millisecond, 2 * time.Millisecond}) {
		t.Errorf("waits = %v, want 1 ms, 2 ms and then the 2 ms that are left of 5, not the 4 that the doubling gives", f.slept)
	}
}

// ------------------------------------------------------------- spending time

// membersByScan makes the fake's n-th scan (from 1) find count(n) members, which
// are the same pids at each scan, as a process that keeps forking is. It returns
// the time, from the start, of the scan that first found a different number.
func membersByScan(f *fakeSystem, p *prober, count func(scan int) int) (changedAt *time.Duration) {
	f.members = map[int]bool{}
	for i := range 2000 {
		f.members[1000+i] = true
	}
	changedAt = new(time.Duration)
	last := -1
	p.list = func() ([]int, error) {
		f.listed++
		n := count(f.listed)
		if n != last {
			last, *changedAt = n, f.clock.Sub(f.t0)
		}
		pids := make([]int, 1, 1+n)
		pids[0] = 10
		for i := range n {
			pids = append(pids, 1000+i)
		}
		return pids, nil
	}
	return changedAt
}

// Scans that keep finding as many members as they did, after they were signaled,
// are a process forking against the teardown, and the teardown stops early.
func TestRunGivesUpOnMembersThatKeepTurningUp(t *testing.T) {
	t.Parallel()
	f := newFake()
	p := f.prober()
	membersByScan(f, &p, func(int) int { return 3 })
	scans, out := p.run(time.Hour)
	elapsed := f.clock.Sub(f.t0)
	if out != endMembers {
		t.Fatalf("out = %v after %d scans; want to give up on members", out, scans)
	}
	if elapsed < giveUpAfter || elapsed > giveUpAfter+backoffMax+50*time.Millisecond {
		t.Errorf("gave up after %v, want about %v", elapsed, giveUpAfter)
	}
}

// The teardown gives up giveUpAfter after the scan that found the fewest members,
// not after the first one that found any: a number that is still falling is a
// program that is ending, however many scans that takes.
func TestRunGivesUpGiveUpAfterTheLastFall(t *testing.T) {
	t.Parallel()
	f := newFake()
	p := f.prober()
	// 5 members for the first 30 scans, then 4 for the rest.
	changedAt := membersByScan(f, &p, func(scan int) int {
		if scan <= 30 {
			return 5
		}
		return 4
	})
	scans, out := p.run(time.Hour)
	elapsed := f.clock.Sub(f.t0)
	if out != endMembers {
		t.Fatalf("out = %v after %d scans; want to give up on members", out, scans)
	}
	if *changedAt < 500*time.Millisecond {
		t.Fatalf("the number fell at %v, too early to tell the windows apart", *changedAt)
	}
	if elapsed < *changedAt+giveUpAfter || elapsed > *changedAt+giveUpAfter+backoffMax+50*time.Millisecond {
		t.Errorf("gave up at %v, want %v after the fall at %v", elapsed, giveUpAfter, *changedAt)
	}
}

// Scans between the ones that find members, which find none, do not start the
// window again.
func TestRunGivesUpThroughScansThatFindNoMember(t *testing.T) {
	t.Parallel()
	f := newFake()
	p := f.prober()
	membersByScan(f, &p, func(scan int) int { return 3 * (scan % 2) })
	// The odd scans find only an unknown pid, so that they are not clean.
	f.unknown = map[int]bool{77: true}
	list := p.list
	p.list = func() ([]int, error) {
		pids, err := list()
		return append(pids, 77), err
	}
	_, out := p.run(time.Hour)
	if out != endMembers {
		t.Errorf("out = %v, want to give up on members", out)
	}
}

// A number that keeps falling is never given up on, over any number of scans or
// seconds: this is what a slow machine's teardown of a program that forks as it
// dies looks like.
func TestRunKeepsTryingWhileTheMembersFall(t *testing.T) {
	t.Parallel()
	f := newFake()
	p := f.prober()
	// One member fewer in each scan, for as long as the budget allows. With the
	// waits at their longest that is 40 scans a second.
	const scansToEnd = 120
	membersByScan(f, &p, func(scan int) int { return max(scansToEnd-scan, 0) })
	scans, out := p.run(5 * time.Second)
	elapsed := f.clock.Sub(f.t0)
	if out != endEmpty || scans != scansToEnd {
		t.Errorf("scans = %d, out = %v; want %d scans and a clean end", scans, out, scansToEnd)
	}
	if elapsed < 2*giveUpAfter {
		t.Errorf("took %v, want it to be well past the %v after which a number that stopped falling is given up on", elapsed, giveUpAfter)
	}
}

// What a slow machine does to the shutdown of a program: members found again for
// a while at each number, but never for as long as the window.
func TestRunDoesNotGiveUpOnASlowShutdown(t *testing.T) {
	t.Parallel()
	f := newFake()
	p := f.prober()
	counts := []int{17, 17, 9, 9, 9, 6, 6, 6, 6, 2, 2, 1, 1, 1, 1, 1, 0}
	membersByScan(f, &p, func(scan int) int { return counts[min(scan, len(counts))-1] })
	scans, out := p.run(5 * time.Second)
	if out != endEmpty || scans != len(counts) {
		t.Errorf("scans = %d, out = %v; want %d scans and a clean end", scans, out, len(counts))
	}
}

// Scans that find no member and only pids they cannot account for are noise, and
// the teardown keeps trying for the whole budget.
func TestRunKeepsTryingThroughNoise(t *testing.T) {
	t.Parallel()
	for name, stat := range map[string]func(f *fakeSystem) func(int, int) (procStat, error){
		"vanished pids": func(f *fakeSystem) func(int, int) (procStat, error) {
			return func(_, pid int) (procStat, error) {
				if pid == 20 {
					return procStat{}, errGone
				}
				return procStat{Start: f.t0.Add(-time.Hour).UnixMicro()}, nil
			}
		},
		"new zombies": func(f *fakeSystem) func(int, int) (procStat, error) {
			n := 0
			return func(_, pid int) (procStat, error) {
				if pid == 20 {
					n++
					return procStat{Zombie: true, PPid: 1, Start: f.t0.Add(-time.Hour).UnixMicro() + int64(n)}, nil
				}
				return procStat{Start: f.t0.Add(-time.Hour).UnixMicro()}, nil
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFake([]int{10, 20})
			f.stat = stat(f)
			budget := 5 * time.Second
			scans, out := f.prober().run(budget)
			if out != endBudget {
				t.Errorf("out = %v after %d scans; want the whole budget spent", out, scans)
			}
			if elapsed := f.clock.Sub(f.t0); elapsed < budget {
				t.Errorf("%d scans in %v: want the whole budget of %v tried, not the %v that members get", scans, elapsed, budget, giveUpAfter)
			}
		})
	}
}

// A program that shuts down normally has its members signaled in the first scan,
// and what they forked as they died in a few more, and then it is gone, however
// many scans that is, so long as they are well within the time for giving up.
func TestRunDoesNotGiveUpOnANormalShutdown(t *testing.T) {
	t.Parallel()
	for _, member := range []int{1, 2, 3, 9} {
		lists := make([][]int, member+1)
		f := newFake()
		f.members = map[int]bool{}
		for i := range member {
			lists[i] = []int{10, 100 + i, 200 + i}
			f.members[100+i], f.members[200+i] = true, true
		}
		lists[member] = []int{10}
		f.lists = lists
		scans, out := f.prober().run(time.Second)
		if out != endEmpty || scans != member+1 {
			t.Errorf("%d scans with members: scans = %d, out = %v; want %d scans and a clean end", member, scans, out, member+1)
		}
	}
	// Members found only now and then, among scans of noise, are counted too, but
	// not as often as they would be by a chain.
	f := newFake([]int{10, 20, 100}, []int{10, 20}, []int{10, 20}, []int{10})
	f.members = map[int]bool{100: true}
	f.stat = func(scan, pid int) (procStat, error) {
		if pid == 20 && scan < 3 {
			return procStat{}, errGone
		}
		return procStat{Start: f.t0.Add(-time.Hour).UnixMicro()}, nil
	}
	if scans, out := f.prober().run(time.Second); out != endEmpty || scans != 3 {
		t.Errorf("scans = %d, out = %v; want 3 and a clean end", scans, out)
	}
}

// --------------------------------------------------- the whole path, for real

func TestTeardownGivesUpOnMembersItCannotEnd(t *testing.T) {
	t.Parallel()
	// The member leaves the command's group, so the stage's signal to the group
	// misses it, and the stage's scan signals nothing, so it finds it again each
	// time, as it would a process that forks faster than it is signaled.
	c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{self(t), "leaver", "keep"}})
	if err != nil {
		t.Fatal(err)
	}
	c.Env = []string{shellPath, stageNoKillEnv + "=1", noRaceExitSleep}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c)
	start := time.Now()
	err = waitWithin(t, c, 9*time.Second)
	if !errors.Is(err, ErrSurvivors) {
		t.Errorf("Wait: %v, want ErrSurvivors", err)
	}
	if d := time.Since(start); d < stageNoKillGiveUp || d > stageNoKillGiveUp+3*time.Second {
		t.Errorf("Wait took %v: the teardown should give up on members in about %v, and Wait not scan again", d, stageNoKillGiveUp)
	}
	if c.run.stageScans < 10 {
		t.Errorf("the stage made %d scans, want many, each finding the member", c.run.stageScans)
	}
	if n := c.run.callerScans.Load(); n != 0 {
		t.Errorf("the caller made %d scans after the stage said it gave up on members", n)
	}
}

// A stage that was killed says nothing, and the caller's own teardown gives up
// on members in the same way. Its signals are taken away here, in this process.
func TestWaitGivesUpOnMembersItCannotEnd(t *testing.T) {
	t.Parallel()
	c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{"/bin/sleep", "30"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c) // ends what the no-op kill left
	// The hook stays: it is on this test's own Cmd, and a Wait that waitWithin
	// abandoned on a timeout may still read it, so no cleanup writes it.
	c.run.proberHook = func(p *prober) { p.kill = func(int) {} }
	eventually(t, 5*time.Second, "the command did not start under the profile", func() bool {
		in, _ := c.run.mark.member(c.run.group)
		return in
	})
	if err := syscall.Kill(c.Pid(), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = waitWithin(t, c, 9*time.Second)
	if !errors.Is(err, ErrSurvivors) {
		t.Errorf("Wait: %v, want ErrSurvivors", err)
	}
	if d := time.Since(start); d < giveUpAfter || d > giveUpAfter+3*time.Second {
		t.Errorf("Wait took %v, want about %v", d, giveUpAfter)
	}
	if n := callerSideScans(c); n < 10 {
		t.Errorf("the caller made %d scans, want many", n)
	}
}

// Processes that re-fork, many at a time, end in a few scans, so the teardown
// does not give up on them and Wait returns nil. This is what normal programs
// that fork while they die look like, at their worst.
func TestTeardownDoesNotGiveUpOnShortChains(t *testing.T) {
	t.Parallel()
	const chains = 8
	// Each chain forks as fast as it can, and stops by itself within 3 seconds.
	script := fmt.Sprintf(`i=0; while [ $i -lt %d ]; do chain 3 0 & i=$((i+1)); done; wait`, chains)
	for range 3 {
		c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: reforkCommand(script)})
		if err != nil {
			t.Fatal(err)
		}
		c.Env = []string{shellPath}
		c.Stdout = &syncBuffer{}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		endAtCleanup(t, c)
		if err := waitWithin(t, c, 9*time.Second); err != nil {
			t.Errorf("Wait with %d chains: %v", chains, err)
		}
		t.Logf("%d chains: stage scans %d, caller scans %d", chains, c.run.stageScans, callerSideScans(c))
	}
}

// ------------------------------------------------------------ the order of checks

// The pids that no earlier scan cleared are checked first, before the stat of
// the ones that were: each of them is a process that can have been a member and
// can vanish before it is read.
func TestScanChecksNewPidsBeforeRememberedOnes(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20, 30, 40, 50})
	p := f.prober()
	p.execPid = 99 // no process is asked about twice
	var events []string
	look, stat := p.look, p.stat
	p.look = func(pid int) lookup { events = append(events, fmt.Sprint("look ", pid)); return look(pid) }
	p.stat = func(pid int) (procStat, error) { events = append(events, fmt.Sprint("stat ", pid)); return stat(pid) }
	old := f.t0.Add(-time.Second).UnixMicro()
	clean, _, _ := p.scan(memory{cleared: map[int]int64{10: old, 30: old, 50: old}})
	if !clean {
		t.Fatal("the scan was not clean")
	}
	want := []string{"look 20", "stat 20", "look 40", "stat 40", "stat 10", "stat 30", "stat 50"}
	if !slices.Equal(events, want) {
		t.Errorf("order of checks = %v, want %v", events, want)
	}
}

// The remembered ones still get their stat. A cleared pid is the same process
// only if its start time is, and a number that was reused may be a member now.
func TestScanDoesNotTrustARememberedNumberAlone(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20})
	f.members = map[int]bool{20: true}
	old := f.t0.Add(-time.Hour).UnixMicro()
	f.stat = func(_, pid int) (procStat, error) {
		if pid == 20 {
			return procStat{Start: old + 7}, nil // another process, with the same number
		}
		return procStat{Start: old}, nil
	}
	clean, next, _ := f.prober().scan(memory{cleared: map[int]int64{10: old, 20: old}})
	if clean || !slices.Equal(f.killed, []int{20}) {
		t.Errorf("clean = %v, killed = %v; want the member that took a cleared pid's number killed", clean, f.killed)
	}
	if _, ok := next.cleared[20]; ok {
		t.Error("the member was remembered as cleared")
	}
}
