package sandbox

import (
	"errors"
	"maps"
	"math"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// unprovable makes the caller's teardown of c unable to prove the sandbox
// empty, and ignore the stage's report that it did: the scan lists a pid that
// is never there, so no scan is clean. With a budget of none, which the test
// sets in c.run.budget, the teardown makes one scan and gives up, which stands
// for a chain of processes that kept ahead of the scan until the budget ran
// out. Only the caller's scans of c are affected, not the stage's, which is
// another process, and not another Cmd's.
func unprovable(c *Cmd) {
	c.run.ignoreStageReport = true
	c.run.proberHook = func(p *prober) {
		list := p.list
		p.list = func() ([]int, error) {
			pids, err := list()
			return append(pids, math.MaxInt32), err
		}
	}
}

// ------------------------------------------------- the scan's logic, with fakes

// fakeSystem is a prober's world for a test. Each scan takes the next entry of
// lists, and the last one stays.
type fakeSystem struct {
	t0 time.Time // now, which a scan notes as T
	// step is added to the clock each time it is read.
	step    time.Duration
	lists   [][]int
	members map[int]bool // pids under the profile
	unknown map[int]bool // pids whose membership the kernel would not say
	// other holds the pids under another profile. A pid in none of members,
	// unknown or other is under no profile.
	other map[int]bool
	looks map[int]int // how often each pid was asked about
	// stat answers a stat of pid in scan number scan (from 1). The default is an
	// ordinary process that started a second before T.
	stat   func(scan, pid int) (procStat, error)
	listed int
	killed []int
	clock  time.Time
	// slept is how long the teardown waited between scans, each time.
	slept []time.Duration
}

func (f *fakeSystem) prober() prober {
	f.clock = f.t0
	return prober{
		list: func() ([]int, error) {
			f.listed++
			return f.lists[min(f.listed, len(f.lists))-1], nil
		},
		look: func(pid int) lookup {
			if f.looks == nil {
				f.looks = map[int]int{}
			}
			f.looks[pid]++
			return lookup{In: f.members[pid], Known: !f.unknown[pid], Free: !f.members[pid] && !f.other[pid]}
		},
		stat: func(pid int) (procStat, error) {
			if f.stat != nil {
				return f.stat(f.listed, pid)
			}
			return procStat{Start: f.t0.Add(-time.Second).UnixMicro()}, nil
		},
		kill: func(pid int) { f.killed = append(f.killed, pid) },
		now: func() time.Time {
			t := f.clock
			f.clock = f.clock.Add(f.step)
			return t
		},
		sleep: func(d time.Duration) {
			f.slept = append(f.slept, d)
			f.clock = f.clock.Add(d)
		},
	}
}

func newFake(lists ...[]int) *fakeSystem {
	// The clock moves a little each time it is read, so that a teardown that a
	// bug keeps from settling runs out its budget and the test fails, not hangs.
	return &fakeSystem{t0: time.Unix(1_700_000_000, 0), lists: lists, step: time.Millisecond}
}

var errGone = errors.New("no such process")

// otherExec is a prober's execPid for a test whose processes are none of them
// the sandbox-exec that was started to apply the profile. 0 would be any pid.
const otherExec = -1

func TestScanCleanFirstScanEnds(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20, 30})
	scans, empty := f.prober().teardown(time.Second)
	if scans != 1 || !empty || len(f.killed) != 0 {
		t.Errorf("scans = %d, empty = %v, killed = %v; want one clean scan and no kill", scans, empty, f.killed)
	}
}

// A pid that vanished between the list and its read may have been a member
// with children that the list does not hold.
func TestScanVanishedPidForcesAnotherScan(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20, 30}, []int{10, 30})
	f.stat = func(_, pid int) (procStat, error) {
		if pid == 20 {
			return procStat{}, errGone
		}
		return procStat{Start: f.t0.Add(-time.Second).UnixMicro()}, nil
	}
	if scans, empty := f.prober().teardown(time.Second); scans != 2 || !empty {
		t.Errorf("scans = %d, empty = %v; want 2 and true", scans, empty)
	}
}

// A pid that started at or after T may be a reuse of one the list held for
// another process, so what the check said may be about the wrong process.
func TestScanReusedPidForcesAnotherScan(t *testing.T) {
	t.Parallel()
	for _, after := range []time.Duration{0, time.Microsecond, time.Second} {
		f := newFake([]int{10, 20})
		f.step = 0 // so that T is t0 exactly
		f.stat = func(scan, pid int) (procStat, error) {
			if pid == 20 && scan == 1 {
				return procStat{Start: f.t0.Add(after).UnixMicro()}, nil
			}
			return procStat{Start: f.t0.Add(-time.Second).UnixMicro()}, nil
		}
		if scans, empty := f.prober().teardown(time.Second); scans != 2 || !empty {
			t.Errorf("started %v after T: scans = %d, empty = %v; want 2 and true", after, scans, empty)
		}
	}
	// One that started before T is the process that was listed.
	f := newFake([]int{10})
	f.step = 0
	f.stat = func(int, int) (procStat, error) { return procStat{Start: f.t0.Add(-time.Microsecond).UnixMicro()}, nil }
	if scans, _ := f.prober().teardown(time.Second); scans != 1 {
		t.Errorf("started just before T: scans = %d, want 1", scans)
	}
}

// A process that fork is still making has no label to check yet.
func TestScanForkingPidForcesAnotherScan(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20})
	f.stat = func(scan, pid int) (procStat, error) {
		return procStat{Forking: pid == 20 && scan == 1, Start: f.t0.Add(-time.Second).UnixMicro()}, nil
	}
	if scans, empty := f.prober().teardown(time.Second); scans != 2 || !empty {
		t.Errorf("scans = %d, empty = %v; want 2 and true", scans, empty)
	}
}

// member says it is not known for a process that is gone, a zombie, or one that
// has begun to exit (kernelFinds), which the real prober does produce.
func TestScanUnknownMembershipForcesAnotherScan(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20})
	f.unknown = map[int]bool{20: true}
	p := f.prober()
	look := p.look
	p.look = func(pid int) lookup {
		l := look(pid)
		if f.listed > 1 {
			l.Known = true
		}
		return l
	}
	if scans, empty := p.teardown(time.Second); scans != 2 || !empty {
		t.Errorf("scans = %d, empty = %v; want 2 and true", scans, empty)
	}
}

// A zombie that is new may have been a member that had children a moment ago.
// One that the previous scan already saw as a zombie was dead before this
// scan's snapshot and forks nothing.
func TestScanZombies(t *testing.T) {
	t.Parallel()
	const start = 1_699_999_000_000_000
	zombie := func(f *fakeSystem, startOf func(scan int) int64) {
		f.stat = func(scan, pid int) (procStat, error) {
			if pid == 20 {
				return procStat{Zombie: true, Start: startOf(scan)}, nil
			}
			return procStat{Start: f.t0.Add(-time.Second).UnixMicro()}, nil
		}
	}
	t.Run("new", func(t *testing.T) {
		t.Parallel()
		f := newFake([]int{10, 20})
		zombie(f, func(int) int64 { return start })
		if scans, empty := f.prober().teardown(time.Second); scans != 2 || !empty {
			t.Errorf("scans = %d, empty = %v; want 2 and true: one scan to see it, one that knows it was dead before", scans, empty)
		}
	})
	t.Run("old", func(t *testing.T) {
		t.Parallel()
		f := newFake([]int{10, 20})
		zombie(f, func(int) int64 { return start })
		clean, next, err := f.prober().scan(memory{dying: map[int]int64{20: start}})
		if err != nil || !clean || next.dying[20] != start {
			t.Errorf("clean = %v, dying = %v, err = %v; want a clean scan that keeps the zombie", clean, next.dying, err)
		}
	})
	t.Run("same pid, another process", func(t *testing.T) {
		t.Parallel()
		// The zombie that was there before was reaped, and its number given
		// to a process that has now exited too.
		f := newFake([]int{10, 20})
		zombie(f, func(int) int64 { return start + 5 })
		clean, _, _ := f.prober().scan(memory{dying: map[int]int64{20: start}})
		if clean {
			t.Error("a zombie with a different start time than the one seen before was taken as the old one")
		}
	})
	t.Run("a zombie's membership is unknown", func(t *testing.T) {
		t.Parallel()
		// The kernel does not find a zombie (kernelFinds), so member says it is
		// unknown, as TestMemberOfGonePids shows, and an old zombie is cleared
		// all the same. PROC_FLAG_INEXIT stays set on a zombie too.
		f := newFake([]int{10, 20})
		f.unknown = map[int]bool{20: true}
		f.stat = func(_, pid int) (procStat, error) {
			if pid == 20 {
				return procStat{Zombie: true, Exiting: true, Start: start}, nil
			}
			return procStat{Start: f.t0.Add(-time.Second).UnixMicro()}, nil
		}
		clean, _, _ := f.prober().scan(memory{dying: map[int]int64{20: start}})
		if !clean {
			t.Error("an old zombie whose membership is unknown, and that is flagged as exiting, made the scan unclean")
		}
	})
	t.Run("a zombie never started before T", func(t *testing.T) {
		t.Parallel()
		f := newFake([]int{10, 20})
		zombie(f, func(int) int64 { return f.t0.UnixMicro() })
		clean, _, _ := f.prober().scan(memory{dying: map[int]int64{20: f.t0.UnixMicro()}})
		if clean {
			t.Error("a zombie that started at T was taken as old")
		}
	})
	t.Run("remembered between scans only", func(t *testing.T) {
		t.Parallel()
		// A zombie seen in one scan and gone from the next must not excuse a
		// new one with the same number two scans later.
		f := newFake([]int{10, 20}, []int{10}, []int{10, 20})
		zombie(f, func(scan int) int64 { return start + int64(scan) })
		p := f.prober()
		clean1, z1, _ := p.scan(memory{})
		clean2, z2, _ := p.scan(z1)
		clean3, _, _ := p.scan(z2)
		if clean1 || !clean2 || clean3 {
			t.Errorf("clean = %v, %v, %v; want false, true, false", clean1, clean2, clean3)
		}
	})
}

// A process that has begun to exit is still returned by proc_pidinfo, alive and
// old, and sandbox_check answers it as a denial. It may have been a member that
// forked after the snapshot.
func TestScanExitingPidForcesAnotherScan(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20})
	f.stat = func(scan, pid int) (procStat, error) {
		return procStat{Exiting: pid == 20 && scan == 1, Start: f.t0.Add(-time.Second).UnixMicro()}, nil
	}
	if scans, empty := f.prober().teardown(time.Second); scans != 2 || !empty {
		t.Errorf("scans = %d, empty = %v; want 2 and true", scans, empty)
	}
}

// A sandbox-exec that is not a member has not applied its profile yet, and will
// be the sandbox when it has. One that is a member is killed as any is.
func TestScanSandboxExecThatHasNotAppliedItsProfile(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20})
	f.stat = func(scan, pid int) (procStat, error) {
		st := procStat{Start: f.t0.Add(-time.Second).UnixMicro()}
		if pid == 20 && scan == 1 {
			st.Comm = "sandbox-exec"
		}
		return st, nil
	}
	if scans, empty := f.prober().teardown(time.Second); scans != 2 || !empty {
		t.Errorf("scans = %d, empty = %v; want 2 and true", scans, empty)
	}
	// A process of another name is nothing special.
	f = newFake([]int{10, 20})
	f.stat = func(_, _ int) (procStat, error) {
		return procStat{Comm: "sandbox-exec2", Start: f.t0.Add(-time.Second).UnixMicro()}, nil
	}
	if scans, _ := f.prober().teardown(time.Second); scans != 1 {
		t.Errorf("another name: scans = %d, want 1", scans)
	}
}

// sandbox-exec is not under any profile until it applies one, so a process of
// that name that is under another profile is not the one that will, and does not
// make a scan unclean. Neither does a process of that name under no profile when
// the caller has the pid of the one it started, and it is another.
func TestScanSandboxExecThatCannotBeTheOne(t *testing.T) {
	t.Parallel()
	named := func(f *fakeSystem) {
		f.stat = func(_, pid int) (procStat, error) {
			st := procStat{Start: f.t0.Add(-time.Second).UnixMicro()}
			if pid == 20 {
				st.Comm = sandboxExecName
			}
			return st, nil
		}
	}
	t.Run("under another profile", func(t *testing.T) {
		t.Parallel()
		f := newFake([]int{10, 20})
		f.other = map[int]bool{20: true}
		named(f)
		if scans, empty := f.prober().teardown(time.Second); scans != 1 || !empty {
			t.Errorf("scans = %d, empty = %v; want 1 and true", scans, empty)
		}
	})
	t.Run("another pid than the one started", func(t *testing.T) {
		t.Parallel()
		f := newFake([]int{10, 20})
		named(f)
		p := f.prober()
		p.execPid = 10
		if scans, empty := p.teardown(time.Second); scans != 1 || !empty {
			t.Errorf("scans = %d, empty = %v; want 1 and true", scans, empty)
		}
	})
	t.Run("the pid that was started", func(t *testing.T) {
		t.Parallel()
		f := newFake([]int{10, 20})
		f.stat = func(scan, pid int) (procStat, error) {
			st := procStat{Start: f.t0.Add(-time.Second).UnixMicro()}
			if pid == 20 && scan == 1 {
				st.Comm = sandboxExecName
			}
			return st, nil
		}
		p := f.prober()
		p.execPid = 20
		if scans, empty := p.teardown(time.Second); scans != 2 || !empty {
			t.Errorf("scans = %d, empty = %v; want 2 and true", scans, empty)
		}
	})
	t.Run("no pid known", func(t *testing.T) {
		t.Parallel()
		f := newFake([]int{10, 20})
		named(f)
		f.step = time.Second
		if scans, empty := f.prober().teardown(10 * time.Second); empty || scans < 5 {
			t.Errorf("scans = %d, empty = %v; want a sandbox-exec under no profile to hold every scan", scans, empty)
		}
	})
}

// A sandbox-exec that was under no profile when it was asked about can have
// applied the profile and started the command by the time its name is read, and
// have another name. It is asked about again.
func TestScanProcessThatAppliedTheProfileBetweenTheCheckAndTheRead(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		after lookup
		kills []int
	}{
		{"a member now", lookup{In: true, Known: true}, []int{20}},
		{"under another profile now", lookup{Known: true}, nil},
		{"not known now", lookup{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFake([]int{10, 20})
			f.stat = func(_, _ int) (procStat, error) {
				return procStat{Comm: "sh", Start: f.t0.Add(-time.Second).UnixMicro()}, nil
			}
			p := f.prober()
			look := p.look
			p.look = func(pid int) lookup {
				if pid == 20 && f.looks[pid] >= 1 {
					f.looks[pid]++
					return tc.after
				}
				return look(pid)
			}
			clean, _, _ := p.scan(memory{})
			if clean {
				t.Error("the scan was clean")
			}
			if !slices.Equal(f.killed, tc.kills) {
				t.Errorf("killed = %v, want %v", f.killed, tc.kills)
			}
		})
	}
	// Any other process is asked about once when the caller has the pid.
	f := newFake([]int{10, 20})
	p := f.prober()
	p.execPid = 10
	if clean, _, _ := p.scan(memory{}); !clean || f.looks[20] != 1 {
		t.Errorf("clean = %v, looks of 20 = %d; want clean and one look", clean, f.looks[20])
	}
}

// What a scan found not to be a member stays so: it is not asked about again,
// and what becomes of it later costs nothing. A process that is not the same one
// (another start time) is asked about, and a pid that has gone is unknown.
func TestScanRemembersWhatItCleared(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20})
	p := f.prober()
	p.execPid = otherExec
	old := f.t0.Add(-time.Second).UnixMicro()
	clean, mem, _ := p.scan(memory{})
	if !clean || mem.cleared[10] != old || mem.cleared[20] != old {
		t.Fatalf("clean = %v, cleared = %v", clean, mem.cleared)
	}
	looks := maps.Clone(f.looks)
	for name, st := range map[string]procStat{
		"exiting": {Exiting: true, Start: old},
		"zombie":  {Zombie: true, Start: old},
		"alive":   {Start: old},
	} {
		f.stat = func(int, int) (procStat, error) { return st, nil }
		clean, next, _ := p.scan(mem)
		if !clean || !maps.Equal(f.looks, looks) || next.cleared[20] != old {
			t.Errorf("%s: clean = %v, looks = %v, cleared = %v; want a clean scan that asks about no one", name, clean, f.looks, next.cleared)
		}
	}
	f.stat = func(_, _ int) (procStat, error) {
		return procStat{Exiting: true, Start: old + 1}, nil
	}
	if clean, _, _ := p.scan(mem); clean {
		t.Error("an exiting process that started at another time than the one cleared was taken as it")
	}
	f.stat = func(_, _ int) (procStat, error) { return procStat{}, errGone }
	if clean, _, _ := p.scan(mem); clean {
		t.Error("a pid that has gone was taken as cleared: whether it is the same process is not known")
	}
}

// A process that may become a member is never remembered as one that cannot, and
// nor is a member.
func TestScanDoesNotRememberWhatMayStillBeAMember(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20, 30})
	f.members = map[int]bool{30: true}
	f.stat = func(_, pid int) (procStat, error) {
		st := procStat{Start: f.t0.Add(-time.Second).UnixMicro()}
		if pid == 20 {
			st.Comm = sandboxExecName
		}
		return st, nil
	}
	_, mem, _ := f.prober().scan(memory{})
	if _, ok := mem.cleared[20]; ok {
		t.Error("a sandbox-exec that has not applied its profile was remembered as cleared")
	}
	if _, ok := mem.cleared[30]; ok {
		t.Error("a member was remembered as cleared")
	}
}

// A caller with no pid for the sandbox-exec it started (abortStart, after a stage
// that was killed) cannot tell which process it is. The stage's child has the
// stage's name until it execs sandbox-exec, so it looks like any other process
// under no profile, and a scan that remembered it would never look at it again,
// though it applies the profile and starts the command a moment later. So no
// pid is remembered, and the next scan finds the command and ends it.
func TestScanWithNoExecPidLooksAgainAtWhatItFoundFree(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20})
	f.stat = func(_, pid int) (procStat, error) {
		st := procStat{Start: f.t0.Add(-time.Second).UnixMicro()}
		if pid == 20 {
			st.Comm = "sandbox.test" // the stage's name, before it execs sandbox-exec
		}
		return st, nil
	}
	p := f.prober()
	_, mem, _ := p.scan(memory{})
	if _, ok := mem.cleared[20]; ok {
		t.Fatal("a pid that may be the stage's child before its exec was remembered as cleared")
	}
	f.members = map[int]bool{20: true} // it has applied the profile since
	clean, _, _ := p.scan(mem)
	if clean || !slices.Equal(f.killed, []int{20}) {
		t.Errorf("clean = %v, killed = %v; want the next scan to find pid 20 a member and end it", clean, f.killed)
	}
}

// A process that is exiting or a zombie, new to the scan, is not a member's if
// its parent is one that was found not to be a member: fork gives a child its
// parent's profile.
func TestScanDyingChildOfAClearedParent(t *testing.T) {
	t.Parallel()
	const parent, kid = 10, 20
	old := func(f *fakeSystem) int64 { return f.t0.Add(-time.Hour).UnixMicro() }
	young := func(f *fakeSystem) int64 { return f.t0.Add(-time.Minute).UnixMicro() }
	for _, tc := range []struct {
		name    string
		lists   [][]int
		prev    func(f *fakeSystem) memory
		kid     func(f *fakeSystem) procStat
		parent  func(f *fakeSystem) procStat
		members []int
		want    bool
	}{
		{
			"parent listed after the child",
			[][]int{{kid, parent}},
			nil,
			func(f *fakeSystem) procStat { return procStat{Zombie: true, PPid: parent, Start: young(f)} },
			func(f *fakeSystem) procStat { return procStat{Start: old(f)} }, nil, true,
		},
		{
			"exiting, not a zombie",
			[][]int{{kid, parent}},
			nil,
			func(f *fakeSystem) procStat { return procStat{Exiting: true, PPid: parent, Start: young(f)} },
			func(f *fakeSystem) procStat { return procStat{Start: old(f)} }, nil, true,
		},
		{
			"parent cleared by an earlier scan",
			[][]int{{kid, parent}},
			func(f *fakeSystem) memory { return memory{cleared: map[int]int64{parent: old(f)}} },
			func(f *fakeSystem) procStat { return procStat{Zombie: true, PPid: parent, Start: young(f)} },
			func(f *fakeSystem) procStat { return procStat{Start: old(f)} }, nil, true,
		},
		{
			"parent is launchd",
			[][]int{{kid, 1}},
			nil,
			func(f *fakeSystem) procStat { return procStat{Zombie: true, PPid: 1, Start: young(f)} },
			func(f *fakeSystem) procStat { return procStat{Start: old(f)} }, nil, false,
		},
		{
			"parent not known to the scan",
			[][]int{{kid}},
			nil,
			func(f *fakeSystem) procStat { return procStat{Zombie: true, PPid: 99, Start: young(f)} },
			func(f *fakeSystem) procStat { return procStat{Start: old(f)} }, nil, false,
		},
		{
			"parent is a member",
			[][]int{{kid, parent}},
			nil,
			func(f *fakeSystem) procStat { return procStat{Zombie: true, PPid: parent, Start: young(f)} },
			func(f *fakeSystem) procStat { return procStat{Start: old(f)} },
			[]int{parent},
			false,
		},
		{
			"parent is younger than the child",
			[][]int{{kid, parent}},
			nil,
			func(f *fakeSystem) procStat { return procStat{Zombie: true, PPid: parent, Start: old(f)} },
			func(f *fakeSystem) procStat { return procStat{Start: young(f)} }, nil, false,
		},
		{
			"parent's number is a younger process now",
			[][]int{{kid, parent}},
			func(f *fakeSystem) memory { return memory{cleared: map[int]int64{parent: old(f)}} },
			func(f *fakeSystem) procStat { return procStat{Zombie: true, PPid: parent, Start: young(f)} },
			func(f *fakeSystem) procStat { return procStat{Start: young(f) + 5} }, nil, false,
		},
		{
			"parent is gone",
			[][]int{{kid, parent}},
			func(f *fakeSystem) memory { return memory{cleared: map[int]int64{parent: old(f)}} },
			func(f *fakeSystem) procStat { return procStat{Zombie: true, PPid: parent, Start: young(f)} },
			nil, nil, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFake(tc.lists...)
			f.members = map[int]bool{}
			for _, m := range tc.members {
				f.members[m] = true
			}
			f.stat = func(_, pid int) (procStat, error) {
				switch {
				case pid == kid:
					return tc.kid(f), nil
				case tc.parent == nil && pid == parent:
					return procStat{}, errGone
				case pid == parent:
					return tc.parent(f), nil
				}
				return procStat{Start: old(f)}, nil
			}
			var prev memory
			if tc.prev != nil {
				prev = tc.prev(f)
			}
			p := f.prober()
			p.execPid = otherExec
			clean, next, _ := p.scan(prev)
			if clean != tc.want {
				t.Errorf("clean = %v, want %v", clean, tc.want)
			}
			if _, ok := next.dying[kid]; !ok {
				t.Error("the child was not remembered as dying")
			}
		})
	}
}

// The command is a member whose parent is not: sandbox-exec applied the profile
// to itself, in place, and the stage that started it is under none. If it
// forks after the scan's list is taken and exits before the scan reads it, its
// parent being cleared says nothing about the child it left, which is not in
// the list. So a scan never excuses that pid by its parent, only by an earlier
// scan that saw it dying. The same layout with another pid is excused, which
// TestScanDyingChildOfAClearedParent checks.
func TestScanDyingCommandIsNotExcusedByItsParent(t *testing.T) {
	t.Parallel()
	const stage, command = 10, 20
	old := func(f *fakeSystem) int64 { return f.t0.Add(-time.Hour).UnixMicro() }
	young := func(f *fakeSystem) int64 { return f.t0.Add(-time.Minute).UnixMicro() }
	for _, tc := range []struct {
		name    string
		dying   procStat // the command's state, with PPid and Start filled in below
		execPid int
		seen    bool // an earlier scan saw the command dying with the same start time
		want    bool // whether the scan is clean
	}{
		{"zombie, new to the scan", procStat{Zombie: true}, command, false, false},
		{"exiting, new to the scan", procStat{Exiting: true}, command, false, false},
		{"zombie, seen dying by the earlier scan", procStat{Zombie: true}, command, true, true},
		{"exiting, seen dying by the earlier scan", procStat{Exiting: true}, command, true, true},
		{"zombie, another pid is the one", procStat{Zombie: true}, 99, false, true},
		{"zombie, the caller does not know the pid", procStat{Zombie: true}, 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFake([]int{command, stage})
			f.stat = func(_, pid int) (procStat, error) {
				if pid == command {
					st := tc.dying
					st.PPid, st.Start = stage, young(f)
					return st, nil
				}
				return procStat{Start: old(f)}, nil // the stage, which is under no profile
			}
			var prev memory
			if tc.seen {
				prev.dying = map[int]int64{command: young(f)}
			}
			p := f.prober()
			p.execPid = tc.execPid
			if clean, _, _ := p.scan(prev); clean != tc.want {
				t.Errorf("clean = %v, want %v", clean, tc.want)
			}
		})
	}
}

// A process that began to exit in one scan and is still at it in the next, or
// is a zombie by then, was exiting before the second snapshot and forks nothing.
// This is what stops one that is stuck in exit from holding every scan.
func TestScanExitingPidSeenBeforeIsSettled(t *testing.T) {
	t.Parallel()
	const start = 1_699_999_000_000_000
	f := newFake([]int{10, 20})
	f.stat = func(_, pid int) (procStat, error) {
		if pid == 20 {
			return procStat{Exiting: true, PPid: 1, Start: start}, nil
		}
		return procStat{Start: f.t0.Add(-time.Second).UnixMicro()}, nil
	}
	if scans, empty := f.prober().teardown(time.Second); scans != 2 || !empty {
		t.Errorf("scans = %d, empty = %v; want 2 and true", scans, empty)
	}
	// Seen exiting, and a zombie now.
	f.stat = func(scan, pid int) (procStat, error) {
		if pid == 20 {
			return procStat{Exiting: true, Zombie: scan > 1, PPid: 1, Start: start}, nil
		}
		return procStat{Start: f.t0.Add(-time.Second).UnixMicro()}, nil
	}
	f.listed = 0
	if scans, empty := f.prober().teardown(time.Second); scans != 2 || !empty {
		t.Errorf("exiting, then a zombie: scans = %d, empty = %v; want 2 and true", scans, empty)
	}
	// Another process of the same number is not the one seen.
	f.stat = func(scan, pid int) (procStat, error) {
		if pid == 20 {
			return procStat{Exiting: true, PPid: 1, Start: start + int64(scan)}, nil
		}
		return procStat{Start: f.t0.Add(-time.Second).UnixMicro()}, nil
	}
	f.listed = 0
	f.step = time.Second
	if scans, empty := f.prober().teardown(3 * time.Second); empty {
		t.Errorf("scans = %d, empty = %v; want a new process in the same pid to be taken as new each time", scans, empty)
	}
}

func TestScanKillsMembersAndScansAgain(t *testing.T) {
	t.Parallel()
	f := newFake([]int{10, 20, 30}, []int{10, 40}, []int{10})
	f.members = map[int]bool{20: true, 30: true, 40: true}
	scans, empty := f.prober().teardown(time.Second)
	if scans != 3 || !empty {
		t.Errorf("scans = %d, empty = %v; want 3 and true", scans, empty)
	}
	if !slices.Equal(f.killed, []int{20, 30, 40}) {
		t.Errorf("killed = %v, want 20 and 30, then 40 on the next scan", f.killed)
	}
}

func TestScanBudget(t *testing.T) {
	t.Parallel()
	// A pid that is never settled, with a clock that moves a second each time
	// it is read.
	stuck := func() *fakeSystem {
		f := newFake([]int{10, 20})
		f.step = time.Second
		f.stat = func(_, pid int) (procStat, error) {
			if pid == 20 {
				return procStat{}, errGone
			}
			return procStat{Start: f.t0.Add(-time.Hour).UnixMicro()}, nil
		}
		return f
	}
	f := stuck()
	scans, empty := f.prober().teardown(3 * time.Second)
	if empty || scans < 2 || scans > 5 {
		t.Errorf("scans = %d, empty = %v; want false after a few scans", scans, empty)
	}
	// A budget of none still scans once.
	f = stuck()
	if scans, empty := f.prober().teardown(0); scans != 1 || empty {
		t.Errorf("budget 0: scans = %d, empty = %v; want 1 and false", scans, empty)
	}
	// And a clean first scan is enough whatever the budget.
	f = newFake([]int{10})
	if scans, empty := f.prober().teardown(0); scans != 1 || !empty {
		t.Errorf("clean, budget 0: scans = %d, empty = %v; want 1 and true", scans, empty)
	}
}

func TestScanListFailureIsNotEmpty(t *testing.T) {
	t.Parallel()
	p := newFake().prober()
	p.list = func() ([]int, error) { return nil, errGone }
	if scans, empty := p.teardown(time.Second); scans != 1 || empty {
		t.Errorf("scans = %d, empty = %v; want 1 and false", scans, empty)
	}
}

// ------------------------------------------------------- the system calls

func TestBSDInfoLayout(t *testing.T) {
	t.Parallel()
	if got := unsafe.Sizeof(bsdInfo{}); got != 136 {
		t.Errorf("sizeof(bsdInfo) = %d, want 136, PROC_PIDTBSDINFO_SIZE", got)
	}
	if got := unsafe.Offsetof(bsdInfo{}.StartSec); got != 120 {
		t.Errorf("offsetof(StartSec) = %d, want 120", got)
	}
}

// zombieChild starts a process that exits at once and is never reaped, until
// the test ends, and returns its pid once it is a zombie.
func zombieChild(t *testing.T) int {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "/usr/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Wait() })
	pid := cmd.Process.Pid
	eventually(t, 5*time.Second, "the child did not become a zombie", func() bool {
		st, err := statPid(pid)
		return err == nil && st.Zombie
	})
	return pid
}

func TestListAndStatSeeProcessesAndZombies(t *testing.T) {
	t.Parallel()
	uid := euid()
	pids, err := listUIDPids(uid)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pids, os.Getpid()) {
		t.Errorf("this process, %d, is not in the list", os.Getpid())
	}
	before := time.Now()
	st, err := statPid(os.Getpid())
	if err != nil || st.Zombie || st.Forking || st.Start <= 0 || st.Start >= before.UnixMicro() {
		t.Errorf("statPid(self) = %+v, %v", st, err)
	}

	z := zombieChild(t)
	pids, err = listUIDPids(uid)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pids, z) {
		t.Errorf("the zombie %d is not in the list", z)
	}
	zs, err := statPid(z)
	if err != nil || !zs.Zombie || zs.Start >= time.Now().UnixMicro() {
		t.Errorf("statPid(zombie) = %+v, %v", zs, err)
	}

	// Reaped, it is gone: ESRCH.
	cmd := exec.CommandContext(t.Context(), "/usr/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := statPid(cmd.Process.Pid); !errors.Is(err, unix.ESRCH) {
		t.Errorf("statPid(reaped) = %v, want ESRCH", err)
	}
	if pids, _ := listUIDPids(uid); slices.Contains(pids, cmd.Process.Pid) {
		t.Errorf("the reaped pid %d is still listed", cmd.Process.Pid)
	}
}

// A scan of the real system, with a lingering zombie, finds the sandbox empty
// in the second scan, and the zombie is what the first one waited for.
func TestRealScanSettlesOnAnOldZombie(t *testing.T) {
	t.Parallel()
	m, err := newMarker()
	if err != nil {
		t.Fatal(err)
	}
	z := zombieChild(t)
	p := m.prober(0)
	// The zombie is a child of this process, which is no member, and so is not
	// one itself (TestRealScanExcusesAZombieOfANonMember). Its parent is hidden
	// here, to leave only what a scan remembers of it.
	stat := p.stat
	p.stat = func(pid int) (procStat, error) {
		st, err := stat(pid)
		if pid == z {
			st.PPid = 1
		}
		return st, err
	}
	p.list = func() ([]int, error) { return []int{os.Getpid(), z}, nil }
	clean, next, err := p.scan(memory{})
	if err != nil {
		t.Fatal(err)
	}
	if clean {
		t.Fatalf("the first scan was clean with the zombie %d lingering: a zombie new to the scan must make it unknown", z)
	}
	if _, ok := next.dying[z]; !ok {
		t.Errorf("dying = %v, want %d among them", next.dying, z)
	}
	// Nothing else is listed, so the load of the machine cannot cost a scan.
	scans, empty := p.teardown(5 * time.Second)
	if !empty || scans != 2 {
		t.Errorf("scans = %d, empty = %v; want 2 and true: one to see the zombie, one that knows it was dead before", scans, empty)
	}
}

// With the real kernel: a zombie whose parent is a process that is not a member
// is not unknown, and one with another parent is, until the scan after.
func TestRealScanExcusesAZombieOfANonMember(t *testing.T) {
	t.Parallel()
	m, err := newMarker()
	if err != nil {
		t.Fatal(err)
	}
	z := zombieChild(t)
	only := func(p *prober) {
		p.list = func() ([]int, error) { return []int{os.Getpid(), z}, nil }
	}
	p := m.prober(otherExec)
	only(&p)
	if clean, _, err := p.scan(memory{}); err != nil || !clean {
		t.Errorf("a zombie child of this process: clean = %v, err = %v; want a clean scan", clean, err)
	}
	stat := p.stat
	p.stat = func(pid int) (procStat, error) {
		st, err := stat(pid)
		if pid == z {
			st.PPid = 1
		}
		return st, err
	}
	clean, next, err := p.scan(memory{})
	if err != nil || clean {
		t.Errorf("a zombie child of launchd: clean = %v, err = %v; want an unclean scan", clean, err)
	}
	if clean, _, _ := p.scan(next); !clean {
		t.Error("the scan after it was seen was not clean")
	}
}
