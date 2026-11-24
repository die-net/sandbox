package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Tests for the findings of the review of the teardown proof.

// denyProfile is a deny-default profile that lets /usr/bin/true run.
const denyProfile = `(version 1)(deny default)(allow process-exec*)(allow file-read*)`

// ------------------------------------------------ membership of gone pids

// A pid the kernel does not find answers sandbox_check as a denial, so member
// must say it does not know, whatever the profile: a gone pid, a zombie, and
// this process, which the kernel finds and which is not a member.
func TestMemberOfGonePids(t *testing.T) {
	t.Parallel()
	m, err := newMarker()
	if err != nil {
		t.Fatal(err)
	}
	if in, known := m.member(os.Getpid()); in || !known {
		t.Errorf("member(self) = %v, %v; want false, true", in, known)
	}
	if !kernelFinds(os.Getpid()) {
		t.Error("kernelFinds(self) = false")
	}
	z := zombieChild(t)
	if in, known := m.member(z); in || known {
		t.Errorf("member(zombie) = %v, %v; want false, false", in, known)
	}
	if kernelFinds(z) {
		t.Error("kernelFinds(zombie) = true")
	}
	cmd := exec.CommandContext(t.Context(), "/usr/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if in, known := m.member(cmd.Process.Pid); in || known {
		t.Errorf("member(reaped) = %v, %v; want false, false", in, known)
	}
	// A process under another deny-default profile is found, and known not to be
	// a member of this one.
	live := exec.CommandContext(t.Context(), "/usr/bin/sandbox-exec", "-p", denyProfile, "/bin/sleep", "2")
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Process.Kill(); _ = live.Wait() })
	eventually(t, 5*time.Second, "sandbox-exec has not applied the profile", func() bool {
		st, err := statPid(live.Process.Pid)
		return err == nil && st.Comm != sandboxExecName
	})
	if in, known := m.member(live.Process.Pid); in || !known {
		t.Errorf("member(under another profile) = %v, %v; want false, true", in, known)
	}
}

// The children of a sandboxed shell are members from birth, so member never says
// that one is known not to be, however far into its exit it is. A process that
// has begun to exit answers sandbox_check as a denial, and the 4000 children
// of the review's run had 16841 such answers.
func TestMemberNeverClearsAnExitingChild(t *testing.T) {
	t.Parallel()
	uid := euid()
	base, _ := listUIDPids(uid)
	old := map[int]bool{}
	for _, p := range base {
		old[p] = true
	}
	c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{"/bin/sh", "-c", "i=0; while [ $i -lt 1500 ]; do /usr/bin/true; i=$((i+1)); done"}})
	if err != nil {
		t.Fatal(err)
	}
	c.Env = []string{shellPath}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c)
	shell := c.run.group
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	checks, exiting, bad := 0, 0, 0
loop:
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Wait: %v", err)
			}
			break loop
		default:
		}
		pids, err := listUIDPids(uid)
		if err != nil {
			t.Fatal(err)
		}
		for _, pid := range pids {
			if old[pid] {
				continue
			}
			b, err := readBSD(pid)
			if err != nil || int(b.PPid) != shell || b.Status == stateZombie {
				continue
			}
			in, known := c.run.mark.member(pid)
			checks++
			if !in && !known {
				exiting++
			}
			if !in && known {
				bad++
				if bad <= 5 {
					t.Errorf("member(%d) = false, true for a child of the sandbox's shell; pid %d flags %#x status %d", pid, pid, b.Flags, b.Status)
				}
			}
		}
	}
	t.Logf("%d checks of children of the shell, %d answered unknown, %d cleared", checks, exiting, bad)
	if checks < 200 {
		t.Errorf("only %d children were checked", checks)
	}
}

// ------------------------------------------------------ the order of checks

// A process that is unsandboxed at the first check and under a deny-default
// profile at the second, which sandbox-exec is as it starts, must not look like
// a member of a profile that has nothing to do with it. Asked In then Out, about
// a third of the starts gave a false match; Out then In, none.
func TestMemberNeverMatchesAProcessApplyingAProfile(t *testing.T) {
	t.Parallel()
	m, err := newMarker()
	if err != nil {
		t.Fatal(err)
	}
	false1, checks := 0, 0
	for range 200 {
		cmd := exec.CommandContext(t.Context(), "/usr/bin/sandbox-exec", "-p", denyProfile, "/usr/bin/true")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid := cmd.Process.Pid
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				checks++
				if in, _ := m.member(pid); in {
					false1++
				}
			}
		})
		_ = cmd.Wait()
		close(stop)
		wg.Wait()
	}
	t.Logf("%d checks", checks)
	if false1 > 0 {
		t.Errorf("%d checks took a process of no sandbox of this marker for a member", false1)
	}
}

// ------------------------------------------- a real scan and a draining chain

// A scan of a sandbox that holds a process re-forking every millisecond is
// never clean, even when the scanner loses the processor between the snapshot
// and its first check, as under load, and the member that was alive at the
// snapshot has begun to exit by the time it is checked. The shell and its sleep,
// which keep the stage from tearing down, are left out of the membership, so
// that only the chain is measured, and the scan's kill is a count, so that the
// chain lives on.
func TestRealScanIsNeverCleanWhileAChainLives(t *testing.T) {
	t.Parallel()
	c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{"/bin/sh", "-c", `/usr/bin/perl -e "$0" 6 & /bin/sleep 3`, reforkScript}})
	if err != nil {
		t.Fatal(err)
	}
	c.Env = []string{shellPath}
	c.Stdout = &syncBuffer{}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c)
	time.Sleep(300 * time.Millisecond)
	p := c.run.mark.prober(c.run.group)
	found := 0
	p.kill = func(int) { found++ }
	fixed := map[int]bool{c.run.group: true}
	all, _ := c.run.mark.processes()
	for _, pid := range all {
		if b, err := readBSD(pid); err == nil && int(b.PPid) == c.run.group && strings.HasPrefix(string(b.Comm[:]), "sleep") {
			fixed[pid] = true
		}
	}
	list := p.list
	p.list = func() ([]int, error) {
		pids, err := list()
		// The scanner is off the processor for a while.
		for end := time.Now().Add(400 * time.Microsecond); time.Now().Before(end); { //nolint:revive // empty-block: the loop spins on purpose, to keep the scanner off the processor.
		}
		return pids, err
	}
	look := p.look
	p.look = func(pid int) lookup {
		if fixed[pid] {
			return lookup{Known: true}
		}
		return look(pid)
	}
	var mem memory
	scans, clean := 0, 0
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
		ok, next, err := p.scan(mem)
		if err != nil {
			t.Fatal(err)
		}
		scans++
		if ok {
			clean++
		}
		mem = next
	}
	t.Logf("%d scans, %d members found, %d clean", scans, found, clean)
	if clean > 0 {
		t.Errorf("%d of %d scans were clean while a process of the sandbox was alive", clean, scans)
	}
	if err := waitWithin(t, c, 9*time.Second); err != nil {
		t.Errorf("Wait: %v", err)
	}
}

// ---------------------------------------------- a sandbox-exec not yet applied

// A sandbox-exec that has not read its profile is unsandboxed and about to be
// the sandbox. The test holds one there, blocked on reading its profile from a
// pipe it never writes to, and no scan is clean while it waits.
func TestRealScanIsNotCleanWhileSandboxExecWaitsForItsProfile(t *testing.T) {
	t.Parallel()
	m, err := newMarker()
	if err != nil {
		t.Fatal(err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "/usr/bin/sandbox-exec", "-f", "/dev/fd/3", "--", "/usr/bin/true")
	cmd.ExtraFiles = []*os.File{pr}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = pr.Close()
	t.Cleanup(func() { _ = pw.Close(); _ = cmd.Wait() })
	pid := cmd.Process.Pid
	// It may not have started its read yet, but its name is the command's until
	// it execs, which it cannot do without a profile.
	eventually(t, 5*time.Second, "sandbox-exec did not start", func() bool {
		st, err := statPid(pid)
		return err == nil && st.Comm == sandboxExecName
	})
	p := m.prober(pid)
	var mem memory
	for i := range 20 {
		clean, next, err := p.scan(mem)
		if err != nil {
			t.Fatal(err)
		}
		if clean {
			t.Fatalf("scan %d was clean with an unsandboxed sandbox-exec (pid %d) waiting for its profile", i, pid)
		}
		mem = next
	}
}

// ----------------------------------------------------------- stage messages

func TestStageMessagesRefuseTheWrongKind(t *testing.T) {
	t.Parallel()
	enc := func(v any) *json.Decoder {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return json.NewDecoder(bytes.NewReader(b))
	}
	if r, err := readReply(enc(stageReply{Kind: kindReply, Group: 7})); err != nil || r.Group != 7 {
		t.Errorf("a reply: %+v, %v", r, err)
	}
	// The stage's last message where the first belongs: this is what a lifeline
	// that closes during Start can make the stage send first.
	if _, err := readReply(enc(stageDone{Kind: kindDone, Empty: true, Scans: 1})); err == nil {
		t.Error("a report was read as a reply")
	}
	if d, err := readDone(enc(stageDone{Kind: kindDone, Empty: true, Scans: 1})); err != nil || !d.Empty {
		t.Errorf("a report: %+v, %v", d, err)
	}
	if _, err := readDone(enc(stageReply{Kind: kindReply, Group: 7})); err == nil {
		t.Error("a reply was read as a report")
	}
	// A message that says nothing of its kind, as an older stage's would.
	if _, err := readDone(json.NewDecoder(strings.NewReader(`{"empty":true}`))); err == nil {
		t.Error("a message with no kind was read as a report")
	}
}

// ----------------------------------------------------------- the list's size

func TestListPidsAsksAgainWhenTheListMayBeCut(t *testing.T) {
	t.Parallel()
	// fake is the kernel, asked for the size, then the list, then the size
	// again, over and over. The list holds n pids, or as many as fit.
	fake := func(before, n, after int) listCall {
		calls := 0
		return func(buf []int32) (int, error) {
			calls++
			switch calls % 3 {
			case 1:
				return before * 4, nil
			case 0:
				return after * 4, nil
			}
			fit := min(n, len(buf))
			for j := range fit {
				buf[j] = int32(1000 + j)
			}
			return fit * 4, nil
		}
	}
	// Whole: shorter than both sizes.
	if pids, err := listPids(fake(100, 40, 100)); err != nil || len(pids) != 40 || pids[0] != 1000 {
		t.Errorf("whole: %d pids, %v", len(pids), err)
	}
	// As long as the size: the kernel stops there, so it may have stopped early.
	if _, err := listPids(fake(100, 100, 100)); err == nil {
		t.Error("a list as long as the size was taken as whole")
	}
	// nprocs fell between the first size and the list, so the kernel's cap was
	// the second size, and the list reached it.
	if _, err := listPids(fake(100, 60, 60)); err == nil {
		t.Error("a list as long as the second size, which is under the first, was taken as whole")
	}
	// Filling the buffer.
	if _, err := listPids(fake(100, 100000, 100000)); err == nil {
		t.Error("a list that filled the buffer was taken as whole")
	}
	// A call that fails ends it.
	if _, err := listPids(func([]int32) (int, error) { return 0, errors.New("boom") }); err == nil {
		t.Error("an error was lost")
	}
}

// ------------------------------------------------------ a cut-short profile

// sandbox-exec takes a profile cut between two rules as it is, with the rules
// after it missing. The profile is one form, so that every prefix of it is a
// syntax error, and sandbox-exec exits without running the command (but for
// a cut right after the version, which is a profile that denies everything).
func TestProfileCutShortDoesNotRun(t *testing.T) {
	t.Parallel()
	m, err := newMarker()
	if err != nil {
		t.Fatal(err)
	}
	home := realTemp(t)
	prof, err := profile(profileInput{Home: home, Write: []string{home}, Self: "/usr/bin/true", Marker: m, Services: []Service{ServiceDirectory}})
	if err != nil {
		t.Fatal(err)
	}
	// The marker comes before every rule that allows anything but the basics.
	if i, j := strings.Index(prof, m.In), strings.Index(prof, "(allow file-read*"); i < 0 || j < 0 || i > j {
		t.Errorf("the marker (at %d) is not before the file rules (at %d)", i, j)
	}
	// The profile is read from a pipe by sandbox-exec, which a shell runs, so that
	// how sandbox-exec ended is reported even if it was killed by a signal. The
	// command it runs writes to a pipe of its own, which shows it started. A
	// failure then says which of three things happened: sandbox-exec refused the
	// profile, it died before it ran the command, or the command ran.
	run := func(p string) cutRun { return runCut(t, p) }
	if r := run(prof); r.rc != 0 || !r.ran {
		t.Fatalf("the whole profile does not run the command: %+v", r)
	}
	cuts, bad := 0, 0
	for i := range len(prof) - 1 {
		// Every end of a line, and a spot in the middle of each.
		if prof[i] != '\n' && i%7 != 0 {
			continue
		}
		cuts++
		r := run(prof[:i])
		// 65 is a syntax error. 71 is a profile that denies everything, so the
		// command could not be started, and only a cut before the (begin makes
		// one: what is left is the version alone. Anything else, 0 included,
		// means the command was started under a profile that is not the one asked
		// for, or that sandbox-exec did not end as it should.
		want := 65
		if i >= len("(version 1)") && i <= strings.Index(prof, "(begin") {
			want = 71
		}
		if r.ran || r.rc != want {
			bad++
			if bad <= 3 {
				t.Errorf("a profile cut at byte %d of %d, after %q: want sandbox-exec to exit %d without running the command, got %s", i, len(prof), prof[max(0, i-40):i], want, r)
			}
		}
	}
	t.Logf("%d cuts tried", cuts)
	if !strings.Contains(prof, "(begin") {
		t.Error("the profile has no (begin")
	}
}

// ------------------------------------------------------- the stage's report

// A stage whose scan cannot prove the sandbox empty says so, and the caller
// scans itself. The stage here is the test binary again, which TestMain gives a
// scan that is never clean and a short budget when its environment says so.
func TestTeardownStageThatCannotProveLeavesItToTheCaller(t *testing.T) {
	t.Parallel()
	c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{"/usr/bin/true"}})
	if err != nil {
		t.Fatal(err)
	}
	c.Env = []string{shellPath, stageUnprovableEnv + "=1"}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Errorf("Wait: %v", err)
	}
	if c.run.stageScans < 2 {
		t.Errorf("the stage made %d scans, want its report of the scans of a budget it ran out of", c.run.stageScans)
	}
	if n := c.run.callerScans.Load(); n < 1 {
		t.Errorf("the caller made %d scans after a stage that could not prove the sandbox empty", n)
	}
}

// A stage that is killed sends nothing, and nothing holds the output open, so
// the stage's own watcher has no tick before Wait returns: Wait's scan alone
// ends what the stage left.
func TestWaitScansWhenTheStageWasKilledAndNothingHoldsTheOutput(t *testing.T) {
	t.Parallel()
	c, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{"/bin/sleep", "30"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, c)
	// The sleep is running under the profile before the stage is killed.
	eventually(t, 5*time.Second, "the sleep did not start", func() bool {
		got, err := c.run.mark.processes()
		return err == nil && len(got) > 0
	})
	// The stage is this process's child, so it is ours to kill.
	if err := syscall.Kill(c.Pid(), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = waitWithin(t, c, 9*time.Second)
	if errors.Is(err, ErrSurvivors) {
		t.Errorf("Wait: %v", err)
	}
	if n := c.run.callerScans.Load(); n < 1 {
		t.Errorf("the caller made %d scans for a stage that never reported", n)
	}
	if c.run.stageScans != 0 {
		t.Errorf("the killed stage reported %d scans", c.run.stageScans)
	}
	if got, err := c.run.mark.processes(); err != nil || len(got) != 0 {
		t.Errorf("processes of the sandbox after Wait (%v): %v, %v", time.Since(start), got, err)
	}
}

// The fields of a proc_bsdinfo that a scan reads.
func TestProcStatOfReadsTheFlagsAndTheName(t *testing.T) {
	t.Parallel()
	b := bsdInfo{Flags: flagInExit | 1, Status: 2, StartSec: 1700000000, StartUsec: 25}
	copy(b.Comm[:], "sandbox-exec")
	st := procStatOf(b)
	if !st.Exiting || st.Zombie || st.Forking || st.Start != 1700000000_000025 || st.Comm != "sandbox-exec" {
		t.Errorf("procStatOf = %+v", st)
	}
	if st := procStatOf(bsdInfo{Flags: 1, Status: stateZombie}); st.Exiting || !st.Zombie {
		t.Errorf("a zombie without the exit flag: %+v", st)
	}
	if st := procStatOf(bsdInfo{Status: stateForking}); !st.Forking {
		t.Errorf("a forking process: %+v", st)
	}
}

// ------------------------------------------- another sandbox's sandbox-exec

func registerSleepForever() {
	childModes["sleep-forever"] = func([]string) int { time.Sleep(time.Minute); return 0 }
}

// A process that runs under another sandbox's profile and is named sandbox-exec
// is not one that will apply this sandbox's profile, since a process under a
// profile cannot take another's name for this. It must not make the teardown of
// an unrelated sandbox wait for the whole budget, then report survivors.
func TestSandboxExecInAnotherSandboxDoesNotStallTeardown(t *testing.T) {
	t.Parallel()
	homeA := realTemp(t)
	body, err := os.ReadFile(self(t))
	if err != nil {
		t.Fatal(err)
	}
	named := homeA + "/" + sandboxExecName
	if err := os.WriteFile(named, body, 0o700); err != nil { //nolint:gosec // G306: the file is a program the test runs, which needs its owner to execute it.
		t.Fatal(err)
	}
	a, err := Command(t.Context(), Spec{Home: homeA, Command: []string{named, "sleep-forever"}})
	if err != nil {
		t.Fatal(err)
	}
	a.Stdout, a.Stderr = &syncBuffer{}, &syncBuffer{}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	endAtCleanup(t, a)
	// The real sandbox-exec has the name until it runs the command, which has it
	// from then on, and is under A's profile.
	eventually(t, 5*time.Second, "A's command did not start under A's profile", func() bool {
		in, _ := a.run.mark.member(a.run.group)
		return in
	})
	if st, err := statPid(a.run.group); err != nil || st.Comm != sandboxExecName {
		t.Fatalf("A's command: %+v, %v; want a process named %s", st, err, sandboxExecName)
	}
	b, err := Command(t.Context(), Spec{Home: realTemp(t), Command: []string{"/usr/bin/true"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	if b.run.mark.look(a.run.group).In {
		t.Fatal("A's command is a member of B")
	}
	start := time.Now()
	err = b.Wait()
	if errors.Is(err, ErrSurvivors) || err != nil {
		t.Errorf("B's Wait: %v, with a process of A named %s", err, sandboxExecName)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("B's Wait took %v", d)
	}
	if n := b.run.callerScans.Load(); n != 0 {
		t.Errorf("B's caller made %d scans: the stage should have proved it empty", n)
	}
}

// ----------------------------------------- the marker with everything allowed

// The marker's rules come first in the profile, and a rule that allows more of
// mach-lookup further down would make the lookup of the name that the profile
// denies succeed, and every process of the sandbox read as not a member: every
// teardown would clear it and leave it running. The profile is built with every
// service and option on, as a rule added later would be, and a command started
// under it must still read as a member.
func TestMarkerSurvivesEveryServiceAndOption(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		spec func(t *testing.T) Spec
	}{
		{"no network", func(*testing.T) Spec {
			return Spec{Listen: 1, Loopback: 1}
		}},
		{"host network", func(*testing.T) Spec {
			return Spec{Network: NetworkHost}
		}},
		{"no network, files and covers", func(t *testing.T) Spec {
			dir := realTemp(t)
			return Spec{Write: []string{mkdirs(t, dir, "w")}, Read: []string{mkdirs(t, dir, "r")}, Cover: []string{mkdirs(t, dir, "c")}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			spec := tc.spec(t)
			spec.Home = realTemp(t)
			spec.Command = []string{"/bin/sleep", "30"}
			spec.Services = []Service{ServiceFirefox, ServiceDirectory}
			spec.BroadLoopback = true
			c, err := Command(t.Context(), spec)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			endAtCleanup(t, c)
			eventually(t, 5*time.Second, "the command did not start", func() bool {
				st, err := statPid(c.run.group)
				return err == nil && st.Comm == "sleep"
			})
			if l := c.run.mark.look(c.run.group); !l.In || !l.Known || l.Free {
				t.Errorf("look(the command) = %+v, want a member", l)
			}
			// And the other half of the marker: the name the profile denies is
			// denied to it.
			if out, ok := lookupAllowed(c.run.group, c.run.mark.Out); out || !ok {
				t.Errorf("the denied name is allowed to the command: %v, %v", out, ok)
			}
			c.stop()
			_ = c.Wait()
		})
	}
}

// ------------------------------------------- the stage's lifeline and settings

// The lifeline reaching EOF ends the sandbox, once. If the main path has
// already ended it, the command is reaped and its group number may be no one's
// or someone else's, so the watcher must not end the group again, and must not
// exit, which would take the command's status over with 137.
func TestLifelineClosedAfterTheStageFinished(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		finished bool
		group    int
		wantEnd  int  // how many times the sandbox is ended
		wantExit bool // whether the stage exits at once
	}{
		{"the main path finished", true, 7, 0, false},
		{"the main path has not finished", false, 7, 1, true},
		{"the command has not started", false, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// finish writes the report to this pipe and closes it.
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			s := &stageState{group: tc.group, finished: tc.finished, status: w}
			ended := 0
			exit := s.lifelineClosed(func(group int, _ marker) (int, endKind) {
				ended++
				if group != tc.group {
					t.Errorf("ended group %d, want %d", group, tc.group)
				}
				return 1, endEmpty
			})
			if ended != tc.wantEnd || exit != tc.wantExit {
				t.Errorf("ended %d times, exit = %v; want %d and %v", ended, exit, tc.wantEnd, tc.wantExit)
			}
			// The lock is held when the stage is to exit, so that nothing runs on and
			// changes its status, and free when it is not.
			if free := s.mu.TryLock(); free == tc.wantExit {
				t.Errorf("the lock is free = %v after the call, want %v", free, !tc.wantExit)
			}
		})
	}
}

// A stage given settings with no marker refuses them and starts nothing, since
// a teardown with no marker takes every pid for one outside the sandbox and
// would call the sandbox empty without looking.
func TestStageRefusesSettingsWithoutAMarker(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		marker marker
		want   bool // whether the stage refuses
	}{
		{"no names", marker{}, true},
		{"no name to look up", marker{Out: "out"}, true},
		{"no name to refuse", marker{In: "in"}, true},
		{"both names", marker{In: "in", Out: "out"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := (stageSettings{Marker: tc.marker}).check(); (err != nil) != tc.want {
				t.Errorf("check = %v, want a refusal = %v", err, tc.want)
			}
		})
	}
	// The stage itself, run as the test binary does: it answers with the error
	// and does not start the command.
	lifeR, lifeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lifeW.Close() })
	setR, setW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	statR, statW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = statR.Close() })
	body, err := json.Marshal(stageSettings{Profile: "(version 1)(allow default)"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setW.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = setW.Close()
	cmd := exec.CommandContext(t.Context(), selfPath(), stageArg, "--", "/usr/bin/true") //nolint:gosec // G204: the stage is this test binary, which TestMain runs as one.
	cmd.ExtraFiles = []*os.File{lifeR, setR, statW}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = lifeR.Close()
	_ = setR.Close()
	_ = statW.Close()
	reply, rerr := readReply(json.NewDecoder(statR))
	if err := cmd.Wait(); err == nil {
		t.Error("the stage exited 0 with settings that have no marker")
	}
	if rerr != nil || !strings.Contains(reply.Error, "marker") || reply.Group != 0 {
		t.Errorf("reply = %+v, %v; want an error that names the marker and no group", reply, rerr)
	}
}

// ------------------------------------------------------------- Wait's report

// Wait takes the stage's report only for what it says, and a report that says
// both that the sandbox is empty and that members are left is taken as the
// worse: the stage never sends one, so it is wrong, and wrong fails closed.
func TestJudgeReport(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		done     stageDone
		reported bool
		want     reportVerdict
	}{
		{"no report", stageDone{}, false, reportNone},
		{"no report, though the message says empty", stageDone{Empty: true}, false, reportNone},
		{"neither", stageDone{Kind: kindDone}, true, reportNone},
		{"empty", stageDone{Empty: true}, true, reportEmpty},
		{"members", stageDone{Members: true}, true, reportGaveUp},
		{"both", stageDone{Empty: true, Members: true}, true, reportGaveUp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := judgeReport(tc.done, tc.reported); got != tc.want {
				t.Errorf("judgeReport = %v, want %v", got, tc.want)
			}
		})
	}
}

// A sandbox-exec that is missing or has no execute bit is an error that says
// which, and one that has no error behind it doesn't print a nil wrapped.
func TestCheckSandboxExec(t *testing.T) {
	t.Parallel()
	dir := realTemp(t)
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "exe")
	if err := os.WriteFile(exe, nil, 0o700); err != nil { //nolint:gosec // G306: the test needs an executable file.
		t.Fatal(err)
	}
	if err := checkSandboxExec(sandboxExec); err != nil {
		t.Errorf("the real %s: %v", sandboxExec, err)
	}
	if err := checkSandboxExec(exe); err != nil {
		t.Errorf("an executable file: %v", err)
	}
	if err := checkSandboxExec(filepath.Join(dir, "gone")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file: %v, want one that wraps ErrNotExist", err)
	}
	err := checkSandboxExec(plain)
	if err == nil || !strings.Contains(err.Error(), "not executable") || strings.Contains(err.Error(), "%!") {
		t.Errorf("a file with no execute bit: %v, want an error that says it is not executable", err)
	}
}

// cutRun is how one run of sandbox-exec under runCut ended.
type cutRun struct {
	// rc is the status sandbox-exec ended with as the shell saw it, 128 plus the
	// signal if it was killed, or -1 if the shell reported nothing.
	rc int
	// ran is whether the command it was to run started.
	ran bool
	// shell is how the shell itself ended, which is an error only if the shell
	// was killed, and the crash reports that appeared during the run.
	shell   error
	reports string
}

func (r cutRun) String() string {
	return fmt.Sprintf("rc %d, command ran %v, shell %v%s", r.rc, r.ran, r.shell, r.reports)
}

// runCut runs sandbox-exec with profile p on its standard input, and a command
// that says it ran. A shell runs sandbox-exec and reports its status on
// descriptor 3, so a crash of sandbox-exec is told from a crash of whatever
// started it. The command reports on descriptor 4.
func runCut(t *testing.T, p string) cutRun {
	t.Helper()
	pipe := func() (r, w *os.File) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		return r, w
	}
	rcR, rcW := pipe()
	ranR, ranW := pipe()
	defer rcR.Close()
	defer ranR.Close()
	const script = `/usr/bin/sandbox-exec -f /dev/stdin -- /bin/sh -c 'echo ran >&4'; echo $? >&3`
	cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", script)
	cmd.Stdin = strings.NewReader(p)
	cmd.ExtraFiles = []*os.File{rcW, ranW}
	start := time.Now()
	err := cmd.Run()
	_ = rcW.Close()
	_ = ranW.Close()
	r := cutRun{rc: -1, shell: err}
	if b, _ := io.ReadAll(rcR); len(b) > 0 {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			r.rc = n
		}
	}
	b, _ := io.ReadAll(ranR)
	r.ran = strings.Contains(string(b), "ran")
	if r.rc > 128 || err != nil {
		r.reports = crashReports(start)
	}
	return r
}

// crashReports describes the crash reports macOS wrote since start, for a
// process that was killed by a signal, so that a failure says what crashed. It
// waits a little, since ReportCrash writes them after the process is gone.
func crashReports(start time.Time) string {
	dir := os.DirFS(filepath.Join(os.Getenv("HOME"), "Library", "Logs", "DiagnosticReports"))
	var out strings.Builder
	for range 20 {
		time.Sleep(250 * time.Millisecond)
		out.Reset()
		files, _ := fs.Glob(dir, "*.ips")
		for _, f := range files {
			if fi, err := fs.Stat(dir, f); err != nil || fi.ModTime().Before(start) {
				continue
			}
			b, err := fs.ReadFile(dir, f)
			if err != nil {
				continue
			}
			fmt.Fprintf(&out, "\ncrash report %s: %s", f, crashSummary(b))
		}
		if out.Len() > 0 {
			break
		}
	}
	if out.Len() == 0 {
		return "\nno crash report appeared"
	}
	return out.String()
}

// crashSummary pulls the process, the exception and the top of the faulting
// thread out of a crash report, which is a JSON header line and then a JSON body.
func crashSummary(b []byte) string {
	_, body, ok := bytes.Cut(b, []byte("\n"))
	if !ok {
		return "unreadable"
	}
	var r struct {
		ProcName  string          `json:"procName"`
		Exception json.RawMessage `json:"exception"`
		Faulting  int             `json:"faultingThread"`
		Threads   []struct {
			Frames []struct {
				Symbol     string `json:"symbol"`
				SymbolLoc  int    `json:"symbolLocation"`
				ImageIndex int    `json:"imageIndex"`
			} `json:"frames"`
		} `json:"threads"`
		UsedImages []struct {
			Name string `json:"name"`
		} `json:"usedImages"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "unreadable: " + err.Error()
	}
	var frames []string
	if r.Faulting >= 0 && r.Faulting < len(r.Threads) {
		for i, f := range r.Threads[r.Faulting].Frames {
			if i == 8 {
				break
			}
			img := ""
			if f.ImageIndex >= 0 && f.ImageIndex < len(r.UsedImages) {
				img = r.UsedImages[f.ImageIndex].Name + ":"
			}
			frames = append(frames, img+f.Symbol)
		}
	}
	return fmt.Sprintf("process %s, exception %s, top frames %v", r.ProcName, r.Exception, frames)
}
