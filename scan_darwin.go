package sandbox

import "time"

// The teardown's proof that a sandbox is empty.
//
// A scan that lists processes one at a time cannot show that nothing is left.
// kern.proc.all (sysctl_prochandle in XNU's bsd/kern/kern_sysctl.c, which calls
// proc_iterate in bsd/kern/kern_proc.c) copies the pids under proc_list_lock,
// skips every process that is still being forked (p_stat SIDL), and fills in
// each one later, dropping any that has gone by then. A process that forks and
// exits again inside that window makes the scan look empty while its child
// lives.
//
// A scan here takes one atomic list instead. proc_listpids(PROC_UID_ONLY),
// which proc_info_internal reaches in XNU's bsd/kern/proc_info.c, builds its
// whole answer inside one hold of proc_list_lock, from allproc and then
// zombproc, so it includes zombies. Every process of the uid that is on those
// lists when the lock is taken is in it, and nothing that forks later is. A
// process that fork is still making is on neither list: forkproc puts it in the
// pid hash, but pinsertchild adds it to allproc only after fork_create_child
// has copied the address space (bsd/kern/kern_fork.c). The proof does not need
// it. The child exists only because its parent is inside fork, so the parent is
// alive and on the list at the snapshot, and if the child will be a member so is
// the parent: the scan kills it, or finds it exiting or gone, and is not clean
// either way. fork1 ends the child if the parent has begun to exit. So if every
// pid in the list is shown not to be under the profile, then
// nobody under the profile existed at that moment, and nothing can under it
// ever again, since a process gets the profile only from a parent that has it,
// or from sandbox-exec applying it to itself (handled below).
//
// Showing it takes care, since the list is only the pids. For each pid the scan
// asks sandbox_check about the process, then reads its proc_bsdinfo, and calls
// the pid cleared only if the second read shows the same process, alive and not
// new:
//
//   - A member of the sandbox is killed, and the scan is not clean.
//   - A pid whose bsdinfo cannot be read (ESRCH) is unknown. The process has
//     exited and been reaped, or is between the states proc_pidinfo can find.
//     Its answer may have been about another process, or the process may have
//     been the sandbox's, with children the list did not hold.
//   - A pid whose p_stat is SIDL is unknown. proc_pidinfo can see one only for
//     the few instructions between pinsertchild and p_stat = SRUN, so this
//     is belt and braces.
//   - A pid that has begun to exit (PROC_FLAG_INEXIT, P_LEXIT) and is not yet a
//     zombie (the flag stays set on one) is unknown. From then until it is a
//     zombie, proc_pidinfo still returns it, alive, with its
//     old start time, and sandbox_check says 1, as for a denial, so a member that
//     was exiting looked like a process that was not one, and it may have
//     forked a child after the snapshot.
//   - A pid that started at or after T, the time the scan noted just before it
//     listed, may be a reuse of a number the list held for another process, so
//     what sandbox_check said may be about a different process than the one
//     listed. It is unknown. A process that started before T and is still
//     there now is the one that was there at the snapshot: forkproc, in
//     bsd/kern/kern_fork.c, skips a pid that is in the pid hash, which holds
//     zombies too, so a number is not given to a second process while the first
//     is listed.
//   - A pid whose membership the kernel would not say is unknown. member makes
//     this real: a process that is gone, a zombie, and one that has begun to
//     exit all answer sandbox_check as a denial, so member asks whether the
//     kernel still finds the pid before it calls an answer known.
//   - A process that is under no profile, is named sandbox-exec, and may be the
//     one that was started to apply this profile is unknown. sandbox-exec
//     applies the profile to itself, in place, and runs the command, so before
//     that it is unsandboxed, and then it is the sandbox. Nothing under the
//     profile starts it, so only a stage that was killed in the few milliseconds
//     before it applied the profile leaves one, and waiting for it to apply the
//     profile costs a rescan. Only a process under no profile can be that one, so
//     a process in another sandbox that is named sandbox-exec does not count, and
//     where the caller has the pid of the one it started (prober.execPid), no
//     other pid counts. What is left is a process of the account's owner, outside
//     any sandbox, that is named sandbox-exec and lives on, with no pid to
//     exclude it: only Start's failure path (abortStart), which does not have the
//     pid, scans that way. A process asked about before it applied the profile
//     can have applied it and started the command by the time its name is read,
//     which changes the name, so such a process is asked about again after.
//   - A zombie (pbi_status SZOMB, found because proc_pidinfo is told to look
//     for them: proc_find_zombref) cannot be asked about, and was alive at the
//     snapshot as far as one scan knows, perhaps as a member that had children.
//     So can a process that is exiting and not yet a zombie. Either is safe if
//     the previous scan's check already saw it so with the same start time: it
//     was dead or dying before this snapshot, so it can fork nothing (fork1
//     ends a child whose parent has begun to exit), and the children it made
//     before are in this snapshot and are asked about themselves. Remembering
//     them from one scan to the next is what stops a zombie that is never reaped,
//     or a process stuck in exit, from making every scan unknown.
//   - A zombie or exiting process that is new to the scan is also safe if its
//     parent (pbi_ppid) is a process that this scan found not to be a member
//     (it is in the list too, or the child's parent would not have been alive at
//     the snapshot), and that started no later than the child. A process that
//     fork makes has its parent's
//     profile, and a non-member cannot become a member, so the child is not
//     one. A parent can change by one of two routes only: the parent exits, and
//     the child goes to launchd (pid 1, never a cleared parent), or a debugger
//     attaches with ptrace, and the child's pbi_ppid is the debugger until it
//     detaches (bsd/kern/mach_process.c; reparenting in proc_exit,
//     bsd/kern/kern_exit.c). A debugger can only be started by the account's
//     owner, outside any sandbox, and it does not change the profile of what it
//     attaches to, so it could make a member look like a non-member's child only
//     by attaching to one, which the owner of the account is trusted not to do.
//
// A pid that a scan found not to be a member is remembered with its start time,
// and a later scan that finds the same process at that pid with the same start
// time does not ask again, whatever has become of it since: a process cannot
// become a member (it can be made one only by sandbox-exec applying the
// profile, and a process that may be that one is never remembered). This keeps
// the processes that are long lived from costing a scan, whatever they do while
// it runs. It does not help for a pid that is gone before the scan reads it,
// which the scan cannot know anything about. Heavy process churn of the
// account, with the CPUs busy, can still keep a scan from ever being clean
// (docs/security-model.md).
//
// A scan that is clean has no unknown pid and killed nothing.

// teardownBudget is how long a teardown keeps scanning, for processes that keep
// being found or pids that stay unknown, before it gives up and says it could
// not confirm the sandbox empty. It is a variable so that a test can change it.
var teardownBudget = 5 * time.Second

// sandboxExecName is the name of the process that applies a profile to itself.
const sandboxExecName = "sandbox-exec"

// procStat is what a scan reads about one pid after it has asked sandbox_check.
type procStat struct {
	// Forking is whether the process is still being forked (SIDL), Exiting
	// whether it has begun to exit, and Zombie whether it has exited and not been
	// reaped (SZOMB).
	Forking, Exiting, Zombie bool
	// Start is when the process started, in microseconds since the epoch.
	Start int64
	// Comm is the process's name, as the kernel keeps it.
	Comm string
	// PPid is the process's parent.
	PPid int
}

// prober is the scan's view of the system, so that a test can supply its own.
type prober struct {
	// list returns every pid of this account at one moment, zombies included.
	// A process that is still being forked is not in it.
	list func() ([]int, error)
	// look asks what profile pid is under (see lookup).
	look func(pid int) lookup
	// stat reads pid's status and start time. An error means it could not be
	// read, as for a process that is gone.
	stat func(pid int) (procStat, error)
	// kill ends pid.
	kill func(pid int)
	// now is the time.
	now func() time.Time
	// sleep waits, between one scan and the next.
	sleep func(time.Duration)
	// execPid is the pid of the sandbox-exec that was started to apply the
	// profile, which is the pid of the command's group: only that process can be
	// one that has not applied the profile yet. It is 0 if the caller does not
	// know the pid, and then any process can be.
	execPid int
}

// mayApply reports whether pid could be the sandbox-exec that has not applied
// the profile yet.
func (p prober) mayApply(pid int) bool { return p.execPid == 0 || pid == p.execPid }

// memory is what a teardown keeps from one scan to the next.
type memory struct {
	// cleared maps each pid that a scan found not to be a member to its start
	// time. The pid stays so for as long as the process lives.
	cleared map[int]int64
	// dying maps each pid that a scan found exiting or a zombie to its start
	// time.
	dying map[int]int64
	// killed is how many members of the sandbox the scan found and signaled.
	killed int
}

// dyingKid is a process that is new to the scan as a zombie or as exiting, whose
// parent is checked once the scan has been through the list.
type dyingKid struct {
	pid, ppid int
	start     int64
}

// scan makes one scan. prev is what the previous scan left. It returns whether
// the scan proved the sandbox empty, and what it leaves for the next.
func (p prober) scan(prev memory) (clean bool, next memory, err error) {
	t := p.now().UnixMicro()
	pids, err := p.list()
	if err != nil {
		return false, memory{}, err
	}
	clean = true
	next = memory{cleared: make(map[int]int64), dying: make(map[int]int64)}
	var kids []dyingKid
	// check is the whole check of one pid.
	check := func(pid int) {
		l := p.look(pid)
		if l.In {
			p.kill(pid)
			next.killed++
			clean = false
			return
		}
		st, err := p.stat(pid)
		switch {
		case err != nil || st.Forking || st.Start >= t:
			clean = false
		case st.Zombie || st.Exiting:
			// A zombie keeps PROC_FLAG_INEXIT, and so is either.
			next.dying[pid] = st.Start
			if start, ok := prev.dying[pid]; !ok || start != st.Start {
				kids = append(kids, dyingKid{pid, st.PPid, st.Start})
			}
		case !l.Known:
			clean = false
		case l.Free && p.mayApply(pid):
			if st.Comm == sandboxExecName {
				// Not a member, and about to be.
				clean = false
				break
			}
			// It may have applied the profile and started the command since it was
			// asked, and so have another name.
			switch again := p.look(pid); {
			case again.In:
				p.kill(pid)
				next.killed++
				clean = false
			case !again.Known || !again.Free:
				clean = false
			default:
				next.cleared[pid] = st.Start
			}
		default:
			next.cleared[pid] = st.Start
		}
	}
	// The pids that no earlier scan cleared go first, since each is the one
	// that can have been a member and can vanish before it is read, and the
	// time from the list to the read is what lets it. A cleared pid is read
	// after them, for its start time alone: that it is the same process cannot
	// be told from the number, which a new process may have taken.
	var remembered []int
	for _, pid := range pids {
		if _, ok := prev.cleared[pid]; ok {
			remembered = append(remembered, pid)
			continue
		}
		check(pid)
	}
	for _, pid := range remembered {
		if st, err := p.stat(pid); err == nil && st.Start == prev.cleared[pid] {
			next.cleared[pid] = st.Start
			continue
		}
		check(pid)
	}
	for _, k := range kids {
		if !parentCleared(next.cleared, k) {
			clean = false
		}
	}
	return clean, next, nil
}

// parentCleared reports whether k's parent is a process that this scan found
// not to be a member, and started no later than k. The parent is the process
// that held the number when k's parent was read. It cannot have been another
// that took the number since: k started before T, and a process that holds a
// number after the parent exits started after T, so it cannot be k's parent
// either (k would have been reparented to launchd when the parent exited).
func parentCleared(cleared map[int]int64, k dyingKid) bool {
	start, ok := cleared[k.ppid]
	return ok && k.ppid > 1 && start <= k.start
}

// endKind is how a teardown ended.
type endKind int

const (
	// endBudget is that the time ran out with pids still unaccounted for,
	// and no member found for long: noise, as when the account's
	// processes start and exit faster than a scan can read them.
	endBudget endKind = iota
	// endEmpty is that a scan proved the sandbox empty.
	endEmpty
	// endMembers is that the teardown gave up because scans kept finding members
	// of the sandbox after it had signaled the ones before, and for giveUpAfter
	// the number they found had not fallen: a process of it keeps forking against
	// the teardown.
	endMembers
)

// The teardown waits between scans, from backoffStart doubling to backoffMax, so
// that the processes it signaled can finish exiting and be reaped, and the
// account's own processes have the processors. The first scan is not delayed.
//
// It gives up on members when scans keep finding them and the number they find
// has stopped falling. A program that shuts down normally has fewer members to
// signal in each scan than in the one before, because each signal ends a process
// before it forks again, and how many scans that takes depends on how fast the
// machine is: eight chains of forking processes took 3 to 5 scans on a fast
// machine and more than 10 on a three core runner. A process that forks on
// purpose, to stay ahead of the signals, does not make the count fall for long.
// So the teardown gives up when giveUpAfter has passed since the scan that found
// the fewest members so far, and that scan found some. It does not count scans,
// which a slow machine makes more of. They are variables so that a test can
// change them.
var (
	backoffStart = time.Millisecond
	backoffMax   = 25 * time.Millisecond
	giveUpAfter  = time.Second
)

// run scans until one proves the sandbox empty, until members have been found
// for giveUpAfter without their number falling, or until budget has passed, and
// says which. It returns how many scans it made. At least one scan is made,
// whatever the budget.
func (p prober) run(budget time.Duration) (scans int, out endKind) {
	deadline := p.now().Add(budget)
	var mem memory
	wait := backoffStart
	// fewest is the smallest number of members a scan has found, and fewestAt
	// when that scan ended. A scan that found none does not count.
	var fewest int
	var fewestAt time.Time
	for {
		scans++
		clean, next, err := p.scan(mem)
		switch {
		case err != nil:
			return scans, endBudget
		case clean:
			return scans, endEmpty
		}
		now := p.now()
		if next.killed > 0 {
			if fewest == 0 || next.killed < fewest {
				fewest, fewestAt = next.killed, now
			} else if now.Sub(fewestAt) >= giveUpAfter {
				return scans, endMembers
			}
		}
		mem = next
		left := deadline.Sub(now)
		if left <= 0 {
			return scans, endBudget
		}
		p.sleep(min(wait, left))
		wait = min(2*wait, backoffMax)
	}
}

// teardown is run, for a caller that wants to know only whether the sandbox was
// proved empty.
func (p prober) teardown(budget time.Duration) (scans int, empty bool) {
	scans, out := p.run(budget)
	return scans, out == endEmpty
}
