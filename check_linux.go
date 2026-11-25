package sandbox

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// netfilterReplace is IPT_SO_SET_REPLACE from linux/netfilter_ipv4/ip_tables.h,
// the setsockopt that replaces an iptables table, which needs CAP_NET_ADMIN.
const netfilterReplace = 64

// platformChecks are the checks that need Linux.
func platformChecks(e *checkEnv) []Result {
	fns := []checkFn{checkStatus, checkUserns, checkMount, checkIOUring, checkNetfilter, checkBPF, checkNested, checkAbstract, checkLimits, checkDelegate}
	groups := make([][]Result, len(fns))
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Go(func() { groups[i] = fn(e) })
	}
	wg.Wait()
	return slices.Concat(groups...)
}

// procStatus is what /proc/self/status says about privilege.
type procStatus struct {
	NoNewPrivs     int
	Seccomp        int
	SeccompFilters int
	CapEff, CapPrm uint64
	CapBnd         uint64
}

// parseStatus reads the privilege fields of /proc/<pid>/status. A field the
// kernel is too old to have stays zero.
func parseStatus(r io.Reader) (procStatus, error) {
	var st procStatus
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		var err error
		switch k {
		case "NoNewPrivs":
			st.NoNewPrivs, err = strconv.Atoi(v)
		case "Seccomp":
			st.Seccomp, err = strconv.Atoi(v)
		case "Seccomp_filters":
			st.SeccompFilters, err = strconv.Atoi(v)
		case "CapEff":
			st.CapEff, err = strconv.ParseUint(v, 16, 64)
		case "CapPrm":
			st.CapPrm, err = strconv.ParseUint(v, 16, 64)
		case "CapBnd":
			st.CapBnd, err = strconv.ParseUint(v, 16, 64)
		}
		if err != nil {
			return st, fmt.Errorf("read %s: %w", k, err)
		}
	}
	return st, sc.Err()
}

// capNames are the capabilities by number, as of Linux 6.x.
var capNames = []string{
	"CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP",
	"LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER",
	"SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE",
	"SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP",
	"MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF",
	"CHECKPOINT_RESTORE",
}

// capList names the capabilities in a mask.
func capList(mask uint64) string {
	var names []string
	for i := range 64 {
		if mask&(1<<i) != 0 {
			if i < len(capNames) {
				names = append(names, "CAP_"+capNames[i])
			} else {
				names = append(names, "CAP_"+strconv.Itoa(i))
			}
		}
	}
	return strings.Join(names, " ")
}

func checkStatus(*checkEnv) []Result {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return []Result{fail("proc.status", "%v", err)}
	}
	defer f.Close()
	st, err := parseStatus(f)
	if err != nil {
		return []Result{fail("proc.status", "%v", err)}
	}
	res := []Result{
		boolResult("proc.no_new_privs", st.NoNewPrivs == 1, "NoNewPrivs is %d", st.NoNewPrivs),
		boolResult("proc.seccomp", st.Seccomp == 2, "Seccomp mode is %d with %d filters", st.Seccomp, st.SeccompFilters),
	}
	for _, c := range []struct {
		name string
		mask uint64
	}{{"caps.effective", st.CapEff}, {"caps.permitted", st.CapPrm}, {"caps.bounding", st.CapBnd}} {
		res = append(res, boolResult(c.name, c.mask == 0, "%016x %s", c.mask, capList(c.mask)))
	}
	return res
}

func boolResult(name string, ok bool, format string, a ...any) Result {
	if ok {
		return pass(name, format, a...)
	}
	return fail(name, format, a...)
}

// parseUIDMap reports whether r, a /proc/<pid>/uid_map, is the initial user
// namespace's: the identity map of every uid.
func parseUIDMap(r io.Reader) bool {
	sc := bufio.NewScanner(r)
	if !sc.Scan() {
		return false
	}
	f := strings.Fields(sc.Text())
	more := sc.Scan()
	return len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295" && !more
}

// initialUserNS reports whether this process is in the initial user
// namespace. An unreadable map counts as not, so only a clear root fails.
func initialUserNS() bool {
	f, err := os.Open("/proc/self/uid_map")
	if err != nil {
		return false
	}
	defer f.Close()
	return parseUIDMap(f)
}

// Modes of the grandchild: this binary, started with a namespace of its own.
const (
	modeNoop    = "noop"
	modeMount   = "mount"
	modeUmount  = "umount"
	modeRemount = "remount"
)

// grandchild runs a namespace attempt in the process the check child made
// for it, so no namespace or mount touches the check child or the caller.
func grandchild(args []string) (int, bool) {
	var err error
	switch args[0] {
	case modeNoop:
	case modeMount:
		// A new mount namespace's mounts may still propagate to the
		// parent's peers, so cut that first.
		if err = unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err == nil {
			err = unix.Mount("tmpfs", "/", "tmpfs", 0, "")
		}
	case modeUmount, modeRemount:
		if len(args) != 2 {
			return checkFailed, true
		}
		if err = unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err == nil {
			if args[0] == modeUmount {
				err = unix.Unmount(args[1], 0)
			} else {
				err = unix.Mount("", args[1], "", unix.MS_REMOUNT|unix.MS_BIND, "")
			}
		}
	default:
		return 0, false
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	return 0, true
}

// spawnNS starts this binary as a grandchild in new namespaces and waits.
// A start error means the kernel or a filter refused the namespace. An exit
// status of 1 means the mode's own call was refused, with the reason on
// stderr.
func spawnNS(flags uintptr, mode ...string) (started bool, detail string) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*netTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", append([]string{checkArg}, mode...)...) //nolint:gosec // G204: this binary, run with the check's own fixed modes.
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: flags}
	if flags&syscall.CLONE_NEWUSER != 0 {
		// Map our uid to root, as bubblewrap does. Without a mapping the
		// namespace's mounts fail on ownership, not on the policy tried.
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return true, ""
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return true, strings.TrimSpace(stderr.String())
	}
	return false, err.Error()
}

func checkUserns(*checkEnv) []Result {
	const name = "userns.create"
	started, d := spawnNS(syscall.CLONE_NEWUSER, modeNoop)
	if started && d == "" {
		return []Result{fail(name, "clone(CLONE_NEWUSER) worked")}
	}
	return []Result{pass(name, "clone(CLONE_NEWUSER) refused: %s", d)}
}

func checkMount(*checkEnv) []Result {
	const name = "mount.tmpfs"
	started, d := spawnNS(syscall.CLONE_NEWUSER|syscall.CLONE_NEWNS, modeMount)
	switch {
	case started && d == "":
		return []Result{fail(name, "mounted a tmpfs in a new user and mount namespace")}
	case started:
		return []Result{pass(name, "mount refused in a new namespace: %s", d)}
	}
	return []Result{pass(name, "no new user namespace to mount in: %s", d)}
}

func checkIOUring(*checkEnv) []Result {
	const name = "io_uring.setup"
	var params [120]byte                                                                             // struct io_uring_params
	fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params[0])), 0) //nolint:gosec // G103: the kernel reads the buffer during the call.
	if errno == 0 {
		unix.Close(int(fd)) //nolint:gosec // G104: the ring was only a probe, and creating it is the result.
		return []Result{fail(name, "io_uring_setup worked")}
	}
	return []Result{pass(name, "io_uring_setup refused: %v", errno)}
}

func checkNetfilter(*checkEnv) []Result {
	const name = "netfilter.setsockopt"
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return []Result{pass(name, "no raw socket to replace a table on: %v", err)}
	}
	defer unix.Close(fd)
	// With no buffer the kernel tests the capability first and returns EPERM,
	// and anything else means the table code was reached.
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), unix.SOL_IP, netfilterReplace, 0, 0, 0)
	switch errno {
	case unix.EPERM, unix.EACCES, unix.ENOPROTOOPT, unix.ENOSYS, unix.EAFNOSUPPORT:
		return []Result{pass(name, "IPT_SO_SET_REPLACE refused: %v", errno)}
	default:
		return []Result{fail(name, "IPT_SO_SET_REPLACE reached the table code: %v", errno)}
	}
}

func checkBPF(*checkEnv) []Result {
	const name = "bpf.load"
	// BPF_MAP_CREATE of a one-entry array map, the least a program can ask of bpf(2).
	var attr [128]byte
	binary.NativeEndian.PutUint32(attr[0:], 2) // BPF_MAP_TYPE_ARRAY
	binary.NativeEndian.PutUint32(attr[4:], 4) // key size
	binary.NativeEndian.PutUint32(attr[8:], 4) // value size
	binary.NativeEndian.PutUint32(attr[12:], 1)
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_CREATE, uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr))) //nolint:gosec // G103: the kernel reads the buffer during the call.
	if errno == 0 {
		unix.Close(int(fd)) //nolint:gosec // G104: the map was only a probe, and creating it is the result.
		return []Result{fail(name, "bpf(BPF_MAP_CREATE) worked")}
	}
	return []Result{pass(name, "bpf(BPF_MAP_CREATE) refused: %v", errno)}
}

// checkNested tries what KernelNested must still refuse. It runs only when
// the spec says nested.
func checkNested(e *checkEnv) []Result {
	names := []string{"nested.umount-cover", "nested.remount-rw", "nested.mount-outside"}
	if e.spec == nil || e.spec.Kernel != KernelNested {
		res := make([]Result, 0, len(names))
		for _, n := range names {
			res = append(res, skipped(n, "the spec is not KernelNested"))
		}
		return res
	}
	flags := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS)
	attempt := func(name, mode string, paths []string, what string) Result {
		if len(paths) == 0 {
			return skipped(name, "the spec has no %s", what)
		}
		var worked []string
		for _, p := range paths {
			if started, d := spawnNS(flags, mode, p); started && d == "" {
				worked = append(worked, p)
			}
		}
		return verdict(name, mode+" of "+what+" in a new user and mount namespace", worked)
	}
	covers := checkedCovers(e.spec)
	return []Result{
		attempt(names[0], modeUmount, covers, "cover"),
		attempt(names[1], modeRemount, e.spec.Read, "read-only Read path"),
		// There is no path outside the view to name from inside it, so
		// nothing can be tried.
		skipped(names[2], "nothing outside the view can be named from inside it"),
	}
}

// platformScratch are the paths inside the covers that the sandbox mounts a
// tmpfs of its own on, which are its scratch directories. They list what the
// command made there, and nothing of the host's.
func platformScratch() []string { return scratchDirs }

// platformSockets are the sockets of this platform that socketCandidates does
// not list: none on Linux, whose list is the generic one.
func platformSockets() []string { return nil }

// platformHints is empty on Linux, where the child finds its own targets in the
// view it is given.
func platformHints(*Spec) checkHints { return checkHints{} }

// foreignPIDs returns the pids in /proc that are neither this process nor
// its descendants, the parent first.
func foreignPIDs() ([]int, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	ppid := map[int]int{}
	for _, d := range ents {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		if b, err := os.ReadFile("/proc/" + d.Name() + "/stat"); err == nil {
			if pp, ok := parseStatPPID(string(b)); ok {
				ppid[pid] = pp
			}
		} else {
			ppid[pid] = -1
		}
	}
	self := os.Getpid()
	inTree := func(pid int) bool {
		for range 4096 {
			if pid == self {
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
	var out []int
	for pid := range ppid {
		if !inTree(pid) {
			out = append(out, pid)
		}
	}
	slices.Sort(out)
	if pp := os.Getppid(); slices.Contains(out, pp) {
		out = append([]int{pp}, slices.DeleteFunc(out, func(p int) bool { return p == pp })...)
	}
	return out, nil
}

// parseStatPPID returns the parent pid from a /proc/<pid>/stat line. The
// command name may hold spaces and parentheses, so it reads after the last ")".
func parseStatPPID(s string) (int, bool) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 {
		return 0, false
	}
	pp, err := strconv.Atoi(f[1])
	return pp, err == nil
}

// probeLimit bounds how many outside processes each attempt tries.
const probeLimit = 16

// outsidePIDs returns the pids that count as outside the check's tree. In a
// sandbox Check built, the check child's parent is pid 1, the sandbox's own
// stage, which started it. It is part of the sandbox, so it isn't outside,
// and signal 0 to it works by design. In its own pid namespace nothing else
// can hold pid 1. A sandbox without a pid namespace of its own gives the
// child a parent with another pid, and then pid 1 counts.
func outsidePIDs(pids []int, inSandbox bool, ppid int) []int {
	if !inSandbox || ppid != 1 {
		return pids
	}
	return slices.DeleteFunc(slices.Clone(pids), func(p int) bool { return p == 1 })
}

func checkProcesses(e *checkEnv) []Result {
	pids, err := foreignPIDs()
	if err != nil {
		return []Result{
			skipped("proc.visible", "%v", err), skipped("proc.signal", "%v", err),
			skipped("proc.trace", "%v", err), skipped("proc.environ", "%v", err),
		}
	}
	outside := outsidePIDs(pids, e.spec != nil, os.Getppid())
	var res []Result
	if len(outside) == 0 {
		res = append(res, pass("proc.visible", "no process outside this tree is listed in /proc"))
	} else {
		res = append(res, fail("proc.visible", "%d processes outside this tree are listed in /proc, such as pid %d", len(outside), outside[0]))
	}
	// pid 1 is still tried for tracing and its environment, since it holds
	// the sandbox's setup and must stay undumpable.
	attempts := []struct {
		name string
		pids []int
		fn   func(pid int) bool
	}{
		{"proc.signal", outside, func(pid int) bool { return syscall.Kill(pid, 0) == nil }},
		{"proc.trace", pids, func(pid int) bool {
			f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/mem")
			if err == nil {
				f.Close() //nolint:gosec // G104: the open worked, which is the result.
			}
			return err == nil
		}},
		{"proc.environ", pids, func(pid int) bool {
			f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/environ")
			if err != nil {
				return false
			}
			defer f.Close()
			_, err = f.Read(make([]byte, 1))
			return err == nil || errors.Is(err, io.EOF)
		}},
	}
	for _, a := range attempts {
		if len(a.pids) == 0 {
			res = append(res, pass(a.name, "no other process to try"))
			continue
		}
		try := a.pids[:min(len(a.pids), probeLimit)]
		var worked []string
		for _, pid := range try {
			if a.fn(pid) {
				worked = append(worked, strconv.Itoa(pid))
			}
		}
		res = append(res, verdict(a.name, fmt.Sprintf("%d other processes tried", len(try)), worked))
	}
	return res
}

// mountPoint returns the longest mount point in mounts that holds path.
func mountPoint(mounts []mount, path string) (mount, bool) {
	var best mount
	found := false
	for _, m := range mounts {
		if under(path, m.point) && (!found || len(m.point) > len(best.point)) {
			best, found = m, true
		}
	}
	return best, found
}

// snapshotCandidates returns the paths where path might show through a
// snapshot directory of the filesystem it is on, given its mount point and a
// way to list a directory: ZFS's .zfs/snapshot/<snap>/ and snapper's
// .snapshots/<n>/snapshot/.
func snapshotCandidates(point, path string, list func(string) []string) []string {
	rel, err := filepath.Rel(point, path)
	if err != nil {
		return nil
	}
	var out []string
	zfs := filepath.Join(point, ".zfs", "snapshot")
	for _, s := range list(zfs) {
		out = append(out, filepath.Join(zfs, s, rel))
	}
	snapper := filepath.Join(point, ".snapshots")
	for _, s := range list(snapper) {
		out = append(out, filepath.Join(snapper, s, "snapshot", rel))
	}
	return out
}

func listDir(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents[:min(len(ents), 64)] {
		out = append(out, e.Name())
	}
	return out
}

func checkSnapshots(paths []string) []Result {
	const name = "snapshots"
	if len(paths) == 0 {
		return []Result{skipped(name, "no Unreadable paths given")}
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return []Result{skipped(name, "%v", err)}
	}
	defer f.Close()
	mounts, err := parseMountinfo(f)
	if err != nil {
		return []Result{skipped(name, "%v", err)}
	}
	var worked []string
	for _, p := range paths {
		m, ok := mountPoint(mounts, p)
		if !ok {
			continue
		}
		for _, c := range snapshotCandidates(m.point, p, listDir) {
			if _, err := os.Lstat(c); err == nil {
				worked = append(worked, c)
				break
			}
		}
	}
	return []Result{verdict(name, fmt.Sprintf("%d Unreadable paths through .zfs/snapshot and .snapshots", len(paths)), worked)}
}

// checkAbstract connects to the abstract sockets listed in this network
// namespace, which are the host's unless the sandbox has its own.
func checkAbstract(*checkEnv) []Result {
	const name = "sockets.abstract"
	b, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return []Result{skipped(name, "%v", err)}
	}
	var names []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 8 && strings.HasPrefix(f[7], "@") {
			names = append(names, f[7])
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	names = names[:min(len(names), probeLimit)]
	var worked []string
	for _, n := range names {
		if out, _ := tryDial("unix", n, netTimeout/2); out == connected {
			worked = append(worked, n)
		}
	}
	return []Result{verdict(name, fmt.Sprintf("connect to %d abstract sockets", len(names)), worked)}
}

// cgroupRoot is where the v2 hierarchy is mounted.
const cgroupRoot = "/sys/fs/cgroup"

// cgroupDir returns this process's cgroup directory under the v2 mount.
func cgroupDir() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return cgroupRoot + filepath.Clean("/"+p), nil
		}
	}
	return "", errors.New("no cgroup v2")
}

// cgroupLimit finds the first finite value of file in dir or an ancestor.
func cgroupLimit(dir, file string) (string, bool) {
	for d := dir; under(d, cgroupRoot); d = filepath.Dir(d) {
		if b, err := os.ReadFile(filepath.Join(d, file)); err == nil { //nolint:gosec // G304: the check reads the limit files of its own cgroup.
			if v := strings.TrimSpace(string(b)); v != "max" {
				return v + " in " + d, true
			}
		}
		if d == cgroupRoot {
			break
		}
	}
	return "", false
}

func checkLimits(*checkEnv) []Result {
	dir, cgErr := cgroupDir()
	one := func(name, file string, rlimit int) Result {
		if cgErr == nil {
			if v, ok := cgroupLimit(dir, file); ok {
				return pass(name, "%s is %s", file, v)
			}
		}
		var rl unix.Rlimit
		if unix.Getrlimit(rlimit, &rl) == nil && rl.Cur != unix.RLIM_INFINITY {
			return pass(name, "no cgroup limit, but the rlimit is %d", rl.Cur)
		}
		return fail(name, "no finite %s on this cgroup or its parents, and no rlimit", file)
	}
	return []Result{
		one("limits.memory", "memory.max", unix.RLIMIT_AS),
		one("limits.tasks", "pids.max", unix.RLIMIT_NPROC),
	}
}

// checkDelegate makes a child of the process's own cgroup, as a unit with
// Delegate=yes allows, and removes it again.
//
// It asks whether the caller can make a cgroup to pass as Cmd.CgroupFD, which
// only the caller's own context answers. Inside a sandbox the cgroup tree is
// read-only, so there it is Skipped.
func checkDelegate(e *checkEnv) []Result {
	const name = "cgroup.delegate"
	if e.spec != nil {
		return []Result{skipped(name, "the check runs inside the sandbox Check started, whose cgroup tree is read-only. Check with no Spec tries it in the caller's own context")}
	}
	dir, err := cgroupDir()
	if err != nil {
		return []Result{fail(name, "%v", err)}
	}
	child := filepath.Join(dir, "sbx-check-"+strconv.Itoa(os.Getpid())+"-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	if err := os.Mkdir(child, 0o750); err != nil {
		return []Result{fail(name, "mkdir in %s: %v", dir, err)}
	}
	res := delegateOffers(name, dir, child)
	if err := os.Remove(child); err != nil {
		return []Result{fail(name, "remove %s: %v", child, err)}
	}
	return []Result{res}
}

// delegateOffers checks that the child cgroup the check made offers the
// memory and pids controllers.
func delegateOffers(name, dir, child string) Result {
	b, err := os.ReadFile(filepath.Join(child, "cgroup.controllers")) //nolint:gosec // G304: a file in the cgroup the check just made.
	if err != nil {
		return fail(name, "%v", err)
	}
	have := strings.Fields(string(b))
	if !slices.Contains(have, "memory") || !slices.Contains(have, "pids") {
		return fail(name, "a child cgroup of %s offers only %v, not memory and pids", dir, have)
	}
	return pass(name, "made a child cgroup of %s with memory and pids", dir)
}

// defaultGateway returns the default route's gateway from /proc/net/route.
func defaultGateway() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return parseGateway(f)
}

// parseGateway finds the IPv4 default route's gateway in /proc/net/route's
// format, where the address is a little-endian hex word.
func parseGateway(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		gw, err2 := strconv.ParseUint(f[2], 16, 32)
		if err != nil || err2 != nil || flags&unix.RTF_GATEWAY == 0 {
			continue
		}
		var octets [4]byte
		binary.LittleEndian.PutUint32(octets[:], uint32(gw))
		return netip.AddrFrom4(octets).String(), nil
	}
	return "", errors.New("no default route")
}

// overflowGID returns the gid that getgroups shows for a group not mapped
// into the caller's user namespace. It is 65534 unless the host changed
// kernel.overflowgid, and 65534 is also what it returns when the sysctl
// can't be read, as DEFAULT_OVERFLOWGID in Linux include/linux/highuid.h.
func overflowGID() int {
	b, err := os.ReadFile("/proc/sys/kernel/overflowgid")
	if err != nil {
		return 65534
	}
	g, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 65534
	}
	return g
}
