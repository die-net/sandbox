//go:build !linux

package sandbox

// platformChecks are the checks that need Linux, which are skipped here, and
// the limits, which nothing here can enforce.
func platformChecks(*checkEnv) []Result {
	var res []Result
	for _, n := range []string{
		"proc.no_new_privs", "proc.seccomp", "caps.effective", "caps.permitted", "caps.bounding",
		"userns.create", "mount.tmpfs", "io_uring.setup", "netfilter.setsockopt", "bpf.load",
		"nested.umount-cover", "nested.remount-rw", "nested.mount-outside",
		"sockets.abstract", "cgroup.delegate",
	} {
		res = append(res, skipped(n, "Linux only"))
	}
	for _, n := range []string{"limits.memory", "limits.tasks"} {
		res = append(res, Result{Name: n, Status: NotEnforceable, Detail: "nothing on this platform can enforce it"})
	}
	return res
}

func checkProcesses(*checkEnv) []Result {
	var res []Result
	for _, n := range []string{"proc.visible", "proc.signal", "proc.trace", "proc.environ"} {
		res = append(res, skipped(n, "not implemented on this platform yet"))
	}
	return res
}

func checkSnapshots([]string) []Result {
	return []Result{skipped("snapshots", "Linux only")}
}

// initialUserNS is true: there are no user namespaces to be in.
func initialUserNS() bool { return true }

// grandchild has no modes here.
func grandchild([]string) (int, bool) { return 0, false }
