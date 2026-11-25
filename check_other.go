//go:build !linux

package sandbox

import (
	"os"
	"path/filepath"
)

// platformChecks are the checks that need Linux, which are skipped here, and
// the limits, which nothing here can enforce.
func platformChecks(*checkEnv) []Result {
	linuxOnly := []string{
		"proc.no_new_privs", "proc.seccomp", "caps.effective", "caps.permitted", "caps.bounding",
		"userns.create", "mount.tmpfs", "io_uring.setup", "netfilter.setsockopt", "bpf.load",
		"nested.umount-cover", "nested.remount-rw", "nested.mount-outside",
		"sockets.abstract", "cgroup.delegate",
	}
	limits := []string{"limits.memory", "limits.tasks"}
	res := make([]Result, 0, len(linuxOnly)+len(limits))
	for _, n := range linuxOnly {
		res = append(res, skipped(n, "Linux only"))
	}
	for _, n := range limits {
		res = append(res, Result{Name: n, Status: NotEnforceable, Detail: "nothing on this platform can enforce it"})
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

// platformSockets are the sockets of the container runtimes that run on macOS
// in a VM, and which a program that reaches can start anything as the user:
// Docker Desktop's, and Colima's, OrbStack's, and Podman's.
func platformSockets() []string {
	socks := []string{"/var/run/docker.sock", "/private/var/run/docker.sock"}
	if home, err := os.UserHomeDir(); err == nil {
		for _, p := range []string{".docker/run/docker.sock", ".colima/default/docker.sock", ".orbstack/run/docker.sock", ".local/share/containers/podman/machine/podman.sock"} {
			socks = append(socks, filepath.Join(home, p))
		}
	}
	return socks
}

// platformScratch is empty here, where the view's only exceptions are the paths
// of the Spec.
func platformScratch() []string { return nil }

// overflowGID returns -1: without user namespaces, no gid stands for groups
// that aren't mapped.
func overflowGID() int { return -1 }
