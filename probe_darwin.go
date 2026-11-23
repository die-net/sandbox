package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Probe tries the macOS backend for real: it applies a trial profile with
// /usr/bin/sandbox-exec. An error means no sandbox can start, and
// Report.Checks says why. The Report is filled in either way, and its
// Checks list what this backend cannot do as NotEnforceable.
func Probe() (Report, error) {
	rep := Report{
		Backend: "seatbelt",
		// One profile for every level, which is at least as strict as each
		// request. Seatbelt filters operations, not system calls, so there is
		// no looser level to give.
		Kernel: map[Kernel]Kernel{KernelStrict: KernelStrict, KernelNested: KernelStrict, KernelOpen: KernelStrict},
		// Teardown ends every process it finds under the profile, by asking the
		// kernel (member_darwin.go), so one that left the command's process
		// group or lost its parent is ended too. A process that forks faster
		// than the scan can keep ahead of it, and then Wait says it could not
		// confirm the sandbox empty (probe.gap.tree-kill).
		TreeKill: true,
		// Listen and Loopback ports are numbers on every address of a host that
		// has other processes, not a loopback of the sandbox's own.
		PrivateLoopback: false,
		Unsupported:     []string{"Rlimits: ResourceAddressSpace"},
		Ignored:         []string{"Hostname", "ScratchSize"},
		Container:       gatherDarwinContext(),
	}
	rep.Checks = diagnoseDarwin(tryProfile(sandboxExec))
	for _, c := range rep.Checks {
		if c.Status == Fail {
			return rep, fmt.Errorf("the sandbox cannot start: %s: %s", c.Name, firstLine(c.Detail))
		}
	}
	rep.Checks = append(rep.Checks, darwinGaps()...)
	return rep, nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// gatherDarwinContext names the context the process runs in, best effort: the
// App Sandbox, or a launchd job such as a LaunchDaemon, which is what an
// operator's service is on macOS. A Terminal session is neither.
func gatherDarwinContext() string {
	if os.Getenv("APP_SANDBOX_CONTAINER_ID") != "" {
		return "app-sandbox"
	}
	if n := os.Getenv("XPC_SERVICE_NAME"); n != "" && n != "0" && !strings.HasPrefix(n, "application.") {
		return "launchd-job"
	}
	return ""
}

// tryProfile applies a trivial profile to /usr/bin/true, and returns
// sandbox-exec's complaint, or "" if it ran. A process that is already inside
// a profile cannot apply another, which Seatbelt reports as
// sandbox_apply: Operation not permitted.
func tryProfile(exe string) string {
	if fi, err := os.Stat(exe); err != nil {
		return "missing: " + err.Error()
	} else if fi.Mode()&0o111 == 0 {
		return "missing: " + exe + " is not executable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, exe, "-p", "(version 1)(allow default)", "/usr/bin/true")
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return msg
	}
	return ""
}

// diagnoseDarwin turns the trial's outcome into findings.
func diagnoseDarwin(tryErr string) []Result {
	switch {
	case strings.HasPrefix(tryErr, "missing:"):
		return []Result{fail("probe.sandbox-exec", "%s, which ships with macOS and which the sandbox runs by that path. Restore it, or run the program on a macOS that has it", strings.TrimPrefix(tryErr, "missing: "))}
	case tryErr != "":
		return []Result{
			pass("probe.sandbox-exec", "%s", sandboxExec),
			fail("probe.seatbelt", "%s refused a trivial profile: %s. A process already inside a Seatbelt profile cannot apply another. Run outside that profile: another tool's sandbox, an App Sandbox, or a sandboxed terminal", sandboxExec, tryErr),
		}
	}
	return []Result{
		pass("probe.sandbox-exec", "%s", sandboxExec),
		pass("probe.seatbelt", "sandbox-exec applied a trial profile and ran a command"),
	}
}

// darwinGaps are what this backend cannot give, which a caller logs once.
func darwinGaps() []Result {
	gap := func(name, detail string) Result {
		return Result{Name: name, Status: NotEnforceable, Detail: detail}
	}
	return []Result{
		gap("probe.gap.pid-namespace", "there is no pid namespace: processes of the same uid are visible, and a profile cannot stop KERN_PROCARGS2 from returning their arguments and environment (it denies signals and process-info to them)"),
		gap("probe.gap.caller-environment", "the caller's own environment is one of those: a command reads it with KERN_PROCARGS2 whatever Env says, so a caller must not hold a secret in its environment on macOS, and the same goes for its arguments and every other process of the account"),
		gap("probe.gap.tree-kill", "teardown lists the account's processes in one atomic list and signals each that runs under the sandbox's profile, until a scan finds none of them and nothing it cannot account for, which proves nothing under the profile can start again. A process that forks again within about a millisecond, or enough of them, can keep ahead of the scan until it chooses to stop, and Wait then returns an error saying it could not confirm the sandbox empty. Such a process keeps the profile's access: the home, the Write paths, and the network the Spec gave"),
		gap("probe.gap.loopback-ports", "Spec.Loopback and Spec.Listen ports are TCP port numbers on every address the host has, since a profile names only * or localhost: a command may bind a Loopback port on the LAN address or the wildcard, and any host that can reach any address of this Mac (the LAN, a VPN, a routable IPv6 address) that connects there reaches it, with NetworkNone. Other local processes reach those ports too. There is no private loopback. Only this Mac dialing its own LAN address was tried, and no second machine. A listener the caller binds on 127.0.0.1 and passes in Spec.Files does not have this gap"),
		gap("probe.gap.broad-loopback", "Spec.BroadLoopback lets the command bind, accept and dial on any port of every address the host has, TCP and UDP, because no per-port deny after a broad allow is reliable. Without it the sandbox reaches only the ports Listen and Loopback name"),
		gap("probe.gap.async-signals", "fcntl(F_SETOWN) with O_ASYNC makes the kernel send SIGIO and SIGURG to a process outside, which Seatbelt cannot filter. They are ignored by default, so only a program that handles them is affected"),
		gap("probe.gap.same-user-files", "the sandbox reads with the caller's uid and groups, so a file of that account outside the default covers is readable whatever its mode, such as /opt/homebrew/var. Name such a path in Spec.Cover"),
		gap("probe.gap.syscalls", "Seatbelt filters operations, not system calls, so there is no system call allowlist, and every Kernel level gets the one profile"),
		gap("probe.gap.limits", "memory and process counts have no limit here: RLIMIT_AS is not enforced and RLIMIT_NPROC counts every process of the uid. Poll Cmd.Footprint instead"),
		gap("probe.gap.scratch", "TMPDIR is a directory in Home, with no size cap beyond RLIMIT_FSIZE per file"),
	}
}
