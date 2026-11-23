package sandbox

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func init() {
	childModes["probe"] = func([]string) int {
		rep, err := Probe()
		if err == nil {
			os.Stdout.WriteString("probe worked\n")
			return 0
		}
		os.Stdout.WriteString(err.Error() + "\n")
		for _, c := range rep.Checks {
			os.Stdout.WriteString(c.Name + ": " + c.Detail + "\n")
		}
		return 1
	}
}

func TestProbeDarwin(t *testing.T) {
	rep, err := Probe()
	if err != nil {
		t.Fatalf("Probe: %v\n%+v", err, rep.Checks)
	}
	if rep.Backend != "seatbelt" {
		t.Errorf("Backend = %q", rep.Backend)
	}
	// Teardown ends every process under the profile: TestEscapeSetpgidAndJobControl
	// and TestEscapeSetsidDiesWithTeardown try the ways out of the process group.
	if !rep.TreeKill {
		t.Error("TreeKill is false, but teardown ends every process under the profile")
	}
	// The ports are numbers on every address of a host with other processes:
	// TestGapLoopbackBindsLANAddress shows it.
	if rep.PrivateLoopback {
		t.Error("PrivateLoopback is true, but Loopback ports are reachable from outside and bind on the LAN address")
	}
	for _, k := range []Kernel{KernelStrict, KernelNested, KernelOpen} {
		if rep.Kernel[k] != KernelStrict {
			t.Errorf("Kernel[%s] = %q, want strict, the one profile there is", k, rep.Kernel[k])
		}
	}
	byName := map[string]Result{}
	for _, c := range rep.Checks {
		byName[c.Name] = c
	}
	for _, name := range []string{"probe.sandbox-exec", "probe.seatbelt"} {
		if byName[name].Status != Pass {
			t.Errorf("%s = %+v", name, byName[name])
		}
	}
	// What cannot be given is reported, as NotEnforceable and with a reason.
	for _, name := range []string{"probe.gap.pid-namespace", "probe.gap.tree-kill", "probe.gap.caller-environment", "probe.gap.loopback-ports", "probe.gap.broad-loopback", "probe.gap.async-signals", "probe.gap.same-user-files", "probe.gap.syscalls", "probe.gap.limits", "probe.gap.scratch"} {
		if r := byName[name]; r.Status != NotEnforceable || len(r.Detail) < 20 {
			t.Errorf("%s = %+v", name, r)
		}
	}
	// The setsid gap is gone. What is left is a process that forks faster than
	// the scan, and the row says that, and says Wait reports it.
	if r := byName["probe.gap.tree-kill"]; r.Status != NotEnforceable || !strings.Contains(r.Detail, "forks again") || !strings.Contains(r.Detail, "Wait") {
		t.Errorf("probe.gap.tree-kill = %+v", r)
	}
	for _, r := range rep.Checks {
		if strings.Contains(r.Detail, "setsid") {
			t.Errorf("%s still describes the setsid gap: %s", r.Name, r.Detail)
		}
	}
	// The Loopback row says who can reach the port, and that no second machine
	// was tried.
	if r := byName["probe.gap.loopback-ports"]; !strings.Contains(r.Detail, "VPN") || !strings.Contains(r.Detail, "no second machine") || !strings.Contains(r.Detail, "Spec.Files") {
		t.Errorf("probe.gap.loopback-ports = %+v", r)
	}
	for _, r := range rep.Checks {
		if r.Status == Fail {
			t.Errorf("a failed check in a report with no error: %+v", r)
		}
	}
}

// TestProbeInsideProfile checks the diagnosis a process gets when it is already
// inside a Seatbelt profile, as under another tool's sandbox: Probe fails, and
// the failed check says to run outside it. (A profile that is allow-default
// does not stop a second one from being applied, so this one is deny-default.)
func TestProbeInsideProfile(t *testing.T) {
	out, err := exec.Command(sandboxExec, "-p", `(version 1)(deny default)(allow process-exec* (subpath "/"))(allow file-read* (subpath "/"))(allow process-fork)(allow sysctl-read)(allow file-write* (literal "/dev/null"))`, self(t), "probe").CombinedOutput()
	if err == nil {
		t.Fatalf("Probe worked inside another profile:\n%s", out)
	}
	s := string(out)
	for _, want := range []string{"probe.seatbelt", "already inside a Seatbelt profile", "Run outside"} {
		if !strings.Contains(s, want) {
			t.Errorf("the diagnosis lacks %q:\n%s", want, s)
		}
	}
}

func TestDiagnoseDarwin(t *testing.T) {
	res := diagnoseDarwin("missing: stat /usr/bin/sandbox-exec: no such file or directory")
	if len(res) != 1 || res[0].Status != Fail || !strings.Contains(res[0].Detail, "ships with macOS") {
		t.Errorf("missing: %+v", res)
	}
	res = diagnoseDarwin("sandbox_apply: Operation not permitted")
	if len(res) != 2 || res[1].Name != "probe.seatbelt" || res[1].Status != Fail || !strings.Contains(res[1].Detail, "Operation not permitted") {
		t.Errorf("nested: %+v", res)
	}
	res = diagnoseDarwin("")
	if len(res) != 2 || res[0].Status != Pass || res[1].Status != Pass {
		t.Errorf("fine: %+v", res)
	}
}

func TestDarwinContext(t *testing.T) {
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{nil, ""},
		{map[string]string{"XPC_SERVICE_NAME": "0"}, ""},
		{map[string]string{"XPC_SERVICE_NAME": "application.com.example.App.123"}, ""},
		{map[string]string{"XPC_SERVICE_NAME": "com.example.render"}, "launchd-job"},
		{map[string]string{"APP_SANDBOX_CONTAINER_ID": "com.example.app"}, "app-sandbox"},
	} {
		for _, k := range []string{"XPC_SERVICE_NAME", "APP_SANDBOX_CONTAINER_ID"} {
			t.Setenv(k, tc.env[k])
		}
		if got := gatherDarwinContext(); got != tc.want {
			t.Errorf("%v: context = %q, want %q", tc.env, got, tc.want)
		}
	}
}
