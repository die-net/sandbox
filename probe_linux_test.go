package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestProbeTrialStartsTheFirstStage puts a bubblewrap on PATH that drops
// every capability from what it starts, as Ubuntu 26.04's bwrap profile does
// through unpriv_bwrap. A trial that runs only true in bubblewrap passes
// there, while every real sandbox's first stage fails. The trial must run the
// first stage, and fail with the stage's own error, not as a trial that was
// never built.
func TestProbeTrialStartsTheFirstStage(t *testing.T) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal(err)
	}
	// --cap-drop ALL goes right before the first "--", after the options
	// that --args reads, so it undoes their --cap-add.
	script := `#!/bin/sh
n=$#; i=0; dropped=
while [ $i -lt $n ]; do
	a=$1; shift; i=$((i+1))
	if [ -z "$dropped" ] && [ "$a" = -- ]; then set -- "$@" --cap-drop ALL; dropped=1; fi
	set -- "$@" "$a"
done
exec ` + bwrap + ` "$@"
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bwrap"), []byte(script), 0o700); err != nil { //nolint:gosec // G306: the file is a program the test runs, which needs its owner to execute it.
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	failed, built := trySandbox(map[Kernel]Kernel{KernelStrict: KernelStrict})
	if built != "" {
		t.Fatalf("the trial was not built: %s", built)
	}
	if want := "copy the view into a mount namespace of its own: operation not permitted"; !strings.Contains(failed, want) {
		t.Errorf("the trial failed with %q, want the first stage's %q", failed, want)
	}
}

// TestProbeTrialNotBuilt checks that a trial that can't be made is
// probe.trial and not blamed on the host's sandboxing: here for want of a
// temporary directory, and from Start, before bubblewrap runs, for a home
// that isn't there.
func TestProbeTrialNotBuilt(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if failed, built := runTrial(Spec{Command: []string{SelfPath, checkArg, modeNoop}, Home: missing}); failed != "" || !strings.Contains(built, "does not exist") {
		t.Errorf("a home that isn't there: failed %q, built %q, want only built", failed, built)
	}
	t.Setenv("TMPDIR", missing)
	rep, err := Probe()
	if err == nil {
		t.Fatalf("Probe passed with no temporary directory: %+v", rep.Checks)
	}
	last := rep.Checks[len(rep.Checks)-1]
	if last.Name != "probe.trial" || last.Status != Fail || !strings.Contains(last.Detail, "make its home") {
		t.Errorf("last check = %+v, want a failed probe.trial", last)
	}
}

// TestBwrapLabel reads the AppArmor label bubblewrap gets, where AppArmor is
// on, which Probe's diagnosis compares with this process's. Under this
// binary's own profile, which scripts/apparmor.sh loads, bubblewrap must keep
// it: that is what lets the first stage keep its capabilities on Ubuntu
// 26.04.
func TestBwrapLabel(t *testing.T) {
	t.Parallel()
	if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err != nil || strings.TrimSpace(string(b)) != "Y" {
		t.Skip("AppArmor is not on")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal(err)
	}
	f := probeFacts{AppArmor: readLabel(os.Getpid()), BwrapLabel: bwrapLabel(bwrap)}
	if f.AppArmor == "" || f.BwrapLabel == "" {
		t.Fatalf("labels not read: this process %q, bubblewrap %q", f.AppArmor, f.BwrapLabel)
	}
	t.Logf("this process is %q, and bubblewrap gets %q", f.AppArmor, f.BwrapLabel)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if f.Self, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	if apparmorOwn(f) && f.BwrapLabel != f.AppArmor {
		t.Errorf("under its own profile %q, this binary runs bubblewrap as %q", f.AppArmor, f.BwrapLabel)
	}
}
