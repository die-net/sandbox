package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteApparmorProfile writes this test binary's AppArmor profile into
// the directory named by SBX_APPARMOR_OUT, under the name to load it by.
// scripts/apparmor.sh uses it, so the profile the suite runs under is the
// one the library prints on this host.
func TestWriteApparmorProfile(t *testing.T) {
	t.Parallel()
	dir := os.Getenv("SBX_APPARMOR_OUT")
	if dir == "" {
		t.Skip("SBX_APPARMOR_OUT is not set")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	f := probeFacts{Self: exe}
	if f.Bwrap, err = exec.LookPath("bwrap"); err != nil {
		t.Fatal(err)
	}
	gatherAppArmor(&f)
	if f.BwrapLabel == "" {
		t.Fatal("could not read the AppArmor label bubblewrap gets, which chooses the profile")
	}
	p, name, err := apparmorProfile(exe, apparmorEnforce(f))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("this process is %q and bubblewrap gets %q, so the profile is:\n%s", f.AppArmor, f.BwrapLabel, p)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(p), 0o600); err != nil { //nolint:gosec // G703: the test touches only paths it made, or was passed, to see whether a sandbox allows it.
		t.Fatal(err)
	}
}

// TestProbeTrialStartsTheFirstStage puts a bubblewrap on PATH that drops
// every capability from what it starts, as Ubuntu's bwrap-userns-restrict
// does through its unpriv_bwrap profile. A trial that runs only true in
// bubblewrap passes there, while every real sandbox's first stage fails. The
// trial must start the stage, and so fail. Which finding follows depends on
// the host, so the test asks only that the trial failed.
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
	rep, err := Probe()
	if err == nil {
		t.Fatalf("Probe passed with a bubblewrap that leaves the first stage no capabilities: %+v", rep.Checks)
	}
	last := rep.Checks[len(rep.Checks)-1]
	if last.Status != Fail || last.Name == "probe.bubblewrap" || last.Name == "probe.seccomp" {
		t.Errorf("want a failed trial, got %+v", last)
	}
	t.Logf("%s: %s", last.Name, last.Detail)
}

// TestBwrapLabel reads the AppArmor label bubblewrap gets, where AppArmor is
// on. Probe chooses the profile it prints by it.
func TestBwrapLabel(t *testing.T) {
	t.Parallel()
	if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err != nil || strings.TrimSpace(string(b)) != "Y" {
		t.Skip("AppArmor is not on")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal(err)
	}
	f := probeFacts{Bwrap: bwrap}
	gatherAppArmor(&f)
	if f.BwrapLabel == "" {
		t.Fatal("no label read")
	}
	t.Logf("this process is %q, and bubblewrap gets %q", f.AppArmor, f.BwrapLabel)
	// Under the profile scripts/apparmor.sh loads, which is the one Probe
	// prints for this host, bubblewrap must keep this process's label: that
	// is what lets the first stage keep its capabilities.
	if exe, err := os.Executable(); err == nil {
		f.Self, _ = filepath.EvalSymlinks(exe)
		if apparmorOwn(f) && f.BwrapLabel != f.AppArmor {
			t.Errorf("under its own profile %q, this binary runs bubblewrap as %q", f.AppArmor, f.BwrapLabel)
		}
	}
}
