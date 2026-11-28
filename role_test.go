//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// oldMarkers are the first arguments by which the stages and the check child
// were once found. A program may take any of them as its own now.
var oldMarkers = []string{"--sandbox-stage", "--sandbox-reaper", "--sandbox-check"}

// roleTouchMode is a child mode that makes the file its argument names: a run
// of the test binary that reaches its main makes it.
const roleTouchMode = "role-touch"

// roleEnvMode is a child mode that prints its environment, as env does, once
// the test binary has reached its main.
const roleEnvMode = "role-env"

// The child modes of the tests below, which a package-level initializer adds
// so that both platforms' TestMain dispatch them. An old marker as the first
// argument is a mode of the test binary's own, which prints its arguments.
var _ = func() bool {
	childModes[roleTouchMode] = func(args []string) int {
		if err := os.WriteFile(args[0], nil, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	childModes[roleEnvMode] = func([]string) int {
		for _, kv := range os.Environ() {
			fmt.Println(kv)
		}
		return 0
	}
	for _, m := range oldMarkers {
		childModes[m] = func(args []string) int {
			fmt.Println(strings.Join(append([]string{m}, args...), "\x00"))
			return 0
		}
	}
	return true
}()

// testBinary returns the path of this test binary.
func testBinary(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// Row: "Stages found by their environment": the command's environment never
// holds roleVar, neither the stages' own, which their init unsets, nor any
// copy the caller's Env holds, which Start replaces. The command can be this
// binary, as a command that starts a sandbox of its own
// is: it runs its own main, which a role it inherited would have taken over.
func TestEscapeRoleNeverReachesTheCommand(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		command []string
	}{
		{"env", []string{"/usr/bin/env"}},
		{"this binary", []string{SelfPath, roleEnvMode}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			c, err := Command(t.Context(), Spec{Command: tc.command, Home: home})
			if err != nil {
				t.Fatal(err)
			}
			c.Env = []string{"PATH=/usr/bin:/bin", roleVar + "=" + roleCheck, roleVar + "=" + roleStage, "KEPT=1"}
			var stdout, stderr bytes.Buffer
			c.Stdout, c.Stderr = &stdout, &stderr
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			if err := c.Wait(); err != nil {
				t.Fatalf("Wait: %v: %s", err, stderr.String())
			}
			if !strings.Contains(stdout.String(), "KEPT=1\n") {
				t.Fatalf("the command's environment lacks the caller's own variable, so the test proved nothing:\n%s", stdout.String())
			}
			if strings.Contains(stdout.String(), roleVar) {
				t.Errorf("the command's environment holds %s:\n%s", roleVar, stdout.String())
			}
		})
	}
}

// Row: "Stages found by their environment": a run of this binary with roleVar
// set by hand, and none of the descriptors a stage or the check child is
// given, fails with an error and runs nothing, neither its part nor the
// program's main, which would make the file. A role no platform has fails too.
func TestRoleSetByHandRunsNothing(t *testing.T) {
	t.Parallel()
	for _, role := range []string{roleStage, roleReaper, roleCheck, roleCheckNS, "no-such-role", ""} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "ran")
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, testBinary(t), roleTouchMode, path) //nolint:gosec // G204: the test binary, run as the test's own child.
			cmd.Env = append(os.Environ(), roleVar+"="+role)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != failed {
				t.Errorf("%s=%q: %v, want exit %d: %s", roleVar, role, err, failed, stderr.String())
			}
			if !strings.Contains(stderr.String(), "sandbox") {
				t.Errorf("%s=%q: no message: %q", roleVar, role, stderr.String())
			}
			if _, err := os.Stat(path); err == nil {
				t.Errorf("%s=%q: the program's main ran", roleVar, role)
			}
		})
	}
}

// Row: "Stages found by their environment": the package reads no argument, so
// a program whose first argument is a marker that once named a stage runs as
// itself, with its arguments as it was given them, and nothing else runs.
func TestOldStageArgumentsAreTheProgramsOwn(t *testing.T) {
	t.Parallel()
	for _, m := range oldMarkers {
		t.Run(m, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "ran")
			args := []string{m, "--", "/usr/bin/touch", path}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, testBinary(t), args...).CombinedOutput() //nolint:gosec // G204: the test binary, run as the test's own child.
			if err != nil {
				t.Fatalf("%q: %v: %s", args, err, out)
			}
			if want := strings.Join(args, "\x00") + "\n"; string(out) != want {
				t.Errorf("%q printed %q, want %q", args, out, want)
			}
			if _, err := os.Stat(path); err == nil {
				t.Errorf("%q ran the command after the marker", args)
			}
		})
	}
}

// The command's argv goes to the stage in its settings, which carry one far
// longer than one message of Linux's control socket holds, or its buffer.
func TestLongCommandLine(t *testing.T) {
	t.Parallel()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const n = 100_000 // three of these are past the 212992 bytes of net.core.wmem_default
	long := strings.Repeat("x", n)
	c, err := Command(t.Context(), Spec{
		Command: []string{"/bin/sh", "-c", `echo "$# ${#1} ${#2} ${#3}"`, "sh", long, long, long},
		Home:    home,
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("Wait: %v: %s", err, stderr.String())
	}
	if want := fmt.Sprintf("3 %d %d %d\n", n, n, n); stdout.String() != want {
		t.Errorf("the command printed %q, want %q", stdout.String(), want)
	}
}

// The command's argv reaches it byte for byte, an argument that isn't UTF-8
// among them, such as a Latin-1 file name. The settings carry it as bytes, since
// encoding/json would write U+FFFD for each such byte of a string.
func TestCommandArgvBytes(t *testing.T) {
	t.Parallel()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Command(t.Context(), Spec{
		Command: []string{"/bin/sh", "-c", `printf %s "$1" | od -An -tx1`, "sh", "caf\xe9\xff\xfe"},
		Home:    home,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Env = []string{"PATH=/usr/bin:/bin"}
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("Wait: %v: %s", err, stderr.String())
	}
	if got, want := strings.Join(strings.Fields(stdout.String()), " "), "63 61 66 e9 ff fe"; got != want {
		t.Errorf("the command got the bytes %q, want %q", got, want)
	}
}

// withRole leaves no setting of roleVar but the one it adds, whatever form a
// copy takes, and keeps everything else in order.
func TestWithRole(t *testing.T) {
	t.Parallel()
	env := []string{"A=1", roleVar + "=" + roleCheck, roleVar, roleVar + "=", roleVar + "X=2", "B=3"}
	for _, tc := range []struct {
		role string
		want []string
	}{
		{roleStage, []string{"A=1", roleVar + "X=2", "B=3", roleVar + "=" + roleStage}},
		{"", []string{"A=1", roleVar + "X=2", "B=3"}},
	} {
		if got := withRole(env, tc.role); !slices.Equal(got, tc.want) {
			t.Errorf("withRole(%q) = %q, want %q", tc.role, got, tc.want)
		}
	}
}

// playRole unsets roleVar before it plays anything, here a role that fails, so
// that nothing a part starts inherits it, whatever starts it. It sets the
// process's environment, so it can't run in parallel.
func TestPlayRoleUnsetsTheVariable(t *testing.T) {
	t.Setenv(roleVar, "no-such-role")
	if code := playRole("no-such-role"); code != failed {
		t.Errorf("playRole = %d, want %d", code, failed)
	}
	if v, ok := os.LookupEnv(roleVar); ok {
		t.Errorf("%s is still %q", roleVar, v)
	}
}

// An argument with a NUL in it, which execve can't take, fails Start, as it did
// when an argv carried the command. The stage starts the command before it
// replies, on both platforms.
func TestStartRefusesAnArgvWithANul(t *testing.T) {
	t.Parallel()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Command(t.Context(), Spec{Command: []string{"/bin/echo", "a\x00b"}, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err == nil || !strings.Contains(err.Error(), "invalid argument") {
		t.Errorf("Start = %v, want EINVAL", err)
		if err == nil {
			_ = c.Wait()
		}
	}
}
