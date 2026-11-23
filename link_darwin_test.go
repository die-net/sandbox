package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Row: "Path and link rules": a Write file can't be hard-linked into the
// home. macOS 27 refuses that link by itself, because the root's unlink and
// create denies make it a link that gains permissions (forbidden-link-priv),
// so on 27 TestEscapeRootsEveryName passes with or without the file-link
// deny. macOS 15 and 26 don't apply that check to those two operations, and
// only the file-link deny refuses it. This test keeps only the file-link part
// of each root's deny, so it fails on 27 too when that part is missing.
func TestRootLinkRefusedByFileLink(t *testing.T) {
	t.Parallel()
	base := realTemp(t)
	home := mkdirs(t, base, "home")
	f := writeFile(t, "caller's file\n", base, "f.txt")
	prof, err := profile(profileInput{Home: home, Write: []string{f}})
	if err != nil {
		t.Fatal(err)
	}
	const rootDeny = "(deny file-write-unlink file-write-create "
	var lines []string
	kept := 0
	for _, l := range strings.Split(prof, "\n") {
		rest, ok := strings.CutPrefix(l, rootDeny)
		if !ok {
			lines = append(lines, l)
			continue
		}
		if path, ok := strings.CutPrefix(rest, "file-link "); ok {
			lines = append(lines, "(deny file-link "+path)
			kept++
		}
	}
	if kept != 2 {
		t.Fatalf("%d roots carry a file-link deny, want 2 (Home and the Write file):\n%s", kept, prof)
	}
	dest := filepath.Join(home, "hard")
	out, err := exec.CommandContext(t.Context(), "/usr/bin/sandbox-exec", "-p", strings.Join(lines, "\n"), "/bin/ln", f, dest).CombinedOutput() //nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	if _, statErr := os.Lstat(dest); statErr == nil || err == nil {
		t.Errorf("a hard link of the Write file into the home worked: %v %s", err, out)
	}
	// Control: the same profile with the file-link denies taken out lets the
	// link through, so the refusal above is that rule's.
	var open []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "(deny file-link ") {
			open = append(open, l)
		}
	}
	_ = os.Remove(dest)
	//nolint:gosec // G204: the test binary or a tool the test names, run as the test's own child.
	if out, err := exec.CommandContext(t.Context(), "/usr/bin/sandbox-exec", "-p", strings.Join(open, "\n"), "/bin/ln", f, dest).CombinedOutput(); err != nil {
		t.Errorf("control: the link failed without the file-link deny, so this test shows nothing: %v %s", err, out)
	}
	_ = os.Remove(dest)
}
