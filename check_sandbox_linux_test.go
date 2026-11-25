package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCheckSandbox runs the suite in a sandbox built from a Spec with no
// network and a home.
func TestCheckSandbox(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	inHome := filepath.Join(home, "inside-home")
	if err := os.Mkdir(inHome, 0o750); err != nil {
		t.Fatal(err)
	}
	spec := Spec{Home: home, Network: NetworkNone}
	want := Expect{Unreadable: []string{secret}, Unwritable: []string{inHome}}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := Check(ctx, &spec, want)
	if err != nil {
		t.Fatal(err)
	}
	m := byName(t, res)
	for name, st := range map[string]Status{
		"userns.create":               Pass,
		"mount.tmpfs":                 Pass,
		"io_uring.setup":              Pass,
		"egress.direct-tcp":           Pass,
		"expect.unreadable:" + secret: Pass,
		// Not vacuous: a path under Home is writable, so the check says so.
		"expect.unwritable:" + inHome: Fail,
	} {
		if r, ok := m[name]; !ok || r.Status != st {
			t.Errorf("%s = %+v, want %v", name, r, st)
		}
	}
	// The covers that the library makes a mount point in, for the files that
	// links in /etc lead to (Ubuntu's resolv.conf into /run, Debian's
	// sgml catalog into /var/lib) and for the scratch directories (/var/tmp),
	// show nothing else. A check by the caller's Spec failed both on every host.
	for _, c := range []string{"/run", "/var"} {
		if r := m["covers:"+c]; r.Status != Pass {
			t.Errorf("covers:%s = %+v, want Pass", c, r)
		}
	}
	for _, name := range []string{"writes.outside", "covers"} {
		ran := false
		for n, r := range m {
			if (n == name || strings.HasPrefix(n, name+":")) && r.Status != Skipped {
				ran = true
			}
		}
		if !ran {
			t.Errorf("%s did not run: %+v", name, m[name])
		}
	}
	for _, r := range res {
		if r.Name == "check.internal" {
			t.Errorf("a check panicked: %s", r.Detail)
		}
	}
	if entries, _ := os.ReadDir(inHome); len(entries) != 0 {
		t.Errorf("a check left files in the Unwritable directory: %v", entries)
	}
}

// TestCheckArgvHoldsNoSettings polls /proc while Check runs, with and
// without a Spec, and requires that no command line holds the payload, and
// that the check child's is only the binary and the marker, or for a namespace attempt a fixed mode.
func TestCheckArgvHoldsNoSettings(t *testing.T) {
	t.Parallel()
	for _, withSpec := range []bool{false, true} {
		t.Run("spec="+strconv.FormatBool(withSpec), func(t *testing.T) {
			t.Parallel()
			const marker = "/nonexistent/argv-marker-7c1e"
			// A proxy that accepts and never answers keeps the child
			// running for netTimeout, long enough to be seen. It needs the
			// host's network.
			silent, err := listenLocal()
			if err != nil {
				t.Fatal(err)
			}
			defer silent.Close()
			var spec *Spec
			if withSpec {
				spec = &Spec{Home: t.TempDir(), Network: NetworkHost}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			var (
				wg       sync.WaitGroup
				children int
				leaks    []string
				stop     = make(chan struct{})
			)
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					files, _ := filepath.Glob("/proc/[0-9]*/cmdline")
					for _, f := range files {
						b, err := readFile(f)
						if err != nil {
							continue
						}
						args := bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0})
						line := string(bytes.Join(args, []byte(" ")))
						if bytes.Contains(b, []byte(marker)) {
							leaks = append(leaks, line)
						}
						if len(args) >= 2 && string(args[1]) == checkArg {
							children++
							// A check child's own namespace attempts are
							// this binary with a fixed mode, which a
							// sampler that is quick enough sees too.
							grandchild := len(args) == 3 && (string(args[2]) == modeNoop || string(args[2]) == modeMount)
							if len(args) != 2 && !grandchild {
								leaks = append(leaks, line)
							}
						}
					}
					time.Sleep(time.Millisecond)
				}
			})
			_, err = Check(ctx, spec, Expect{Unreadable: []string{marker}, Proxy: silent.Addr().String(), Allowed: []string{"x.example:443"}})
			close(stop)
			wg.Wait()
			if err != nil {
				t.Fatal(err)
			}
			if children == 0 {
				t.Error("never saw the check child, so the test proved nothing")
			}
			if len(leaks) > 0 {
				t.Errorf("settings in argv: %q", leaks)
			}
		})
	}
}
