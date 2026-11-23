package sandbox

// Firefox under the backend's own generated profile: a headless --screenshot
// of a page, as trmnl's renderer takes it. This is the main macOS consumer, so
// the profile the library makes, and not a hand-written one, has to run it.
// docs/spikes.md (M2) found the minimal profile by hand; this checks that the
// generated one, with Services [ServiceFirefox], does the same.

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const firefoxApp = "/Applications/Firefox.app/Contents/MacOS/firefox"

// firefoxEnv is what the render needs of the environment. The three
// MOZ_DISABLE switches are the ones Firefox's own sandboxes need off, since a
// process already in a profile cannot apply another (bug 1417005).
var firefoxEnv = []string{
	shellPath, "MOZ_HEADLESS=1", "MOZ_CRASHREPORTER_DISABLE=1",
	"MOZ_DISABLE_CONTENT_SANDBOX=1", "MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1", "MOZ_DISABLE_RDD_SANDBOX=1",
}

// firefoxArgs is the command that renders page into shot.
func firefoxArgs(home, page, shot string) []string {
	return []string{firefoxApp, "--headless", "-no-remote", "-profile", filepath.Join(home, "prof"), "--screenshot", shot, "--window-size=800,480", "file://" + page}
}

// pixels counts the pixels of img that are mostly c.
func pixels(img image.Image, c color.RGBA) int {
	n := 0
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			if abs(int(r>>8)-int(c.R)) < 40 && abs(int(g>>8)-int(c.G)) < 40 && abs(int(bl>>8)-int(c.B)) < 40 {
				n++
			}
		}
	}
	return n
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// readPNG decodes the file, which must exist: a sandbox denial can leave
// Firefox exiting 0 with no output, which is why the caller checks for the
// file and not only for the status.
func readPNG(t *testing.T, path string) (image.Image, [16]byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no screenshot: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("the screenshot is not a PNG: %v", err)
	}
	return img, md5.Sum(b)
}

// firefoxHome returns a fresh home for a Firefox run. Firefox makes
// Library/Application Support in it, which macOS gives an ACL that denies
// deleting, so the test removes the ACLs before the directory is removed.
func firefoxHome(t *testing.T) string {
	t.Helper()
	home := realTemp(t)
	t.Cleanup(func() {
		_ = exec.Command("/bin/chmod", "-RN", home).Run()
		if dir := os.Getenv("SBX_KEEP_DIR"); dir != "" && t.Failed() {
			if b, err := os.ReadFile(filepath.Join(home, "shot.png")); err == nil {
				_ = os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "_")+".png"), b, 0o644)
			}
		}
	})
	return home
}

// serveImage serves a solid-color PNG of 200x100 on l, and counts requests.
func serveImage(t *testing.T, l net.Listener, c color.RGBA) *atomic.Int64 {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 200, 100))
	for y := range 100 {
		for x := range 200 {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	hits := new(atomic.Int64)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(buf.Bytes())
	})}
	go srv.Serve(l)
	t.Cleanup(func() { _ = srv.Close() })
	return hits
}

// TestFirefoxScreenshot renders a page under the generated profile, with no
// network at all, and checks the PNG against an unsandboxed render. The page
// has a heading in Helvetica and a red box.
func TestFirefoxScreenshot(t *testing.T) {
	if _, err := os.Stat(firefoxApp); err != nil {
		t.Skip("Firefox is not installed")
	}
	const html = `<!doctype html><html><body style="margin:0"><h1 style="font-family:Helvetica">Sandboxed</h1><div style="width:200px;height:100px;background:#f00"></div></body></html>`
	red := color.RGBA{R: 255, A: 255}

	// Unsandboxed, for what the render should be.
	base := firefoxHome(t)
	basePage := writeFile(t, html, base, "page.html")
	baseShot := filepath.Join(base, "shot.png")
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, firefoxApp, firefoxArgs(base, basePage, baseShot)[1:]...)
	cmd.Env = append(firefoxEnv[:len(firefoxEnv):len(firefoxEnv)], "HOME="+base, "CFFIXED_USER_HOME="+base, "TMPDIR="+mkdirs(t, base, "tmp"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("Firefox does not render outside the sandbox either: %v\n%s", err, out)
	}
	baseImg, baseSum := readPNG(t, baseShot)

	// In the sandbox.
	home := firefoxHome(t)
	page := writeFile(t, html, home, "page.html")
	shot := filepath.Join(home, "shot.png")
	spec := Spec{Home: home, Services: []Service{ServiceFirefox}, Command: firefoxArgs(home, page, shot)}
	c, err := Command(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	c.Env = firefoxEnv
	var out syncBuffer
	c.Stdout, c.Stderr = &out, &out
	start := time.Now()
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("Firefox under the profile: %v\n%s", err, out.buf.String())
	}
	t.Logf("rendered in %v", time.Since(start))
	img, sum := readPNG(t, shot)
	if img.Bounds() != baseImg.Bounds() {
		t.Errorf("size %v, unsandboxed %v", img.Bounds(), baseImg.Bounds())
	}
	if n, want := pixels(img, red), pixels(baseImg, red); n == 0 || n != want {
		t.Errorf("red pixels = %d, unsandboxed %d", n, want)
	}
	if sum != baseSum {
		t.Logf("the PNG differs from the unsandboxed render (%x, %x), though it has the same size and colors", sum, baseSum)
	}
	// Firefox kept to the sandbox's own home: it made its library there.
	if _, err := os.Stat(filepath.Join(home, "Library")); err != nil {
		t.Logf("Firefox made no Library in the sandbox's home: %v", err)
	}
	// Whatever the sandbox's Firefox refused, it did not print a crash.
	if strings.Contains(out.buf.String(), "sandbox_init() failed") {
		t.Errorf("a Firefox process tried to apply a profile of its own:\n%s", out.buf.String())
	}
}

// TestFirefoxNetwork renders a page that loads two images from loopback: one
// from the port the sandbox was given with Listen, one from a port it was not.
// The first loads and the second does not, as spikes.md M2 found with a
// hand-written profile.
func TestFirefoxNetwork(t *testing.T) {
	if _, err := os.Stat(firefoxApp); err != nil {
		t.Skip("Firefox is not installed")
	}
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	blueHits := serveImage(t, other, color.RGBA{B: 255, A: 255})
	home := firefoxHome(t)
	spec := Spec{Home: home, Services: []Service{ServiceFirefox}, Listen: 1}
	spec.Command = []string{"unset"}
	c, err := Command(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	proxy := c.ListenAddrs()[0]
	html := fmt.Sprintf(`<!doctype html><html><body style="margin:0"><img src="http://%s/green.png"><img src="http://%s/blue.png"></body></html>`, proxy, other.Addr())
	page := writeFile(t, html, home, "page.html")
	shot := filepath.Join(home, "shot.png")
	c.spec.Command = firefoxArgs(home, page, shot)
	c.Env = firefoxEnv
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	greenHits := serveImage(t, c.Listeners()[0], color.RGBA{G: 255, A: 255})
	if err := c.Wait(); err != nil {
		t.Fatal(err)
	}
	img, _ := readPNG(t, shot)
	green, blue := pixels(img, color.RGBA{G: 255, A: 255}), pixels(img, color.RGBA{B: 255, A: 255})
	if green < 10000 {
		t.Errorf("the image from the Listen port did not load: %d green pixels (%d requests)", green, greenHits.Load())
	}
	if blue != 0 || blueHits.Load() != 0 {
		t.Errorf("an image from a port the sandbox was not given loaded: %d blue pixels, %d requests", blue, blueHits.Load())
	}
}
