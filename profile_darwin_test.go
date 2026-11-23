package sandbox

import (
	"strings"
	"testing"
)

func TestQuote(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in, want string
	}{
		{"/plain", `"/plain"`},
		{`/a"b`, `"/a\"b"`},
		{`/a\b`, `"/a\\b"`},
		{`/a\"b`, `"/a\\\"b"`},
		{"/a b (c);d#e", `"/a b (c);d#e"`},
		{"/héllo ☃", `"/héllo ☃"`},
		{`/a"); (allow default`, `"/a\"); (allow default"`},
	} {
		got, err := quote(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("quote(%q) = %s, %v, want %s", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "relative", "/new\nline", "/tab\there", "/nul\x00", "/del\x7f", "/bad\xff\xfeutf8", "/cr\r"} {
		if got, err := quote(bad); err == nil {
			t.Errorf("quote(%q) = %s, want a refusal", bad, got)
		}
	}
}

// lines returns the profile's lines, with the comments left out.
func lines(p string) []string {
	var out []string
	for _, l := range strings.Split(p, "\n") {
		if l != "" && !strings.HasPrefix(l, ";") {
			out = append(out, l)
		}
	}
	return out
}

// indexOf returns the index of the first line that holds sub, or -1.
func indexOf(p, sub string) int {
	for i, l := range lines(p) {
		if strings.Contains(l, sub) {
			return i
		}
	}
	return -1
}

func TestProfileBasics(t *testing.T) {
	t.Parallel()
	p, err := profile(profileInput{Home: "/h"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(version 1)", "(deny default)", `(allow file-read* (subpath "/"))`,
		"(deny process-info*)", "(allow process-info* (target same-sandbox))", "(allow signal (target same-sandbox))",
		`(allow file-read* file-write* process-exec* (subpath "/h"))`,
	} {
		if indexOf(p, want) < 0 {
			t.Errorf("profile lacks %s:\n%s", want, p)
		}
	}
	// The home is allowed after the broad read and after the covers, and the
	// process-info deny comes before its allow.
	if indexOf(p, `(subpath "/"))`) >= indexOf(p, `(subpath "/h")`) {
		t.Error("the home comes before the broad allow")
	}
	if indexOf(p, "(deny process-info*)") > indexOf(p, "(allow process-info*") {
		t.Error("process-info is allowed before it is denied")
	}
	// No network at all by default.
	for _, l := range lines(p) {
		if strings.Contains(l, "network") {
			t.Errorf("a network rule in a profile with no network: %s", l)
		}
	}
}

func TestProfileOrder(t *testing.T) {
	t.Parallel()
	p, err := profile(profileInput{
		Home:  "/Users/a/home",
		Cover: []string{"/Users", "/Users/a/tool/secrets", "/private/var"},
		Read:  []string{"/Users/a/tool", "/Users/a/tool/secrets/public"},
		Write: []string{"/private/var/w"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Shallowest first, so the nearest rule above a path is the last that
	// matches: each of these pairs is a path and one inside it.
	for _, pair := range [][2]string{
		{`(deny file-read* file-write* process-exec* (subpath "/Users"))`, `(allow file-read* process-exec* (subpath "/Users/a/tool"))`},
		{`(deny file-read* file-write* process-exec* (subpath "/Users"))`, `(allow file-read* file-write* process-exec* (subpath "/Users/a/home"))`},
		{`(allow file-read* process-exec* (subpath "/Users/a/tool"))`, `(deny file-read* file-write* process-exec* (subpath "/Users/a/tool/secrets"))`},
		{`(deny file-read* file-write* process-exec* (subpath "/Users/a/tool/secrets"))`, `(allow file-read* process-exec* (subpath "/Users/a/tool/secrets/public"))`},
		{`(deny file-read* file-write* process-exec* (subpath "/private/var"))`, `(allow file-read* file-write* process-exec* (subpath "/private/var/w"))`},
		{`(deny file-read* file-write* process-exec* (subpath "/private/var"))`, `(allow file-read* process-exec* (subpath "/private/var/select"))`},
	} {
		a, b := indexOf(p, pair[0]), indexOf(p, pair[1])
		if a < 0 || b < 0 {
			t.Fatalf("a rule is missing, %d %d, from:\n%s", a, b, p)
		}
		if a > b {
			t.Errorf("%s comes after %s in:\n%s", pair[0], pair[1], p)
		}
	}
	// The default reads are shown under the default covers, after them.
	if indexOf(p, `(allow file-read* process-exec* (subpath "/private/var/select"))`) < indexOf(p, `(subpath "/private/var"))`) {
		t.Error("/private/var/select is shown before /private/var is covered")
	}
	// At one path the deny goes first, so the allow wins.
	p, err = profile(profileInput{Home: "/h", Cover: []string{"/x"}, Read: []string{"/x"}})
	if err != nil {
		t.Fatal(err)
	}
	if indexOf(p, `(deny file-read* file-write* process-exec* (subpath "/x"))`) > indexOf(p, `(allow file-read* process-exec* (subpath "/x"))`) {
		t.Errorf("the cover comes after the read at one path:\n%s", p)
	}
}

func TestProfileNetwork(t *testing.T) {
	t.Parallel()
	has := func(p, want string) bool { return indexOf(p, want) >= 0 }
	none, err := profile(profileInput{Home: "/h", Listen: []int{4001}, Loopback: []int{4002, 4003}, Sockets: []string{"/w/mcp.sock"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(allow network-outbound (remote tcp "localhost:4001"))`,
		`(allow network-bind (local tcp "localhost:4002"))`, `(allow network-inbound (local tcp "localhost:4002"))`, `(allow network-outbound (remote tcp "localhost:4002"))`,
		`(allow network-outbound (remote tcp "localhost:4003"))`,
		`(allow network-outbound (remote unix-socket (path-literal "/w/mcp.sock")))`,
	} {
		if !has(none, want) {
			t.Errorf("NetworkNone lacks %s", want)
		}
	}
	// The Listen port is outbound only: the parent serves it.
	if has(none, `(local tcp "localhost:4001")`) {
		t.Error("the Listen port can be bound")
	}
	for _, bad := range []string{`"*:*"`, "localhost:*", "mDNSResponder"} {
		if has(none, bad) {
			t.Errorf("NetworkNone allows %s", bad)
		}
	}
	host, err := profile(profileInput{Home: "/h", Network: NetworkHost})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`(allow network-outbound (remote tcp "*:*"))`, `(allow network-outbound (remote udp "*:*"))`, `(deny network-outbound (remote ip "localhost:*"))`, "mDNSResponder"} {
		if !has(host, want) {
			t.Errorf("NetworkHost lacks %s", want)
		}
	}
	// The deny of localhost comes after the broad allow, and is written as the
	// one form that held in testing: not as (remote ip "*:*"), which it did
	// not follow.
	if indexOf(host, `(deny network-outbound (remote ip "localhost:*"))`) < indexOf(host, `(allow network-outbound (remote tcp "*:*"))`) {
		t.Error("the deny of localhost comes before the allow")
	}
	if has(host, `(remote ip "*:*")`) {
		t.Error(`NetworkHost uses (remote ip "*:*"), whose localhost deny held for nothing`)
	}
	broad, err := profile(profileInput{Home: "/h", Network: NetworkHost, BroadLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if has(broad, `(deny network-outbound`) || !has(broad, `(allow network-outbound (remote ip "localhost:*"))`) || !has(broad, `(allow network-bind (local ip "localhost:*"))`) {
		t.Errorf("BroadLoopback with NetworkHost:\n%s", broad)
	}
}

func TestProfileServices(t *testing.T) {
	t.Parallel()
	p, err := profile(profileInput{Home: "/h", Services: []Service{ServiceFirefox, ServiceFirefox, ServiceDirectory}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(allow mach-register (global-name-regex #"^org\.mozilla\.machname\."))`,
		`(allow mach-lookup (global-name-regex #"^org\.mozilla\.machname\."))`,
		`(allow mach-lookup (global-name "com.apple.coreservices.launchservicesd"))`,
		`(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))`,
		`(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))`,
	} {
		if strings.Count(p, want) != 1 {
			t.Errorf("want %s once:\n%s", want, p)
		}
	}
	if _, err := profile(profileInput{Home: "/h", Services: []Service{"fonts\n(allow default)"}}); err == nil {
		t.Error("an unknown service was accepted")
	}
	// None means no Mach rule at all.
	p, _ = profile(profileInput{Home: "/h"})
	if strings.Contains(p, "mach-") {
		t.Errorf("a Mach rule with no Services:\n%s", p)
	}
}

func TestProfileRefusesPaths(t *testing.T) {
	t.Parallel()
	for _, in := range []profileInput{
		{Home: "/h\n(allow default)"},
		{Home: "/h", Read: []string{"/r\x00"}},
		{Home: "/h", Write: []string{"/w\r"}},
		{Home: "/h", Cover: []string{"/c\x1b"}},
		{Home: "/h", Sockets: []string{"/s\n"}},
		{Home: "/h", Self: "/bad\xff"},
		{Home: "relative"},
	} {
		if p, err := profile(in); err == nil {
			t.Errorf("profile(%+v) = %q, want a refusal", in, p)
		}
	}
}

func TestDepth(t *testing.T) {
	t.Parallel()
	for p, want := range map[string]int{"/": 0, "/a": 1, "/a/b": 2, "/a/b/c": 3} {
		if got := depth(p); got != want {
			t.Errorf("depth(%s) = %d, want %d", p, got, want)
		}
	}
}

func TestRlimitFor(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		r       Rlimit
		wantErr bool
	}{
		{Rlimit{ResourceCPU, 1, 2}, false},
		{Rlimit{ResourceOpenFiles, ^uint64(0), ^uint64(0)}, false},
		{Rlimit{ResourceAddressSpace, 1, 2}, true},
	} {
		l, err := rlimitFor(tc.r)
		if (err != nil) != tc.wantErr {
			t.Errorf("rlimitFor(%+v) = %+v, %v", tc.r, l, err)
		}
		if err == nil && l.Soft > l.Hard {
			t.Errorf("rlimitFor(%+v) has a soft limit above the hard one: %+v", tc.r, l)
		}
	}
}
