package sandbox

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// profileInput is everything the Seatbelt profile is made from. Paths are
// absolute and resolved, as prepare returns them.
type profileInput struct {
	Home               string
	Write, Read, Cover []string
	// Sockets are the Write paths that are sockets, which the command may
	// connect to.
	Sockets []string
	// Self is this binary, which the check child and a command that runs it
	// again need.
	Self          string
	Network       Network
	BroadLoopback bool
	// Listen are the ports the caller serves, which the command may connect
	// to. Loopback are the ports the command may bind and dial itself.
	Listen, Loopback []int
	Services         []Service
	// Marker is the pair of Mach names that tells this sandbox's processes
	// from all others, which teardown and Footprint look for. An empty one
	// leaves them out of the profile.
	Marker marker
}

// defaultRead lists the paths under a default cover that every sandbox may
// read. /bin/sh is a stub that reads /private/var/select/sh to find its
// shell, so without it no shell script runs, and /etc/localtime leads into
// /private/var/db/timezone. Neither holds anything private.
var defaultRead = []string{"/private/var/select", "/private/var/db/timezone"}

// serviceRules are the Mach services each Service group allows, as profile
// rules. A new group is a reviewed change.
var serviceRules = map[Service][]string{
	ServiceFirefox: {
		`(allow mach-register (global-name-regex #"^org\.mozilla\.machname\."))`,
		`(allow mach-lookup (global-name-regex #"^org\.mozilla\.machname\."))`,
		`(allow mach-lookup (global-name "com.apple.coreservices.launchservicesd"))`,
		`(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))`,
	},
	ServiceDirectory: {
		`(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))`,
	},
}

// mdnsSocket is the socket that name lookups go through, which a sandbox with
// NetworkHost needs. /private/var is covered, and a connect to a unix socket
// is an operation of its own, so it takes a rule of its own.
const mdnsSocket = "/private/var/run/mDNSResponder"

// quote returns p as a profile string literal. Only a backslash and a double
// quote need escaping inside one. A path with a control character, or bytes
// that are not UTF-8, is refused, since nothing here can say what the profile
// parser makes of it, and a profile that means something other than what was
// asked is worse than none. A user's path only ever goes into a literal or
// subpath filter, never a regular expression, so a parenthesis or a semicolon
// in a name is only a character.
func quote(p string) (string, error) {
	if p == "" || p[0] != '/' {
		return "", fmt.Errorf("path %q is not absolute", p)
	}
	if !utf8.ValidString(p) {
		return "", fmt.Errorf("path %q is not valid UTF-8, so it cannot be named in a profile", p)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("path %q holds a control character, so it cannot be named in a profile", p)
		}
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p) + `"`, nil
}

// builder writes a profile, and keeps the first path it had to refuse.
type builder struct {
	strings.Builder
	err error
}

func (b *builder) line(format string, a ...any) {
	fmt.Fprintf(b, format+"\n", a...)
}

// q quotes p, or records why not.
func (b *builder) q(p string) string {
	s, err := quote(p)
	if err != nil && b.err == nil {
		b.err = err
	}
	return s
}

// fileRule is one allow or deny of a path.
type fileRule struct {
	path  string
	deny  bool
	write bool // an allow that also lets the path be written
}

// depth is how many directories lie above p, so that a rule for a deeper
// path comes after, and so overrides, a rule for the path it lies in.
func depth(p string) int {
	if p == "/" {
		return 0
	}
	return strings.Count(p, "/")
}

// profile returns the Seatbelt profile for in: deny by default, then the host's
// files read-only, a deny for each cover and an allow for each read path, the
// home and the write paths read-write, and last the network and Mach services.
// Seatbelt takes the last rule that matches, so the order is the view: a path
// is shown or hidden by the nearest rule above it, which is why file rules go
// in order of depth, with a cover before an allow at the same path.
//
// Seatbelt resolves links and firmlinks before it matches, so a rule for a real
// path holds however the sandbox names it, and a link planted in a writable
// directory leads out of the rule that allowed it, so nothing written through
// it is allowed. The profile never allows lsopen, which would let the command
// open any app or URL through LaunchServices, outside the profile. It never
// allows process-info or signal outside the sandbox, a Mach service outside a
// requested group, or iokit.
//
// It refuses a path that cannot be quoted, and a service it does not know.
func profile(in profileInput) (string, error) {
	var b builder
	// Everything after the version is one form, so that a profile cut short, as
	// when the stage is killed while sandbox-exec is still reading it from the
	// pipe, is a syntax error and does not run. sandbox-exec takes a profile cut
	// between two rules as it is, with the rules after it missing, which can be
	// every deny that follows an allow (TestProfileCutShortDoesNotRun).
	b.line("(version 1)")
	b.line("(begin")
	b.line("(deny default)")
	if in.Marker.In != "" {
		// First, so that a profile cut short anywhere still carries them (it
		// does not run: see the wrapper above). A lookup of these names finds no
		// service, and no rule below names them. They only tell the kernel's
		// answer for this profile from every other's (member_darwin.go).
		b.line("; The marker: teardown tells this sandbox's processes by it.")
		for _, n := range []string{in.Marker.In, in.Marker.Out} {
			if strings.Trim(n, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" {
				return "", fmt.Errorf("marker name %q is not plain", n)
			}
		}
		b.line(`(allow mach-lookup (global-name "%s"))`, in.Marker.In)
		b.line(`(deny mach-lookup (global-name "%s"))`, in.Marker.Out)
	}
	b.line("; Processes stay in the sandbox, and so do the signals they send.")
	b.line("(allow process-fork)")
	b.line(`(allow process-exec* (subpath "/"))`)
	b.line("(allow signal (target same-sandbox))")
	// Under (deny default) process-info is still allowed: proc_pidinfo and
	// proc_pid_rusage of any process of the uid work, so it is denied by name
	// first, and then allowed for the sandbox's own processes.
	b.line("(deny process-info*)")
	b.line("(allow process-info* (target same-sandbox))")
	b.line("(allow sysctl-read)")
	b.line("; The host's files, read-only.")
	b.line(`(allow file-read* (subpath "/"))`)
	// Every device is refused but the few a program uses, so a console, a
	// serial port, a terminal, packet capture or a disk opens only as a
	// descriptor handed in. A list of what to refuse missed /dev/console and
	// /dev/cu.*, which stay openable by their permissions.
	b.line("; Devices: none but these.")
	b.line(`(deny file-read* file-write* file-ioctl (subpath "/dev"))`)
	b.line(`(allow file-read-metadata (literal "/dev") (literal "/dev/fd"))`)
	b.line(`(allow file-read* (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom"))`)
	b.line(`(allow file-write* (literal "/dev/null") (literal "/dev/zero"))`)
	b.line(`(allow file-read* file-write* (regex #"^/dev/fd/[0-9]+$"))`)

	var rules []fileRule
	for _, c := range in.Cover {
		rules = append(rules, fileRule{path: c, deny: true})
	}
	for _, r := range slices.Concat(defaultRead, in.Read) {
		rules = append(rules, fileRule{path: r})
	}
	for _, w := range slices.Concat([]string{in.Home}, in.Write) {
		rules = append(rules, fileRule{path: w, write: true})
	}
	slices.SortStableFunc(rules, func(a, b fileRule) int {
		if d := depth(a.path) - depth(b.path); d != 0 {
			return d
		}
		// At one path the deny goes first, so the allow wins, as a bind
		// shows a path a cover would have hidden.
		switch {
		case a.deny && !b.deny:
			return -1
		case !a.deny && b.deny:
			return 1
		}
		return 0
	})
	b.line("; Covers, and what is shown again under them, shallowest first.")
	for _, r := range rules {
		switch {
		case r.deny:
			b.line("(deny file-read* file-write* process-exec* (subpath %s))", b.q(r.path))
		case r.write:
			b.line("(allow file-read* file-write* process-exec* (subpath %s))", b.q(r.path))
		default:
			b.line("(allow file-read* process-exec* (subpath %s))", b.q(r.path))
		}
	}
	// A root cannot be removed, renamed or made again, or the sandbox could
	// replace its Home or a Write path, which the caller reads and writes by
	// name, with a link to somewhere of the caller's. The allows above cover the
	// root itself, so unlink and create at it are denied by name, after them.
	//
	// A root can't be hard-linked elsewhere either, which would give it a
	// second name in the home that these rules don't cover. macOS 27 refuses
	// that link by itself, since the source has a write operation denied that
	// the target allows (the log says forbidden-link-priv). macOS 15 and 26
	// apply that check to other write operations but not to these two, so
	// file-link is denied by name too (TestRootLinkRefusedByFileLink).
	roots := slices.Concat([]string{in.Home}, in.Write)
	slices.Sort(roots)
	for _, r := range slices.Compact(roots) {
		b.line("(deny file-write-unlink file-write-create file-link (literal %s))", b.q(r))
	}
	if in.Self != "" {
		b.line("; This binary, for the check child and a command that runs it again.")
		b.line("(allow file-read* process-exec* (literal %s))", b.q(in.Self))
	}

	b.line("; The network.")
	for _, s := range in.Sockets {
		b.line("(allow network-outbound (remote unix-socket (path-literal %s)))", b.q(s))
	}
	if in.Network == NetworkHost {
		b.line(`(allow network-outbound (remote tcp "*:*"))`)
		b.line(`(allow network-outbound (remote udp "*:*"))`)
		b.line("(allow network-outbound (remote unix-socket (path-literal %s)))", b.q(mdnsSocket))
		b.line(`(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))`)
		b.line(`(allow mach-lookup (global-name "com.apple.dnssd.service"))`)
		// Certificate checks, which curl needs from macOS 27.2 on (earlier,
		// 27.0.1, it verified without).
		b.line(`(allow mach-lookup (global-name "com.apple.TrustEvaluationAgent"))`)
		if !in.BroadLoopback {
			// "localhost" in a profile means every address the host has, so
			// this refuses its LAN address too. The same deny after an allow
			// written as (remote ip "*:*") held for nothing.
			b.line(`(deny network-outbound (remote ip "localhost:*"))`)
		}
	}
	if in.BroadLoopback {
		b.line(`(allow network-bind (local ip "localhost:*"))`)
		b.line(`(allow network-inbound (local ip "localhost:*"))`)
		b.line(`(allow network-outbound (remote ip "localhost:*"))`)
	}
	// These are TCP, as the ports are, and not the UDP that "ip" adds. "localhost"
	// is every address the host has, so a Loopback port may be bound on the
	// LAN address or the wildcard, and a peer on the LAN may connect to it.
	// Seatbelt takes no other host than "*" or "localhost" in an address, and
	// checks a connection's remote address at connect and not at accept, so
	// there is no rule that limits it to 127.0.0.1 (docs/macos.md, The network).
	for _, p := range in.Listen {
		b.line(`(allow network-outbound (remote tcp "localhost:%s"))`, strconv.Itoa(p))
	}
	for _, p := range in.Loopback {
		b.line(`(allow network-bind (local tcp "localhost:%s"))`, strconv.Itoa(p))
		b.line(`(allow network-inbound (local tcp "localhost:%s"))`, strconv.Itoa(p))
		b.line(`(allow network-outbound (remote tcp "localhost:%s"))`, strconv.Itoa(p))
	}

	var done []Service
	for _, s := range in.Services {
		if slices.Contains(done, s) {
			continue
		}
		done = append(done, s)
		rules, ok := serviceRules[s]
		if !ok {
			return "", fmt.Errorf("unknown service %q", s)
		}
		b.line("; Mach services: %s.", string(s))
		for _, r := range rules {
			b.line("%s", r)
		}
	}
	b.line(")")
	if b.err != nil {
		return "", b.err
	}
	return b.String(), nil
}
