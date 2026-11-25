package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Status is the outcome of one check.
type Status int

const (
	// Pass means the attempt failed, or the property holds.
	Pass Status = iota
	// Fail means the attempt worked.
	Fail
	// NotEnforceable means the check applies, but nothing on this platform
	// can enforce it.
	NotEnforceable
	// Skipped means the check does not apply here, or was not asked for.
	Skipped
)

// String returns the status's name.
func (s Status) String() string {
	switch s {
	case Pass:
		return "pass"
	case Fail:
		return "fail"
	case NotEnforceable:
		return "not-enforceable"
	case Skipped:
		return "skipped"
	}
	return "status(" + strconv.Itoa(int(s)) + ")"
}

// Result is one check's finding.
type Result struct {
	// Name is stable, such as "userns.create". A check run once per path
	// or target appends ":" and it.
	Name   string `json:"name"`
	Status Status `json:"status"`
	// Detail says what was tried and what happened, with the fix when
	// there is one.
	Detail string `json:"detail,omitempty"`
}

// Expect is what a project says its sandbox must enforce, beyond the checks
// every sandbox gets.
type Expect struct {
	// Unreadable lists paths the code must not read. Each is also tried
	// through its filesystem's snapshot directories.
	Unreadable []string `json:"unreadable,omitempty"`
	// Unwritable lists paths the code must not write.
	Unwritable []string `json:"unwritable,omitempty"`
	// Unreachable lists endpoints the code must not reach, as
	// "tcp:127.0.0.1:8080", "udp:host:port" or "unix:/path".
	Unreachable []string `json:"unreachable,omitempty"`
	// Proxy is the host:port the code should use for egress.
	Proxy string `json:"proxy,omitempty"`
	// Allowed lists CONNECT targets the proxy must allow.
	Allowed []string `json:"allowed,omitempty"`
	// Refused lists CONNECT targets the proxy must refuse.
	Refused []string `json:"refused,omitempty"`
}

// checkArg is the first argument of the run of this binary that Check starts.
// Stage hands such a run to checkStage.
const checkArg = "--sandbox-check"

// checkFailed is the exit status of a check child that could not run its suite.
const checkFailed = 125

// The check child's descriptors: it writes its results to resultFD and reads
// its settings from payloadFD, so nothing about the Spec is in its argv.
const (
	resultFD  = 3
	payloadFD = 4
)

// netTimeout bounds each network attempt, so a check run never hangs.
const netTimeout = 2 * time.Second

// checkInput is what the runner hands the child, as JSON on payloadFD.
type checkInput struct {
	Want  Expect     `json:"want"`
	Spec  *Spec      `json:"spec,omitempty"`
	Hints checkHints `json:"hints"`
}

// checkHints are targets the caller works out for the child, where the child
// cannot. A sandbox gives the child its own HOME and an empty environment, so
// what it would build from them, such as the user's ~/.ssh or the socket in
// SSH_AUTH_SOCK, names nothing of the caller's, and a check that tries those
// passes without trying anything. Set is false where the child finds its own,
// as on Linux.
type checkHints struct {
	Set bool `json:"set,omitempty"`
	// Secrets are well-known secret paths that exist, and Sockets well-known
	// sockets that exist. WriteTargets are directories outside the sandbox's
	// own that the caller can write, so that a refusal in the child is the
	// sandbox's and not the permissions'.
	Secrets      []string `json:"secrets,omitempty"`
	Sockets      []string `json:"sockets,omitempty"`
	WriteTargets []string `json:"write_targets,omitempty"`
}

// Check runs the suite in a child of this binary and returns the results,
// in a fixed order. With spec the child runs inside a sandbox built from it,
// and judges what the view shows by the Spec as the sandbox prepares it.
// With nil it inherits this process's context as it is, which is what an
// operator's container or unit gives.
//
// The child is started as the current binary with checkArg as its first
// argument, so the program must call Stage first in main.
func Check(ctx context.Context, spec *Spec, want Expect) ([]Result, error) {
	var in checkInput
	if spec != nil {
		h, err := currentHost()
		if err != nil {
			return nil, fmt.Errorf("check: %w", err)
		}
		c, err := checkSpec(*spec, h)
		if err != nil {
			return nil, fmt.Errorf("check: %w", err)
		}
		in.Spec = &c
	}
	in.Want, in.Hints = want, platformHints(in.Spec)
	payload, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("check: %w", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("check: %w", err)
	}
	defer r.Close()
	defer w.Close() // on an error path. The success path closes it below, before reading.
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("check: %w", err)
	}
	defer pr.Close()
	// The child's end of the payload pipe may close early, so a failed write
	// is the child's own error to report. The write runs alongside the start,
	// since a payload larger than the pipe waits for the child to read.
	go func() {
		defer pw.Close()
		_, _ = pw.Write(payload)
	}()
	var stderr bytes.Buffer
	var wait func() error
	if spec == nil {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("check: find this binary: %w", err)
		}
		cmd := exec.CommandContext(ctx, exe, checkArg) //nolint:gosec // G204: the check child is this binary, run with a fixed argument.
		cmd.ExtraFiles = []*os.File{w, pr}
		cmd.Stderr = &stderr
		cmd.WaitDelay = netTimeout
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("check: start the child: %w", err)
		}
		wait = cmd.Wait
	} else if wait, err = startInSandbox(ctx, *spec, w, pr, &stderr); err != nil {
		return nil, fmt.Errorf("check: start the sandbox: %w", err)
	}
	// The child holds the only write end now, so the reader sees its end of
	// file. A close error changes neither, and the deferred closes above
	// are the same calls on a descriptor that is already closed.
	w.Close()  //nolint:gosec // G104: see the comment above. Nothing can be done about a failed close.
	pr.Close() //nolint:gosec // G104: ends the payload writer's blocked write if the child never reads it.

	var results []Result
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var res Result
		if err := json.Unmarshal(sc.Bytes(), &res); err != nil {
			return results, fmt.Errorf("check: bad result line %q: %w", sc.Text(), err)
		}
		results = append(results, res)
	}
	werr := wait()
	if werr != nil || len(results) == 0 {
		msg := strings.TrimSpace(stderr.String())
		if werr == nil {
			werr = errors.New("no results")
		}
		return results, fmt.Errorf("check: the child failed: %w: %s", werr, msg)
	}
	return results, nil
}

// checkSpec returns the Spec the check child runs under, which is spec as
// prepare returns it for h. The child judges what its view shows by that, and
// not by the caller's Spec, since prepare adds the covers of the homes and the
// mount table and the files that links in /etc lead to under a cover, and only
// the caller's side can see the host those come from. Command is empty, as
// the child's own is set at the start.
func checkSpec(spec Spec, h hostView) (Spec, error) {
	spec.Command = []string{SelfPath, checkArg}
	spec, err := prepare(spec, h)
	if err != nil {
		return Spec{}, err
	}
	spec.Command = nil
	return spec, nil
}

// checkStage is the check child's entry point, which Stage calls when
// os.Args[1] is checkArg. It returns the exit status.
func checkStage() int {
	if len(os.Args) >= 3 {
		if code, ok := grandchild(os.Args[2:]); ok {
			return code
		}
	}
	var in checkInput
	if err := json.NewDecoder(os.NewFile(payloadFD, "payload")).Decode(&in); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox check: %v\n", err)
		return checkFailed
	}
	out := os.NewFile(resultFD, "results")
	if out == nil {
		fmt.Fprintln(os.Stderr, "sandbox check: no result descriptor")
		return checkFailed
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	for _, res := range runChecks(&checkEnv{want: in.Want, spec: in.Spec, hints: in.Hints, scratch: platformScratch()}) {
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "sandbox check: %v\n", err)
			return checkFailed
		}
	}
	return 0
}

// checkEnv is what each check sees: the caller's Expect, and the Spec the
// child runs under, nil when it runs as it is.
type checkEnv struct {
	want  Expect
	spec  *Spec
	hints checkHints
	// scratch are the paths inside the covers that the sandbox mounts a
	// tmpfs of its own on. The covers check explains them and still walks
	// into them, so anything there the sandbox didn't write shows.
	scratch []string
}

// checkFn runs one check, or a group of them, and returns its results.
type checkFn func(*checkEnv) []Result

// genericChecks is the suite, in the order of the results. The checks that
// only exist on Linux come from platformChecks.
var genericChecks = []checkFn{
	checkIdentity,
	checkGroups,
	platformChecks,
	checkProcesses,
	checkSecrets,
	checkSockets,
	checkWrites,
	checkCovers,
	checkEgress,
	checkMetadata,
	checkLAN,
	checkProxy,
	checkExpect,
}

// runChecks runs every check at once, since most wait on a network, and
// returns the results in table order. A check that panics is a failure.
func runChecks(e *checkEnv) []Result {
	groups := make([][]Result, len(genericChecks))
	var wg sync.WaitGroup
	for i, fn := range genericChecks {
		wg.Go(func() {
			defer func() {
				if p := recover(); p != nil {
					groups[i] = []Result{{Name: "check.internal", Status: Fail, Detail: fmt.Sprint("check panicked: ", p)}}
				}
			}()
			groups[i] = fn(e)
		})
	}
	wg.Wait()
	return slices.Concat(groups...)
}

func pass(name, format string, a ...any) Result {
	return Result{Name: name, Status: Pass, Detail: fmt.Sprintf(format, a...)}
}

func fail(name, format string, a ...any) Result {
	return Result{Name: name, Status: Fail, Detail: fmt.Sprintf(format, a...)}
}

func skipped(name, format string, a ...any) Result {
	return Result{Name: name, Status: Skipped, Detail: fmt.Sprintf(format, a...)}
}

// verdict makes a Result from an attempt that is a failure if it worked.
// worked lists what the attempt got, and tried says what was tried.
func verdict(name, tried string, worked []string) Result {
	if len(worked) > 0 {
		return fail(name, "%s: worked for %s", tried, strings.Join(worked, ", "))
	}
	return pass(name, "%s: refused or absent", tried)
}

// checkGroups fails when the process holds a group beyond its own gid and
// egid. getgroups may list the primary gid too, as Docker and initgroups do,
// which grants nothing the process doesn't already have.
func checkGroups(*checkEnv) []Result {
	gs, err := os.Getgroups()
	if err != nil {
		return []Result{fail("groups.supplementary", "getgroups: %v", err)}
	}
	gid, egid := os.Getgid(), os.Getegid()
	if extra := extraGroups(gs, gid, egid); len(extra) > 0 {
		return []Result{fail("groups.supplementary", "getgroups returned %v, beyond the process's own gid %d and egid %d", extra, gid, egid)}
	}
	return []Result{pass("groups.supplementary", "getgroups returned no group beyond the process's own gid %d and egid %d", gid, egid)}
}

// extraGroups returns the groups in gs other than gid and egid.
func extraGroups(gs []int, gid, egid int) []int {
	return slices.DeleteFunc(slices.Clone(gs), func(g int) bool { return g == gid || g == egid })
}

func checkIdentity(*checkEnv) []Result {
	const name = "uid.root-initial-ns"
	if os.Geteuid() != 0 {
		return []Result{pass(name, "euid is %d", os.Geteuid())}
	}
	if initialUserNS() {
		return []Result{fail(name, "euid 0 in the initial user namespace")}
	}
	return []Result{pass(name, "euid 0, but in a user namespace of its own")}
}

// homeDirs returns the home directories to look for secrets in: this
// process's own, and every account's in /etc/passwd.
func homeDirs() []string {
	var homes []string
	if h := os.Getenv("HOME"); h != "" {
		homes = append(homes, h)
	}
	if b, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 6 && filepath.IsAbs(f[5]) && f[5] != "/" {
				homes = append(homes, f[5])
			}
		}
	}
	slices.Sort(homes)
	return slices.Compact(homes)
}

// secretFiles are the well-known secrets, under a home. /etc/shadow and the
// like are listed in secretPaths.
var secretFiles = []string{".ssh", ".aws", ".config/gcloud", ".kube/config", ".docker/config.json", ".netrc", ".npmrc", ".gem/credentials", "Library/Keychains"}

var secretPaths = []string{"/etc/shadow"}

// readable reports whether path can be opened for reading, and for a
// directory listed, which is what covers a home that is only searchable.
func readable(path string) bool {
	f, err := os.Open(path) //nolint:gosec // G304: the check opens the paths it was asked to probe.
	if err != nil {
		return false
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.IsDir() {
		_, err = f.Readdirnames(1)
		return err == nil || errors.Is(err, io.EOF)
	}
	return true
}

// secretPathsFor returns the secret paths to try to read: those the caller
// found, or else the well-known ones under every home this process can name.
func secretPathsFor(hints checkHints) []string {
	if hints.Set {
		return hints.Secrets
	}
	tried := slices.Clone(secretPaths)
	for _, h := range homeDirs() {
		for _, s := range secretFiles {
			tried = append(tried, filepath.Join(h, s))
		}
	}
	return tried
}

func checkSecrets(e *checkEnv) []Result {
	var worked []string
	tried := secretPathsFor(e.hints)
	if e.hints.Set && len(tried) == 0 {
		return []Result{skipped("secrets.readable", "none of the well-known secret paths exists on this host, so there is nothing to try to read")}
	}
	for _, p := range tried {
		if readable(p) {
			worked = append(worked, p)
		}
	}
	return []Result{verdict("secrets.readable", fmt.Sprintf("open of %d well-known secret paths", len(tried)), worked)}
}

// socketCandidates are the well-known sockets to connect to.
func socketCandidates() []string {
	uid := strconv.Itoa(os.Getuid())
	socks := []string{
		"/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock",
		"/run/user/" + uid + "/podman/podman.sock", "/run/containerd/containerd.sock",
		"/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket",
		"/run/user/" + uid + "/bus", "/run/user/" + uid + "/systemd/private",
		os.Getenv("SSH_AUTH_SOCK"),
	}
	for _, a := range strings.Split(os.Getenv("DBUS_SESSION_BUS_ADDRESS"), ",") {
		if p, ok := strings.CutPrefix(a, "unix:path="); ok {
			socks = append(socks, p)
		}
	}
	socks = append(socks, platformSockets()...)
	socks = slices.DeleteFunc(socks, func(s string) bool { return s == "" })
	slices.Sort(socks)
	return slices.Compact(socks)
}

func checkSockets(e *checkEnv) []Result {
	var worked []string
	socks := socketCandidates()
	if e.hints.Set {
		socks = e.hints.Sockets
		if len(socks) == 0 {
			return []Result{skipped("sockets.reachable", "none of the well-known sockets exists on this host, so there is nothing to try to connect to")}
		}
	}
	for _, s := range socks {
		if out, _ := tryDial("unix", s, netTimeout); out == connected {
			worked = append(worked, s)
		}
	}
	return []Result{verdict("sockets.reachable", fmt.Sprintf("connect to %d well-known sockets", len(socks)), worked)}
}

// outcome is how a connection attempt ended.
type outcome int

const (
	connected outcome = iota
	refused
	timedOut
	failedOther
)

// dialTimeout connects to addr, giving up after timeout.
func dialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(context.Background(), network, addr)
}

// tryDial connects to addr and closes at once.
func tryDial(network, addr string, timeout time.Duration) (outcome, string) {
	c, err := dialTimeout(network, addr, timeout)
	if err == nil {
		c.Close() //nolint:gosec // G104: the connection is only a probe, and connecting is the result.
		return connected, "connected"
	}
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return refused, "refused"
	case errors.As(err, &ne) && ne.Timeout():
		return timedOut, fmt.Sprintf("timed out after %v, with no answer, not a refusal", timeout)
	}
	return failedOther, "failed: " + err.Error()
}

// reachResult turns a dial's outcome into a Result, where connecting is a
// failure.
func reachResult(name, what string, out outcome, detail string) Result {
	if out == connected {
		return fail(name, "%s: %s", what, detail)
	}
	return pass(name, "%s: %s", what, detail)
}

func checkEgress(*checkEnv) []Result {
	out, d := tryDial("tcp", "1.1.1.1:443", netTimeout)
	return []Result{
		reachResult("egress.direct-tcp", "TCP to 1.1.1.1:443", out, d),
		dnsProbe("egress.direct-udp", "9.9.9.9:53"),
	}
}

// dnsQuery asks for the root's NS records, which any resolver answers.
var dnsQuery = []byte{0xbe, 0xef, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}

func dnsProbe(name, addr string) Result {
	what := "UDP DNS query to " + addr
	c, err := dialTimeout("udp", addr, netTimeout)
	if err != nil {
		return pass(name, "%s: %v", what, err)
	}
	defer c.Close()
	return dnsQueryOn(name, what, c)
}

// dnsQueryOn sends the query on c, which is connected to a resolver, and fails
// if an answer comes back. If it can't set a deadline the read could wait for
// good, and nothing was asked, so the check is skipped and not passed.
func dnsQueryOn(name, what string, c net.Conn) Result {
	if err := c.SetDeadline(time.Now().Add(netTimeout)); err != nil {
		return skipped(name, "%s: could not set a deadline, so nothing was sent: %v", what, err)
	}
	if _, err := c.Write(dnsQuery); err == nil {
		var buf [512]byte
		n, err := c.Read(buf[:])
		if err == nil && n >= 12 {
			return fail(name, "%s: got a %d-byte answer", what, n)
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return pass(name, "%s: timed out after %v, with no answer, not a refusal", what, netTimeout)
		}
	}
	return pass(name, "%s: no answer", what)
}

func checkMetadata(*checkEnv) []Result {
	res := make([]Result, 0, 2)
	for _, m := range []struct{ name, addr string }{{"metadata.v4", "169.254.169.254:80"}, {"metadata.v6", "[fd00:ec2::254]:80"}} {
		out, d := tryDial("tcp", m.addr, netTimeout)
		res = append(res, reachResult(m.name, "TCP to "+m.addr, out, d))
	}
	return res
}

func checkLAN(*checkEnv) []Result {
	const name = "lan.gateway"
	gw, err := defaultGateway()
	if err != nil {
		return []Result{skipped(name, "no default gateway: %v", err)}
	}
	ports := []string{"22", "80", "443"}
	var worked []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range ports {
		wg.Go(func() {
			// A refusal comes from the gateway itself, so it was reached.
			if out, d := tryDial("tcp", net.JoinHostPort(gw, p), netTimeout); out == connected || out == refused {
				mu.Lock()
				worked = append(worked, p+" ("+d+")")
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	slices.Sort(worked)
	return []Result{verdict(name, "TCP to gateway "+gw+" on "+strings.Join(ports, ", "), worked)}
}

// connectVia asks proxy to CONNECT to target and returns the status code,
// closing the connection at once.
func connectVia(proxy, target string) (int, error) {
	c, err := dialTimeout("tcp", proxy, netTimeout)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(2 * netTimeout)); err != nil {
		return 0, err
	}
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return 0, err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return 0, err
	}
	f := strings.Fields(line)
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/") {
		return 0, fmt.Errorf("not an HTTP status line: %q", strings.TrimSpace(line))
	}
	return strconv.Atoi(f[1])
}

func checkProxy(e *checkEnv) []Result {
	if e.want.Proxy == "" {
		return []Result{skipped("proxy", "no proxy given")}
	}
	var res []Result
	for _, t := range e.want.Allowed {
		name := "proxy.allowed:" + t
		code, err := connectVia(e.want.Proxy, t)
		switch {
		case err != nil:
			res = append(res, fail(name, "CONNECT %s through %s: %v", t, e.want.Proxy, err))
		case code/100 != 2:
			res = append(res, fail(name, "CONNECT %s through %s: status %d, want 2xx", t, e.want.Proxy, code))
		default:
			res = append(res, pass(name, "CONNECT %s through %s: status %d", t, e.want.Proxy, code))
		}
	}
	for _, t := range e.want.Refused {
		name := "proxy.refused:" + t
		code, err := connectVia(e.want.Proxy, t)
		switch {
		case err != nil:
			// The proxy not answering is no evidence of a refusal.
			res = append(res, fail(name, "CONNECT %s through %s: %v, so no refusal was seen", t, e.want.Proxy, err))
		case code/100 == 2:
			res = append(res, fail(name, "CONNECT %s through %s: status %d, want a refusal", t, e.want.Proxy, code))
		default:
			res = append(res, pass(name, "CONNECT %s through %s: status %d", t, e.want.Proxy, code))
		}
	}
	return res
}

// tryCreate creates and removes a file of a random name in dir, and for a
// path that is not a directory opens it for writing without truncating.
func tryCreate(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // G304: the check opens the paths it was asked to probe.
		if err == nil {
			f.Close() //nolint:gosec // G104: the open worked, which is the result. A failed close changes nothing.
		}
		return err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	name := filepath.Join(path, ".sandbox-check-"+hex.EncodeToString(b[:]))
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the check creates a file in the directory it was asked to probe.
	if err != nil {
		return err
	}
	f.Close() //nolint:gosec // G104: the create worked, which is the result. The file is removed next either way.
	return os.Remove(name)
}

// under reports whether path is root or inside it.
func under(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func checkWrites(e *checkEnv) []Result {
	const name = "writes.outside"
	if e.spec == nil {
		return []Result{skipped(name, "no sandbox spec given")}
	}
	allowed := append([]string{e.spec.Home}, e.spec.Write...)
	var tried, worked []string
	candidates := append([]string{"/"}, e.spec.Read...)
	if e.hints.Set {
		if len(e.hints.WriteTargets) == 0 {
			return []Result{skipped(name, "this account can write no directory outside the sandbox's own that is known to try")}
		}
		candidates = slices.Concat(e.hints.WriteTargets, candidates)
	}
	for _, p := range candidates {
		if slices.ContainsFunc(allowed, func(a string) bool { return under(p, a) }) {
			continue
		}
		tried = append(tried, p)
		if tryCreate(p) == nil {
			worked = append(worked, p)
		}
	}
	return []Result{verdict(name, "create of a random name in "+strings.Join(tried, ", "), worked)}
}

// coverLimit bounds the entries looked at under one cover.
const coverLimit = 5000

// checkedCovers returns the covers the checks try, sorted and each once: the
// default covers and spec's, which the child gets prepared, so its Cover
// already holds the defaults that exist on the host.
func checkedCovers(spec *Spec) []string {
	covers := slices.Concat(defaultCover, spec.Cover)
	slices.Sort(covers)
	return slices.Compact(covers)
}

func checkCovers(e *checkEnv) []Result {
	if e.spec == nil {
		return []Result{skipped("covers", "no sandbox spec given")}
	}
	// Paths the sandbox shows on purpose, and the directories that lead to them.
	// The Spec is the prepared one, which has the files that links in /etc
	// lead to under a cover.
	shown := slices.Concat([]string{e.spec.Home, e.spec.Dir}, e.spec.Write, e.spec.Read)
	shown = slices.DeleteFunc(shown, func(s string) bool { return s == "" })
	covers := checkedCovers(e.spec)
	res := make([]Result, 0, len(covers))
	for _, c := range covers {
		name := "covers:" + c
		if _, err := os.Lstat(c); err != nil {
			res = append(res, pass(name, "%s: %v", c, err))
			continue
		}
		leak := coverLeak(c, shown, e.scratch)
		if leak != "" {
			res = append(res, fail(name, "%s shows %s, which no Home, Write or Read path explains", c, leak))
		} else {
			res = append(res, pass(name, "%s lists nothing but paths the spec shows", c))
		}
	}
	return res
}

// coverLeak walks the cover c and returns the first path in it that neither
// a shown path nor a scratch directory explains, or "". A shown path is
// skipped whole. A scratch directory is a tmpfs the sandbox made, so it is
// walked into, and anything in it shows.
func coverLeak(c string, shown, scratch []string) string {
	var leak string
	n := 0
	_ = filepath.WalkDir(c, func(p string, _ fs.DirEntry, err error) error {
		if p == c || err != nil {
			return nil
		}
		n++
		if n > coverLimit {
			return fs.SkipAll
		}
		if slices.ContainsFunc(shown, func(s string) bool { return under(p, s) }) {
			return fs.SkipDir
		}
		if slices.ContainsFunc(shown, func(s string) bool { return under(s, p) }) || slices.Contains(scratch, p) {
			return nil // on the way to a shown path, or the sandbox's scratch
		}
		leak = p
		return fs.SkipAll
	})
	return leak
}

func checkExpect(e *checkEnv) []Result {
	var res []Result
	for _, p := range e.want.Unreadable {
		name := "expect.unreadable:" + p
		if readable(p) {
			res = append(res, fail(name, "open of %s worked", p))
		} else {
			res = append(res, pass(name, "open of %s refused or absent", p))
		}
	}
	res = append(res, checkSnapshots(e.want.Unreadable)...)
	for _, p := range e.want.Unwritable {
		name := "expect.unwritable:" + p
		if err := tryCreate(p); err == nil {
			res = append(res, fail(name, "write to %s worked", p))
		} else {
			res = append(res, pass(name, "write to %s: %v", p, err))
		}
	}
	for _, u := range e.want.Unreachable {
		name := "expect.unreachable:" + u
		network, addr, ok := strings.Cut(u, ":")
		switch {
		case !ok || (network != "tcp" && network != "udp" && network != "unix"):
			res = append(res, fail(name, "%q is not tcp:, udp: or unix: followed by an address", u))
		case network == "udp":
			res = append(res, dnsLike(name, addr))
		default:
			out, d := tryDial(network, addr, netTimeout)
			res = append(res, reachResult(name, "connect to "+u, out, d))
		}
	}
	return res
}

// dnsLike sends a datagram to addr and fails the check if anything comes
// back. UDP has no handshake, so an answer is the only proof of reach.
func dnsLike(name, addr string) Result {
	c, err := dialTimeout("udp", addr, netTimeout)
	if err != nil {
		return pass(name, "udp:%s: %v", addr, err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(netTimeout)); err != nil {
		return pass(name, "udp:%s: %v", addr, err)
	}
	if _, err := c.Write(dnsQuery); err != nil {
		return pass(name, "udp:%s: %v", addr, err)
	}
	var buf [512]byte
	if n, err := c.Read(buf[:]); err == nil {
		return fail(name, "udp:%s answered with %d bytes", addr, n)
	}
	return pass(name, "udp:%s gave no answer", addr)
}
