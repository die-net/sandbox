package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Spec describes one sandbox: the command it runs and the host paths it
// sees.
type Spec struct {
	// Command is the program to run and its arguments. A program name
	// without a slash is looked up on PATH inside the sandbox.
	Command []string `json:"command"`
	// Home is the sandbox's own directory. It is writable, and it is the
	// command's HOME.
	Home string `json:"home"`
	// Dir is the command's working directory. Empty means Home, except
	// that Run uses the directory it is called from, so a caller that
	// starts each command in a directory of its own, as the runner does a
	// turn's scratch directory, needs no flag naming it. Either way it must
	// be a directory the sandbox shows from the host: its home, a Write or
	// Read path, or a path no cover hides. It is followed through a link only where the link
	// lies outside every directory a sandbox can write.
	Dir string `json:"dir,omitempty"`
	// Write lists more host paths the command may write. A socket listed
	// here is one the command may connect to, such as a bridge socket.
	Write []string `json:"write,omitempty"`
	// Read lists host paths the command may read even where they lie under
	// a covered path, such as an install directory under a home.
	Read []string `json:"read,omitempty"`
	// Cover lists host paths to hide in addition to defaultCover, such as
	// the caller's own config and state.
	Cover []string `json:"cover,omitempty"`
	// Kernel is how much of the kernel the command may reach. Empty means
	// KernelStrict.
	Kernel Kernel `json:"kernel,omitempty"`
	// Network is what the command can reach. The zero value is
	// NetworkNone.
	Network Network `json:"network,omitempty"`
	// Services and BroadLoopback only mean something on macOS, and Linux
	// ignores them.
	Services      []Service `json:"services,omitempty"`
	BroadLoopback bool      `json:"broad_loopback,omitempty"`
	// Listen is how many TCP listeners the caller serves for the command,
	// which reaches them on ListenAddrs. On Linux the first stage binds
	// them on 127.0.0.1 in the sandbox's own network namespace, from port
	// 3128 up, so it needs NetworkNone, and Listeners returns them once
	// Start has. It may not exceed maxListen.
	Listen int `json:"listen,omitempty"`
	// Loopback is how many loopback TCP ports the command may bind and dial
	// itself, which LoopbackPorts gives. On Linux the loopback is private
	// to the sandbox under NetworkNone, and the ports are fixed, from 4444
	// up. It may not exceed maxListen either.
	Loopback int `json:"loopback,omitempty"`
	// Files are the descriptors the command gets as 3, 4, and so on. The
	// caller keeps them open, and closes them when it likes after Start.
	//
	// A descriptor grants whatever its object's owner and mode let the
	// sandbox's uid do, whatever mode it was opened in and whatever the
	// sandbox covers. On Linux the command can reopen a file through
	// /proc/self/fd/N with more access: a file under a covered directory
	// that was opened read-only can be opened for writing and overwritten.
	// Where that matters, pass a pipe or a socket, which cannot be reopened,
	// not a file.
	Files []*os.File `json:"-"`
	// Rlimits are the resource limits pid 1 sets before it starts the
	// command, and so holds itself as well.
	Rlimits []Rlimit `json:"rlimits,omitempty"`
	// Hostname is the sandbox's hostname on Linux. Empty means "sandbox".
	Hostname string `json:"hostname,omitempty"`
	// ScratchSize is the size in bytes of each private tmpfs (/tmp,
	// /var/tmp and /dev/shm) on Linux. Zero means 1 GiB, and a negative
	// size is an error. Nothing else the sandbox can write is a tmpfs, since
	// the rest of /dev is read-only. It bounds files only: memfd_create and
	// anonymous shared memory are not files on those tmpfs, and only a
	// delegated cgroup's memory.max (Cmd.CgroupFD) bounds them.
	ScratchSize int64 `json:"scratch_size,omitempty"`
}

// maxListen is the most Listen and Loopback may each be, which keeps their
// fixed Linux ports apart.
const maxListen = 1000

// Network is what a sandbox's command can reach of the network.
type Network int

const (
	// NetworkNone gives the command a network namespace of its own with
	// only a loopback, private to it, which also makes the host's abstract
	// sockets unreachable. It is the zero value.
	NetworkNone Network = iota
	// NetworkHost shares the host's network, with the host's loopback and
	// abstract sockets. It must be asked for.
	NetworkHost
)

// String returns n's name, for a flag's default.
func (n *Network) String() string {
	switch {
	case n == nil || *n == NetworkNone:
		return "none"
	case *n == NetworkHost:
		return "host"
	}
	return fmt.Sprintf("Network(%d)", int(*n))
}

// Set sets n from a flag's value, refusing a name it does not know.
func (n *Network) Set(v string) error {
	switch v {
	case "none":
		*n = NetworkNone
	case "host":
		*n = NetworkHost
	default:
		return fmt.Errorf("network %q is not none or host", v)
	}
	return nil
}

// Service is a reviewed group of macOS Mach services a sandbox may look up.
// None are defined yet, and Linux ignores the field.
type Service string

// Resource is a limit Rlimit sets.
type Resource int

const (
	// ResourceCPU is CPU seconds, RLIMIT_CPU.
	ResourceCPU Resource = iota + 1
	// ResourceFileSize is the largest file a process may write,
	// RLIMIT_FSIZE.
	ResourceFileSize
	// ResourceCore is the largest core file, RLIMIT_CORE.
	ResourceCore
	// ResourceOpenFiles is the most open descriptors, RLIMIT_NOFILE.
	ResourceOpenFiles
	// ResourceProcesses is the most processes the account may have,
	// counting every process of its uid on the host, RLIMIT_NPROC.
	ResourceProcesses
	// ResourceAddressSpace is the most virtual memory a process may map,
	// RLIMIT_AS.
	ResourceAddressSpace
)

// Rlimit is one resource limit. A limit of [math.MaxUint64] is none.
type Rlimit struct {
	Resource Resource `json:"resource"`
	Soft     uint64   `json:"soft"`
	Hard     uint64   `json:"hard"`
}

// checkRequest checks the parts of spec that need no host: the
// network and listener counts, the limits, and the files. It is shared by
// every backend.
func (s Spec) checkRequest() error {
	if len(s.Command) == 0 {
		return errors.New("no command")
	}
	if s.Network != NetworkNone && s.Network != NetworkHost {
		return fmt.Errorf("unknown network %d", int(s.Network))
	}
	if s.Listen < 0 || s.Listen > maxListen || s.Loopback < 0 || s.Loopback > maxListen {
		return fmt.Errorf("listen and loopback must each be from 0 to %d", maxListen)
	}
	if s.Network == NetworkHost && (s.Listen > 0 || s.Loopback > 0) {
		return errors.New("listeners and loopback ports need NetworkNone, since the host's network has no private loopback")
	}
	if s.ScratchSize < 0 {
		return fmt.Errorf("scratch size %d is negative", s.ScratchSize)
	}
	for _, f := range s.Files {
		if f == nil {
			return errors.New("a nil file in Files")
		}
	}
	for _, r := range s.Rlimits {
		if r.Resource < ResourceCPU || r.Resource > ResourceAddressSpace {
			return fmt.Errorf("unknown resource %d", int(r.Resource))
		}
		if r.Soft > r.Hard {
			return fmt.Errorf("limit %d has a soft limit above its hard limit", int(r.Resource))
		}
	}
	return nil
}

// Kernel is how much of the kernel's system calls a sandbox may reach.
type Kernel string

const (
	// KernelStrict allows the system calls ordinary programs make, and no
	// namespaces or mounts.
	KernelStrict Kernel = "strict"
	// KernelNested also allows user namespaces, mounts, and chroot, for
	// software that runs a sandbox of its own, such as Chromium.
	KernelNested Kernel = "nested"
	// KernelOpen gives up the system call allowlist. It still refuses
	// other ABIs and the ioctls that type into a terminal.
	KernelOpen Kernel = "open"
)

// String returns k's name, for a flag's default.
func (k *Kernel) String() string {
	if k == nil {
		return ""
	}
	return string(*k)
}

// Set sets k from a flag's value, refusing a name it does not know.
func (k *Kernel) Set(v string) error {
	switch Kernel(v) {
	case KernelStrict, KernelNested, KernelOpen:
		*k = Kernel(v)
		return nil
	}
	return fmt.Errorf("kernel %q is not strict, nested, or open", v)
}

// defaultCover lists the host paths every sandbox has hidden: people's homes,
// and the places services keep their state, sockets, and temporary files.
var defaultCover = []string{"/home", "/root", "/run", "/tmp", "/var", "/mnt", "/media", "/dev/shm", "/.snapshots", "/sysroot"}

// The default covers end with two that hold another view of the host's
// files rather than files of their own: snapper's btrfs snapshots, and the
// physical root of an ostree host, where /var and /home also are.

// prepare checks spec and returns it with every path absolute, clean, and
// with symlinks resolved. Cover gains the defaults and homes, the people's
// homes found on the host, which may live outside /home, and loses each cover
// that another already hides. Read gains the files that links in the host's
// /etc lead to under a default cover. host is the host's root, as [os.DirFS]
// gives it, and mounts is its mount table, which shows where else a covered
// file can be reached.
//
// The home and the Write paths are what some sandbox can write, so a link
// inside one of them may have been planted by an earlier run to point this
// one at the caller's data. They must have no link in them at all, and every
// other path is resolved without following a link inside one of them, a cover inside one of them that has gone missing is refused, since
// a sandbox could have moved it away to uncover what it hid, and so is any
// other path inside one of them, since bubblewrap would mount on it.
func prepare(spec Spec, homes []string, host fs.FS, mounts []mount) (Spec, error) {
	if len(spec.Command) == 0 {
		return Spec{}, errors.New("no command")
	}
	if spec.Home == "" {
		return Spec{}, errors.New("no home directory")
	}
	if spec.Kernel == "" {
		spec.Kernel = KernelStrict
	}
	if err := spec.Kernel.Set(string(spec.Kernel)); err != nil {
		return Spec{}, err
	}
	if spec.Dir != "" && !filepath.IsAbs(spec.Dir) {
		return Spec{}, fmt.Errorf("working directory %q is not absolute", spec.Dir)
	}
	home, err := realPath(host, spec.Home)
	if errors.Is(err, fs.ErrNotExist) {
		return Spec{}, fmt.Errorf("home directory %s does not exist", spec.Home)
	}
	if err != nil {
		return Spec{}, err
	}
	var write []string
	for _, w := range spec.Write {
		r, err := realPath(host, w)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return Spec{}, err
		}
		write = append(write, r)
	}
	spec.Write = write
	writable := append([]string{home}, write...)
	if spec.Read, err = resolveAll(host, spec.Read, writable, nil); err != nil {
		return Spec{}, err
	}
	shared, err := resolveAll(host, defaultCover, writable, nil)
	if err != nil {
		return Spec{}, err
	}
	private, err := resolveAll(host, slices.Concat(spec.Cover, homes), writable, writable)
	if err != nil {
		return Spec{}, err
	}
	elsewhere, err := resolveAll(host, mountCovers(slices.Concat(shared, private), writable, mounts), writable, nil)
	if err != nil {
		return Spec{}, err
	}
	spec.Home = home
	binds := slices.Concat([]string{home}, spec.Write, spec.Read)
	spec.Cover = covers(slices.Concat(shared, private, elsewhere), binds)
	linked, err := linkedFiles(host, "etc", shared, slices.Concat(private, []string{home}, spec.Write))
	if err != nil {
		return Spec{}, err
	}
	for _, f := range linked {
		if !slices.Contains(spec.Read, f) {
			spec.Read = append(spec.Read, f)
		}
	}
	// bubblewrap before 0.12.0 follows a link it finds while it makes a
	// mount point (CVE-2026-87766), so no mount may land inside content a
	// sandbox could have written, where it could have planted one.
	for _, p := range slices.Concat(spec.Write, spec.Read, spec.Cover) {
		for _, w := range slices.Concat([]string{home}, spec.Write) {
			if p != w && within(p, w) {
				return Spec{}, fmt.Errorf("%s lies inside %s, which a sandbox can write, so nothing may be mounted there", p, w)
			}
		}
	}
	if spec.Dir != "" {
		dir, err := resolve(host, spec.Dir, writable)
		if err != nil {
			return Spec{}, fmt.Errorf("working directory: %w", err)
		}
		if !shown(dir, binds, spec.Cover) {
			return Spec{}, fmt.Errorf("working directory %s lies under a covered path", spec.Dir)
		}
		spec.Dir = dir
	}
	return spec, nil
}

// shown reports whether the view shows p from the host: the nearest path at
// or above p that the view mounts something on is one of binds, or there is
// none and the host's root shows it.
func shown(p string, binds, covered []string) bool {
	var nearest string
	ok := true
	for _, b := range binds {
		if within(p, b) && len(b) > len(nearest) {
			nearest, ok = b, true
		}
	}
	for _, c := range covered {
		if within(p, c) && len(c) > len(nearest) {
			nearest, ok = c, false
		}
	}
	return ok
}

// realPath returns p, absolute and clean, and refuses it if a link lies
// anywhere in it. A path a sandbox will write must be named this way: a
// sandbox that could write a directory on the way, as a turn's CLI can
// write the scratch directory that holds its shell commands' directory,
// could have planted the link, and nothing here can tell one from a link
// the operator made.
func realPath(host fs.FS, p string) (string, error) {
	r, err := resolve(host, p, nil)
	if err != nil {
		return "", err
	}
	if r != filepath.Clean(p) {
		return "", fmt.Errorf("%s leads through a link to %s, so it cannot be one a sandbox writes; name its real path", p, r)
	}
	return r, nil
}

// resolveAll resolves each of paths, as resolve does with writable, and
// drops one that does not exist, unless it lies inside one of keep.
func resolveAll(host fs.FS, paths, writable, keep []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		r, err := resolve(host, p, writable)
		if errors.Is(err, fs.ErrNotExist) {
			if slices.ContainsFunc(keep, func(k string) bool { return within(filepath.Clean(p), k) }) {
				return nil, fmt.Errorf("%s is missing from a directory a sandbox can write, which could have moved it", p)
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// maxLinks is how many links resolve follows in one path, as the kernel's
// own limit is.
const maxLinks = 40

// resolve returns p, an absolute path, with every link in it followed, as
// host shows the host's root. It refuses to follow a link that lies inside
// one of writable, rather than resolve to wherever the link leads. A path
// that does not exist gives an error that wraps [fs.ErrNotExist].
func resolve(host fs.FS, p string, writable []string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("path %q is not absolute", p)
	}
	done := "/"
	rest := strings.Split(p, "/")
	for links := 0; len(rest) > 0; {
		name := rest[0]
		rest = rest[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			done = filepath.Dir(done)
			continue
		}
		next := filepath.Join(done, name)
		fi, err := fs.Lstat(host, strings.TrimPrefix(next, "/"))
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", p, err)
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			done = next
			continue
		}
		if slices.ContainsFunc(writable, func(w string) bool { return within(next, w) }) {
			return "", fmt.Errorf("resolve %s: %s is a link inside a directory a sandbox can write", p, next)
		}
		links++
		if links > maxLinks {
			return "", fmt.Errorf("resolve %s: more than %d links", p, maxLinks)
		}
		target, err := fs.ReadLink(host, strings.TrimPrefix(next, "/"))
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", p, err)
		}
		if filepath.IsAbs(target) {
			done = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	return done, nil
}

// linkedFiles returns the regular files that links under dir in host lead to
// inside shared, the paths every sandbox has covered, and not inside private,
// which holds the caller's data, people's homes, and the sandbox's own
// directories. The view binds them back read-only, since a covered target
// breaks the link: Ubuntu's /etc/resolv.conf leads into /run, and without it
// a resolver falls back to a nameserver that is not there. A link to a
// directory is left out, so a link never uncovers a whole tree, and so is a
// directory the walk cannot read.
//
// Resolving every link fully cost 18 ms on a Debian host with 549 links in
// /etc, most of them into /usr, so a link is resolved only where its own
// target lies under shared. A chain through another link in /etc is still
// found, since that link is checked too, but a chain through a link
// elsewhere that leads under shared is not.
func linkedFiles(host fs.FS, dir string, shared, private []string) ([]string, error) {
	under := func(p string, paths []string) bool {
		return slices.ContainsFunc(paths, func(c string) bool { return within(p, c) })
	}
	var files []string
	err := fs.WalkDir(host, dir, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		next, err := fs.ReadLink(host, name)
		if err != nil {
			return nil
		}
		if !filepath.IsAbs(next) {
			next = "/" + filepath.Join(filepath.Dir(name), next)
		}
		if !under(filepath.Clean(next), shared) {
			return nil
		}
		target, err := resolve(host, "/"+name, nil)
		if err != nil || !under(target, shared) || under(target, private) || slices.Contains(files, target) {
			return nil
		}
		if fi, err := fs.Stat(host, strings.TrimPrefix(target, "/")); err == nil && fi.Mode().IsRegular() {
			files = append(files, target)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("find links in /%s: %w", dir, err)
	}
	return files, nil
}

// accountHomes returns the homes to cover for the accounts in passwd, which
// is in /etc/passwd's format. A home counts only where its account owns it,
// which leaves out the system directories that service accounts give as
// their homes, such as /bin and /usr/sbin. Where two or more of those homes
// are {prefix}/{username} with the same prefix, the prefix is a directory of
// homes and is covered whole, which also hides the homes of accounts passwd
// does not list. owner returns the uid that owns a path.
func accountHomes(passwd []byte, owner func(string) (uint64, error)) []string {
	type entry struct{ name, home string }
	var owned []entry
	perPrefix := map[string]int{}
	for line := range strings.Lines(string(passwd)) {
		fields := strings.Split(strings.TrimRight(line, "\n"), ":")
		if len(fields) < 7 || fields[0] == "" || strings.ContainsAny(fields[0][:1], "#+-") {
			continue
		}
		name, home := fields[0], filepath.Clean(fields[5])
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || !filepath.IsAbs(home) {
			continue
		}
		if o, err := owner(home); err != nil || o != uid {
			continue
		}
		owned = append(owned, entry{name, home})
		if dir := filepath.Dir(home); filepath.Base(home) == name && dir != "/" {
			perPrefix[dir]++
		}
	}
	homes := make([]string, 0, len(owned))
	for _, e := range owned {
		if dir := filepath.Dir(e.home); filepath.Base(e.home) == e.name && perPrefix[dir] >= 2 {
			homes = append(homes, dir)
		} else {
			homes = append(homes, e.home)
		}
	}
	return homes
}

// mount is one line of the host's mount table, /proc/self/mountinfo.
type mount struct {
	// dev is the filesystem's device, as major:minor. Two mounts with the
	// same dev show the same files.
	dev string
	// root is the directory of the filesystem the mount shows, and point
	// is where it shows it.
	root, point string
	fsType      string
}

// parseMountinfo reads mounts from r, in /proc/self/mountinfo's format.
func parseMountinfo(r io.Reader) ([]mount, error) {
	var mounts []mount
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		sep := slices.Index(fields, "-")
		if len(fields) < 5 || sep < 6 || sep+1 >= len(fields) {
			return nil, fmt.Errorf("read mount table: malformed line %q", sc.Text())
		}
		mounts = append(mounts, mount{
			dev:    fields[2],
			root:   unescapeMount(fields[3]),
			point:  unescapeMount(fields[4]),
			fsType: fields[sep+1],
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read mount table: %w", err)
	}
	return mounts, nil
}

// unescapeMount undoes the octal escapes the kernel writes in a mount
// table's paths for a space, tab, newline, or backslash.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountCovers returns more paths to cover, so that the files under covered
// cannot be reached another way: through the snapshots of every ZFS
// dataset, under its .zfs directory, or through another mount of the same
// filesystem that shows a covered path somewhere else, as a bind mount or an
// ostree host's /sysroot does. A dataset's .zfs inside a directory the
// sandbox can write is left alone, since its snapshots hold only what the
// sandbox can read there already.
func mountCovers(covered, writable []string, mounts []mount) []string {
	inside := func(p string, dirs []string) bool {
		return slices.ContainsFunc(dirs, func(d string) bool { return within(p, d) })
	}
	// rel is p relative to base, with a leading slash.
	rel := func(p, base string) string {
		if base == "/" {
			return p
		}
		return strings.TrimPrefix(p, base)
	}
	var out []string
	for _, m := range mounts {
		// A dataset's .zfs is only at its own root, so a bind of a
		// directory inside it has none.
		if dir := filepath.Join(m.point, ".zfs"); m.fsType == "zfs" && m.root == "/" && !inside(dir, writable) {
			out = append(out, dir)
		}
	}
	for _, c := range covered {
		// The mount c lies on is the one with the longest mount point
		// above it, and the last one listed where two share a point.
		var on mount
		found := false
		for _, m := range mounts {
			if within(c, m.point) && (!found || len(m.point) >= len(on.point)) {
				on, found = m, true
			}
		}
		if !found {
			continue
		}
		inFS := filepath.Join(on.root, rel(c, on.point))
		for _, m := range mounts {
			switch {
			case m == on || m.dev != on.dev:
			case within(inFS, m.root):
				out = append(out, filepath.Join(m.point, rel(inFS, m.root)))
			case within(m.root, inFS):
				out = append(out, m.point)
			}
		}
	}
	return out
}

// covers returns the paths to cover, sorted and without duplicates. A cover
// inside another is left out when nothing in binds lies between them, since
// the outer cover's empty tmpfs already hides it and holds nothing to mount
// it on. One inside a bind that is itself inside a cover stays, such as a
// secret inside a tool's directory that is bound back read-only.
//
// A cover at the same path as a bind is left out too. The bind shows that
// path whole, so the cover would hide nothing, and bubblewrap's remount of
// the cover read-only would land on the bind on top of it instead, making a
// writable home or write path read-only. Refusing the overlap instead would
// refuse a deployment whose sandbox home is the account's own home, which
// Run covers as one of people's homes.
func covers(paths, binds []string) []string {
	sorted := slices.Clone(paths)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	var out []string
	for _, c := range sorted {
		if slices.Contains(binds, c) {
			continue
		}
		// The nearest path above c that the view mounts something on
		// decides: a cover hides c already, and a bind shows it.
		var nearest string
		covered := false
		for _, p := range slices.Concat(out, binds) {
			if p != c && within(c, p) && len(p) > len(nearest) {
				nearest = p
				covered = slices.Contains(out, p)
			}
		}
		if !covered {
			out = append(out, c)
		}
	}
	return out
}

// within reports whether p is dir or lies under it.
func within(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}
