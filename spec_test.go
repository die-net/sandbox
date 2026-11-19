package sandbox

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func TestCovers(t *testing.T) {
	for _, tc := range []struct {
		name               string
		paths, binds, want []string
	}{
		{"nested covers", []string{"/var", "/var/lib", "/home"}, nil, []string{"/home", "/var"}},
		{"a prefix that is not a parent", []string{"/users/aaron", "/users/aaron/.config/app", "/users/aaronx"}, nil, []string{"/users/aaron", "/users/aaronx"}},
		{"duplicates", []string{"/tmp", "/tmp"}, nil, []string{"/tmp"}},
		{
			"a cover inside a bind inside a cover",
			[]string{"/home", "/home/agent", "/home/agent/.claude/projects", "/home/agent/.claude/projects/old/x"},
			[]string{"/home/agent", "/home/agent/.claude/projects/a"},
			[]string{"/home", "/home/agent/.claude/projects"},
		},
		// A home outside every default cover that is also a person's home,
		// as the account's own is when it is the sandbox's. Covering it
		// would make the bind on top of it read-only.
		{"a cover that is the home", []string{"/srv/app", "/tmp"}, []string{"/srv/app"}, []string{"/tmp"}},
		{"a cover inside a read path that is a cover", []string{"/opt/tool", "/opt/tool/secret"}, []string{"/opt/tool"}, []string{"/opt/tool/secret"}},
	} {
		if got := covers(tc.paths, tc.binds); !slices.Equal(got, tc.want) {
			t.Errorf("%s: covers = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// fakeHost returns a host with dirs, files, and links, given as absolute
// paths.
func fakeHost(dirs, files []string, links map[string]string) fstest.MapFS {
	host := fstest.MapFS{}
	for _, d := range dirs {
		host[strings.TrimPrefix(d, "/")] = &fstest.MapFile{Mode: fs.ModeDir | 0o755}
	}
	for _, f := range files {
		host[strings.TrimPrefix(f, "/")] = &fstest.MapFile{}
	}
	for l, target := range links {
		host[strings.TrimPrefix(l, "/")] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(target)}
	}
	return host
}

func TestResolve(t *testing.T) {
	host := fakeHost(
		[]string{"/run/app", "/srv/app/state", "/home/agent/.claude/projects/a", "/data"},
		[]string{"/srv/app/state/db"},
		map[string]string{
			"/var/run":                       "/run",
			"/state":                         "../srv/app/state",
			"/home/agent/.claude/projects/b": "/srv/app/state",
			"/home/agent/data":               "/data",
			"/loop":                          "/loop",
		},
	)
	writable := []string{"/home/agent"}
	for _, tc := range []struct {
		name, path, want string
		missing, refused bool
	}{
		{name: "plain", path: "/run/app", want: "/run/app"},
		{name: "an absolute link", path: "/var/run/app", want: "/run/app"},
		{name: "a relative link", path: "/state/db", want: "/srv/app/state/db"},
		{name: "dot dot after a link", path: "/var/run/../srv", want: "/srv"},
		{name: "inside a writable directory", path: "/home/agent/.claude/projects/a", want: "/home/agent/.claude/projects/a"},
		{name: "a planted link", path: "/home/agent/.claude/projects/b", refused: true},
		{name: "through a planted link", path: "/home/agent/data/x", refused: true},
		{name: "missing", path: "/run/gone", missing: true},
		{name: "a loop", path: "/loop", refused: true},
		{name: "relative", path: "run", refused: true},
	} {
		got, err := resolve(host, tc.path, writable)
		switch {
		case tc.missing:
			if !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s: resolve = %q, %v, want not found", tc.name, got, err)
			}
		case tc.refused:
			if err == nil || errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s: resolve = %q, %v, want refused", tc.name, got, err)
			}
		case err != nil || got != tc.want:
			t.Errorf("%s: resolve = %q, %v, want %q", tc.name, got, err, tc.want)
		}
	}
}

func TestPrepare(t *testing.T) {
	host := fakeHost(
		[]string{
			"/home", "/root", "/run", "/tmp", "/var", "/mnt", "/dev/shm", "/srv/app/state/servers/a",
			"/users/aaron", "/srv/agent/.claude/projects/a", "/srv/agent/.claude/projects/b",
		},
		[]string{"/var/lib/sgml-base/supercatalog"},
		map[string]string{
			"/var/run":          "/run",
			"/state":            "/srv/app/state",
			"/etc/sgml/catalog": "/var/lib/sgml-base/supercatalog",
		},
	)
	spec, err := prepare(Spec{
		Command: []string{"true"},
		Home:    "/srv/app/state/servers/a",
		Write:   []string{"/gone"},
		Cover:   []string{"/state", "/var/run"},
	}, []string{"/users/aaron"}, host, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/dev/shm", "/home", "/mnt", "/root", "/run", "/srv/app/state", "/tmp", "/users/aaron", "/var"}
	if !slices.Equal(spec.Cover, want) {
		t.Errorf("Cover = %q, want %q", spec.Cover, want)
	}
	if len(spec.Write) != 0 {
		t.Errorf("Write = %q, want a missing path dropped", spec.Write)
	}
	if want := []string{"/var/lib/sgml-base/supercatalog"}; !slices.Equal(spec.Read, want) {
		t.Errorf("Read = %q, want %q", spec.Read, want)
	}

	for _, tc := range []struct{ dir, want string }{
		{"/srv/app/state/servers/a", "/srv/app/state/servers/a"},
		{"/srv/agent", "/srv/agent"},
		{"/state/servers/a", "/srv/app/state/servers/a"},
	} {
		spec, err := prepare(Spec{Command: []string{"true"}, Home: "/srv/app/state/servers/a", Dir: tc.dir}, nil, host, nil)
		if err != nil {
			t.Errorf("dir %s: %v", tc.dir, err)
		} else if spec.Dir != tc.want {
			t.Errorf("dir %s: Dir = %q, want %q", tc.dir, spec.Dir, tc.want)
		}
	}

	planted := fakeHost(
		[]string{"/home", "/srv/agent/.claude/projects", "/srv/app/state"},
		nil,
		map[string]string{"/srv/agent/.claude/projects/a": "/srv/app/state"},
	)
	moved := fakeHost([]string{"/home", "/srv/agent/.claude-moved/projects/a"}, nil, nil)
	for _, tc := range []struct {
		name string
		host fstest.MapFS
		spec Spec
	}{
		{"no command", host, Spec{Home: "/h"}},
		{"no home", host, Spec{Command: []string{"true"}}},
		{"missing home", host, Spec{Command: []string{"true"}, Home: "/gone"}},
		{"relative write", host, Spec{Command: []string{"true"}, Home: "/home", Write: []string{"x"}}},
		{"relative dir", host, Spec{Command: []string{"true"}, Home: "/home", Dir: "x"}},
		{"a dir under a cover", host, Spec{Command: []string{"true"}, Home: "/srv/agent", Dir: "/var"}},
		{"a dir under a cover inside a read path", host, Spec{Command: []string{"true"}, Home: "/home", Read: []string{"/srv/agent"}, Cover: []string{"/srv/agent/.claude"}, Dir: "/srv/agent/.claude/projects"}},
		{"a missing dir", host, Spec{Command: []string{"true"}, Home: "/srv/agent", Dir: "/srv/gone"}},
		{"a dir through a link the sandbox planted", planted, Spec{Command: []string{"true"}, Home: "/srv/agent", Dir: "/srv/agent/.claude/projects/a"}},
		{"unknown kernel", host, Spec{Command: []string{"true"}, Home: "/home", Kernel: "none"}},
		{
			"a write path through a link the sandbox planted", planted,
			Spec{Command: []string{"true"}, Home: "/srv/agent", Write: []string{"/srv/agent/.claude/projects/a"}},
		},
		{
			"a home through a link", planted,
			Spec{Command: []string{"true"}, Home: "/srv/agent/.claude/projects/a"},
		},
		{
			"a cover a sandbox moved away", moved,
			Spec{Command: []string{"true"}, Home: "/srv/agent", Cover: []string{"/srv/agent/.claude/projects"}},
		},
		{
			"a cover inside the home", host,
			Spec{Command: []string{"true"}, Home: "/srv/agent", Cover: []string{"/srv/agent/.claude/projects"}},
		},
		{
			"a write path inside the home", host,
			Spec{Command: []string{"true"}, Home: "/srv/agent", Write: []string{"/srv/agent/.claude/projects/a"}},
		},
		{
			"a read path inside a write path", host,
			Spec{Command: []string{"true"}, Home: "/home", Write: []string{"/srv/agent"}, Read: []string{"/srv/agent/.claude"}},
		},
	} {
		if _, err := prepare(tc.spec, nil, tc.host, nil); err == nil {
			t.Errorf("%s: prepare succeeded", tc.name)
		}
	}
}

func TestParseMountinfo(t *testing.T) {
	table := `4449 3733 0:60 / / rw,relatime shared:2207 master:81 - zfs rpool/data/subvol-7002-disk-0 rw,xattr
4450 4449 0:86 / /users/aaron rw,nosuid shared:2208 - zfs raft/users/aaron rw
4512 4449 0:60 /home /srv/old\040homes rw - zfs rpool/data/subvol-7002-disk-0 rw
`
	got, err := parseMountinfo(strings.NewReader(table))
	if err != nil {
		t.Fatal(err)
	}
	want := []mount{
		{dev: "0:60", root: "/", point: "/", fsType: "zfs"},
		{dev: "0:86", root: "/", point: "/users/aaron", fsType: "zfs"},
		{dev: "0:60", root: "/home", point: "/srv/old homes", fsType: "zfs"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseMountinfo = %+v, want %+v", got, want)
	}
	if _, err := parseMountinfo(strings.NewReader("1 2 3\n")); err == nil {
		t.Error("parseMountinfo took a malformed line")
	}
}

func TestMountCovers(t *testing.T) {
	mounts := []mount{
		// A root on ZFS, as on a Proxmox container.
		{dev: "0:60", root: "/", point: "/", fsType: "zfs"},
		// A dataset of the sandbox's own home, whose snapshots it may see.
		{dev: "0:61", root: "/", point: "/srv/agent", fsType: "zfs"},
		// The root filesystem's /home shown again elsewhere, as a bind.
		{dev: "0:60", root: "/home", point: "/export/homes", fsType: "zfs"},
		// One home alone shown elsewhere.
		{dev: "0:60", root: "/home/aaron", point: "/mnt/aaron", fsType: "zfs"},
		// An ostree host's physical root, which holds /var's files.
		{dev: "8:3", root: "/ostree/deploy/os/var", point: "/var", fsType: "xfs"},
		{dev: "8:3", root: "/", point: "/sysroot", fsType: "xfs"},
		// Another filesystem entirely.
		{dev: "0:99", root: "/", point: "/data", fsType: "ext4"},
	}
	got := mountCovers([]string{"/home", "/var/lib/app"}, []string{"/srv/agent"}, mounts)
	slices.Sort(got)
	want := []string{"/.zfs", "/export/homes", "/mnt/aaron", "/sysroot/ostree/deploy/os/var/lib/app"}
	if !slices.Equal(got, want) {
		t.Errorf("mountCovers = %q, want %q", got, want)
	}
}

func TestLinkedFiles(t *testing.T) {
	host := fakeHost(
		nil,
		[]string{
			"/etc/hosts", "/run/systemd/resolve/stub-resolv.conf", "/run/systemd/resolve/resolv.conf",
			"/var/lib/sgml-base/supercatalog", "/usr/lib/os-release", "/srv/app/config.yaml",
			"/home/aaron/notes", "/var/lib/state/db",
		},
		map[string]string{
			"/etc/resolv.conf":     "/run/systemd/resolve/stub-resolv.conf",
			"/etc/resolv.conf.old": "/run/systemd/resolve/stub-resolv.conf",
			"/etc/sgml/catalog":    "/var/lib/sgml-base/supercatalog",
			"/etc/os-release":      "/usr/lib/os-release",
			"/etc/app":             "/srv/app/config.yaml",
			"/etc/notes":           "/home/aaron/notes",
			"/etc/state":           "/var/lib/state",
			"/etc/missing":         "/run/missing",
			// A relative link, and a chain through another link in /etc.
			"/etc/resolv.conf.rel":      "../run/systemd/resolve/resolv.conf",
			"/etc/alternatives/catalog": "/etc/sgml/catalog",
		},
	)
	got, err := linkedFiles(host, "etc", []string{"/home", "/run", "/var"}, []string{"/home/aaron", "/srv/app"})
	if err != nil {
		t.Fatal(err)
	}
	// os-release is not covered, config.yaml and notes are private, state
	// is a directory, and missing leads nowhere.
	want := []string{"/run/systemd/resolve/stub-resolv.conf", "/run/systemd/resolve/resolv.conf", "/var/lib/sgml-base/supercatalog"}
	if !slices.Equal(got, want) {
		t.Errorf("linkedFiles = %q, want %q", got, want)
	}
	if got, err := linkedFiles(fstest.MapFS{}, "etc", nil, nil); err != nil || len(got) != 0 {
		t.Errorf("linkedFiles with no /etc = %q, %v, want nothing", got, err)
	}
}

func TestAccountHomes(t *testing.T) {
	owners := map[string]uint64{
		"/": 0, "/bin": 0, "/usr/sbin": 0, "/usr/games": 0, "/root": 0,
		"/var/cache/man": 6,
		"/users/aaron":   1000, "/users/bob": 1001,
		"/opt/alice": 1002, "/srv/shared": 0, "/srv/carol-home": 1004,
		"/usr/dave": 1005,
	}
	owner := func(p string) (uint64, error) {
		if uid, ok := owners[p]; ok {
			return uid, nil
		}
		return 0, fs.ErrNotExist
	}
	for _, tc := range []struct {
		name, passwd string
		want         []string
	}{
		{
			"system homes owned by root",
			"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nbin:x:2:2::/bin:/usr/sbin/nologin\n" +
				"games:x:5:60::/usr/games:/usr/sbin/nologin\nman:x:6:12::/var/cache/man:/usr/sbin/nologin\ncoredump:x:999:999::/:/usr/sbin/nologin\n",
			[]string{"/root", "/var/cache/man"},
		},
		{
			"a directory of homes",
			"aaron:x:1000:1000::/users/aaron:/bin/bash\nbob:x:1001:1001::/users/bob/:/bin/bash\n",
			[]string{"/users", "/users"},
		},
		{
			"one home under a prefix",
			"aaron:x:1000:1000::/users/aaron:/bin/bash\nalice:x:1002:1002::/opt/alice:/bin/bash\n",
			[]string{"/users/aaron", "/opt/alice"},
		},
		{
			"homes the account does not own, or that are missing",
			"bob:x:1003:1003::/srv/shared:/bin/bash\neve:x:1006:1006::/users/eve:/bin/bash\n",
			nil,
		},
		{
			"a home not named for its account",
			"aaron:x:1000:1000::/users/aaron:/bin/bash\ncarol:x:1004:1004::/srv/carol-home:/bin/bash\n",
			[]string{"/users/aaron", "/srv/carol-home"},
		},
		{
			"a root-owned home does not make its prefix a directory of homes",
			"games:x:5:60::/usr/games:/usr/sbin/nologin\ndave:x:1005:1005::/usr/dave:/bin/bash\n",
			[]string{"/usr/dave"},
		},
		{
			"comments, NIS lines, and malformed entries",
			"# comment\n+::::::\naaron:x:1000:1000::/users/aaron\nbob:x:bob:1001::/users/bob:/bin/bash\nx:x:1001:1001::users/bob:/bin/bash\n",
			nil,
		},
	} {
		if got := accountHomes([]byte(tc.passwd), owner); !slices.Equal(got, tc.want) {
			t.Errorf("%s: accountHomes = %q, want %q", tc.name, got, tc.want)
		}
	}
}
