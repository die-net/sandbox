//go:build !darwin

package sandbox

// defaultCover lists the host paths every sandbox has hidden: people's homes,
// and the places services keep their state, sockets, and temporary files.
var defaultCover = []string{"/home", "/root", "/run", "/tmp", "/var", "/mnt", "/media", "/dev/shm", "/.snapshots", "/sysroot"}

// The default covers end with two that hold another view of the host's
// files rather than files of their own: snapper's btrfs snapshots, and the
// physical root of an ostree host, where /var and /home also are.

// canonicalName returns the name a path is matched by, which is its own here.
func canonicalName(p string) string { return p }
