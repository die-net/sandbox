package sandbox

import (
	"os"
	"strings"
	"sync"
)

// defaultCover lists the host paths every sandbox has hidden on macOS:
// people's homes, other volumes, and /private/var and /private/tmp, which
// hold the per-user temporary and cache directories, the sockets of system
// services, and the state of the system's databases. /var and /tmp are links
// to them, and Seatbelt matches a path by where it leads, so the real names
// are the ones to list. /System/Volumes/Data is the same files again under
// another name, and Seatbelt follows that firmlink as well, which
// TestEscapeDefaultCovers checks.
var defaultCover = []string{"/Users", "/Volumes", "/private/var", "/private/tmp"}

// coverAliases are the links that lead to a default cover. /etc has links
// such as /etc/localtime that lead to /var/db/timezone/..., a path that
// is covered but does not start with the cover's real name.
var coverAliases = []string{"/var", "/tmp"}

// dataVolume is where the system volume's firmlinked directories really live.
// /System/Volumes/Data/Users is the same directory as /Users, and Seatbelt
// matches the name /Users, so a rule for the other name matches nothing: a
// Cover written that way covered nothing, silently.
const dataVolume = "/System/Volumes/Data"

// firmlinks are the top-level paths the system volume takes from the data
// volume, which /usr/share/firmlinks lists. This is the list as of macOS 27,
// for a host where that file cannot be read.
var firmlinks = sync.OnceValue(func() []string {
	fallback := []string{
		"/AppleInternal", "/Applications", "/Library", "/Users", "/Volumes", "/cores", "/opt", "/pkg", "/private",
		"/usr/local", "/usr/libexec/cups", "/usr/share/snmp",
		"/System/Library/Caches", "/System/Library/Assets", "/System/Library/PreinstalledAssets",
		"/System/Library/AssetsV2", "/System/Library/PreinstalledAssetsV2", "/System/Library/Speech",
		"/System/Library/CoreServices/CoreTypes.bundle/Contents/Library",
	}
	b, err := os.ReadFile("/usr/share/firmlinks")
	if err != nil {
		return fallback
	}
	var out []string
	for line := range strings.Lines(string(b)) {
		if f, _, ok := strings.Cut(line, "\t"); ok && strings.HasPrefix(f, "/") {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
})

// canonicalName returns the name Seatbelt matches for p: p without its
// /System/Volumes/Data prefix where what follows is a firmlinked directory, and
// p as it is otherwise, since a path that exists only on the data volume has
// no other name.
func canonicalName(p string) string {
	rest, ok := strings.CutPrefix(p, dataVolume+"/")
	if !ok {
		return p
	}
	rest = "/" + rest
	for _, f := range firmlinks() {
		if within(rest, f) {
			return rest
		}
	}
	return p
}
