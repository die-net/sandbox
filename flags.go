package sandbox

import (
	"flag"
	"strings"
)

// RegisterFlags adds flags to fs that set s's fields, for a binary that
// offers the sandbox on its command line. The command to run is the
// arguments left after parsing, which the caller puts in s.Command.
func (s *Spec) RegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&s.Home, "home", "", "the sandbox's own directory, writable, and the command's HOME")
	fs.StringVar(&s.Dir, "dir", "", "the command's working directory; the current one when empty")
	fs.Var((*paths)(&s.Write), "write", "another host path the command may write, or a socket it may connect to; repeatable")
	fs.Var((*paths)(&s.Read), "read", "a host path the command may read even under a covered path; repeatable")
	fs.Var((*paths)(&s.Cover), "cover", "another host path to hide; repeatable")
	fs.Var(&s.Kernel, "kernel", "how much of the kernel the command may reach: strict, nested, or open; strict when empty")
	fs.Var(&s.Network, "network", "what the command can reach of the network: none, or host to share the host's; none when empty")
}

// paths is a flag that adds one path each time it is given.
type paths []string

func (p *paths) String() string {
	if p == nil {
		return ""
	}
	return strings.Join(*p, ",")
}

func (p *paths) Set(v string) error {
	*p = append(*p, v)
	return nil
}
