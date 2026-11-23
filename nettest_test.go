package sandbox

import (
	"context"
	"net"
)

// The tests start listeners from helpers and from the processes they run
// inside a sandbox, none of which has a context of its own to give.

// listenLocal listens on a free TCP port of the loopback, with a context that
// is never canceled.
func listenLocal() (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
}
