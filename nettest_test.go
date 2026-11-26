package sandbox

import (
	"context"
	"net"
	"strconv"
	"syscall"
	"testing"
)

// The tests start listeners from helpers and from the processes they run
// inside a sandbox, none of which has a context of its own to give.

// listenLocal listens on a free TCP port of the loopback, with a context that
// is never canceled.
func listenLocal() (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
}

// heldLocalAddr returns a loopback TCP address that nothing listens on, and
// that no listener can take until the test ends. A port freed by closing a
// listener can be handed at once to another test's listener, which then
// answers. Here the port is held by a socket that is bound but never listens,
// so a connection to it is refused and a listener can't bind it. The client end
// of an open connection would not do. On macOS a listener can still bind its
// port, since XNU's in_pcbbind looks only for sockets with no peer when the
// new one has SO_REUSEADDR, as Go's listeners do (seen in a run of this
// helper). The helper checks that a listener can't take the address.
func heldLocalAddr(t *testing.T) string {
	t.Helper()
	// Hold ForkLock while the descriptor is still inherited, as package net
	// does where there is no SOCK_CLOEXEC.
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	in4, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		t.Fatalf("getsockname gave %T", sa)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(in4.Port))
	var lc net.ListenConfig
	if l, err := lc.Listen(t.Context(), "tcp", addr); err == nil {
		t.Fatalf("a listener could take the held address %s (closing it: %v)", addr, l.Close())
	}
	return addr
}
