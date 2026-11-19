package sandbox

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/net/route"
)

// defaultGateway returns the IPv4 default route's gateway from the routing
// table.
func defaultGateway() (string, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return "", err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return "", err
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= syscall.RTAX_GATEWAY || rm.Flags&syscall.RTF_GATEWAY == 0 {
			continue
		}
		dst, ok1 := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		gw, ok2 := rm.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr)
		if ok1 && ok2 && dst.IP == [4]byte{} {
			return net.IP(gw.IP[:]).String(), nil
		}
	}
	return "", errors.New("no default route")
}
