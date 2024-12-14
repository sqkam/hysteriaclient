package udphop

import (
	"context"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/component/resolver"

	"github.com/apernet/hysteria/extras/v2/utils"
)

type InvalidPortError struct {
	PortStr string
}

func (e InvalidPortError) Error() string {
	return fmt.Sprintf("%s is not a valid port number or range", e.PortStr)
}

// UDPHopAddr contains an IP address and a list of ports.
type UDPHopAddr struct {
	IP      net.IP
	Ports   []uint16
	PortStr string
}

func (a *UDPHopAddr) Network() string {
	return "udphop"
}

func (a *UDPHopAddr) String() string {
	return net.JoinHostPort(a.IP.String(), a.PortStr)
}

// Addrs returns a list of net.Addr's, one for each port.
func (a *UDPHopAddr) Addrs() ([]net.Addr, error) {
	var addrs []net.Addr
	for _, port := range a.Ports {
		addr := &net.UDPAddr{
			IP:   a.IP,
			Port: int(port),
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

func ResolveUDPHopAddr(addr string) (*UDPHopAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	taddr, err := resolver.ResolveIPWithResolver(context.Background(), host, resolver.SystemResolver)
	if err != nil {
		return nil, err
	}

	result := &UDPHopAddr{
		IP:      net.ParseIP(taddr.String()),
		PortStr: portStr,
	}

	pu := utils.ParsePortUnion(portStr)
	if pu == nil {
		return nil, InvalidPortError{portStr}
	}
	result.Ports = pu.Ports()

	return result, nil
}
