package udphop

import "net"

type Addrs interface {
	net.Addr
	Addrs() ([]net.Addr, error)
}
