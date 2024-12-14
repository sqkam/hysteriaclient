package proxymux

import (
	"context"
	"net"
	"sync"

	"github.com/apernet/hysteria/extras/v2/correctnet"
	"github.com/metacubex/mihomo/component/resolver"
)

type muxManager struct {
	listeners map[string]*muxListener
	lock      sync.Mutex
}

var globalMuxManager *muxManager

func init() {
	globalMuxManager = &muxManager{
		listeners: make(map[string]*muxListener),
	}
}

func (m *muxManager) GetOrCreate(address string) (*muxListener, error) {
	key, err := m.canonicalizeAddrPort(address)
	if err != nil {
		return nil, err
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	if ml, ok := m.listeners[key]; ok {
		return ml, nil
	}

	listener, err := correctnet.Listen("tcp", key)
	if err != nil {
		return nil, err
	}

	ml := newMuxListener(listener, func() {
		m.lock.Lock()
		defer m.lock.Unlock()
		delete(m.listeners, key)
	})
	m.listeners[key] = ml
	return ml, nil
}

func (m *muxManager) canonicalizeAddrPort(address string) (string, error) {
	taddr, err := resolver.ResolveIPWithResolver(context.Background(), address, resolver.SystemResolver)
	if err != nil {
		return address, nil
	}
	return taddr.String(), nil
}

func ListenHTTP(address string) (net.Listener, error) {
	ml, err := globalMuxManager.GetOrCreate(address)
	if err != nil {
		return nil, err
	}
	return ml.ListenHTTP()
}

func ListenSOCKS(address string) (net.Listener, error) {
	ml, err := globalMuxManager.GetOrCreate(address)
	if err != nil {
		return nil, err
	}
	return ml.ListenSOCKS()
}
