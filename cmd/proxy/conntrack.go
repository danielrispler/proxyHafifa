package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	tcpTTL          = 1800 * time.Second
	udpTTL          = 60 * time.Second
	refreshInterval = 30 * time.Second
	redisOpTimeout  = 2 * time.Second

	portRangeStart   = 32768
	portRangeEnd     = 60999
	portRangeSize    = portRangeEnd - portRangeStart + 1
	maxAllocAttempts = 16
)

func redisCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), redisOpTimeout)
}

func natClientToServerKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) string {
	return fmt.Sprintf("nat:clientToServer:%s:%d:%s:%d", srcIP, srcPort, dstIP, dstPort)
}

func natServerToClientKey(port uint16, dstIP net.IP, dstPort uint16) string {
	return fmt.Sprintf("nat:serverToClient:%d:%s:%d", port, dstIP, dstPort)
}

type natMapping struct {
	clientToServerKey, serverToClientKey string
	proxyPort                            uint16
	clientIP                             net.IP
	clientPort                           uint16
	ttl                                  time.Duration
	expiresAt                            time.Time
	lastRefresh                          time.Time
}

func (m *natMapping) touch(now time.Time) bool {
	m.expiresAt = now.Add(m.ttl)
	if now.Sub(m.lastRefresh) >= refreshInterval {
		m.lastRefresh = now
		return true
	}
	return false
}

type conntrack struct {
	mu             sync.Mutex
	clientToServer map[string]*natMapping
	serverToClient map[string]*natMapping
}

func newConntrack() *conntrack {
	return &conntrack{clientToServer: map[string]*natMapping{}, serverToClient: map[string]*natMapping{}}
}

func (ct *conntrack) insert(m *natMapping) {
	ct.mu.Lock()
	ct.clientToServer[m.clientToServerKey] = m
	ct.serverToClient[m.serverToClientKey] = m
	ct.mu.Unlock()
}

func (ct *conntrack) drop(m *natMapping) {
	delete(ct.clientToServer, m.clientToServerKey)
	delete(ct.serverToClient, m.serverToClientKey)
}

func (ct *conntrack) lookupClientToServer(key string, now time.Time) (*natMapping, bool, bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	m, ok := ct.clientToServer[key]
	if !ok {
		return nil, false, false
	}
	if now.After(m.expiresAt) {
		ct.drop(m)
		return nil, false, false
	}
	return m, true, m.touch(now)
}

func (ct *conntrack) lookupServerToClient(key string, now time.Time) (*natMapping, bool, bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	m, ok := ct.serverToClient[key]
	if !ok {
		return nil, false, false
	}
	if now.After(m.expiresAt) {
		ct.drop(m)
		return nil, false, false
	}
	return m, true, m.touch(now)
}
