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
	maxAllocAttempts = 64

	janitorInterval = 60 * time.Second
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

func newNATMapping(c2sKey, s2cKey string, proxyPort uint16, clientIP net.IP, clientPort uint16, ttl time.Duration, now time.Time) *natMapping {
	return &natMapping{
		clientToServerKey: c2sKey,
		serverToClientKey: s2cKey,
		proxyPort:         proxyPort,
		clientIP:          clientIP,
		clientPort:        clientPort,
		ttl:               ttl,
		expiresAt:         now.Add(ttl),
		lastRefresh:       now,
	}
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

// lookup finds a live mapping by key in the given map, evicting it if expired.
// Returns (mapping, found, refreshDue). Caller must not hold ct.mu.
func (ct *conntrack) lookup(m map[string]*natMapping, key string, now time.Time) (*natMapping, bool, bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	mapping, ok := m[key]
	if !ok {
		return nil, false, false
	}
	if now.After(mapping.expiresAt) {
		ct.drop(mapping)
		return nil, false, false
	}
	return mapping, true, mapping.touch(now)
}

func (ct *conntrack) lookupClientToServer(key string, now time.Time) (*natMapping, bool, bool) {
	return ct.lookup(ct.clientToServer, key, now)
}

func (ct *conntrack) lookupServerToClient(key string, now time.Time) (*natMapping, bool, bool) {
	return ct.lookup(ct.serverToClient, key, now)
}

// sweep drops every mapping whose TTL has expired. Silent flows never trigger a
// same-key lookup, so without this they would leak until the process OOMs.
func (ct *conntrack) sweep(now time.Time) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	for _, m := range ct.clientToServer {
		if now.After(m.expiresAt) {
			ct.drop(m)
		}
	}
}

// janitor periodically sweeps expired mappings until stop is closed.
func (ct *conntrack) janitor(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			ct.sweep(now)
		}
	}
}
