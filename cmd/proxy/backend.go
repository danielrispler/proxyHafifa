package main

import (
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	backendPort     = 8080
	healthInterval  = 3 * time.Second
	healthTimeout   = 1 * time.Second
	apiListenAddr   = ":8081"
	healthScanBatch = 256
)

type backendSelector struct {
	all       []net.IP
	probePort uint16
	healthy   atomic.Pointer[[]net.IP]
	counter   atomic.Uint32
}

func newBackendSelector(pool []net.IP, probePort uint16) *backendSelector {
	bs := &backendSelector{all: pool, probePort: probePort}

	initial := append([]net.IP(nil), pool...)
	bs.healthy.Store(&initial)
	return bs
}

func (bs *backendSelector) pick() net.IP {
	pool := *bs.healthy.Load()
	if len(pool) == 0 {
		pool = bs.all
	}
	if len(pool) == 0 {
		return nil
	}
	i := bs.counter.Add(1) - 1
	return pool[int(i%uint32(len(pool)))]
}

func (bs *backendSelector) healthyList() []net.IP {
	return *bs.healthy.Load()
}

func (bs *backendSelector) monitor(interval, timeout time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	bs.probe(timeout)
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			bs.probe(timeout)
		}
	}
}

func (bs *backendSelector) probe(timeout time.Duration) {
	healthy := make([]net.IP, 0, len(bs.all))
	for _, ip := range bs.all {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(int(bs.probePort)))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			continue
		}
		conn.Close()
		healthy = append(healthy, ip)
	}
	prev := *bs.healthy.Load()
	if len(prev) != len(healthy) {
		log.Printf("[Proxy] health: %d/%d backends up %v", len(healthy), len(bs.all), healthy)
	}
	bs.healthy.Store(&healthy)
}
