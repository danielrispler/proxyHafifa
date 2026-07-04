package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type macCache struct {
	mu        sync.RWMutex
	resolveMu sync.Mutex
	cache     map[string]net.HardwareAddr
}

func newMacCache() *macCache {
	return &macCache{cache: make(map[string]net.HardwareAddr)}
}

func (mc *macCache) Get(ip net.IP) (net.HardwareAddr, error) {
	ipStr := ip.String()
	mc.mu.RLock()
	mac, found := mc.cache[ipStr]
	mc.mu.RUnlock()
	if found {
		return mac, nil
	}

	mc.resolveMu.Lock()
	defer mc.resolveMu.Unlock()

	mc.mu.RLock()
	mac, found = mc.cache[ipStr]
	mc.mu.RUnlock()
	if found {
		return mac, nil
	}

	mac, err := getMACWithRetry(ip)
	if err != nil {
		return nil, err
	}

	mc.set(ip, mac)
	return mac, nil
}

func (mc *macCache) set(ip net.IP, mac net.HardwareAddr) {
	mc.mu.Lock()
	mc.cache[ip.String()] = mac
	mc.mu.Unlock()
}

func triggerARP(ip net.IP) {
	conn, err := net.Dial("udp", ip.String()+":9")
	if err == nil {
		_, _ = conn.Write([]byte{0})
		_ = conn.Close()
	}
}

func getMACFromARP(ip net.IP) (net.HardwareAddr, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ipStr := ip.String()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == ipStr && fields[2] == "0x2" {
			mac, err := net.ParseMAC(fields[3])
			if err == nil {
				return mac, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("MAC address not found in ARP table for IP %s", ipStr)
}

func getMACWithRetry(ip net.IP) (net.HardwareAddr, error) {
	for i := range 20 {
		mac, err := getMACFromARP(ip)
		if err == nil {
			return mac, nil
		}
		log.Printf("[Proxy] resolving MAC for %v (attempt %d/20)...", ip, i+1)
		triggerARP(ip)
		time.Sleep(500 * time.Millisecond)
	}
	return nil, fmt.Errorf("failed to resolve MAC address for %v", ip)
}
