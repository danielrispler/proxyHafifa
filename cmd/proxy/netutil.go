package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

const (
	defaultVIP      = "172.21.0.2"
	backendDNSAlias = "backend"
)

func pinnedVIP() net.IP {
	raw := os.Getenv("PROXY_VIP")
	if raw == "" {
		raw = defaultVIP
	}
	ip := net.ParseIP(raw)
	if ip == nil || ip.To4() == nil {
		log.Fatalf("[Proxy] invalid PROXY_VIP %q", raw)
	}
	return ip.To4()
}

func resolveBackendPool(vip net.IP) []net.IP {
	pool := []net.IP{vip}
	seen := map[string]bool{vip.String(): true}
	for _, ip := range lookupIPv4(backendDNSAlias, 15*time.Second) {
		if !seen[ip.String()] {
			seen[ip.String()] = true
			pool = append(pool, ip)
		}
	}
	return pool
}

func lookupIPv4(name string, timeout time.Duration) []net.IP {
	deadline := time.Now().Add(timeout)
	for {
		if ips, err := net.LookupIP(name); err == nil {
			var out []net.IP
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					out = append(out, v4)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
		if time.Now().After(deadline) {
			log.Printf("[Proxy] warning: could not resolve %q pool within %s; falling back", name, timeout)
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func findInterfaceForTarget(target net.IP) (string, net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil && ipnet.Contains(target) {
					return iface.Name, ipnet.IP, nil
				}
			}
		}
	}
	return "", nil, fmt.Errorf("no interface found in subnet of target IP %v", target)
}

func resolveContainerIP(serviceName string) net.IP {
	deadline := time.Now().Add(30 * time.Second)
	for {
		ips, err := net.LookupIP(serviceName)
		if err == nil {

			for _, ip := range ips {
				if ip.To4() != nil {
					return ip
				}
			}
		}
		if time.Now().After(deadline) {
			log.Fatalf("[Proxy] failed to resolve IP for container %s: %v", serviceName, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
