package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

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
		if err == nil && len(ips) > 0 {
			return ips[0]
		}
		if time.Now().After(deadline) {
			log.Fatalf("[Proxy] failed to resolve IP for container %s: %v", serviceName, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
