package main

import (
	"net"
	"time"
)

type Config struct {
	clientInterface string
	serverInterface string

	clientIP net.IP

	serverIP net.IP

	backendIPs    []net.IP
	proxyEgressIP net.IP

	proxyClientMAC net.HardwareAddr
	proxyServerMAC net.HardwareAddr

	snapshotLen int32
	promiscuous bool
	timeout     time.Duration
}
