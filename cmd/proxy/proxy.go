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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type Config struct {
	clientInterface string
	serverInterface string

	clientIP      net.IP
	serverIP      net.IP
	proxyEgressIP net.IP

	proxyClientMAC net.HardwareAddr
	proxyServerMAC net.HardwareAddr

	snapshotLen int32
	promiscuous bool
	timeout     time.Duration
}

type pcapDump struct {
	mu sync.Mutex
	f  *os.File
	w  *pcapgo.Writer
}

func newPcapDump(path string, linkType layers.LinkType) (*pcapDump, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, linkType); err != nil {
		f.Close()
		return nil, err
	}
	return &pcapDump{f: f, w: w}, nil
}

func (d *pcapDump) writePacket(ci gopacket.CaptureInfo, data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.w.WritePacket(ci, data)
}

func (d *pcapDump) close() error {
	return d.f.Close()
}

type NATProxy struct {
	cfg          Config
	clientHandle *pcap.Handle
	serverHandle *pcap.Handle
	clientMAC    net.HardwareAddr
	serverMAC    net.HardwareAddr
	origDump     *pcapDump
	rewDump      *pcapDump
}

func NewNATProxy() (*NATProxy, error) {
	clientIP := resolveContainerIP("client")
	serverIP := resolveContainerIP("server")

	clientDev, _, err := findInterfaceForTarget(clientIP)
	if err != nil {
		return nil, fmt.Errorf("find client interface: %w", err)
	}
	serverDev, proxyEgressIP, err := findInterfaceForTarget(serverIP)
	if err != nil {
		return nil, fmt.Errorf("find server interface: %w", err)
	}

	clientIface, err := net.InterfaceByName(clientDev)
	if err != nil {
		return nil, fmt.Errorf("get client interface info: %w", err)
	}
	serverIface, err := net.InterfaceByName(serverDev)
	if err != nil {
		return nil, fmt.Errorf("get server interface info: %w", err)
	}

	cfg := Config{
		clientInterface: clientDev,
		serverInterface: serverDev,
		clientIP:        clientIP,
		serverIP:        serverIP,
		proxyEgressIP:   proxyEgressIP,
		proxyClientMAC:  clientIface.HardwareAddr,
		proxyServerMAC:  serverIface.HardwareAddr,
		snapshotLen:     65535,
		promiscuous:     true,
		timeout:         pcap.BlockForever,
	}

	clientHandle, err := pcap.OpenLive(cfg.clientInterface, cfg.snapshotLen, cfg.promiscuous, cfg.timeout)
	if err != nil {
		return nil, fmt.Errorf("open client capture handle: %w", err)
	}

	serverHandle, err := pcap.OpenLive(cfg.serverInterface, cfg.snapshotLen, cfg.promiscuous, cfg.timeout)
	if err != nil {
		clientHandle.Close()
		return nil, fmt.Errorf("open server capture handle: %w", err)
	}

	log.Printf("[Proxy] Resolving Client MAC (%s) and Server MAC (%s)...", cfg.clientIP, cfg.serverIP)
	clientMAC := getMACWithRetry(cfg.clientIP)
	serverMAC := getMACWithRetry(cfg.serverIP)
	log.Printf("[Proxy] Resolved MACs - Client: %s, Server: %s", clientMAC, serverMAC)

	origDump, err := newPcapDump("original.pcap", layers.LinkTypeEthernet)
	if err != nil {
		clientHandle.Close()
		serverHandle.Close()
		return nil, fmt.Errorf("create original pcap dump: %w", err)
	}

	rewDump, err := newPcapDump("rewritten.pcap", layers.LinkTypeEthernet)
	if err != nil {
		clientHandle.Close()
		serverHandle.Close()
		origDump.close()
		return nil, fmt.Errorf("create rewritten pcap dump: %w", err)
	}

	return &NATProxy{
		cfg:          cfg,
		clientHandle: clientHandle,
		serverHandle: serverHandle,
		clientMAC:    clientMAC,
		serverMAC:    serverMAC,
		origDump:     origDump,
		rewDump:      rewDump,
	}, nil
}

func (p *NATProxy) Close() {
	p.clientHandle.Close()
	p.serverHandle.Close()
	p.origDump.close()
	p.rewDump.close()
}

func (p *NATProxy) Run() {
	log.Printf("[Proxy] Starting packet-forwarding loops. Client interface: %s, Server interface: %s", p.cfg.clientInterface, p.cfg.serverInterface)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		src := gopacket.NewPacketSource(p.clientHandle, p.clientHandle.LinkType())
		for pkt := range src.Packets() {
			if err := p.forwardPacket(pkt, p.cfg.clientIP, true, p.cfg.proxyEgressIP, p.cfg.proxyServerMAC, p.serverMAC, p.serverHandle); err != nil {
				log.Printf("[Proxy] client -> server route error: %v", err)
			}
		}
	}()

	go func() {
		defer wg.Done()
		src := gopacket.NewPacketSource(p.serverHandle, p.serverHandle.LinkType())
		for pkt := range src.Packets() {
			if err := p.forwardPacket(pkt, p.cfg.serverIP, false, p.cfg.clientIP, p.cfg.proxyClientMAC, p.clientMAC, p.clientHandle); err != nil {
				log.Printf("[Proxy] server -> client route error: %v", err)
			}
		}
	}()

	wg.Wait()
}

func (p *NATProxy) forwardPacket(pkt gopacket.Packet, srcFilter net.IP, modifySource bool, targetIP net.IP, srcMAC, dstMAC net.HardwareAddr, outHandle *pcap.Handle) error {
	ip, err := getIPv4Layer(pkt)
	if err != nil || ip == nil {
		return err
	}

	if !ip.SrcIP.Equal(srcFilter) {
		return nil
	}

	if err := p.origDump.writePacket(pkt.Metadata().CaptureInfo, pkt.Data()); err != nil {
		return fmt.Errorf("pcap original dump: %w", err)
	}

	var ipField *net.IP
	if modifySource {
		ipField = &ip.SrcIP
	} else {
		ipField = &ip.DstIP
	}

	rewritten, err := p.rewritePacket(pkt, ipField, targetIP, srcMAC, dstMAC)
	if err != nil {
		return fmt.Errorf("rewrite packet: %w", err)
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     pkt.Metadata().Timestamp,
		CaptureLength: len(rewritten),
		Length:        len(rewritten),
	}
	if err := p.rewDump.writePacket(ci, rewritten); err != nil {
		return fmt.Errorf("pcap rewritten dump: %w", err)
	}

	return outHandle.WritePacketData(rewritten)
}

func (p *NATProxy) rewritePacket(pkt gopacket.Packet, ipField *net.IP, newIP net.IP, srcMAC, dstMAC net.HardwareAddr) ([]byte, error) {
	*ipField = newIP

	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			eth.SrcMAC = srcMAC
			eth.DstMAC = dstMAC
		}
	}

	return serialize(pkt)
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

func getMACWithRetry(ip net.IP) net.HardwareAddr {
	for i := range 20 {
		mac, err := getMACFromARP(ip)
		if err == nil {
			return mac
		}
		log.Printf("[Proxy] resolving MAC for %v (attempt %d/20)...", ip, i+1)
		triggerARP(ip)
		time.Sleep(500 * time.Millisecond)
	}
	panic(fmt.Sprintf("[Proxy] failed to resolve MAC address for %v", ip))
}

func getIPv4Layer(pkt gopacket.Packet) (*layers.IPv4, error) {
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, nil
	}
	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("IPv4 layer type assertion failed")
	}
	return ip, nil
}

func serialize(pkt gopacket.Packet) ([]byte, error) {
	if netLayer := pkt.NetworkLayer(); netLayer != nil {
		switch t := pkt.TransportLayer().(type) {
		case *layers.TCP:
			t.SetNetworkLayerForChecksum(netLayer)
		case *layers.UDP:
			t.SetNetworkLayerForChecksum(netLayer)
		}
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializePacket(buf, opts, pkt); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
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
