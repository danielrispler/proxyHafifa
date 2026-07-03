package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type Config struct {
	Device        string
	serverIP      net.IP
	clientIP      net.IP
	proxyEgressIP net.IP
	SnapshotLen   int32
	Promiscuous   bool
	Timeout       time.Duration
}

type pcapDump struct {
	f *os.File
	w *pcapgo.Writer
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
	return d.w.WritePacket(ci, data)
}

func (d *pcapDump) close() error {
	return d.f.Close()
}

func main() {
	cfg := parseFlags()

	handle, err := openHandle(cfg)
	if err != nil {
		log.Fatalf("open handle: %v", err)
	}
	defer handle.Close()

	linkType := handle.LinkType()
	origDump, err := newPcapDump("original.pcap", linkType)
	if err != nil {
		log.Fatalf("open original dump: %v", err)
	}
	defer origDump.close()

	rewDump, err := newPcapDump("rewritten.pcap", linkType)
	if err != nil {
		log.Fatalf("open rewritten dump: %v", err)
	}
	defer rewDump.close()

	src := gopacket.NewPacketSource(handle, linkType)
	for pkt := range src.Packets() {
		if err := handlePacket(handle, cfg, pkt, origDump, rewDump); err != nil {
			log.Printf("handle packet: %v", err)
		}
	}
}

func parseFlags() Config {
	return Config{
		Device:        "any",
		serverIP:      resolveContainerIP("client"),
		clientIP:      resolveContainerIP("server"),
		proxyEgressIP: localIPInSameSubnet(resolveContainerIP("server")),
		SnapshotLen:   int32(65535),
		Promiscuous:   true,
		Timeout:       pcap.BlockForever,
	}
}

func openHandle(cfg Config) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(cfg.Device, cfg.SnapshotLen, cfg.Promiscuous, cfg.Timeout)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", cfg.Device, err)
		return nil, err
	}

	return handle, nil
}

func handlePacket(handle *pcap.Handle, cfg Config, pkt gopacket.Packet, origDump, rewDump *pcapDump) error {
	pktIp, ipErr := getPacketIp(pkt)
	if ipErr != nil {
		return fmt.Errorf("Error in retrieving ip %v", ipErr)
	}

	if err := origDump.writePacket(pkt.Metadata().CaptureInfo, pkt.Data()); err != nil {
		return fmt.Errorf("dump original: %w", err)
	}

	rewritten, err := rewriteForDirection(cfg, pkt, pktIp)
	if err != nil {
		return fmt.Errorf("Error in rewite %v", err)
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     pkt.Metadata().Timestamp,
		CaptureLength: len(rewritten),
		Length:        len(rewritten),
	}
	if err := rewDump.writePacket(ci, rewritten); err != nil {
		return fmt.Errorf("dump rewritten: %w", err)
	}

	return forward(handle, rewritten)
}

func rewriteForDirection(cfg Config, pkt gopacket.Packet, pktIp *layers.IPv4) ([]byte, error) {
	if isFromClient(cfg, pktIp) {
		return rewritePkt(pkt, &pktIp.SrcIP, cfg.proxyEgressIP)
	}
	return rewritePkt(pkt, &pktIp.DstIP, cfg.clientIP)
}

func getPacketIp(pkt gopacket.Packet) (*layers.IPv4, error) {
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, fmt.Errorf("packet has no IPv4 layer")
	}
	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("IPv4 layer type assertion failed")
	}

	return ip, nil
}

func isFromClient(cfg Config, pktIp *layers.IPv4) bool {
	return cfg.clientIP.Equal(pktIp.SrcIP)
}

func rewritePkt(pkt gopacket.Packet, targetIP *net.IP, newIP net.IP) ([]byte, error) {
	*targetIP = newIP

	data, err := serialize(pkt)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	return data, nil
}

func serialize(pkt gopacket.Packet) ([]byte, error) {
	if net := pkt.NetworkLayer(); net != nil {
		switch t := pkt.TransportLayer().(type) {
		case *layers.TCP:
			t.SetNetworkLayerForChecksum(net)
		case *layers.UDP:
			t.SetNetworkLayerForChecksum(net)
		}
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializePacket(buf, opts, pkt); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func forward(handle *pcap.Handle, data []byte) error {
	return handle.WritePacketData(data)
}

func localIPInSameSubnet(target net.IP) net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalf("list interface addrs: %v", err)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.Contains(target) {
			return ipnet.IP
		}
	}
	log.Fatalf("no local interface in same subnet as %v", target)
	return nil
}

func resolveContainerIP(serviceName string) net.IP {
	ips, err := net.LookupIP(serviceName)
	if err != nil {
		log.Fatalf("Failed to resolve IP for container %s: %v", serviceName, err)
	}
	return ips[0]
}
