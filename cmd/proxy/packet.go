package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parsePorts(pkt gopacket.Packet, proto layers.IPProtocol) (srcPort, dstPort uint16) {
	switch proto {
	case layers.IPProtocolTCP:
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			if tcp, ok := tcpLayer.(*layers.TCP); ok {
				return uint16(tcp.SrcPort), uint16(tcp.DstPort)
			}
		}
	case layers.IPProtocolUDP:
		if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
			if udp, ok := udpLayer.(*layers.UDP); ok {
				return uint16(udp.SrcPort), uint16(udp.DstPort)
			}
		}
	}
	return 0, 0
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

func rewritePacket(ip *layers.IPv4, pkt gopacket.Packet, newSrcIP, newDstIP net.IP, newSrcPort, newDstPort uint16, srcMAC, dstMAC net.HardwareAddr) ([]byte, error) {
	ip.SrcIP = newSrcIP
	ip.DstIP = newDstIP

	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			eth.SrcMAC = srcMAC
			eth.DstMAC = dstMAC
		}
	}

	if newSrcPort != 0 || newDstPort != 0 {
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			if tcp, ok := tcpLayer.(*layers.TCP); ok {
				if newSrcPort != 0 {
					tcp.SrcPort = layers.TCPPort(newSrcPort)
				}
				if newDstPort != 0 {
					tcp.DstPort = layers.TCPPort(newDstPort)
				}
			}
		} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
			if udp, ok := udpLayer.(*layers.UDP); ok {
				if newSrcPort != 0 {
					udp.SrcPort = layers.UDPPort(newSrcPort)
				}
				if newDstPort != 0 {
					udp.DstPort = layers.UDPPort(newDstPort)
				}
			}
		}
	}

	return serialize(pkt)
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
