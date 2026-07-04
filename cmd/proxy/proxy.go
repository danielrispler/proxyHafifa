package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/redis/go-redis/v9"
)

type NATProxy struct {
	cfg          Config
	clientHandle *pcap.Handle
	serverHandle *pcap.Handle
	clientMAC    net.HardwareAddr
	serverMAC    net.HardwareAddr
	origDump     *pcapDump
	rewDump      *pcapDump
	rdb          *redis.Client
	portAlloc    *portAllocator
	macCache     *macCache
	conntrack    *conntrack
}

func NewNATProxy() (*NATProxy, error) {
	clientIP := resolveContainerIP("client")
	serverIP := resolveContainerIP("server")
	redisIP := resolveContainerIP("redis")

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
	clientMAC, err := getMACWithRetry(cfg.clientIP)
	if err != nil {
		clientHandle.Close()
		serverHandle.Close()
		return nil, fmt.Errorf("resolve client MAC: %w", err)
	}
	serverMAC, err := getMACWithRetry(cfg.serverIP)
	if err != nil {
		clientHandle.Close()
		serverHandle.Close()
		return nil, fmt.Errorf("resolve server MAC: %w", err)
	}
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

	redisAddr := fmt.Sprintf("%s:6379", redisIP)
	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		clientHandle.Close()
		serverHandle.Close()
		origDump.close()
		rewDump.close()
		rdb.Close()
		return nil, fmt.Errorf("connect to redis: %w", err)
	}
	log.Printf("[Proxy] Redis connected")

	mCache := newMacCache()
	mCache.set(cfg.clientIP, clientMAC)

	return &NATProxy{
		cfg:          cfg,
		clientHandle: clientHandle,
		serverHandle: serverHandle,
		clientMAC:    clientMAC,
		serverMAC:    serverMAC,
		origDump:     origDump,
		rewDump:      rewDump,
		rdb:          rdb,
		portAlloc:    newPortAllocator(rdb),
		macCache:     mCache,
		conntrack:    newConntrack(),
	}, nil
}

func (p *NATProxy) Close() {
	p.clientHandle.Close()
	p.serverHandle.Close()
	p.origDump.close()
	p.rewDump.close()
	p.rdb.Close()
}

func (p *NATProxy) Run() {
	log.Printf("[Proxy] Starting packet-forwarding loops. Client interface: %s, Server interface: %s", p.cfg.clientInterface, p.cfg.serverInterface)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		p.pump(p.clientHandle, clientToServer, p.cfg.proxyServerMAC, p.serverMAC, p.serverHandle, "client -> server")
	}()

	go func() {
		defer wg.Done()
		p.pump(p.serverHandle, serverToClient, p.cfg.proxyClientMAC, nil, p.clientHandle, "server -> client")
	}()

	wg.Wait()
}

func (p *NATProxy) pump(in *pcap.Handle, dir direction, srcMAC, dstMAC net.HardwareAddr, out *pcap.Handle, label string) {
	src := gopacket.NewPacketSource(in, in.LinkType())
	for pkt := range src.Packets() {
		if err := p.forwardPacket(pkt, dir, srcMAC, dstMAC, out); err != nil {
			log.Printf("[Proxy] %s route error: %v", label, err)
		}
	}
}

type direction int

const (
	clientToServer direction = iota
	serverToClient
)

// shouldForward reports whether a captured packet belongs to a flow this proxy
// handles. Promiscuous capture also sees the proxy's own injected frames and
// unrelated wire traffic; those must be ignored to avoid double-NAT and loops.
func (p *NATProxy) shouldForward(ip *layers.IPv4, dir direction) bool {
	if dir == clientToServer {
		// Drop our own injected replies and anything sourced from the server.
		if ip.SrcIP.Equal(p.cfg.proxyEgressIP) || ip.SrcIP.Equal(p.cfg.serverIP) {
			return false
		}
		// Only NAT the client -> server flow.
		return ip.DstIP.Equal(p.cfg.serverIP)
	}
	// server -> client: only genuine replies from the server.
	return ip.SrcIP.Equal(p.cfg.serverIP)
}

func (p *NATProxy) forwardPacket(pkt gopacket.Packet, dir direction, srcMAC, dstMAC net.HardwareAddr, outHandle *pcap.Handle) error {
	ip, err := getIPv4Layer(pkt)
	if err != nil || ip == nil {
		return err
	}

	if !p.shouldForward(ip, dir) {
		return nil
	}

	if err := p.origDump.writePacket(pkt.Metadata().CaptureInfo, pkt.Data()); err != nil {
		return fmt.Errorf("pcap original dump: %w", err)
	}

	var rewritten []byte
	proto := ip.Protocol
	now := time.Now()

	if proto == layers.IPProtocolTCP || proto == layers.IPProtocolUDP {
		srcPort, dstPort := parsePorts(pkt, proto)

		ttl := tcpTTL
		if proto == layers.IPProtocolUDP {
			ttl = udpTTL
		}

		if dir == clientToServer {
			rewritten, err = p.forwardClientToServer(ip, pkt, srcPort, dstPort, ttl, now, srcMAC, dstMAC)
		} else {
			rewritten, err = p.forwardServerToClient(ip, pkt, srcPort, dstPort, ttl, now, srcMAC)
		}
		if err != nil {
			return err
		}
		if rewritten == nil {

			return nil
		}
	} else {
		rewritten, err = p.forwardOther(ip, pkt, dir, srcMAC)
		if err != nil {
			return err
		}
		if rewritten == nil {
			return nil
		}
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

func (p *NATProxy) forwardClientToServer(ip *layers.IPv4, pkt gopacket.Packet, srcPort, dstPort uint16, ttl time.Duration, now time.Time, srcMAC, dstMAC net.HardwareAddr) ([]byte, error) {
	clientToServerKey := natClientToServerKey(ip.SrcIP, srcPort, ip.DstIP, dstPort)
	m, found, refreshDue := p.conntrack.lookupClientToServer(clientToServerKey, now)
	if !found {
		var err error
		m, err = p.loadOrCreateClientToServer(clientToServerKey, ip.SrcIP, srcPort, ip.DstIP, dstPort, ttl, now)
		if err != nil {
			return nil, err
		}
	} else if refreshDue {
		p.refreshTTL(m.clientToServerKey, m.serverToClientKey, ttl)
	}

	rewritten, err := rewritePacket(ip, pkt, p.cfg.proxyEgressIP, ip.DstIP, m.proxyPort, dstPort, srcMAC, dstMAC)
	if err != nil {
		return nil, fmt.Errorf("rewrite client -> server packet: %w", err)
	}
	return rewritten, nil
}

func (p *NATProxy) forwardServerToClient(ip *layers.IPv4, pkt gopacket.Packet, srcPort, dstPort uint16, ttl time.Duration, now time.Time, srcMAC net.HardwareAddr) ([]byte, error) {
	serverToClientKey := natServerToClientKey(dstPort, ip.SrcIP, srcPort)
	m, found, refreshDue := p.conntrack.lookupServerToClient(serverToClientKey, now)
	if !found {
		var err error
		m, found, err = p.loadServerToClient(serverToClientKey, ip.SrcIP, srcPort, dstPort, ttl, now)
		if err != nil {
			return nil, err
		}
		if !found {
			log.Printf("[Proxy] warning: unsolicited packet dropped: no server -> client NAT mapping for %s:%d -> %s:%d", ip.SrcIP, srcPort, ip.DstIP, dstPort)
			return nil, nil
		}
	} else if refreshDue {
		p.refreshTTL(m.clientToServerKey, m.serverToClientKey, ttl)
	}

	clientMAC, err := p.macCache.Get(m.clientIP)
	if err != nil {
		log.Printf("[Proxy] server -> client packet dropped: resolve client MAC %s: %v", m.clientIP, err)
		return nil, nil
	}

	rewritten, err := rewritePacket(ip, pkt, ip.SrcIP, m.clientIP, srcPort, m.clientPort, srcMAC, clientMAC)
	if err != nil {
		return nil, fmt.Errorf("rewrite server -> client packet: %w", err)
	}
	return rewritten, nil
}

func (p *NATProxy) forwardOther(ip *layers.IPv4, pkt gopacket.Packet, dir direction, srcMAC net.HardwareAddr) ([]byte, error) {
	var rewritten []byte
	var err error
	if dir == clientToServer {
		rewritten, err = rewritePacket(ip, pkt, p.cfg.proxyEgressIP, ip.DstIP, 0, 0, srcMAC, p.serverMAC)
	} else {
		clientMAC, mErr := p.macCache.Get(p.cfg.clientIP)
		if mErr != nil {
			log.Printf("[Proxy] server -> client packet dropped: resolve client MAC %s: %v", p.cfg.clientIP, mErr)
			return nil, nil
		}
		rewritten, err = rewritePacket(ip, pkt, ip.SrcIP, p.cfg.clientIP, 0, 0, srcMAC, clientMAC)
	}
	if err != nil {
		return nil, fmt.Errorf("rewrite non-TCP/UDP packet: %w", err)
	}
	return rewritten, nil
}

func (p *NATProxy) loadOrCreateClientToServer(clientToServerKey string, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, ttl time.Duration, now time.Time) (*natMapping, error) {
	ctx, cancel := redisCtx()
	defer cancel()

	var proxyPort uint16
	val, err := p.rdb.Get(ctx, clientToServerKey).Result()
	switch {
	case err == nil:
		portVal, perr := strconv.ParseUint(val, 10, 16)
		if perr != nil {
			return nil, fmt.Errorf("parse proxy port %q: %w", val, perr)
		}
		proxyPort = uint16(portVal)
		p.refreshTTL(clientToServerKey, natServerToClientKey(proxyPort, dstIP, dstPort), ttl)
	case errors.Is(err, redis.Nil):
		serverToClientVal := net.JoinHostPort(srcIP.String(), strconv.Itoa(int(srcPort)))
		proxyPort, err = p.portAlloc.Allocate(ctx, dstIP, dstPort, serverToClientVal, ttl)
		if err != nil {
			return nil, fmt.Errorf("allocate port: %w", err)
		}

		if err := p.rdb.Set(ctx, clientToServerKey, strconv.Itoa(int(proxyPort)), ttl).Err(); err != nil {
			return nil, fmt.Errorf("store client -> server NAT mapping: %w", err)
		}
	default:
		return nil, fmt.Errorf("lookup client -> server mapping: %w", err)
	}

	m := &natMapping{
		clientToServerKey: clientToServerKey,
		serverToClientKey: natServerToClientKey(proxyPort, dstIP, dstPort),
		proxyPort:         proxyPort,
		clientIP:          srcIP,
		clientPort:        srcPort,
		ttl:               ttl,
		expiresAt:         now.Add(ttl),
		lastRefresh:       now,
	}
	p.conntrack.insert(m)
	return m, nil
}

func (p *NATProxy) loadServerToClient(serverToClientKey string, serverIP net.IP, serverPort uint16, proxyPort uint16, ttl time.Duration, now time.Time) (*natMapping, bool, error) {
	ctx, cancel := redisCtx()
	defer cancel()

	val, err := p.rdb.Get(ctx, serverToClientKey).Result()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("lookup server -> client mapping: %w", err)
	}

	host, portStr, err := net.SplitHostPort(val)
	if err != nil {
		return nil, false, fmt.Errorf("invalid server -> client mapping %q: %w", val, err)
	}
	clientIP := net.ParseIP(host)
	clientPortVal, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || clientIP == nil {
		return nil, false, fmt.Errorf("invalid client addr in server -> client mapping %q", val)
	}
	clientPort := uint16(clientPortVal)

	clientToServerKey := natClientToServerKey(clientIP, clientPort, serverIP, serverPort)
	p.refreshTTL(clientToServerKey, serverToClientKey, ttl)

	m := &natMapping{
		clientToServerKey: clientToServerKey,
		serverToClientKey: serverToClientKey,
		proxyPort:         proxyPort,
		clientIP:          clientIP,
		clientPort:        clientPort,
		ttl:               ttl,
		expiresAt:         now.Add(ttl),
		lastRefresh:       now,
	}
	p.conntrack.insert(m)
	return m, true, nil
}

func (p *NATProxy) refreshTTL(clientToServerKey, serverToClientKey string, ttl time.Duration) {
	ctx, cancel := redisCtx()
	defer cancel()
	pipe := p.rdb.Pipeline()
	pipe.Expire(ctx, clientToServerKey, ttl)
	pipe.Expire(ctx, serverToClientKey, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		log.Printf("[Proxy] failed to refresh TTL: %v", err)
	}
}
