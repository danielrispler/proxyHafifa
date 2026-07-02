package main

import (
	"io"
	"log"
	"net/http"
	"time"
)

// target points directly at the server. The proxy is hidden at the network
// layer: the client's default route is the proxy, which captures, NATs, and
// re-injects the raw packets (gopacket/pcap). This code has no knowledge of
// any proxy — it just talks to the server.
const target = "http://server:8080/"

func fetch() {
	resp, err := http.Get(target)
	if err != nil {
		log.Printf("client: request error: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("client: read error: %v", err)
		return
	}
	log.Printf("client: status=%d body=%q", resp.StatusCode, string(body))
}

func main() {
	log.Printf("client: starting, polling %s every minute", target)

	fetch() // immediate first fire

	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	for range ticker.C {
		fetch()
	}
}
