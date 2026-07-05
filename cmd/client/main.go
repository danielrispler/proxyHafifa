package main

import (
	"io"
	"log"
	"net/http"
	"time"
)

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

	fetch()

	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	for range ticker.C {
		fetch()
	}
}
