package main

import (
	"log"
)

func main() {
	proxy, err := NewNATProxy()
	if err != nil {
		log.Fatalf("[Proxy] Initialization failure: %v", err)
	}
	defer proxy.Close()

	proxy.Run()
}
