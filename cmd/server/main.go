package main

import (
	"log"
	"math/rand"
	"net/http"
	"strings"
)

var words = []string{
	"alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
	"golf", "hotel", "india", "juliet", "kilo", "lima",
	"mango", "nimbus", "ocean", "pixel", "quartz", "raven",
}

func randomText() string {
	n := 3 + rand.Intn(5)
	parts := make([]string, n)
	for i := range parts {
		parts[i] = words[rand.Intn(len(words))]
	}
	return strings.Join(parts, " ")
}

func handler(w http.ResponseWriter, r *http.Request) {
	text := randomText()
	log.Printf("server: %s %s from %s -> %q", r.Method, r.URL.Path, r.RemoteAddr, text)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(text + "\n"))
}

func main() {
	http.HandleFunc("/", handler)
	addr := ":8080"
	log.Printf("server: listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server: %v", err)
	}
}
