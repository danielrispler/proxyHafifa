package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/redis/go-redis/v9"
)

type apiServer struct {
	rdb      *redis.Client
	selector *backendSelector
	srv      *http.Server
}

func newAPIServer(rdb *redis.Client, selector *backendSelector, addr string) *apiServer {
	a := &apiServer{rdb: rdb, selector: selector}
	mux := http.NewServeMux()
	mux.HandleFunc("/connections", a.handleConnections)
	mux.HandleFunc("/", a.handleConnections)
	a.srv = &http.Server{Addr: addr, Handler: mux}
	return a
}

func (a *apiServer) start() {
	log.Printf("[Proxy] management API listening on %s", a.srv.Addr)
	if err := a.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[Proxy] management API error: %v", err)
	}
}

func (a *apiServer) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), redisOpTimeout)
	defer cancel()
	_ = a.srv.Shutdown(ctx)
}

type connRow struct {
	Client    string
	ProxyPort string
	Backend   string
}

type connPage struct {
	Rows    []connRow
	Healthy []string
}

func (a *apiServer) scanConnections(ctx context.Context) ([]connRow, error) {
	var keys []string
	var cursor uint64
	for {
		batch, next, err := a.rdb.Scan(ctx, cursor, "nat:serverToClient:*", healthScanBatch).Result()
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}

	vals, err := a.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	rows := make([]connRow, 0, len(keys))
	for i, key := range keys {

		parts := strings.Split(key, ":")
		if len(parts) != 5 {
			continue
		}
		client, ok := vals[i].(string)
		if !ok {
			continue
		}
		rows = append(rows, connRow{
			Client:    client,
			ProxyPort: parts[2],
			Backend:   parts[3],
		})
	}
	return rows, nil
}

func (a *apiServer) handleConnections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := a.scanConnections(ctx)
	if err != nil {
		http.Error(w, "failed to read connections: "+err.Error(), http.StatusInternalServerError)
		return
	}

	page := connPage{Rows: rows}
	for _, ip := range a.selector.healthyList() {
		page.Healthy = append(page.Healthy, ip.String())
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := connTmpl.Execute(w, page); err != nil {
		log.Printf("[Proxy] render connections: %v", err)
	}
}

var connTmpl = template.Must(template.New("connections").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>proxyhafifa connections</title>
<style>
body{font-family:system-ui,monospace;margin:2rem;background:#0f1115;color:#e6e6e6}
h1,h2{font-weight:600}
table{border-collapse:collapse;margin-top:.5rem}
th,td{border:1px solid #333;padding:.4rem .8rem;text-align:left}
th{background:#1b1f27}
.up{color:#4ade80}
</style></head><body>
<h1>Active NAT connections ({{len .Rows}})</h1>
<table>
<tr><th>Client</th><th>Proxy Port</th><th>Backend Server</th></tr>
{{range .Rows}}<tr><td>{{.Client}}</td><td>{{.ProxyPort}}</td><td>{{.Backend}}</td></tr>
{{else}}<tr><td colspan="3">no active flows</td></tr>{{end}}
</table>
<h2>Healthy backends</h2>
<p class="up">{{range .Healthy}}{{.}} {{else}}none{{end}}</p>
</body></html>`))
