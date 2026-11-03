package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dnsway/internal/cache"
	"dnsway/internal/config"
	"dnsway/internal/router"
	"dnsway/internal/stats"
)

func TestStatsEndpoint(t *testing.T) {
	collector := stats.New()
	collector.Record(router.Result{Rule: "rules[0]", Action: "block"}, 10*time.Millisecond)
	collector.Record(router.Result{Rule: "default", Action: "default", CacheHit: true}, 30*time.Millisecond)

	c := cache.New(100, 0, 0, 0)
	storeCacheEntry(t, c)
	srv, err := New(config.API{
		Enabled:    true,
		AllowedIPs: []string{"127.0.0.1"},
	}, collector, c, 100)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://api/stats", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	srv.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var body statsResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !body.Cache.Enabled || body.Cache.Entries != 1 || body.Cache.MaxSize != 100 {
		t.Fatalf("cache = %+v", body.Cache)
	}
	if body.Queries.Total != 2 || body.Queries.Blocked != 1 || body.Queries.Rules != 1 ||
		body.Queries.Default != 1 || body.Queries.CacheHits != 1 {
		t.Fatalf("queries = %+v", body.Queries)
	}
	if body.Queries.AvgElapsedMS != 20 {
		t.Fatalf("avg_elapsed_ms = %v", body.Queries.AvgElapsedMS)
	}
	if body.Runtime.Goroutines < 1 {
		t.Fatalf("goroutines = %d", body.Runtime.Goroutines)
	}
}

func TestRunServesStatsAndStops(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	collector := stats.New()
	collector.Record(router.Result{Rule: "default"}, 10*time.Millisecond)
	srv, err := New(config.API{
		Enabled:    true,
		Listen:     addr,
		AllowedIPs: []string{"127.0.0.1/32"},
	}, collector, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() { errs <- srv.Run(ctx) }()

	client := &http.Client{Timeout: 200 * time.Millisecond}
	var resp *http.Response
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = client.Get("http://" + addr + "/stats")
		if err == nil {
			break
		}
		select {
		case runErr := <-errs:
			t.Fatalf("api stopped before serving: %v", runErr)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("api did not start: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var body statsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Queries.Total != 1 {
		t.Fatalf("total = %d", body.Queries.Total)
	}

	cancel()
	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("api did not stop")
	}
}

func TestStatsForbidden(t *testing.T) {
	srv, err := New(config.API{
		Enabled:    true,
		AllowedIPs: []string{"127.0.0.1"},
	}, stats.New(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://api/stats", nil)
	req.RemoteAddr = "203.0.113.1:1234"
	srv.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestStatsDefaultsToLoopback(t *testing.T) {
	srv, err := New(config.API{Enabled: true}, stats.New(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		remote string
		status int
	}{
		{"127.0.0.1:1", http.StatusOK},
		{"[::1]:1", http.StatusOK},
		{"192.0.2.1:1", http.StatusForbidden},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://api/stats", nil)
		req.RemoteAddr = tc.remote
		srv.http.Handler.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("%s: status = %d", tc.remote, rec.Code)
		}
	}
}

func TestStatsMethodNotAllowed(t *testing.T) {
	srv, err := New(config.API{
		Enabled:    true,
		AllowedIPs: []string{"127.0.0.1/32"},
	}, stats.New(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://api/stats", nil)
	req.RemoteAddr = "127.0.0.1:1"
	srv.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}
}

func storeCacheEntry(t *testing.T, c *cache.Cache) {
	t.Helper()
	key := cache.Key{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassINET}
	msg := new(dns.Msg)
	msg.SetQuestion(key.Name, key.Type)
	msg.Response = true
	rr, err := dns.NewRR(key.Name + " 300 IN A 1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	msg.Answer = []dns.RR{rr}
	c.Store(key, msg, time.Now())
}
