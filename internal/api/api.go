package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"dnsway/internal/cache"
	"dnsway/internal/config"
	"dnsway/internal/stats"
)

type Server struct {
	http         *http.Server
	collector    *stats.Collector
	cache        *cache.Cache
	cacheMaxSize int
	allowed      []netip.Prefix
}

func New(cfg config.API, collector *stats.Collector, c *cache.Cache, cacheMaxSize int) (*Server, error) {
	allowed, err := parseAllowedIPs(cfg.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("api.allowed_ips: %w", err)
	}

	listen := cfg.Listen
	if listen == "" {
		listen = "127.0.0.1:8080"
	}
	s := &Server{
		collector:    collector,
		cache:        c,
		cacheMaxSize: cacheMaxSize,
		allowed:      allowed,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/stats", s.handleStats)
	s.http = &http.Server{
		Addr:              listen,
		Handler:           s.withACL(mux),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s, nil
}

func (s *Server) Run(ctx context.Context) error {
	errs := make(chan error, 1)
	go func() { errs <- s.http.ListenAndServe() }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) withACL(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allowedRemote(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowedRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range s.allowed {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

type cacheStats struct {
	Enabled bool `json:"enabled"`
	Entries int  `json:"entries"`
	MaxSize int  `json:"max_size"`
}

type statsResponse struct {
	Cache         cacheStats       `json:"cache"`
	Queries       stats.QueryStats `json:"queries"`
	UptimeSeconds int64            `json:"uptime_seconds"`
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries := 0
	if s.cache != nil {
		entries = s.cache.Len(time.Now())
	}
	var snapshot stats.Snapshot
	if s.collector != nil {
		snapshot = s.collector.Snapshot()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(statsResponse{
		Cache: cacheStats{
			Enabled: s.cache != nil,
			Entries: entries,
			MaxSize: s.cacheMaxSize,
		},
		Queries:       snapshot.Queries,
		UptimeSeconds: snapshot.UptimeSeconds,
	})
}

func parseAllowedIPs(items []string) ([]netip.Prefix, error) {
	if len(items) == 0 {
		return []netip.Prefix{
			netip.MustParsePrefix("127.0.0.1/32"),
			netip.MustParsePrefix("::1/128"),
		}, nil
	}

	prefixes := make([]netip.Prefix, 0, len(items))
	for _, raw := range items {
		if strings.Contains(raw, "/") {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, err
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}
