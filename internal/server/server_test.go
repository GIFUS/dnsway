package server

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dnsway/internal/config"
	"dnsway/internal/router"
	"dnsway/internal/rules"
	"dnsway/internal/stats"
	"dnsway/internal/upstream"
)

func TestHandlerServesUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	collector := stats.New()
	srv := &dns.Server{PacketConn: pc, Handler: newHandler(testRouter(t), logger, collector)}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	client := &dns.Client{Net: "udp", Timeout: time.Second}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp, _, err := client.Exchange(req, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "1.2.3.4" {
		t.Fatalf("answer = %v", resp.Answer)
	}
	if snapshot := collector.Snapshot(); snapshot.Queries.Total != 1 {
		t.Fatalf("total queries = %d", snapshot.Queries.Total)
	}

	line := logs.String()
	for _, want := range []string{"dns query", "proto=udp", "name=example.com.", "rule=default", "action=default", "rcode=NOERROR"} {
		if !strings.Contains(line, want) {
			t.Fatalf("log %q does not contain %q", line, want)
		}
	}
}

func TestTruncate(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)
	for i := 0; i < 100; i++ {
		rr, err := dns.NewRR("example.com. 60 IN A 1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		resp.Answer = append(resp.Answer, rr)
	}

	truncate(req, resp)
	if !resp.Truncated || len(resp.Answer) != 0 {
		t.Fatalf("truncated = %v, answers = %d", resp.Truncated, len(resp.Answer))
	}
}

type stubResolver struct{}

func (stubResolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	rr, err := dns.NewRR(req.Question[0].Name + " 60 IN A 1.2.3.4")
	if err != nil {
		return nil, err
	}
	resp.Answer = []dns.RR{rr}
	return resp, nil
}

func testRouter(t *testing.T) *router.Router {
	t.Helper()
	cfg := &config.Config{
		DNS:     config.DNS{Timeout: config.Duration(time.Second)},
		Routing: config.Routing{Default: []string{"default"}, Strategy: "first"},
	}
	store, err := rules.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return router.New(cfg, store, nil, map[string]upstream.Resolver{"default": stubResolver{}}, nil, nil)
}
