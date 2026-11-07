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

type resolverFunc func(context.Context, *dns.Msg) (*dns.Msg, error)

func (f resolverFunc) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return f(ctx, req)
}

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

func TestTruncatePreservesOPT(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(512, false)

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.SetEdns0(512, false)
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
	opt := resp.IsEdns0()
	if opt == nil || opt.UDPSize() != 512 {
		t.Fatalf("OPT = %v", opt)
	}
}

func TestTruncateNoopForSmallResponse(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(1232, false)

	resp := new(dns.Msg)
	resp.SetReply(req)
	truncate(req, resp)

	if resp.Truncated {
		t.Fatal("small response must not be truncated")
	}
}

func TestHandlerUsesContext(t *testing.T) {
	started := make(chan struct{}, 1)
	resolver := resolverFunc(func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})

	cfg := &config.Config{
		DNS:     config.DNS{Timeout: config.Duration(5 * time.Second)},
		Routing: config.Routing{Default: []string{"default"}, Strategy: "first"},
	}
	store, err := rules.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := router.New(cfg, store, nil, map[string]upstream.Resolver{"default": resolver}, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	h := newHandlerContext(ctx, r, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), nil)
	w := &stubResponseWriter{}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	done := make(chan struct{})
	go func() {
		h.ServeDNS(w, req)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("resolver was not called")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not stop after context cancellation")
	}
	if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("response = %v", w.msg)
	}
}

func TestRcodeName(t *testing.T) {
	if got := rcodeName(dns.RcodeSuccess); got != "NOERROR" {
		t.Fatalf("rcode = %q", got)
	}
	if got := rcodeName(9999); got != "9999" {
		t.Fatalf("rcode = %q", got)
	}
}

type stubResponseWriter struct {
	msg *dns.Msg
}

func (w *stubResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (w *stubResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (w *stubResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg
	return nil
}

func (w *stubResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (w *stubResponseWriter) Close() error {
	return nil
}

func (w *stubResponseWriter) TsigStatus() error {
	return nil
}

func (w *stubResponseWriter) TsigTimersOnly(bool) {}

func (w *stubResponseWriter) Hijack() {}

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
