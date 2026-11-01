package router

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dnsway/internal/cache"
	"dnsway/internal/config"
	"dnsway/internal/rules"
	"dnsway/internal/upstream"
)

type fakeResolver struct {
	count atomic.Int32
	fn    func(*dns.Msg) (*dns.Msg, error)
}

func (f *fakeResolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	f.count.Add(1)
	return f.fn(req)
}

func TestResolveActions(t *testing.T) {
	defaultResolver := &fakeResolver{fn: answer("9.9.9.9")}
	r := newRouter(t, []config.Rule{
		{Match: []string{"*.ads.com"}, Block: true},
		{Match: []string{"static.local"}, Resolve: "10.0.0.1"},
	}, map[string]upstream.Resolver{"default": defaultResolver}, nil)

	resp := resolve(r, "banner.ads.com", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("block rcode = %d", resp.Rcode)
	}

	resp = resolve(r, "static.local", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "10.0.0.1" {
		t.Fatalf("static answer = %v", resp.Answer)
	}

	resp = resolve(r, "static.local", dns.TypeAAAA)
	if len(resp.Answer) != 0 || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("aaaa answer = %v", resp.Answer)
	}

	resp = resolve(r, "other.test", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "9.9.9.9" {
		t.Fatalf("default answer = %v", resp.Answer)
	}
}

func TestResolveFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.txt"), []byte("192.168.1.10 nas.local\nfd00::10 nas.local\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig([]config.Rule{{ResolveFile: []string{"hosts.txt"}}})
	cfg.Dir = dir
	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{}, nil)

	result := r.Resolve(context.Background(), request("nas.local", dns.TypeA))
	if result.Action != "resolve_file" || result.Rule != "rules[0]" {
		t.Fatalf("action = %q, rule = %q", result.Action, result.Rule)
	}
	if len(result.Msg.Answer) != 1 || result.Msg.Answer[0].(*dns.A).A.String() != "192.168.1.10" {
		t.Fatalf("A answer = %v", result.Msg.Answer)
	}

	result = r.Resolve(context.Background(), request("nas.local", dns.TypeAAAA))
	if len(result.Msg.Answer) != 1 || result.Msg.Answer[0].(*dns.AAAA).AAAA.String() != "fd00::10" {
		t.Fatalf("AAAA answer = %v", result.Msg.Answer)
	}

	result = r.Resolve(context.Background(), request("nas.local", dns.TypeMX))
	if len(result.Msg.Answer) != 0 || result.Msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("MX answer = %v", result.Msg.Answer)
	}
}

func TestFirstSkipsFailedUpstream(t *testing.T) {
	failing := &fakeResolver{fn: func(*dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("unreachable")
	}}
	good := &fakeResolver{fn: answer("1.1.1.1")}
	cfg := testConfig(nil)
	cfg.Routing.Default = []string{"failing", "good"}

	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{
		"failing": failing,
		"good":    good,
	}, nil)

	resp := resolve(r, "example.com", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Fatalf("answer = %v", resp.Answer)
	}
}

func TestCacheHitSkipsUpstream(t *testing.T) {
	resolver := &fakeResolver{fn: answer("1.1.1.1")}
	c := cache.New(100, time.Second, time.Hour)
	r := newRouter(t, nil, map[string]upstream.Resolver{"default": resolver}, c)

	for i := 0; i < 2; i++ {
		result := r.Resolve(context.Background(), request("example.com", dns.TypeA))
		if len(result.Msg.Answer) != 1 {
			t.Fatalf("answer = %v", result.Msg.Answer)
		}
		if i == 0 && result.CacheHit {
			t.Fatal("first response must not be a cache hit")
		}
		if i == 1 && !result.CacheHit {
			t.Fatal("second response must be a cache hit")
		}
	}
	if got := resolver.count.Load(); got != 1 {
		t.Fatalf("upstream calls = %d", got)
	}
}

func newRouter(t *testing.T, ruleList []config.Rule, resolvers map[string]upstream.Resolver, c *cache.Cache) *Router {
	t.Helper()
	return newRouterWithConfig(t, testConfig(ruleList), resolvers, c)
}

func newRouterWithConfig(t *testing.T, cfg *config.Config, resolvers map[string]upstream.Resolver, c *cache.Cache) *Router {
	t.Helper()
	store, err := rules.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, store, c, resolvers)
}

func testConfig(ruleList []config.Rule) *config.Config {
	return &config.Config{
		DNS:     config.DNS{Timeout: config.Duration(time.Second)},
		Routing: config.Routing{Default: []string{"default"}, Strategy: "first"},
		Rules:   ruleList,
	}
}

func resolve(r *Router, name string, qtype uint16) *dns.Msg {
	return r.Resolve(context.Background(), request(name, qtype)).Msg
}

func request(name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	return msg
}

func answer(ip string) func(*dns.Msg) (*dns.Msg, error) {
	return func(req *dns.Msg) (*dns.Msg, error) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		rr, err := dns.NewRR(req.Question[0].Name + " 300 IN A " + ip)
		if err != nil {
			return nil, err
		}
		msg.Answer = []dns.RR{rr}
		return msg, nil
	}
}
