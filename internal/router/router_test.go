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

func TestFirstPrefersPositiveOverNXDOMAIN(t *testing.T) {
	negative := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		return replyCode(req, dns.RcodeNameError), nil
	}}
	positive := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		time.Sleep(30 * time.Millisecond)
		return answer("1.1.1.1")(req)
	}}
	cfg := testConfig(nil)
	cfg.Routing.Default = []string{"negative", "positive"}

	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{
		"negative": negative,
		"positive": positive,
	}, nil)

	resp := resolve(r, "example.com", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Fatalf("answer = %v", resp.Answer)
	}
}

func TestFastReturnsFirstValidResponse(t *testing.T) {
	negative := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		return replyCode(req, dns.RcodeNameError), nil
	}}
	positive := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		time.Sleep(30 * time.Millisecond)
		return answer("1.1.1.1")(req)
	}}
	cfg := testConfig(nil)
	cfg.Routing.Strategy = "fast"
	cfg.Routing.Default = []string{"negative", "positive"}

	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{
		"negative": negative,
		"positive": positive,
	}, nil)

	resp := resolve(r, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d", resp.Rcode)
	}
}

func TestFastSkipsInvalidResponses(t *testing.T) {
	servfail := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		return replyCode(req, dns.RcodeServerFailure), nil
	}}
	positive := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		time.Sleep(20 * time.Millisecond)
		return answer("1.1.1.1")(req)
	}}
	cfg := testConfig(nil)
	cfg.Routing.Strategy = "fast"
	cfg.Routing.Default = []string{"servfail", "positive"}

	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{
		"servfail": servfail,
		"positive": positive,
	}, nil)

	resp := resolve(r, "example.com", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Fatalf("answer = %v", resp.Answer)
	}
}

func TestFastReturnsSERVFAILWhenAllResponsesAreInvalid(t *testing.T) {
	failing := &fakeResolver{fn: func(*dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("unreachable")
	}}
	cfg := testConfig(nil)
	cfg.Routing.Strategy = "fast"
	cfg.Routing.Default = []string{"a", "b"}

	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{
		"a": failing,
		"b": failing,
	}, nil)

	resp := resolve(r, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d", resp.Rcode)
	}
}

func TestFirstPrefersPositiveOverNODATA(t *testing.T) {
	nodata := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		return nodataReply(req), nil
	}}
	positive := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		time.Sleep(30 * time.Millisecond)
		return answer("1.1.1.1")(req)
	}}
	cfg := testConfig(nil)
	cfg.Routing.Default = []string{"nodata", "positive"}

	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{
		"nodata":   nodata,
		"positive": positive,
	}, nil)

	resp := resolve(r, "example.com", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Fatalf("answer = %v", resp.Answer)
	}
}

func TestFirstPrioritizesNXDOMAINOverNODATA(t *testing.T) {
	nxdomain := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		return replyCode(req, dns.RcodeNameError), nil
	}}
	nodata := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		return nodataReply(req), nil
	}}
	cfg := testConfig(nil)
	cfg.Routing.Default = []string{"nodata", "nxdomain"}

	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{
		"nodata":   nodata,
		"nxdomain": nxdomain,
	}, nil)

	resp := resolve(r, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d", resp.Rcode)
	}
}

func TestFirstReturnsSERVFAILWhenAllResponsesFail(t *testing.T) {
	servfail := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		return replyCode(req, dns.RcodeServerFailure), nil
	}}
	cfg := testConfig(nil)
	cfg.Routing.Default = []string{"servfail"}

	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{
		"servfail": servfail,
	}, nil)

	resp := resolve(r, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d", resp.Rcode)
	}
}

func TestFirstReturnsNegativeOnPartialFailure(t *testing.T) {
	nxdomain := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		return replyCode(req, dns.RcodeNameError), nil
	}}
	cfg := testConfig(nil)
	cfg.DNS.Timeout = config.Duration(30 * time.Millisecond)
	cfg.Routing.Default = []string{"nxdomain", "blocked"}

	c := cache.New(100, time.Second, time.Hour, 30*time.Second)
	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{
		"nxdomain": nxdomain,
		"blocked":  blockingResolver{},
	}, c)

	first := r.Resolve(context.Background(), request("example.com", dns.TypeA))
	if first.Msg.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d", first.Msg.Rcode)
	}
	if first.CacheHit {
		t.Fatal("first response must not be a cache hit")
	}
	second := r.Resolve(context.Background(), request("example.com", dns.TypeA))
	if second.Msg.Rcode != dns.RcodeNameError || !second.CacheHit {
		t.Fatalf("partial negative response must be cached: %+v", second)
	}
}

func TestFirstCachesNegativeWhenAllResponsesValid(t *testing.T) {
	nxdomain := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		return replyCode(req, dns.RcodeNameError), nil
	}}
	cfg := testConfig(nil)
	cfg.Routing.Default = []string{"nxdomain"}

	c := cache.New(100, time.Second, time.Hour, 30*time.Second)
	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{"nxdomain": nxdomain}, c)

	first := r.Resolve(context.Background(), request("example.com", dns.TypeA))
	if first.Msg.Rcode != dns.RcodeNameError || first.CacheHit {
		t.Fatalf("first result = %+v", first)
	}
	second := r.Resolve(context.Background(), request("example.com", dns.TypeA))
	if second.Msg.Rcode != dns.RcodeNameError || !second.CacheHit {
		t.Fatalf("second result = %+v", second)
	}
}

func TestFirstIgnoresTruncatedResponses(t *testing.T) {
	truncated := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Truncated = true
		return resp, nil
	}}
	cfg := testConfig(nil)
	cfg.Routing.Default = []string{"truncated"}

	r := newRouterWithConfig(t, cfg, map[string]upstream.Resolver{
		"truncated": truncated,
	}, nil)

	resp := resolve(r, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d", resp.Rcode)
	}
}

func TestPositiveResponseRequiresRequestedType(t *testing.T) {
	req := request("example.com", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	rr, err := dns.NewRR("example.com. 300 IN CNAME target.example.")
	if err != nil {
		t.Fatal(err)
	}
	resp.Answer = []dns.RR{rr}

	if positiveResponse(resp, dns.TypeA) {
		t.Fatal("CNAME-only response must not satisfy an A query")
	}
	if !positiveResponse(resp, dns.TypeCNAME) {
		t.Fatal("CNAME response must satisfy a CNAME query")
	}
}

func TestCacheHitSkipsUpstream(t *testing.T) {
	resolver := &fakeResolver{fn: answer("1.1.1.1")}
	c := cache.New(100, time.Second, time.Hour, 0)
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
	return New(cfg, store, c, resolvers, nil, nil)
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

func replyCode(req *dns.Msg, rcode int) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Rcode = rcode
	return msg
}

func nodataReply(req *dns.Msg) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	return msg
}

type blockingResolver struct{}

func (blockingResolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
