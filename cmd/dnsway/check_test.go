package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dnsway/internal/config"
	"dnsway/internal/upstream"
)

type fakeResolver struct {
	calls atomic.Int32
	fn    func(context.Context, *dns.Msg) (*dns.Msg, error)
}

func (f *fakeResolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	f.calls.Add(1)
	return f.fn(ctx, req)
}

func fixedResolver(rcode int) *fakeResolver {
	return &fakeResolver{fn: func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = rcode
		return resp, nil
	}}
}

func failingResolver(err error) *fakeResolver {
	return &fakeResolver{fn: func(context.Context, *dns.Msg) (*dns.Msg, error) {
		return nil, err
	}}
}

func TestCheckUpstreams(t *testing.T) {
	cfg := &config.Config{
		DNS: config.DNS{
			Timeout:   config.Duration(time.Second),
			Bootstrap: []string{"ok"},
			Upstreams: map[string]config.Upstream{
				"ok":  {Address: "1.1.1.1:53", Protocol: "udp"},
				"bad": {Address: "1.1.1.2:53", Protocol: "tcp"},
			},
		},
		Routing: config.Routing{Default: []string{"ok"}},
	}
	good := fixedResolver(dns.RcodeServerFailure)
	bad := failingResolver(errors.New("timeout"))
	resolvers := map[string]upstream.Resolver{"ok": good, "bad": bad}

	results := checkUpstreams(cfg, resolvers)
	if len(results) != 2 {
		t.Fatalf("results = %d", len(results))
	}
	if results[0].name != "bad" || results[0].ok || results[0].successes != 0 ||
		results[0].probes != checkProbes || results[0].err == nil {
		t.Fatalf("bad result = %+v", results[0])
	}
	if results[1].name != "ok" || !results[1].ok || results[1].successes != checkProbes ||
		results[1].probes != checkProbes || results[1].rcode != dns.RcodeServerFailure {
		t.Fatalf("ok result = %+v", results[1])
	}
	if results[1].role != "bootstrap,default" {
		t.Fatalf("role = %q", results[1].role)
	}
	if got := good.calls.Load(); got != int32(checkProbes) {
		t.Fatalf("good probes = %d", got)
	}
	if got := bad.calls.Load(); got != int32(checkProbes) {
		t.Fatalf("bad probes = %d", got)
	}
}

func TestSummarizeProbes(t *testing.T) {
	u := config.Upstream{Address: "1.1.1.1:53", Protocol: "udp"}

	result := summarize("test", u, "default", testProbes(3))
	if !result.ok || result.successes != 3 || result.probes != checkProbes {
		t.Fatalf("result = %+v", result)
	}
	if result.avg != 20*time.Millisecond || formatAverage(result) != "20ms" {
		t.Fatalf("avg = %s, formatted = %q", result.avg, formatAverage(result))
	}
	if result.rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d", result.rcode)
	}
	if got := checkError(result); !strings.Contains(got, "2/5 failed") {
		t.Fatalf("error = %q", got)
	}

	result = summarize("test", u, "default", testProbes(2))
	if result.ok || result.successes != 2 || result.avg != 15*time.Millisecond {
		t.Fatalf("result = %+v", result)
	}

	result = summarize("test", u, "default", testProbes(0))
	if result.ok || result.successes != 0 || result.avg != 0 {
		t.Fatalf("result = %+v", result)
	}
	if checkRcode(result) != "-" || formatAverage(result) != "-" {
		t.Fatalf("rcode = %q, avg = %q", checkRcode(result), formatAverage(result))
	}
	if got := checkError(result); !strings.Contains(got, "5/5 failed") {
		t.Fatalf("error = %q", got)
	}
}

func TestRunCheck(t *testing.T) {
	cfg := &config.Config{
		DNS: config.DNS{
			Listen:    "127.0.0.1:53",
			Timeout:   config.Duration(time.Second),
			Bootstrap: []string{"good"},
			Upstreams: map[string]config.Upstream{
				"good": {Address: "1.1.1.1:53", Protocol: "udp"},
				"bad":  {Address: "1.1.1.2:53", Protocol: "tcp"},
			},
		},
		Routing: config.Routing{Default: []string{"good"}, Strategy: "first"},
		Cache:   config.Cache{Enabled: true, MaxSize: 1000, MinTTL: config.Duration(10 * time.Second), MaxTTL: config.Duration(time.Hour)},
		Rules: []config.Rule{
			{Match: []string{"*.ads.com"}, Block: true},
			{Match: []string{"local.test"}, Resolve: "192.168.1.2"},
			{ResolveFile: []string{"hosts.txt"}},
		},
	}
	resolvers := map[string]upstream.Resolver{
		"good": fixedResolver(dns.RcodeSuccess),
		"bad":  failingResolver(errors.New("timeout")),
	}

	var out bytes.Buffer
	err := runCheck(cfg, "config.json", &out, resolvers)
	if !errors.Is(err, errCheckFailed) {
		t.Fatalf("error = %v", err)
	}

	report := out.String()
	for _, want := range []string{
		"Config: config.json (valid)",
		"Listen: 127.0.0.1:53",
		"Strategy: first",
		"Cache: enabled, max_size=1000",
		"Bootstrap: good",
		"[0] block",
		"resolve_file",
		"Testing upstreams (2 total, 5 probes each, timeout 1s)...",
		"PROBES",
		"AVG",
		"5/5",
		"0/5",
		"5/5 failed: timeout",
		"bootstrap,default",
		"FAIL",
		"NOERROR",
		"Summary: reachable 1/2",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report does not contain %q:\n%s", want, report)
		}
	}
}

func TestRunCheckSuccess(t *testing.T) {
	cfg := &config.Config{
		DNS: config.DNS{
			Listen:  "127.0.0.1:53",
			Timeout: config.Duration(time.Second),
			Upstreams: map[string]config.Upstream{
				"good": {Address: "1.1.1.1:53", Protocol: "udp"},
			},
		},
		Routing: config.Routing{Default: []string{"good"}, Strategy: "first"},
	}
	resolvers := map[string]upstream.Resolver{
		"good": fixedResolver(dns.RcodeSuccess),
	}

	var out bytes.Buffer
	if err := runCheck(cfg, "config.json", &out, resolvers); err != nil {
		t.Fatal(err)
	}
	report := out.String()
	if !strings.Contains(report, "Testing upstreams (1 total, 5 probes each, timeout 1s)...") {
		t.Fatalf("report:\n%s", report)
	}
	if !strings.Contains(report, "Summary: reachable 1/1") {
		t.Fatalf("report:\n%s", report)
	}
	if !strings.Contains(report, "5/5") {
		t.Fatalf("report:\n%s", report)
	}
}

func testProbes(successes int) []probeResult {
	probes := make([]probeResult, checkProbes)
	for i := range probes {
		if i < successes {
			probes[i] = probeResult{
				ok:      true,
				rcode:   dns.RcodeSuccess,
				elapsed: time.Duration(i+1) * 10 * time.Millisecond,
			}
			continue
		}
		probes[i] = probeResult{rcode: -1, err: errors.New("timeout")}
	}
	return probes
}
