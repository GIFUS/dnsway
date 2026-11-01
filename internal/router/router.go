package router

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"dnsway/internal/cache"
	"dnsway/internal/config"
	"dnsway/internal/rules"
	"dnsway/internal/upstream"
)

const localTTL = 60

type Result struct {
	Msg      *dns.Msg
	Rule     string
	Action   string
	Servers  []string
	CacheHit bool
}

type Router struct {
	rules     *rules.Store
	cache     *cache.Cache
	upstreams map[string]upstream.Resolver
	defaults  []string
	strategy  string
	timeout   time.Duration
	counter   atomic.Uint32
}

func New(cfg *config.Config, store *rules.Store, c *cache.Cache, upstreams map[string]upstream.Resolver) *Router {
	return &Router{
		rules:     store,
		cache:     c,
		upstreams: upstreams,
		defaults:  cfg.Routing.Default,
		strategy:  cfg.Routing.Strategy,
		timeout:   cfg.DNS.Timeout.Duration(),
	}
}

func (r *Router) Resolve(ctx context.Context, req *dns.Msg) Result {
	if len(req.Question) != 1 {
		return Result{Msg: errorReply(req, dns.RcodeFormatError), Rule: "none", Action: "format_error"}
	}

	name := normalizeName(req.Question[0].Name)
	if m, ok := r.rules.Match(name); ok {
		switch m.Action {
		case rules.Block:
			return Result{Msg: errorReply(req, dns.RcodeNameError), Rule: m.Name, Action: "block"}
		case rules.Static:
			return Result{Msg: localReply(req, m.IPs), Rule: m.Name, Action: "resolve"}
		case rules.Hosts:
			return Result{Msg: localReply(req, m.IPs), Rule: m.Name, Action: "resolve_file"}
		case rules.Route:
			resp, cached := r.resolve(ctx, req, m.Servers)
			return Result{Msg: resp, Rule: m.Name, Action: "servers", Servers: m.Servers, CacheHit: cached}
		}
	}

	resp, cached := r.resolve(ctx, req, r.defaults)
	return Result{Msg: resp, Rule: "default", Action: "default", Servers: r.defaults, CacheHit: cached}
}

func (r *Router) resolve(ctx context.Context, req *dns.Msg, servers []string) (*dns.Msg, bool) {
	key := cacheKey(req)
	if r.cache != nil {
		if resp, ok := r.cache.Get(key, time.Now()); ok {
			resp.Id = req.Id
			resp.Question = req.Question
			return resp, true
		}
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	resp := r.exchange(ctx, req, servers)
	if resp == nil {
		return errorReply(req, dns.RcodeServerFailure), false
	}
	resp.Id = req.Id
	resp.Question = req.Question
	if r.cache != nil {
		r.cache.Store(key, resp, time.Now())
	}
	return resp, false
}

func (r *Router) exchange(ctx context.Context, req *dns.Msg, servers []string) *dns.Msg {
	if len(servers) == 0 {
		return nil
	}
	switch r.strategy {
	case "random":
		return r.exchangeOne(ctx, req, servers[rand.IntN(len(servers))])
	case "round_robin":
		i := int(r.counter.Add(1)-1) % len(servers)
		return r.exchangeOne(ctx, req, servers[i])
	default:
		return r.exchangeFirst(ctx, req, servers)
	}
}

func (r *Router) exchangeOne(ctx context.Context, req *dns.Msg, name string) *dns.Msg {
	resolver, ok := r.upstreams[name]
	if !ok {
		return nil
	}
	resp, err := resolver.Exchange(ctx, req.Copy())
	if err != nil || !validResponse(req, resp) {
		return nil
	}
	return resp
}

func (r *Router) exchangeFirst(ctx context.Context, req *dns.Msg, servers []string) *dns.Msg {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan *dns.Msg, len(servers))
	var wg sync.WaitGroup
	for _, name := range servers {
		resolver, ok := r.upstreams[name]
		if !ok {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := resolver.Exchange(ctx, req.Copy())
			if err != nil || !validResponse(req, resp) {
				return
			}
			select {
			case results <- resp:
			case <-ctx.Done():
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	resp, ok := <-results
	if !ok {
		return nil
	}
	cancel()
	return resp
}

func validResponse(req, resp *dns.Msg) bool {
	if resp == nil || resp.Id != req.Id || len(resp.Question) != 1 {
		return false
	}
	q, rq := req.Question[0], resp.Question[0]
	if q.Qtype != rq.Qtype || q.Qclass != rq.Qclass || !strings.EqualFold(q.Name, rq.Name) {
		return false
	}
	return resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError
}

func cacheKey(req *dns.Msg) cache.Key {
	q := req.Question[0]
	edns := req.IsEdns0()
	return cache.Key{
		Name:  normalizeName(q.Name),
		Type:  q.Qtype,
		Class: q.Qclass,
		DO:    edns != nil && edns.Do(),
		EDNS:  edns != nil,
	}
}

func errorReply(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	addOPT(req, m)
	return m
}

func localReply(req *dns.Msg, ips []netip.Addr) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	q := req.Question[0]

	for _, ip := range ips {
		switch {
		case q.Qtype == dns.TypeA && ip.Is4():
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: localTTL},
				A:   ip.AsSlice(),
			})
		case q.Qtype == dns.TypeAAAA && ip.Is6() && !ip.Is4In6():
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: localTTL},
				AAAA: ip.AsSlice(),
			})
		}
	}
	addOPT(req, m)
	return m
}

func addOPT(req, resp *dns.Msg) {
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	}
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}
