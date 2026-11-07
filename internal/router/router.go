package router

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
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

type Observer interface {
	ObserveUpstream(name string, rcode int, err error, valid bool)
}

type Router struct {
	rules     *rules.Store
	cache     *cache.Cache
	upstreams map[string]upstream.Resolver
	defaults  []string
	strategy  string
	timeout   time.Duration
	counter   atomic.Uint32
	logger    *slog.Logger
	observer  Observer
}

func New(
	cfg *config.Config,
	store *rules.Store,
	c *cache.Cache,
	upstreams map[string]upstream.Resolver,
	logger *slog.Logger,
	observer Observer,
) *Router {
	return &Router{
		rules:     store,
		cache:     c,
		upstreams: upstreams,
		defaults:  cfg.Routing.Default,
		strategy:  cfg.Routing.Strategy,
		timeout:   cfg.DNS.Timeout.Duration(),
		logger:    logger,
		observer:  observer,
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

	resp, cacheable := r.exchange(ctx, req, servers)
	if resp == nil {
		return errorReply(req, dns.RcodeServerFailure), false
	}
	resp.Id = req.Id
	resp.Question = req.Question
	if r.cache != nil && cacheable {
		r.cache.Store(key, resp, time.Now())
	}
	return resp, false
}

func (r *Router) exchange(ctx context.Context, req *dns.Msg, servers []string) (*dns.Msg, bool) {
	if len(servers) == 0 {
		return nil, false
	}
	switch r.strategy {
	case "fast":
		return r.exchangeFast(ctx, req, servers)
	case "round_robin":
		available := r.availableServers(servers)
		if len(available) == 0 {
			return nil, false
		}
		i := int(r.counter.Add(1)-1) % len(available)
		resp := r.exchangeOne(ctx, req, available[i])
		return resp, resp != nil
	default:
		return r.exchangeFirst(ctx, req, servers)
	}
}

func (r *Router) availableServers(servers []string) []string {
	available := make([]string, 0, len(servers))
	for _, name := range servers {
		if _, ok := r.upstreams[name]; ok {
			available = append(available, name)
		}
	}
	return available
}

func (r *Router) exchangeOne(ctx context.Context, req *dns.Msg, name string) *dns.Msg {
	resolver, ok := r.upstreams[name]
	if !ok {
		r.observeUpstream(name, nil, nil, false)
		return nil
	}
	resp, err := resolver.Exchange(ctx, req.Copy())
	valid := err == nil && validResponse(req, resp)
	r.observeUpstream(name, resp, err, valid)
	if !valid {
		return nil
	}
	return resp
}

func (r *Router) observeUpstream(name string, resp *dns.Msg, err error, valid bool) {
	rcode := -1
	if resp != nil {
		rcode = resp.Rcode
	}
	if r.observer != nil {
		r.observer.ObserveUpstream(name, rcode, err, valid)
	}
	if r.logger != nil {
		r.logger.Debug("upstream result",
			"name", name,
			"rcode", rcode,
			"valid", valid,
			"err", err,
		)
	}
}

type firstOutcome struct {
	index int
	resp  *dns.Msg
	valid bool
}

func (r *Router) exchangeFast(ctx context.Context, req *dns.Msg, servers []string) (*dns.Msg, bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan firstOutcome, len(servers))
	started := 0
	for index, name := range servers {
		resolver, ok := r.upstreams[name]
		if !ok {
			r.observeUpstream(name, nil, nil, false)
			continue
		}
		started++
		go func(index int, name string, resolver upstream.Resolver) {
			resp, err := resolver.Exchange(ctx, req.Copy())
			outcome := firstOutcome{index: index, resp: resp}
			if err == nil {
				outcome.valid = validResponse(req, resp)
			}
			if !errors.Is(err, context.Canceled) {
				r.observeUpstream(name, resp, err, outcome.valid)
			}
			select {
			case results <- outcome:
			case <-ctx.Done():
			}
		}(index, name, resolver)
	}
	if started == 0 {
		return nil, false
	}

	received := 0
	for received < started {
		select {
		case outcome := <-results:
			received++
			if outcome.valid {
				cancel()
				return outcome.resp, true
			}
		case <-ctx.Done():
			return nil, false
		}
	}
	return nil, false
}

func (r *Router) exchangeFirst(ctx context.Context, req *dns.Msg, servers []string) (*dns.Msg, bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan firstOutcome, len(servers))
	started := 0
	for index, name := range servers {
		resolver, ok := r.upstreams[name]
		if !ok {
			r.observeUpstream(name, nil, nil, false)
			continue
		}
		started++
		go func(index int, name string, resolver upstream.Resolver) {
			resp, err := resolver.Exchange(ctx, req.Copy())
			outcome := firstOutcome{index: index, resp: resp}
			if err == nil {
				outcome.valid = validEnvelope(req, resp) && !resp.Truncated
			}
			if !errors.Is(err, context.Canceled) {
				r.observeUpstream(name, resp, err, outcome.valid)
			}
			select {
			case results <- outcome:
			case <-ctx.Done():
			}
		}(index, name, resolver)
	}
	if started == 0 {
		return nil, false
	}

	var best *dns.Msg
	bestPriority := 0
	bestIndex := -1
	received := 0
	qtype := req.Question[0].Qtype
	for received < started {
		select {
		case outcome := <-results:
			received++
			if !outcome.valid {
				continue
			}
			if positiveResponse(outcome.resp, qtype) {
				cancel()
				return outcome.resp, true
			}
			priority := responsePriority(outcome.resp)
			if best == nil || priority > bestPriority || (priority == bestPriority && outcome.index > bestIndex) {
				best = outcome.resp
				bestPriority = priority
				bestIndex = outcome.index
			}
		case <-ctx.Done():
			if best != nil {
				return best, true
			}
			return nil, false
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}

func validEnvelope(req, resp *dns.Msg) bool {
	if resp == nil || resp.Id != req.Id || len(resp.Question) != 1 {
		return false
	}
	q, rq := req.Question[0], resp.Question[0]
	return q.Qtype == rq.Qtype && q.Qclass == rq.Qclass && strings.EqualFold(q.Name, rq.Name)
}

func validResponse(req, resp *dns.Msg) bool {
	if !validEnvelope(req, resp) {
		return false
	}
	return resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError
}

func positiveResponse(resp *dns.Msg, qtype uint16) bool {
	if resp.Rcode != dns.RcodeSuccess || resp.Truncated {
		return false
	}
	if qtype == dns.TypeANY {
		return len(resp.Answer) > 0
	}
	for _, rr := range resp.Answer {
		if rr != nil && rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

func responsePriority(resp *dns.Msg) int {
	switch resp.Rcode {
	case dns.RcodeNameError:
		return 3
	case dns.RcodeSuccess:
		return 2
	default:
		return 1
	}
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
