package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"

	"dnsway/internal/config"
)

type Resolver interface {
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

type Client struct {
	name       string
	protocol   string
	address    string
	serverName string
	timeout    time.Duration
	dial       dialFunc
	http       *http.Client
}

func New(cfg *config.Config) map[string]Resolver {
	timeout := cfg.DNS.Timeout.Duration()
	direct := func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, address)
	}

	var bootstrap []Resolver
	for _, id := range cfg.DNS.Bootstrap {
		bootstrap = append(bootstrap, newClient(id, cfg.DNS.Upstreams[id], timeout, direct))
	}

	dial := direct
	if len(bootstrap) > 0 {
		dial = newBootstrapper(bootstrap).DialContext
	}

	result := make(map[string]Resolver, len(cfg.DNS.Upstreams))
	for id, u := range cfg.DNS.Upstreams {
		result[id] = newClient(id, u, timeout, dial)
	}
	return result
}

func newClient(name string, u config.Upstream, timeout time.Duration, dial dialFunc) *Client {
	c := &Client{
		name:       name,
		protocol:   u.Protocol,
		address:    u.Address,
		serverName: u.ServerName,
		timeout:    timeout,
		dial:       dial,
	}
	if u.Protocol == "doh" {
		c.http = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				ForceAttemptHTTP2: true,
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					return dial(ctx, network, address)
				},
			},
		}
	}
	return c
}

func (c *Client) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if c.protocol == "doh" {
		return c.exchangeDoH(ctx, req)
	}

	network := "tcp"
	useTLS := false
	switch c.protocol {
	case "udp":
		network = "udp"
	case "dot":
		useTLS = true
	}

	resp, err := c.exchangeStream(ctx, network, useTLS, req)
	if err != nil {
		return nil, err
	}
	if c.protocol == "udp" && resp.Truncated {
		if tcpResp, err := c.exchangeStream(ctx, "tcp", false, req); err == nil {
			return tcpResp, nil
		}
	}
	return resp, nil
}

func (c *Client) exchangeStream(ctx context.Context, network string, useTLS bool, req *dns.Msg) (*dns.Msg, error) {
	conn, err := c.dial(ctx, network, c.address)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.name, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(c.timeout))
	}

	if useTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: c.serverName,
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("%s: tls: %w", c.name, err)
		}
		conn = tlsConn
	}

	dc := &dns.Conn{Conn: conn, UDPSize: dns.MaxMsgSize}
	if err := dc.WriteMsg(req); err != nil {
		return nil, fmt.Errorf("%s: write: %w", c.name, err)
	}
	resp, err := dc.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("%s: read: %w", c.name, err)
	}
	return resp, nil
}

func (c *Client) exchangeDoH(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("%s: pack: %w", c.name, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.address, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.name, err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s: http %s", c.name, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("%s: read: %w", c.name, err)
	}
	var msg dns.Msg
	if err := msg.Unpack(body); err != nil {
		return nil, fmt.Errorf("%s: unpack: %w", c.name, err)
	}
	return &msg, nil
}

type bootstrapEntry struct {
	ips     []netip.Addr
	expires time.Time
}

type bootstrapper struct {
	resolvers []Resolver
	mu        sync.Mutex
	cache     map[string]bootstrapEntry
}

func newBootstrapper(resolvers []Resolver) *bootstrapper {
	return &bootstrapper{resolvers: resolvers, cache: make(map[string]bootstrapEntry)}
}

func (b *bootstrapper) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := b.lookup(ctx, host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no addresses for %s", host)
	}
	return nil, lastErr
}

func (b *bootstrapper) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	now := time.Now()
	b.mu.Lock()
	if e, ok := b.cache[host]; ok && now.Before(e.expires) {
		ips := e.ips
		b.mu.Unlock()
		return ips, nil
	}
	b.mu.Unlock()

	ips, ttl, err := b.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.cache[host] = bootstrapEntry{ips: ips, expires: now.Add(ttl)}
	b.mu.Unlock()
	return ips, nil
}

func (b *bootstrapper) resolve(ctx context.Context, host string) ([]netip.Addr, time.Duration, error) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(host), qtype)
		req.RecursionDesired = true

		for _, resolver := range b.resolvers {
			resp, err := resolver.Exchange(ctx, req.Copy())
			if err != nil || resp.Rcode != dns.RcodeSuccess {
				continue
			}
			ips, ttl := answerAddrs(resp.Answer)
			if len(ips) > 0 {
				return ips, ttl, nil
			}
		}
	}
	return nil, 0, fmt.Errorf("cannot resolve %s", host)
}

func answerAddrs(rrs []dns.RR) ([]netip.Addr, time.Duration) {
	ttl := ^uint32(0)
	var ips []netip.Addr
	for _, rr := range rrs {
		var ip netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			ip, _ = netip.AddrFromSlice(v.A)
		case *dns.AAAA:
			ip, _ = netip.AddrFromSlice(v.AAAA)
		default:
			continue
		}
		if !ip.IsValid() {
			continue
		}
		ips = append(ips, ip.Unmap())
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	seconds := uint32(60)
	if ttl != ^uint32(0) && ttl >= 10 {
		seconds = ttl
	}
	return ips, time.Duration(seconds) * time.Second
}
