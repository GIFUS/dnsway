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

const (
	maxIdleStreamConns = 4
	streamIdleTimeout  = 90 * time.Second
)

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

type Client struct {
	name       string
	protocol   string
	address    string
	serverName string
	timeout    time.Duration
	dial       dialFunc
	http       *http.Client
	tlsConfig  *tls.Config
	pool       *streamPool
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
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = dial
		transport.ForceAttemptHTTP2 = true
		transport.MaxIdleConns = 100
		transport.MaxIdleConnsPerHost = 10
		transport.IdleConnTimeout = streamIdleTimeout
		transport.TLSHandshakeTimeout = timeout
		transport.ExpectContinueTimeout = time.Second
		c.http = &http.Client{Timeout: timeout, Transport: transport}
		return c
	}

	c.pool = newStreamPool(maxIdleStreamConns, streamIdleTimeout)
	if u.Protocol == "dot" {
		c.tlsConfig = &tls.Config{
			ServerName:         u.ServerName,
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),
		}
	}
	return c
}

func (c *Client) Close() error {
	if c.pool != nil {
		c.pool.close()
	}
	if c.http != nil {
		c.http.CloseIdleConnections()
	}
	return nil
}

type pooledConn struct {
	conn     *dns.Conn
	lastUsed time.Time
}

type streamPool struct {
	mu          sync.Mutex
	idle        []pooledConn
	maxIdle     int
	idleTimeout time.Duration
}

func newStreamPool(maxIdle int, idleTimeout time.Duration) *streamPool {
	return &streamPool{maxIdle: maxIdle, idleTimeout: idleTimeout}
}

func (p *streamPool) get() *dns.Conn {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()

	for len(p.idle) > 0 {
		last := len(p.idle) - 1
		item := p.idle[last]
		p.idle = p.idle[:last]
		if p.idleTimeout > 0 && now.Sub(item.lastUsed) >= p.idleTimeout {
			_ = item.conn.Conn.Close()
			continue
		}
		return item.conn
	}
	return nil
}

func (p *streamPool) put(conn *dns.Conn) {
	if conn == nil {
		return
	}
	if p.maxIdle <= 0 {
		_ = conn.Conn.Close()
		return
	}

	p.mu.Lock()
	if len(p.idle) >= p.maxIdle {
		p.mu.Unlock()
		_ = conn.Conn.Close()
		return
	}
	p.idle = append(p.idle, pooledConn{conn: conn, lastUsed: time.Now()})
	p.mu.Unlock()
}

func (p *streamPool) clear() {
	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	for _, item := range idle {
		_ = item.conn.Conn.Close()
	}
}

func (p *streamPool) close() {
	p.clear()
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
	var lastErr error
	forceFresh := false
	for attempt := 0; attempt < 2; attempt++ {
		dc, reused, err := c.streamConn(ctx, network, useTLS, forceFresh)
		if err != nil {
			return nil, err
		}

		resp, err := c.exchangeConn(ctx, dc, req)
		if err == nil {
			if network == "tcp" && c.pool != nil {
				c.pool.put(dc)
			} else {
				_ = dc.Conn.Close()
			}
			return resp, nil
		}
		_ = dc.Conn.Close()
		lastErr = err
		if !reused || ctx.Err() != nil {
			break
		}
		if c.pool != nil {
			c.pool.clear()
		}
		forceFresh = true
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%s: exchange failed", c.name)
	}
	return nil, lastErr
}

func (c *Client) streamConn(ctx context.Context, network string, useTLS, forceFresh bool) (*dns.Conn, bool, error) {
	if !forceFresh && network == "tcp" && c.pool != nil {
		if dc := c.pool.get(); dc != nil {
			return dc, true, nil
		}
	}

	conn, err := c.dial(ctx, network, c.address)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", c.name, err)
	}
	if useTLS {
		cfg := c.tlsConfig
		if cfg == nil {
			cfg = &tls.Config{ServerName: c.serverName, MinVersion: tls.VersionTLS12}
		}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, false, fmt.Errorf("%s: tls: %w", c.name, err)
		}
		conn = tlsConn
	}
	return &dns.Conn{Conn: conn, UDPSize: dns.MaxMsgSize}, false, nil
}

func (c *Client) exchangeConn(ctx context.Context, dc *dns.Conn, req *dns.Msg) (*dns.Msg, error) {
	stop := context.AfterFunc(ctx, func() { _ = dc.Conn.Close() })
	defer stop()

	if deadline, ok := ctx.Deadline(); ok {
		_ = dc.Conn.SetDeadline(deadline)
	} else {
		_ = dc.Conn.SetDeadline(time.Now().Add(c.timeout))
	}

	if err := dc.WriteMsg(req); err != nil {
		return nil, fmt.Errorf("%s: write: %w", c.name, err)
	}
	resp, err := dc.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("%s: read: %w", c.name, err)
	}
	if !stop() {
		_ = dc.Conn.Close()
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", c.name, err)
		}
		return nil, fmt.Errorf("%s: connection canceled", c.name)
	}
	if err := dc.Conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("%s: reset deadline: %w", c.name, err)
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
