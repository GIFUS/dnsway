package upstream

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dnsway/internal/config"
)

func TestUDPExchange(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp, err := reply("1.2.3.4", req)
		if err != nil {
			return
		}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	client := newClient("udp", config.Upstream{Address: pc.LocalAddr().String(), Protocol: "udp"}, time.Second, directDial)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := client.Exchange(ctx, query("example.com."))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "1.2.3.4" {
		t.Fatalf("answer = %v", resp.Answer)
	}
}

func TestDoHExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(dohHandler))
	defer srv.Close()

	client := newClient("doh", config.Upstream{Address: srv.URL, Protocol: "doh"}, time.Second, directDial)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := client.Exchange(ctx, query("example.com."))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "5.6.7.8" {
		t.Fatalf("answer = %v", resp.Answer)
	}
}

func TestDoHReusesConnections(t *testing.T) {
	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(dohHandler))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	client := newClient("doh", config.Upstream{Address: srv.URL, Protocol: "doh"}, time.Second, directDial)
	defer client.Close()

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		resp, err := client.Exchange(ctx, query("example.com."))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("answer = %v", resp.Answer)
		}
	}
	if got := newConns.Load(); got != 1 {
		t.Fatalf("HTTP connections = %d, want 1", got)
	}
}

func TestTCPReusesConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingListener{Listener: listener}
	srv := &dns.Server{
		Listener: counted,
		Net:      "tcp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp, err := reply("1.2.3.4", req)
			if err == nil {
				_ = w.WriteMsg(resp)
			}
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	client := newClient("tcp", config.Upstream{Address: listener.Addr().String(), Protocol: "tcp"}, time.Second, directDial)
	defer client.Close()

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		resp, err := client.Exchange(ctx, query("example.com."))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("answer = %v", resp.Answer)
		}
	}
	if got := counted.count.Load(); got != 1 {
		t.Fatalf("TCP connections = %d, want 1", got)
	}
}

func TestTCPReconnectsStaleConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingListener{Listener: listener}
	srv := &dns.Server{
		Listener:      counted,
		Net:           "tcp",
		MaxTCPQueries: 1,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp, err := reply("1.2.3.4", req)
			if err == nil {
				_ = w.WriteMsg(resp)
			}
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	client := newClient("tcp", config.Upstream{Address: listener.Addr().String(), Protocol: "tcp"}, time.Second, directDial)
	defer client.Close()

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		resp, err := client.Exchange(ctx, query("example.com."))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("answer = %v", resp.Answer)
		}
	}
	if got := counted.count.Load(); got != 2 {
		t.Fatalf("TCP connections = %d, want 2", got)
	}
}

func TestDoTReusesConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingListener{Listener: listener}
	tlsListener := tls.NewListener(counted, &tls.Config{
		Certificates: []tls.Certificate{testCertificate(t)},
	})
	srv := &dns.Server{
		Listener: tlsListener,
		Net:      "tcp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp, err := reply("5.6.7.8", req)
			if err == nil {
				_ = w.WriteMsg(resp)
			}
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	client := newClient("dot", config.Upstream{
		Address:    listener.Addr().String(),
		Protocol:   "dot",
		ServerName: "localhost",
	}, time.Second, directDial)
	client.tlsConfig.InsecureSkipVerify = true
	defer client.Close()

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		resp, err := client.Exchange(ctx, query("example.com."))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("answer = %v", resp.Answer)
		}
	}
	if got := counted.count.Load(); got != 1 {
		t.Fatalf("TLS connections = %d, want 1", got)
	}
}

func TestStreamPoolExpiresIdleConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pool := &streamPool{
		maxIdle:     4,
		idleTimeout: time.Second,
		idle: []pooledConn{{
			conn:     &dns.Conn{Conn: client},
			lastUsed: time.Now().Add(-time.Hour),
		}},
	}
	if conn := pool.get(); conn != nil {
		conn.Conn.Close()
		t.Fatal("expired connection must not be reused")
	}
}

func TestBootstrapLookupCaches(t *testing.T) {
	fake := &fakeResolver{ip: "9.9.9.9", ttl: 120}
	b := newBootstrapper([]Resolver{fake})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	for i := 0; i < 2; i++ {
		ips, err := b.lookup(ctx, "dns.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if len(ips) != 1 || ips[0].String() != "9.9.9.9" {
			t.Fatalf("ips = %v", ips)
		}
	}
	if fake.count != 1 {
		t.Fatalf("lookups = %d", fake.count)
	}
}

func TestBootstrapLookupRetries(t *testing.T) {
	fake := &fakeResolver{err: errors.New("unreachable")}
	b := newBootstrapper([]Resolver{fake})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := b.lookupWithRetry(ctx, "dns.example.com", bootstrapAttempts, time.Millisecond)
	if err == nil {
		t.Fatal("expected error")
	}
	if fake.count < bootstrapAttempts {
		t.Fatalf("lookups = %d, want at least %d", fake.count, bootstrapAttempts)
	}
}

func TestPrepareIPUpstream(t *testing.T) {
	cfg := &config.Config{
		DNS: config.DNS{
			Timeout: config.Duration(time.Second),
			Upstreams: map[string]config.Upstream{
				"cf": {Address: "1.1.1.1:53", Protocol: "udp"},
			},
		},
	}

	prepared, err := Prepare(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Ready) != 1 || prepared.Ready[0] != "cf" {
		t.Fatalf("ready = %v", prepared.Ready)
	}
	if prepared.Resolvers["cf"] == nil {
		t.Fatal("cf resolver is missing")
	}
	if len(prepared.Skipped) != 0 {
		t.Fatalf("skipped = %v", prepared.Skipped)
	}
}

func TestPrepareSkipsUnresolvedHostname(t *testing.T) {
	cfg := &config.Config{
		DNS: config.DNS{
			Timeout: config.Duration(time.Second),
			Upstreams: map[string]config.Upstream{
				"bad":  {Address: "https://bad.example/dns-query", Protocol: "doh"},
				"good": {Address: "1.1.1.1:53", Protocol: "udp"},
			},
		},
	}
	bs := newBootstrapper([]Resolver{&fakeResolver{err: errors.New("nxdomain")}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	prepared, err := prepare(ctx, cfg, bs, directDial, time.Second, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := prepared.Resolvers["bad"]; ok {
		t.Fatal("unresolved upstream must be skipped")
	}
	if _, ok := prepared.Skipped["bad"]; !ok {
		t.Fatalf("skipped = %v", prepared.Skipped)
	}
	if _, ok := prepared.Resolvers["good"]; !ok {
		t.Fatal("IP upstream must be ready")
	}
}

func TestPrepareFailsWhenAllUpstreamsSkipped(t *testing.T) {
	cfg := &config.Config{
		DNS: config.DNS{
			Timeout: config.Duration(time.Second),
			Upstreams: map[string]config.Upstream{
				"bad": {Address: "https://bad.example/dns-query", Protocol: "doh"},
			},
		},
	}
	bs := newBootstrapper([]Resolver{&fakeResolver{err: errors.New("nxdomain")}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	prepared, err := prepare(ctx, cfg, bs, directDial, time.Second, discardLogger())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no upstreams available") || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("error = %v", err)
	}
	if len(prepared.Ready) != 0 {
		t.Fatalf("ready = %v", prepared.Ready)
	}
}

type fakeResolver struct {
	ip    string
	ttl   uint32
	err   error
	count int
}

func (f *fakeResolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	f.count++
	if f.err != nil {
		return nil, f.err
	}
	msg := new(dns.Msg)
	msg.SetReply(req)
	rr, err := dns.NewRR(req.Question[0].Name + " " + strconv.FormatUint(uint64(f.ttl), 10) + " IN A " + f.ip)
	if err != nil {
		return nil, err
	}
	msg.Answer = []dns.RR{rr}
	return msg, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func dohHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req dns.Msg
	if err := req.Unpack(body); err != nil {
		http.Error(w, "bad message", http.StatusBadRequest)
		return
	}
	resp, err := reply("5.6.7.8", &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	wire, err := resp.Pack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(wire)
}

type countingListener struct {
	net.Listener
	count atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.count.Add(1)
	}
	return conn, err
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func reply(ip string, req *dns.Msg) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	rr, err := dns.NewRR(req.Question[0].Name + " 300 IN A " + ip)
	if err != nil {
		return nil, err
	}
	msg.Answer = []dns.RR{rr}
	return msg, nil
}

func query(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	return msg
}

func directDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}
