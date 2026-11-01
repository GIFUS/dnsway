package upstream

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer srv.Close()

	client := newClient("doh", config.Upstream{Address: srv.URL, Protocol: "doh"}, time.Second, directDial)
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

type fakeResolver struct {
	ip    string
	ttl   uint32
	count int
}

func (f *fakeResolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	f.count++
	msg := new(dns.Msg)
	msg.SetReply(req)
	rr, err := dns.NewRR(req.Question[0].Name + " " + strconv.FormatUint(uint64(f.ttl), 10) + " IN A " + f.ip)
	if err != nil {
		return nil, err
	}
	msg.Answer = []dns.RR{rr}
	return msg, nil
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
