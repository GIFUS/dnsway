package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestGetDecrementsTTL(t *testing.T) {
	c := New(100, 0, 0)
	key := Key{Name: "example.com", Type: dns.TypeA, Class: dns.ClassINET}
	now := time.Unix(1000, 0)
	c.Store(key, answerMsg("example.com.", "300"), now)

	msg, ok := c.Get(key, now.Add(100*time.Second))
	if !ok {
		t.Fatal("cache miss")
	}
	if ttl := msg.Answer[0].Header().Ttl; ttl != 200 {
		t.Fatalf("ttl = %d", ttl)
	}
	if _, ok := c.Get(key, now.Add(301*time.Second)); ok {
		t.Fatal("entry should be expired")
	}
}

func TestNegativeTTLUsesSOA(t *testing.T) {
	c := New(100, 0, 0)
	key := Key{Name: "missing.com", Type: dns.TypeA, Class: dns.ClassINET}
	now := time.Now()
	msg := new(dns.Msg)
	msg.SetQuestion("missing.com.", dns.TypeA)
	msg.Response = true
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{rr(t, "missing.com. 300 IN SOA ns.missing.com. host.missing.com. 1 2 3 4 60")}
	c.Store(key, msg, now)

	if _, ok := c.Get(key, now.Add(30*time.Second)); !ok {
		t.Fatal("negative entry should be cached")
	}
	if _, ok := c.Get(key, now.Add(61*time.Second)); ok {
		t.Fatal("negative entry should expire after SOA minimum")
	}
}

func TestClampTTL(t *testing.T) {
	c := New(100, 10*time.Second, time.Hour)
	now := time.Now()

	low := Key{Name: "low.com", Type: dns.TypeA, Class: dns.ClassINET}
	c.Store(low, answerMsg("low.com.", "5"), now)
	msg, ok := c.Get(low, now)
	if !ok || msg.Answer[0].Header().Ttl != 10 {
		t.Fatalf("low ttl = %v, ok %v", msg, ok)
	}

	high := Key{Name: "high.com", Type: dns.TypeA, Class: dns.ClassINET}
	c.Store(high, answerMsg("high.com.", "7200"), now)
	msg, ok = c.Get(high, now)
	if !ok || msg.Answer[0].Header().Ttl != 3600 {
		t.Fatalf("high ttl = %v, ok %v", msg, ok)
	}
}

func TestDoesNotCacheErrors(t *testing.T) {
	c := New(100, 0, 0)
	key := Key{Name: "fail.com", Type: dns.TypeA, Class: dns.ClassINET}
	now := time.Now()

	msg := new(dns.Msg)
	msg.SetQuestion("fail.com.", dns.TypeA)
	msg.Response = true
	msg.Rcode = dns.RcodeServerFailure
	c.Store(key, msg, now)

	truncated := answerMsg("fail.com.", "300")
	truncated.Truncated = true
	c.Store(key, truncated, now)

	if _, ok := c.Get(key, now); ok {
		t.Fatal("error responses must not be cached")
	}
}

func TestEviction(t *testing.T) {
	c := New(shardCount, 0, 0)
	now := time.Now()
	var keys []Key
	for i := 0; i < 100; i++ {
		key := Key{Name: fmt.Sprintf("host%d.test", i), Type: dns.TypeA, Class: dns.ClassINET}
		c.Store(key, answerMsg(key.Name+".", "300"), now)
		keys = append(keys, key)
	}

	found := 0
	for _, key := range keys {
		if _, ok := c.Get(key, now); ok {
			found++
		}
	}
	if found == 0 || found > shardCount {
		t.Fatalf("cached %d entries, want 1..%d", found, shardCount)
	}
}

func TestClear(t *testing.T) {
	c := New(100, 0, 0)
	key := Key{Name: "clear.com", Type: dns.TypeA, Class: dns.ClassINET}
	now := time.Now()
	c.Store(key, answerMsg("clear.com.", "300"), now)
	c.Clear()
	if _, ok := c.Get(key, now); ok {
		t.Fatal("cache should be empty")
	}
}

func answerMsg(name, ttl string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Response = true
	msg.Answer = []dns.RR{mustRR(name + " " + ttl + " IN A 1.2.3.4")}
	return msg
}

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustRR(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return r
}
