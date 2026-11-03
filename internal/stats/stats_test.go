package stats

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dnsway/internal/router"
)

func TestSnapshot(t *testing.T) {
	c := New()
	c.Record(router.Result{Rule: "rules[0]", Action: "block"}, 10*time.Millisecond)
	c.Record(router.Result{Rule: "rules[1]", Action: "servers", CacheHit: true}, 30*time.Millisecond)
	c.Record(router.Result{Rule: "default", Action: "default", CacheHit: true}, 20*time.Millisecond)
	c.Record(router.Result{Rule: "none", Action: "format_error"}, 0)

	snapshot := c.Snapshot()
	if snapshot.Queries.Total != 4 {
		t.Fatalf("total = %d", snapshot.Queries.Total)
	}
	if snapshot.Queries.Blocked != 1 {
		t.Fatalf("blocked = %d", snapshot.Queries.Blocked)
	}
	if snapshot.Queries.Rules != 2 {
		t.Fatalf("rules = %d", snapshot.Queries.Rules)
	}
	if snapshot.Queries.Default != 1 {
		t.Fatalf("default = %d", snapshot.Queries.Default)
	}
	if snapshot.Queries.CacheHits != 2 {
		t.Fatalf("cache_hits = %d", snapshot.Queries.CacheHits)
	}
	if snapshot.Queries.AvgElapsedMS != 15 {
		t.Fatalf("avg_elapsed_ms = %v", snapshot.Queries.AvgElapsedMS)
	}
}

func TestSnapshotRoundsAverage(t *testing.T) {
	c := New()
	c.Record(router.Result{Rule: "default"}, 10*time.Millisecond)
	c.Record(router.Result{Rule: "default"}, 10*time.Millisecond)
	c.Record(router.Result{Rule: "default"}, 11*time.Millisecond)

	if got := c.Snapshot().Queries.AvgElapsedMS; got != 10.33 {
		t.Fatalf("avg_elapsed_ms = %v", got)
	}
}

func TestSnapshotDiagnostics(t *testing.T) {
	c := New()
	c.QueryStarted()
	c.ObserveUpstream("bad", -1, context.DeadlineExceeded, false)
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeServerFailure
	c.Record(router.Result{Rule: "default", Msg: msg}, time.Millisecond)

	snapshot := c.Snapshot()
	if snapshot.Queries.Servfail != 1 {
		t.Fatalf("servfail = %d", snapshot.Queries.Servfail)
	}
	if snapshot.Queries.UpstreamErrors != 1 || snapshot.Queries.UpstreamTimeouts != 1 {
		t.Fatalf("upstream = %+v", snapshot.Queries)
	}
	if snapshot.Runtime.ActiveQueries != 1 || snapshot.Runtime.Goroutines < 1 {
		t.Fatalf("runtime = %+v", snapshot.Runtime)
	}
	c.QueryFinished()
	if got := c.Snapshot().Runtime.ActiveQueries; got != 0 {
		t.Fatalf("active_queries = %d", got)
	}
}

func TestSnapshotEmpty(t *testing.T) {
	snapshot := New().Snapshot()
	if snapshot.Queries.Total != 0 || snapshot.Queries.AvgElapsedMS != 0 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}
