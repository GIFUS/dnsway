package stats

import (
	"testing"
	"time"

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

func TestSnapshotEmpty(t *testing.T) {
	snapshot := New().Snapshot()
	if snapshot.Queries.Total != 0 || snapshot.Queries.AvgElapsedMS != 0 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}
