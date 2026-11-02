package stats

import (
	"math"
	"sync/atomic"
	"time"

	"dnsway/internal/router"
)

type QueryStats struct {
	Total        uint64  `json:"total"`
	Blocked      uint64  `json:"blocked"`
	Rules        uint64  `json:"rules"`
	Default      uint64  `json:"default"`
	CacheHits    uint64  `json:"cache_hits"`
	AvgElapsedMS float64 `json:"avg_elapsed_ms"`
}

type Snapshot struct {
	Queries       QueryStats `json:"queries"`
	UptimeSeconds int64      `json:"uptime_seconds"`
}

type Collector struct {
	started      time.Time
	total        atomic.Uint64
	blocked      atomic.Uint64
	rules        atomic.Uint64
	defaultCount atomic.Uint64
	cacheHits    atomic.Uint64
	elapsed      atomic.Int64
}

func New() *Collector {
	return &Collector{started: time.Now()}
}

func (c *Collector) Record(result router.Result, elapsed time.Duration) {
	c.total.Add(1)
	c.elapsed.Add(int64(elapsed))

	switch {
	case result.Rule == "default":
		c.defaultCount.Add(1)
	case result.Rule != "" && result.Rule != "none":
		c.rules.Add(1)
	}

	if result.Action == "block" {
		c.blocked.Add(1)
	}
	if result.CacheHit {
		c.cacheHits.Add(1)
	}
}

func (c *Collector) Snapshot() Snapshot {
	total := c.total.Load()
	avg := 0.0
	if total > 0 {
		avg = float64(c.elapsed.Load()) / float64(total) / float64(time.Millisecond)
		avg = math.Round(avg*100) / 100
	}
	return Snapshot{
		Queries: QueryStats{
			Total:        total,
			Blocked:      c.blocked.Load(),
			Rules:        c.rules.Load(),
			Default:      c.defaultCount.Load(),
			CacheHits:    c.cacheHits.Load(),
			AvgElapsedMS: avg,
		},
		UptimeSeconds: int64(time.Since(c.started).Seconds()),
	}
}
