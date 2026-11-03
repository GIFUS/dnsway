package stats

import (
	"context"
	"errors"
	"math"
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"dnsway/internal/router"
)

type QueryStats struct {
	Total            uint64  `json:"total"`
	Blocked          uint64  `json:"blocked"`
	Rules            uint64  `json:"rules"`
	Default          uint64  `json:"default"`
	CacheHits        uint64  `json:"cache_hits"`
	Servfail         uint64  `json:"servfail"`
	UpstreamErrors   uint64  `json:"upstream_errors"`
	UpstreamTimeouts uint64  `json:"upstream_timeouts"`
	AvgElapsedMS     float64 `json:"avg_elapsed_ms"`
}

type RuntimeStats struct {
	Goroutines    int   `json:"goroutines"`
	ActiveQueries int64 `json:"active_queries"`
}

type Snapshot struct {
	Queries       QueryStats   `json:"queries"`
	Runtime       RuntimeStats `json:"runtime"`
	UptimeSeconds int64        `json:"uptime_seconds"`
}

type Collector struct {
	started          time.Time
	total            atomic.Uint64
	blocked          atomic.Uint64
	rules            atomic.Uint64
	defaultCount     atomic.Uint64
	cacheHits        atomic.Uint64
	servfail         atomic.Uint64
	upstreamErrors   atomic.Uint64
	upstreamTimeouts atomic.Uint64
	activeQueries    atomic.Int64
	elapsed          atomic.Int64
}

func New() *Collector {
	return &Collector{started: time.Now()}
}

func (c *Collector) QueryStarted() {
	c.activeQueries.Add(1)
}

func (c *Collector) QueryFinished() {
	c.activeQueries.Add(-1)
}

func (c *Collector) ObserveUpstream(_ string, _ int, err error, valid bool) {
	if err != nil || !valid {
		c.upstreamErrors.Add(1)
	}
	if isTimeout(err) {
		c.upstreamTimeouts.Add(1)
	}
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
	if result.Msg != nil && result.Msg.Rcode == dns.RcodeServerFailure {
		c.servfail.Add(1)
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
			Total:            total,
			Blocked:          c.blocked.Load(),
			Rules:            c.rules.Load(),
			Default:          c.defaultCount.Load(),
			CacheHits:        c.cacheHits.Load(),
			Servfail:         c.servfail.Load(),
			UpstreamErrors:   c.upstreamErrors.Load(),
			UpstreamTimeouts: c.upstreamTimeouts.Load(),
			AvgElapsedMS:     avg,
		},
		Runtime: RuntimeStats{
			Goroutines:    runtime.NumGoroutine(),
			ActiveQueries: c.activeQueries.Load(),
		},
		UptimeSeconds: int64(time.Since(c.started).Seconds()),
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
