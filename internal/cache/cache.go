package cache

import (
	"container/list"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	shardCount = 16
	offset64   = 14695981039346656037
	prime64    = 1099511628211
)

type Key struct {
	Name  string
	Type  uint16
	Class uint16
	DO    bool
	EDNS  bool
}

type item struct {
	key    Key
	msg    *dns.Msg
	stored time.Time
	ttl    time.Duration
}

type shard struct {
	mu       sync.Mutex
	lru      *list.List
	items    map[Key]*list.Element
	capacity int
}

type Cache struct {
	shards      []shard
	minTTL      time.Duration
	maxTTL      time.Duration
	negativeTTL time.Duration
}

func New(maxSize int, minTTL, maxTTL, negativeTTL time.Duration) *Cache {
	if maxSize <= 0 {
		maxSize = 100000
	}
	capacity := (maxSize + shardCount - 1) / shardCount
	if capacity < 1 {
		capacity = 1
	}
	c := &Cache{
		shards:      make([]shard, shardCount),
		minTTL:      minTTL,
		maxTTL:      maxTTL,
		negativeTTL: negativeTTL,
	}
	for i := range c.shards {
		c.shards[i] = shard{
			lru:      list.New(),
			items:    make(map[Key]*list.Element),
			capacity: capacity,
		}
	}
	return c
}

func (c *Cache) Get(key Key, now time.Time) (*dns.Msg, bool) {
	sh := c.shard(key)
	sh.mu.Lock()
	el, ok := sh.items[key]
	if !ok {
		sh.mu.Unlock()
		return nil, false
	}
	it := el.Value.(*item)
	elapsed := now.Sub(it.stored)
	if elapsed >= it.ttl {
		sh.lru.Remove(el)
		delete(sh.items, key)
		sh.mu.Unlock()
		return nil, false
	}
	sh.lru.MoveToFront(el)
	msg := it.msg.Copy()
	sh.mu.Unlock()

	decay(msg, elapsed)
	return msg, true
}

func (c *Cache) Store(key Key, msg *dns.Msg, now time.Time) {
	ttl, ok := cacheTTL(msg, c.minTTL, c.maxTTL, c.negativeTTL)
	if !ok {
		return
	}
	stored := msg.Copy()
	clampTTL(stored, c.minTTL, c.maxTTL)

	sh := c.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if el, ok := sh.items[key]; ok {
		it := el.Value.(*item)
		it.msg = stored
		it.stored = now
		it.ttl = ttl
		sh.lru.MoveToFront(el)
		return
	}

	el := sh.lru.PushFront(&item{key: key, msg: stored, stored: now, ttl: ttl})
	sh.items[key] = el
	if sh.lru.Len() > sh.capacity {
		if back := sh.lru.Back(); back != nil {
			delete(sh.items, back.Value.(*item).key)
			sh.lru.Remove(back)
		}
	}
}

func (c *Cache) Clear() {
	for i := range c.shards {
		sh := &c.shards[i]
		sh.mu.Lock()
		sh.lru.Init()
		sh.items = make(map[Key]*list.Element)
		sh.mu.Unlock()
	}
}

func (c *Cache) shard(key Key) *shard {
	return &c.shards[hashKey(key)%shardCount]
}

func hashKey(k Key) uint64 {
	h := uint64(offset64)
	for i := 0; i < len(k.Name); i++ {
		h ^= uint64(k.Name[i])
		h *= prime64
	}
	h ^= uint64(k.Type)
	h *= prime64
	h ^= uint64(k.Class)
	h *= prime64
	if k.DO {
		h ^= 1
		h *= prime64
	}
	if k.EDNS {
		h ^= 2
		h *= prime64
	}
	return h
}

func cacheTTL(msg *dns.Msg, minTTL, maxTTL, fallbackNegativeTTL time.Duration) (time.Duration, bool) {
	if msg.Truncated {
		return 0, false
	}

	var seconds uint32
	switch msg.Rcode {
	case dns.RcodeSuccess:
		if len(msg.Answer) > 0 {
			seconds = minRRTTL(msg.Answer)
		} else {
			seconds = negativeTTL(msg.Ns)
		}
	case dns.RcodeNameError:
		seconds = negativeTTL(msg.Ns)
	default:
		return 0, false
	}
	if seconds == 0 {
		if !isNegativeResponse(msg) || fallbackNegativeTTL <= 0 {
			return 0, false
		}
		seconds = uint32(fallbackNegativeTTL / time.Second)
		if seconds == 0 {
			return 0, false
		}
	}

	ttl := time.Duration(seconds) * time.Second
	if minTTL > 0 && ttl < minTTL {
		ttl = minTTL
	}
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}
	if ttl <= 0 {
		return 0, false
	}
	return ttl, true
}

func isNegativeResponse(msg *dns.Msg) bool {
	return msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0)
}

func minRRTTL(rrs []dns.RR) uint32 {
	ttl := ^uint32(0)
	for _, rr := range rrs {
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	if ttl == ^uint32(0) {
		return 0
	}
	return ttl
}

func negativeTTL(rrs []dns.RR) uint32 {
	ttl := ^uint32(0)
	for _, rr := range rrs {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		v := min(soa.Hdr.Ttl, soa.Minttl)
		if v < ttl {
			ttl = v
		}
	}
	if ttl == ^uint32(0) {
		return 0
	}
	return ttl
}

func clampTTL(msg *dns.Msg, minTTL, maxTTL time.Duration) {
	minSec := uint32(minTTL / time.Second)
	maxSec := uint32(maxTTL / time.Second)
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			h := rr.Header()
			if minTTL > 0 && h.Ttl < minSec {
				h.Ttl = minSec
			}
			if maxTTL > 0 && h.Ttl > maxSec {
				h.Ttl = maxSec
			}
		}
	}
}

func decay(msg *dns.Msg, elapsed time.Duration) {
	seconds := uint32(elapsed / time.Second)
	if seconds == 0 {
		return
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if h.Ttl > seconds {
				h.Ttl -= seconds
			} else {
				h.Ttl = 0
			}
		}
	}
}
