package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) Duration() time.Duration { return time.Duration(d) }

type Config struct {
	DNS     DNS     `json:"dns"`
	Routing Routing `json:"routing"`
	Cache   Cache   `json:"cache"`
	Rules   []Rule  `json:"rules"`
	Dir     string  `json:"-"`
}

type DNS struct {
	Listen    string              `json:"listen"`
	Timeout   Duration            `json:"timeout"`
	Bootstrap []string            `json:"bootstrap"`
	Upstreams map[string]Upstream `json:"upstreams"`
}

type Upstream struct {
	Address    string `json:"address"`
	Protocol   string `json:"protocol"`
	ServerName string `json:"server_name"`
}

type Routing struct {
	Default  []string `json:"default"`
	Strategy string   `json:"strategy"`
}

const defaultNegativeTTL = 30 * time.Second

type Cache struct {
	Enabled     bool      `json:"enabled"`
	MaxSize     int       `json:"max_size"`
	MinTTL      Duration  `json:"min_ttl"`
	MaxTTL      Duration  `json:"max_ttl"`
	NegativeTTL *Duration `json:"negative_ttl"`
}

func (c Cache) NegativeTTLDuration() time.Duration {
	if c.NegativeTTL == nil {
		return defaultNegativeTTL
	}
	return c.NegativeTTL.Duration()
}

type Rule struct {
	Match       []string `json:"match"`
	MatchFile   string   `json:"match_file"`
	Servers     []string `json:"servers"`
	Block       bool     `json:"block"`
	Resolve     string   `json:"resolve"`
	ResolveFile []string `json:"resolve_file"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	cfg.Dir = filepath.Dir(abs)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Path(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.Dir, p)
}

func (c *Config) RuleFiles() []string {
	var files []string
	for _, r := range c.Rules {
		if r.MatchFile != "" {
			files = append(files, c.Path(r.MatchFile))
		}
		for _, f := range r.ResolveFile {
			files = append(files, c.Path(f))
		}
	}
	return files
}

func (c *Config) Validate() error {
	if c.DNS.Listen == "" {
		return fmt.Errorf("dns.listen is required")
	}
	if _, port, err := net.SplitHostPort(c.DNS.Listen); err != nil {
		return fmt.Errorf("dns.listen: %w", err)
	} else if err := validPort(port); err != nil {
		return fmt.Errorf("dns.listen: %w", err)
	}

	if c.DNS.Timeout == 0 {
		c.DNS.Timeout = Duration(3 * time.Second)
	}
	if c.DNS.Timeout < 0 {
		return fmt.Errorf("dns.timeout must be positive")
	}

	if len(c.DNS.Upstreams) == 0 {
		return fmt.Errorf("dns.upstreams is empty")
	}
	for id, u := range c.DNS.Upstreams {
		if id == "" {
			return fmt.Errorf("dns.upstreams: empty id")
		}
		u.Protocol = strings.ToLower(u.Protocol)
		u.Address = strings.TrimSpace(u.Address)
		u.ServerName = strings.TrimSpace(u.ServerName)
		c.DNS.Upstreams[id] = u
		if err := validateUpstream(u); err != nil {
			return fmt.Errorf("dns.upstreams.%s: %w", id, err)
		}
	}

	for _, id := range c.DNS.Bootstrap {
		u, ok := c.DNS.Upstreams[id]
		if !ok {
			return fmt.Errorf("dns.bootstrap: unknown upstream %q", id)
		}
		if !isIP(upstreamHost(u)) {
			return fmt.Errorf("dns.bootstrap: upstream %q must use an IP address", id)
		}
	}
	for id, u := range c.DNS.Upstreams {
		if !isIP(upstreamHost(u)) && len(c.DNS.Bootstrap) == 0 {
			return fmt.Errorf("dns.upstreams.%s: hostname requires dns.bootstrap", id)
		}
	}

	if len(c.Routing.Default) == 0 {
		return fmt.Errorf("routing.default is empty")
	}
	for _, id := range c.Routing.Default {
		if _, ok := c.DNS.Upstreams[id]; !ok {
			return fmt.Errorf("routing.default: unknown upstream %q", id)
		}
	}
	c.Routing.Strategy = strings.ToLower(c.Routing.Strategy)
	if c.Routing.Strategy == "" {
		c.Routing.Strategy = "first"
	}
	switch c.Routing.Strategy {
	case "first", "random", "round_robin":
	default:
		return fmt.Errorf("routing.strategy: unsupported value %q", c.Routing.Strategy)
	}

	if c.Cache.MaxSize == 0 {
		c.Cache.MaxSize = 100000
	}
	if c.Cache.MaxSize < 0 {
		return fmt.Errorf("cache.max_size must be positive")
	}
	if c.Cache.MinTTL < 0 || c.Cache.MaxTTL < 0 {
		return fmt.Errorf("cache TTL values must not be negative")
	}
	if c.Cache.NegativeTTL != nil && c.Cache.NegativeTTL.Duration() < 0 {
		return fmt.Errorf("cache.negative_ttl must not be negative")
	}
	if c.Cache.MaxTTL > 0 && c.Cache.MinTTL > c.Cache.MaxTTL {
		return fmt.Errorf("cache.min_ttl must not exceed cache.max_ttl")
	}

	for i, r := range c.Rules {
		if err := c.validateRule(r); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}

func (c *Config) validateRule(r Rule) error {
	actions := 0
	if r.Block {
		actions++
	}
	if r.Resolve != "" {
		actions++
	}
	if len(r.Servers) > 0 {
		actions++
	}
	if len(r.ResolveFile) > 0 {
		actions++
	}
	if actions != 1 {
		return fmt.Errorf("exactly one action is required (block, resolve, servers or resolve_file)")
	}

	if len(r.ResolveFile) == 0 && len(r.Match) == 0 && r.MatchFile == "" {
		return fmt.Errorf("match or match_file is required")
	}
	if r.Resolve != "" {
		if _, err := netip.ParseAddr(r.Resolve); err != nil {
			return fmt.Errorf("resolve: %w", err)
		}
	}
	for _, id := range r.Servers {
		if _, ok := c.DNS.Upstreams[id]; !ok {
			return fmt.Errorf("unknown upstream %q", id)
		}
	}
	return nil
}

func validateUpstream(u Upstream) error {
	if u.Address == "" {
		return fmt.Errorf("address is required")
	}
	switch u.Protocol {
	case "udp", "tcp", "dot":
		host, port, err := net.SplitHostPort(u.Address)
		if err != nil {
			return err
		}
		if host == "" {
			return fmt.Errorf("address host is empty")
		}
		if err := validPort(port); err != nil {
			return err
		}
		if u.Protocol == "dot" && u.ServerName == "" {
			return fmt.Errorf("server_name is required for dot")
		}
	case "doh":
		if _, err := parseDoH(u.Address); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported protocol %q", u.Protocol)
	}
	return nil
}

func parseDoH(address string) (*url.URL, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("doh address must be an https URL")
	}
	return u, nil
}

func upstreamHost(u Upstream) string {
	if u.Protocol == "doh" {
		parsed, err := url.Parse(u.Address)
		if err != nil {
			return ""
		}
		return parsed.Hostname()
	}
	host, _, err := net.SplitHostPort(u.Address)
	if err != nil {
		return ""
	}
	return host
}

func validPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

func isIP(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}
