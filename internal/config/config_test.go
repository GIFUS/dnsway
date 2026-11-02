package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDuration(t *testing.T) {
	var d Duration
	if err := d.UnmarshalJSON([]byte(`"1h30m"`)); err != nil {
		t.Fatal(err)
	}
	if d.Duration() != 90*time.Minute {
		t.Fatalf("got %v", d.Duration())
	}
	if err := d.UnmarshalJSON([]byte(`"bad"`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg := load(t, `{
		"dns": {
			"listen": "127.0.0.1:53",
			"upstreams": {"cf": {"address": "1.1.1.1:53", "protocol": "udp"}}
		},
		"routing": {"default": ["cf"]}
	}`)
	if cfg.DNS.Timeout.Duration() != 3*time.Second {
		t.Fatalf("timeout = %v", cfg.DNS.Timeout.Duration())
	}
	if cfg.Routing.Strategy != "first" {
		t.Fatalf("strategy = %q", cfg.Routing.Strategy)
	}
	if cfg.Cache.MaxSize != 100000 {
		t.Fatalf("max_size = %d", cfg.Cache.MaxSize)
	}
	if got := cfg.Cache.NegativeTTLDuration(); got != 30*time.Second {
		t.Fatalf("negative_ttl = %v", got)
	}
}

func TestLoadValid(t *testing.T) {
	cfg := load(t, `{
		"dns": {
			"listen": "127.0.0.1:53",
			"timeout": "2s",
			"upstreams": {"cf": {"address": "1.1.1.1:53", "protocol": "udp"}}
		},
		"routing": {"default": ["cf"], "strategy": "round_robin"},
		"cache": {"enabled": true, "max_size": 10, "min_ttl": "1s", "max_ttl": "1h", "negative_ttl": "45s"},
		"rules": [{"match": ["example.com"], "resolve": "192.168.1.2"}]
	}`)
	if cfg.Routing.Strategy != "round_robin" {
		t.Fatalf("strategy = %q", cfg.Routing.Strategy)
	}
	if got := cfg.Cache.NegativeTTLDuration(); got != 45*time.Second {
		t.Fatalf("negative_ttl = %v", got)
	}
}

func TestLoadExplicitZeroNegativeTTL(t *testing.T) {
	cfg := load(t, `{
		"dns": {
			"listen": "127.0.0.1:53",
			"upstreams": {"cf": {"address": "1.1.1.1:53", "protocol": "udp"}}
		},
		"routing": {"default": ["cf"]},
		"cache": {"negative_ttl": "0s"}
	}`)
	if got := cfg.Cache.NegativeTTLDuration(); got != 0 {
		t.Fatalf("negative_ttl = %v", got)
	}
}

func TestLoadAPI(t *testing.T) {
	cfg := load(t, `{
		"dns": {
			"listen": "127.0.0.1:53",
			"upstreams": {"cf": {"address": "1.1.1.1:53", "protocol": "udp"}}
		},
		"routing": {"default": ["cf"]},
		"api": {
			"enabled": true,
			"allowed_ips": ["127.0.0.1", "192.0.2.0/24"]
		}
	}`)
	if !cfg.API.Enabled {
		t.Fatal("api.enabled = false")
	}
	if cfg.API.Listen != "127.0.0.1:8080" {
		t.Fatalf("api.listen = %q", cfg.API.Listen)
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown upstream",
			body: `{"dns":{"listen":"127.0.0.1:53","upstreams":{"cf":{"address":"1.1.1.1:53","protocol":"udp"}}},"routing":{"default":["x"]}}`,
			want: "unknown upstream",
		},
		{
			name: "conflicting actions",
			body: `{"dns":{"listen":"127.0.0.1:53","upstreams":{"cf":{"address":"1.1.1.1:53","protocol":"udp"}}},"routing":{"default":["cf"]},"rules":[{"match":["a.com"],"block":true,"servers":["cf"]}]}`,
			want: "exactly one action",
		},
		{
			name: "dot without server name",
			body: `{"dns":{"listen":"127.0.0.1:53","upstreams":{"cf":{"address":"1.1.1.1:853","protocol":"dot"}}},"routing":{"default":["cf"]}}`,
			want: "server_name",
		},
		{
			name: "hostname without bootstrap",
			body: `{"dns":{"listen":"127.0.0.1:53","upstreams":{"cf":{"address":"dns.example.com:53","protocol":"udp"}}},"routing":{"default":["cf"]}}`,
			want: "bootstrap",
		},
		{
			name: "bad protocol",
			body: `{"dns":{"listen":"127.0.0.1:53","upstreams":{"cf":{"address":"1.1.1.1:53","protocol":"quic"}}},"routing":{"default":["cf"]}}`,
			want: "unsupported protocol",
		},
		{
			name: "negative negative ttl",
			body: `{"dns":{"listen":"127.0.0.1:53","upstreams":{"cf":{"address":"1.1.1.1:53","protocol":"udp"}}},"routing":{"default":["cf"]},"cache":{"negative_ttl":"-1s"}}`,
			want: "cache.negative_ttl",
		},
		{
			name: "invalid api listen",
			body: `{"dns":{"listen":"127.0.0.1:53","upstreams":{"cf":{"address":"1.1.1.1:53","protocol":"udp"}}},"routing":{"default":["cf"]},"api":{"enabled":true,"listen":"127.0.0.1"}}`,
			want: "api.listen",
		},
		{
			name: "invalid api allowed ip",
			body: `{"dns":{"listen":"127.0.0.1:53","upstreams":{"cf":{"address":"1.1.1.1:53","protocol":"udp"}}},"routing":{"default":["cf"]},"api":{"enabled":true,"allowed_ips":["not-an-ip"]}}`,
			want: "api.allowed_ips",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadErr(t, tt.body)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func load(t *testing.T, body string) *Config {
	t.Helper()
	cfg, err := loadErr(t, body)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func loadErr(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}
