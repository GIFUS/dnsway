package rules

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnsway/internal/config"
)

func TestMatch(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "match.txt", "# comment\n*.example.org\nsite.test\n\n")
	writeFile(t, dir, "hosts.txt", "192.168.1.10 nas.local\nfd00::10 nas.local\n")

	store, err := New(&config.Config{
		Dir: dir,
		Rules: []config.Rule{
			{Match: []string{"*.ads.example.com"}, Block: true},
			{Match: []string{"example.com"}, Servers: []string{"cf"}},
			{MatchFile: "match.txt", Servers: []string{"google"}},
			{Match: []string{"static.local"}, Resolve: "192.168.1.5"},
			{ResolveFile: []string{"hosts.txt"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		action Action
	}{
		{"banner.ads.example.com", Block},
		{"ads.example.com", Block},
		{"example.com", Route},
		{"sub.example.org", Route},
		{"example.org", Route},
		{"site.test", Route},
		{"static.local", Static},
		{"nas.local", Hosts},
	}
	for _, tt := range tests {
		m, ok := store.Match(tt.name)
		if !ok || m.Action != tt.action {
			t.Fatalf("%s: got action %v, ok %v", tt.name, m.Action, ok)
		}
	}

	for _, name := range []string{"sub.example.com", "unknown.test", "notexample.org", "example.org.evil"} {
		if _, ok := store.Match(name); ok {
			t.Fatalf("%s should not match", name)
		}
	}

	m, _ := store.Match("nas.local")
	if len(m.IPs) != 2 {
		t.Fatalf("ips = %v", m.IPs)
	}
}

func TestWildcardIncludesApex(t *testing.T) {
	m, err := newMatcher([]string{"*.google.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"google.com", "www.google.com", "mail.api.google.com"} {
		if !m.match(name) {
			t.Fatalf("%s should match", name)
		}
	}
	for _, name := range []string{"notgoogle.com", "google.com.evil", "google.co"} {
		if m.match(name) {
			t.Fatalf("%s should not match", name)
		}
	}
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "match.txt", "one.test\n")
	cfg := &config.Config{
		Dir:   dir,
		Rules: []config.Rule{{MatchFile: "match.txt", Servers: []string{"cf"}}},
	}
	store, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Match("one.test"); !ok {
		t.Fatal("one.test should match")
	}

	writeFile(t, dir, "match.txt", "two.test\n")
	if err := store.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Match("one.test"); ok {
		t.Fatal("one.test should be gone")
	}
	if _, ok := store.Match("two.test"); !ok {
		t.Fatal("two.test should match")
	}
}

func TestNewMatcherRejectsInvalid(t *testing.T) {
	for _, p := range []string{"", "a.*.com", "*com"} {
		if _, err := newMatcher([]string{p}); err == nil {
			t.Fatalf("%q should be rejected", p)
		}
	}
}

func TestBuildErrors(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		rule config.Rule
		want string
	}{
		{"missing match file", config.Rule{MatchFile: "missing.txt", Block: true}, "match_file"},
		{"invalid resolve", config.Rule{Match: []string{"a.test"}, Resolve: "not-an-ip"}, "resolve"},
		{"missing resolve file", config.Rule{ResolveFile: []string{"missing.txt"}}, "resolve_file"},
		{"no action", config.Rule{Match: []string{"a.test"}}, "no action"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(&config.Config{Dir: dir, Rules: []config.Rule{tt.rule}})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestReadHosts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hosts.txt", "# comment\n192.168.1.10 nas.local printer.local # comment\nfd00::10 nas.local\n")
	hosts := make(map[string][]netip.Addr)
	if err := readHosts(filepath.Join(dir, "hosts.txt"), hosts); err != nil {
		t.Fatal(err)
	}
	if len(hosts["nas.local"]) != 2 {
		t.Fatalf("nas.local = %v", hosts["nas.local"])
	}
	if got := hosts["printer.local"]; len(got) != 1 || got[0].String() != "192.168.1.10" {
		t.Fatalf("printer.local = %v", got)
	}

	writeFile(t, dir, "bad-hosts.txt", "192.168.1.10\n")
	if err := readHosts(filepath.Join(dir, "bad-hosts.txt"), hosts); err == nil {
		t.Fatal("expected missing hostname error")
	}

	writeFile(t, dir, "bad-ip.txt", "not-an-ip nas.local\n")
	if err := readHosts(filepath.Join(dir, "bad-ip.txt"), hosts); err == nil {
		t.Fatal("expected invalid IP error")
	}
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
