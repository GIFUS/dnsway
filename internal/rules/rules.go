package rules

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"

	"dnsway/internal/config"
)

const maxFileSize = 32 << 20

type Action int

const (
	Block Action = iota + 1
	Route
	Static
	Hosts
)

type Match struct {
	Action  Action
	Name    string
	Servers []string
	IPs     []netip.Addr
}

type compiled struct {
	action     Action
	name       string
	matcher    matcher
	hasMatcher bool
	servers    []string
	ips        []netip.Addr
	hosts      map[string][]netip.Addr
}

type Store struct {
	rules atomic.Pointer[[]compiled]
}

func New(cfg *config.Config) (*Store, error) {
	s := new(Store)
	if err := s.Reload(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Reload(cfg *config.Config) error {
	rules, err := build(cfg)
	if err != nil {
		return err
	}
	s.rules.Store(&rules)
	return nil
}

func (s *Store) Match(name string) (Match, bool) {
	for _, r := range *s.rules.Load() {
		if r.action == Hosts {
			ips, ok := r.hosts[name]
			if !ok {
				continue
			}
			if r.hasMatcher && !r.matcher.match(name) {
				continue
			}
			return Match{Action: Hosts, Name: r.name, IPs: ips}, true
		}
		if !r.hasMatcher || !r.matcher.match(name) {
			continue
		}
		return Match{Action: r.action, Name: r.name, Servers: r.servers, IPs: r.ips}, true
	}
	return Match{}, false
}

func build(cfg *config.Config) ([]compiled, error) {
	result := make([]compiled, 0, len(cfg.Rules))
	for i, rc := range cfg.Rules {
		patterns := append([]string(nil), rc.Match...)
		if rc.MatchFile != "" {
			lines, err := readDomains(cfg.Path(rc.MatchFile))
			if err != nil {
				return nil, fmt.Errorf("rules[%d].match_file: %w", i, err)
			}
			patterns = append(patterns, lines...)
		}
		m, err := newMatcher(patterns)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}

		r := compiled{name: fmt.Sprintf("rules[%d]", i), matcher: m, hasMatcher: len(patterns) > 0}
		switch {
		case rc.Block:
			r.action = Block
		case rc.Resolve != "":
			ip, err := netip.ParseAddr(rc.Resolve)
			if err != nil {
				return nil, fmt.Errorf("rules[%d].resolve: %w", i, err)
			}
			r.action = Static
			r.ips = []netip.Addr{ip}
		case len(rc.Servers) > 0:
			r.action = Route
			r.servers = rc.Servers
		case len(rc.ResolveFile) > 0:
			hosts := make(map[string][]netip.Addr)
			for _, file := range rc.ResolveFile {
				if err := readHosts(cfg.Path(file), hosts); err != nil {
					return nil, fmt.Errorf("rules[%d].resolve_file: %w", i, err)
				}
			}
			r.action = Hosts
			r.hosts = hosts
		default:
			return nil, fmt.Errorf("rules[%d]: no action", i)
		}
		result = append(result, r)
	}
	return result, nil
}

type matcher struct {
	exact    map[string]struct{}
	wildcard []string
}

func newMatcher(patterns []string) (matcher, error) {
	m := matcher{exact: make(map[string]struct{})}
	for _, p := range patterns {
		p = normalize(p)
		if p == "" {
			return m, errors.New("empty domain pattern")
		}
		if strings.HasPrefix(p, "*.") {
			suffix := p[2:]
			if suffix == "" || strings.Contains(suffix, "*") {
				return m, fmt.Errorf("invalid pattern %q", p)
			}
			m.wildcard = append(m.wildcard, suffix)
			continue
		}
		if strings.Contains(p, "*") {
			return m, fmt.Errorf("invalid pattern %q", p)
		}
		m.exact[p] = struct{}{}
	}
	return m, nil
}

func (m matcher) match(name string) bool {
	if _, ok := m.exact[name]; ok {
		return true
	}
	for _, suffix := range m.wildcard {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func readDomains(path string) ([]string, error) {
	var domains []string
	err := scanFile(path, func(_ int, line string) error {
		domains = append(domains, line)
		return nil
	})
	return domains, err
}

func readHosts(path string, hosts map[string][]netip.Addr) error {
	return scanFile(path, func(_ int, line string) error {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return errors.New("expected IP address followed by hostname")
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			return err
		}
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "#") {
				break
			}
			if name := normalize(field); name != "" {
				hosts[name] = append(hosts[name], ip)
			}
		}
		return nil
	})
}

func scanFile(path string, fn func(lineNo int, line string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxFileSize {
		return fmt.Errorf("%s: file exceeds %d bytes", path, maxFileSize)
	}

	scanner := bufio.NewScanner(io.LimitReader(f, maxFileSize))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := fn(lineNo, line); err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
	}
	return scanner.Err()
}
