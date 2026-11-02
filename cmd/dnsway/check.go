package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/miekg/dns"

	"dnsway/internal/config"
	"dnsway/internal/upstream"
)

const (
	checkQueryName  = "example.com."
	checkProbes     = 5
	checkMinSuccess = 3
)

var errCheckFailed = errors.New("configuration check failed")

type probeResult struct {
	ok      bool
	rcode   int
	elapsed time.Duration
	err     error
}

type upstreamResult struct {
	name      string
	protocol  string
	address   string
	role      string
	probes    int
	successes int
	ok        bool
	rcode     int
	avg       time.Duration
	err       error
}

func runCheck(cfg *config.Config, path string, out io.Writer, resolvers map[string]upstream.Resolver) error {
	printConfig(out, path, cfg)
	printRules(out, cfg)
	fmt.Fprintf(out, "\nTesting upstreams (%d total, %d probes each, timeout %s)...\n", len(resolvers), checkProbes, checkTimeout(cfg))

	results := checkUpstreams(cfg, resolvers)
	printUpstreams(out, results)

	failed := 0
	for _, result := range results {
		if !result.ok {
			failed++
		}
	}
	fmt.Fprintf(out, "\nSummary: reachable %d/%d\n", len(results)-failed, len(results))
	if failed > 0 {
		return errCheckFailed
	}
	return nil
}

func checkUpstreams(cfg *config.Config, resolvers map[string]upstream.Resolver) []upstreamResult {
	timeout := checkTimeout(cfg)
	results := make([]upstreamResult, 0, len(resolvers))
	ch := make(chan upstreamResult, len(resolvers))
	for name, resolver := range resolvers {
		u := cfg.DNS.Upstreams[name]
		role := upstreamRole(cfg, name)
		go func() {
			probes := make([]probeResult, checkProbes)
			for i := range probes {
				probes[i] = checkProbe(resolver, timeout)
			}
			ch <- summarize(name, u, role, probes)
		}()
	}

	for range resolvers {
		results = append(results, <-ch)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].name < results[j].name })
	return results
}

func checkProbe(resolver upstream.Resolver, timeout time.Duration) probeResult {
	req := new(dns.Msg)
	req.SetQuestion(checkQueryName, dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	resp, err := resolver.Exchange(ctx, req)
	result := probeResult{rcode: -1, elapsed: time.Since(start)}
	switch {
	case err != nil:
		result.err = err
	case resp == nil:
		result.err = errors.New("empty response")
	default:
		result.ok = true
		result.rcode = resp.Rcode
	}
	return result
}

func summarize(name string, u config.Upstream, role string, probes []probeResult) upstreamResult {
	result := upstreamResult{
		name:     name,
		protocol: u.Protocol,
		address:  u.Address,
		role:     role,
		probes:   len(probes),
		rcode:    -1,
	}

	var total time.Duration
	for _, probe := range probes {
		if probe.ok {
			if result.successes == 0 {
				result.rcode = probe.rcode
			}
			result.successes++
			total += probe.elapsed
			continue
		}
		if result.err == nil && probe.err != nil {
			result.err = probe.err
		}
	}

	result.ok = result.successes >= checkMinSuccess
	if result.successes > 0 {
		result.avg = total / time.Duration(result.successes)
	}
	return result
}

func checkTimeout(cfg *config.Config) time.Duration {
	timeout := cfg.DNS.Timeout.Duration()
	if timeout <= 0 {
		return 3 * time.Second
	}
	return timeout
}

func printConfig(out io.Writer, path string, cfg *config.Config) {
	fmt.Fprintf(out, "Config: %s (valid)\n", path)
	fmt.Fprintf(out, "Listen: %s (udp+tcp)\n", cfg.DNS.Listen)
	fmt.Fprintf(out, "Timeout: %s\n", cfg.DNS.Timeout.Duration())
	fmt.Fprintf(out, "Strategy: %s\n", cfg.Routing.Strategy)
	printCache(out, cfg)
	printAPI(out, cfg)
	fmt.Fprintf(out, "Bootstrap: %s\n", listOrNone(cfg.DNS.Bootstrap))
	fmt.Fprintf(out, "Default: %s\n", listOrNone(cfg.Routing.Default))
}

func printCache(out io.Writer, cfg *config.Config) {
	if !cfg.Cache.Enabled {
		fmt.Fprintln(out, "Cache: disabled")
		return
	}
	minTTL := "none"
	if d := cfg.Cache.MinTTL.Duration(); d > 0 {
		minTTL = d.String()
	}
	maxTTL := "unlimited"
	if d := cfg.Cache.MaxTTL.Duration(); d > 0 {
		maxTTL = d.String()
	}
	negativeTTL := "disabled"
	if d := cfg.Cache.NegativeTTLDuration(); d > 0 {
		negativeTTL = d.String()
	}
	fmt.Fprintf(out, "Cache: enabled, max_size=%d, min_ttl=%s, max_ttl=%s, negative_ttl=%s\n", cfg.Cache.MaxSize, minTTL, maxTTL, negativeTTL)
}

func printAPI(out io.Writer, cfg *config.Config) {
	if !cfg.API.Enabled {
		fmt.Fprintln(out, "API: disabled")
		return
	}
	listen := cfg.API.Listen
	if listen == "" {
		listen = "127.0.0.1:8080"
	}
	allowed := cfg.API.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"127.0.0.1/32", "::1/128"}
	}
	fmt.Fprintf(out, "API: enabled, listen=%s, allowed_ips=%s\n", listen, strings.Join(allowed, ", "))
}

func printRules(out io.Writer, cfg *config.Config) {
	fmt.Fprintln(out, "\nRules:")
	if len(cfg.Rules) == 0 {
		fmt.Fprintln(out, "  none")
		return
	}
	for i, rule := range cfg.Rules {
		fmt.Fprintf(out, "  [%d] %-12s %s\n", i, ruleAction(rule), ruleDetails(rule))
	}
}

func printUpstreams(out io.Writer, results []upstreamResult) {
	fmt.Fprintf(out, "\nTest query: %s A\n\n", checkQueryName)

	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tPROTO\tADDRESS\tROLE\tSTATUS\tPROBES\tRCODE\tAVG\tERROR")
	for _, result := range results {
		status := "OK"
		if !result.ok {
			status = "FAIL"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d/%d\t%s\t%s\t%s\n",
			result.name,
			result.protocol,
			result.address,
			result.role,
			status,
			result.successes,
			result.probes,
			checkRcode(result),
			formatAverage(result),
			checkError(result),
		)
	}
	_ = tw.Flush()
}

func ruleAction(rule config.Rule) string {
	switch {
	case rule.Block:
		return "block"
	case rule.Resolve != "":
		return "resolve"
	case len(rule.Servers) > 0:
		return "servers"
	case len(rule.ResolveFile) > 0:
		return "resolve_file"
	default:
		return "unknown"
	}
}

func ruleDetails(rule config.Rule) string {
	match := ruleMatch(rule)
	switch {
	case rule.Block:
		return match
	case rule.Resolve != "":
		return match + " -> " + rule.Resolve
	case len(rule.Servers) > 0:
		return match + " -> " + strings.Join(rule.Servers, ", ")
	case len(rule.ResolveFile) > 0:
		files := strings.Join(rule.ResolveFile, ", ")
		if match != "" {
			return match + " -> " + files
		}
		return files
	default:
		return match
	}
}

func ruleMatch(rule config.Rule) string {
	items := append([]string(nil), rule.Match...)
	if rule.MatchFile != "" {
		items = append(items, "file:"+rule.MatchFile)
	}
	return strings.Join(items, ", ")
}

func upstreamRole(cfg *config.Config, name string) string {
	var roles []string
	if slices.Contains(cfg.DNS.Bootstrap, name) {
		roles = append(roles, "bootstrap")
	}
	if slices.Contains(cfg.Routing.Default, name) {
		roles = append(roles, "default")
	}
	if len(roles) == 0 {
		return "-"
	}
	return strings.Join(roles, ",")
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func checkRcode(result upstreamResult) string {
	if result.successes == 0 {
		return "-"
	}
	if name, ok := dns.RcodeToString[result.rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", result.rcode)
}

func checkError(result upstreamResult) string {
	failed := result.probes - result.successes
	if failed == 0 {
		return "-"
	}
	errText := "unknown error"
	if result.err != nil {
		errText = result.err.Error()
	}
	return fmt.Sprintf("%d/%d failed: %s", failed, result.probes, errText)
}

func formatAverage(result upstreamResult) string {
	if result.successes == 0 {
		return "-"
	}
	if result.avg < time.Millisecond {
		return "<1ms"
	}
	return result.avg.Round(time.Millisecond).String()
}
