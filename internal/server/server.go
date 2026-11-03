package server

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"

	"dnsway/internal/router"
	"dnsway/internal/stats"
)

type Server struct {
	udp *dns.Server
	tcp *dns.Server
}

func New(addr string, r *router.Router, logger *slog.Logger, collector *stats.Collector) *Server {
	handler := newHandler(r, logger, collector)
	return &Server{
		udp: &dns.Server{Addr: addr, Net: "udp", Handler: handler, UDPSize: dns.MaxMsgSize},
		tcp: &dns.Server{Addr: addr, Net: "tcp", Handler: handler},
	}
}

func newHandler(r *router.Router, logger *slog.Logger, collector *stats.Collector) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if collector != nil {
			collector.QueryStarted()
			defer collector.QueryFinished()
		}
		start := time.Now()
		result := r.Resolve(context.Background(), req)
		elapsed := time.Since(start)
		if collector != nil {
			collector.Record(result, elapsed)
		}
		answers := len(result.Msg.Answer)

		proto := "tcp"
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			proto = "udp"
			truncate(req, result.Msg)
		}

		name, qtype := "-", "-"
		if len(req.Question) == 1 {
			name = req.Question[0].Name
			qtype = dns.Type(req.Question[0].Qtype).String()
		}

		logger.Info("dns query",
			"client", w.RemoteAddr().String(),
			"proto", proto,
			"name", name,
			"type", qtype,
			"rule", result.Rule,
			"action", result.Action,
			"upstreams", result.Servers,
			"cache", result.CacheHit,
			"rcode", rcodeName(result.Msg.Rcode),
			"answers", answers,
			"elapsed", elapsed.Round(time.Millisecond),
		)

		_ = w.WriteMsg(result.Msg)
	})
}

func rcodeName(rcode int) string {
	if name, ok := dns.RcodeToString[rcode]; ok {
		return name
	}
	return strconv.Itoa(rcode)
}

func (s *Server) Run(ctx context.Context) error {
	errs := make(chan error, 2)
	go func() { errs <- s.udp.ListenAndServe() }()
	go func() { errs <- s.tcp.ListenAndServe() }()

	select {
	case <-ctx.Done():
		_ = s.udp.Shutdown()
		_ = s.tcp.Shutdown()
		return nil
	case err := <-errs:
		_ = s.udp.Shutdown()
		_ = s.tcp.Shutdown()
		return err
	}
}

func truncate(req, resp *dns.Msg) {
	if resp.Truncated {
		return
	}
	size := dns.MinMsgSize
	if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
		size = int(opt.UDPSize())
	}
	if resp.Len() <= size {
		return
	}

	resp.Truncated = true
	resp.Answer = nil
	resp.Ns = nil
	var opt dns.RR
	for _, rr := range resp.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			opt = rr
			break
		}
	}
	resp.Extra = nil
	if opt != nil {
		resp.Extra = []dns.RR{opt}
	}
}
