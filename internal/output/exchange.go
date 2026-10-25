package output

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// HTTPFilter keeps the HTTP exchanges (a request and its response) that
// match all of what's set: a method, a path, a status. An event shows if
// it's part of a matching exchange, as its request, its response, or their
// bodies. Since a request's status isn't known when it's sent, with Status
// set only responses show, saying which request they answer.
type HTTPFilter struct {
	Methods []string // any of these, ignoring case
	Paths   []string // starting with any of these, query left out
	Status  []StatusRange
}

// StatusRange is a range of status codes, as in "500", "5xx" or "400-499".
type StatusRange struct{ From, To int }

// ParseStatus parses a status code, a class like 5xx, or a range.
func ParseStatus(s string) (StatusRange, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) == 3 && s[0] >= '1' && s[0] <= '5' && s[1:] == "xx" {
		n := int(s[0]-'0') * 100
		return StatusRange{n, n + 99}, nil
	}
	from, to, isRange := strings.Cut(s, "-")
	a, err := strconv.Atoi(from)
	if err != nil || a < 100 || a > 599 {
		return StatusRange{}, fmt.Errorf("%q isn't a status code, a class like 5xx, or a range like 400-499", s)
	}
	if !isRange {
		return StatusRange{a, a}, nil
	}
	b, err := strconv.Atoi(to)
	if err != nil || b < a || b > 599 {
		return StatusRange{}, fmt.Errorf("%q isn't a status code, a class like 5xx, or a range like 400-499", s)
	}
	return StatusRange{a, b}, nil
}

// exchange is an HTTP request and its response, as far as they were seen.
type exchange struct {
	method, path string
	status       int // 0 until the response's headers are seen
	reqDir       tracer.Direction
}

func (e *exchange) String() string {
	if e.method == "" {
		return "a request from before snoopy"
	}
	return e.method + " " + e.path
}

// label is String, with the target's secrets masked if redact is set.
func (e *exchange) label(redact bool) string {
	if redact && e.method != "" {
		return e.method + " " + redactTarget(e.path)
	}
	return e.String()
}

func (f *HTTPFilter) match(e *exchange) bool {
	if len(f.Methods) > 0 {
		ok := false
		for _, m := range f.Methods {
			ok = ok || strings.EqualFold(m, e.method)
		}
		if !ok {
			return false
		}
	}
	if len(f.Paths) > 0 {
		path, _, _ := strings.Cut(e.path, "?")
		ok := false
		for _, p := range f.Paths {
			ok = ok || strings.HasPrefix(path, p)
		}
		if !ok {
			return false
		}
	}
	if len(f.Status) > 0 {
		ok := false
		for _, r := range f.Status {
			ok = ok || e.status >= r.From && e.status <= r.To
		}
		if !ok {
			return false
		}
	}
	return true
}

// exchangeTracker follows HTTP exchanges across events, as HAR does: in
// order on an HTTP/1.x connection, by stream on HTTP/2 and HTTP/3.
type exchangeTracker struct {
	conns map[harConnKey]*exConn
}

type exConn struct {
	queue   []*exchange
	current map[tracer.Direction]*exchange
	streams streams[*exchange]
}

// connKey returns the connection an event belongs to, of the process that
// made it: connection handles are only unique within a process (Go's are
// heap addresses, the Java agent numbers connections from 1, and file
// descriptors are reused across processes).
func connKey(ev *tracer.Event, dc decoded) harConnKey {
	if dc.isQUIC {
		return harConnKey{pid: ev.PID, quic: dc.quicConn}
	}
	return harConnKey{pid: ev.PID, tcp: connOf(ev)}
}

// maxConnStreams bounds how many exchanges are kept by stream on a
// connection, and keepFinished how many finished ones are kept a while, for
// the rest of their last DATA frames; maxQueued bounds the HTTP/1.x
// requests waiting for their responses on one.
const (
	maxConnStreams = 4096
	keepFinished   = 64
	maxQueued      = 1024
)

// streams holds what's open on the streams of an HTTP/2 or HTTP/3
// connection. A stream is forgotten when keepFinished more have finished
// after it, or, if more than maxConnStreams are open, with the oldest half
// (streams are numbered in the order they're opened).
type streams[T any] struct {
	m        map[uint64]T
	finished []uint64
}

func (s *streams[T]) get(id uint64) T { return s.m[id] }

func (s *streams[T]) set(id uint64, v T) {
	if s.m == nil {
		s.m = map[uint64]T{}
	}
	if _, ok := s.m[id]; !ok && len(s.m) >= maxConnStreams {
		ids := slices.Sorted(maps.Keys(s.m))
		for _, old := range ids[:len(ids)/2] {
			delete(s.m, old)
		}
	}
	s.m[id] = v
}

func (s *streams[T]) finish(id uint64) {
	if _, ok := s.m[id]; !ok || slices.Contains(s.finished, id) {
		return
	}
	s.finished = append(s.finished, id)
	if len(s.finished) > keepFinished {
		delete(s.m, s.finished[0])
		s.finished = slices.Delete(s.finished, 0, 1)
	}
}

// streamEnd is a stream that an event ends in its direction, or resets.
type streamEnd struct {
	id    uint64
	reset bool
}

// streamEnds returns the streams an HTTP/2 or HTTP/3 event ends or resets.
func streamEnds(dc decoded) []streamEnd {
	var out []streamEnd
	for _, f := range dc.http2 {
		switch {
		case f.Type == "RST_STREAM":
			out = append(out, streamEnd{uint64(f.Stream), true})
		case slices.Contains(f.Flags, "END_STREAM"):
			out = append(out, streamEnd{uint64(f.Stream), false})
		}
	}
	for _, it := range dc.quic {
		rest, reset := strings.CutPrefix(it.Frame, "RESET_STREAM id=")
		if !reset {
			var ok bool
			if rest, ok = strings.CutPrefix(it.Frame, "STREAM id="); !ok || !strings.HasSuffix(it.Frame, " FIN") {
				continue
			}
		}
		id, _, _ := strings.Cut(rest, " ")
		if n, err := strconv.ParseUint(id, 10, 64); err == nil {
			out = append(out, streamEnd{n, reset})
		}
	}
	return out
}

func newExchangeTracker() *exchangeTracker {
	return &exchangeTracker{conns: map[harConnKey]*exConn{}}
}

// touched returns the exchanges an event is part of.
func (t *exchangeTracker) touched(ev *tracer.Event, dc decoded) []*exchange {
	key := connKey(ev, dc)
	c := t.conns[key]
	if c == nil {
		if len(t.conns) >= maxHARConns {
			clear(t.conns)
		}
		c = &exConn{current: map[tracer.Direction]*exchange{}}
		t.conns[key] = c
	}
	dir := ev.Function.Direction()
	var out []*exchange
	add := func(e *exchange) {
		if e != nil && (len(out) == 0 || out[len(out)-1] != e) {
			out = append(out, e)
		}
	}
	switch {
	case dc.isQUIC:
		for _, it := range dc.quic {
			switch {
			case it.HTTP3 == "HEADERS" && it.Headers != nil:
				add(c.headers(dir, it.Stream, it.Headers))
			case strings.HasPrefix(it.HTTP3, "DATA"):
				add(c.streams.get(it.Stream))
			}
		}
	case dc.isHTTP2:
		for _, f := range dc.http2 {
			switch {
			case f.Headers != nil:
				add(c.headers(dir, uint64(f.Stream), f.Headers))
			case f.Type == "DATA":
				add(c.streams.get(uint64(f.Stream)))
			}
		}
	default:
		for _, s := range dc.http1 {
			switch {
			case s.msg != nil:
				add(c.http1(dir, s.msg))
			case s.inBody || s.body.Encoding != "":
				add(c.current[dir])
			}
		}
	}
	// A response's end ends its exchange.
	for _, end := range streamEnds(dc) {
		if e := c.streams.get(end.id); e != nil && (end.reset || dir != e.reqDir) {
			c.streams.finish(end.id)
		}
	}
	return out
}

func (c *exConn) http1(dir tracer.Direction, m *httpMessage) *exchange {
	if !strings.HasPrefix(m.startLine, "HTTP/") {
		method, rest, _ := strings.Cut(m.startLine, " ")
		target, _, _ := strings.Cut(rest, " ")
		e := &exchange{method: method, path: target, reqDir: dir}
		c.queue = append(c.queue, e)
		if len(c.queue) > maxQueued {
			c.queue = c.queue[1:]
		}
		c.current[dir] = e
		return e
	}
	_, status, _ := strings.Cut(m.startLine, " ")
	code, _, _ := strings.Cut(status, " ")
	n, _ := strconv.Atoi(code)
	var e *exchange
	if len(c.queue) > 0 {
		e = c.queue[0]
		if n < 100 || n >= 200 || n == 101 {
			c.queue = c.queue[1:]
		}
	}
	if e == nil {
		e = &exchange{reqDir: opposite(dir)}
	}
	e.status = n
	c.current[dir] = e
	return e
}

func (c *exConn) headers(dir tracer.Direction, stream uint64, fields []hpack.HeaderField) *exchange {
	var method, path, status string
	for _, f := range fields {
		switch f.Name {
		case ":method":
			method = f.Value
		case ":path":
			path = f.Value
		case ":status":
			status = f.Value
		}
	}
	e := c.streams.get(stream)
	switch {
	case method != "":
		e = &exchange{method: method, path: path, reqDir: dir}
		c.streams.set(stream, e)
	case status != "":
		if e == nil {
			e = &exchange{reqDir: opposite(dir)}
			c.streams.set(stream, e)
		}
		e.status, _ = strconv.Atoi(status)
	}
	return e
}

// filtered reports whether an event is left out by the filter, and if it
// isn't, the requests of the responses it carries, to say which they
// answer when Status is set (else ""), their secrets masked with redact.
func (f *HTTPFilter) filtered(t *exchangeTracker, ev *tracer.Event, dc decoded, redact bool) (out bool, answers string) {
	var matched []string
	for _, e := range t.touched(ev, dc) {
		if !f.match(e) {
			continue
		}
		if len(f.Status) > 0 {
			matched = append(matched, e.label(redact))
		} else {
			return false, ""
		}
	}
	if len(matched) == 0 {
		return true, ""
	}
	return false, "for " + strings.Join(matched, ", ")
}
