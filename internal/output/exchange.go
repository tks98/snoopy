package output

import (
	"fmt"
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
	streams map[uint64]*exchange
}

func newExchangeTracker() *exchangeTracker {
	return &exchangeTracker{conns: map[harConnKey]*exConn{}}
}

// touched returns the exchanges an event is part of.
func (t *exchangeTracker) touched(ev *tracer.Event, dc decoded) []*exchange {
	key := harConnKey{tcp: connOf(ev)}
	if dc.isQUIC {
		key = harConnKey{quic: dc.quicConn}
	}
	c := t.conns[key]
	if c == nil {
		if len(t.conns) >= maxHARConns {
			clear(t.conns)
		}
		c = &exConn{current: map[tracer.Direction]*exchange{}, streams: map[uint64]*exchange{}}
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
				add(c.streams[it.Stream])
			}
		}
	case dc.isHTTP2:
		for _, f := range dc.http2 {
			switch {
			case f.Headers != nil:
				add(c.headers(dir, uint64(f.Stream), f.Headers))
			case f.Type == "DATA":
				add(c.streams[uint64(f.Stream)])
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
	return out
}

func (c *exConn) http1(dir tracer.Direction, m *httpMessage) *exchange {
	if !strings.HasPrefix(m.startLine, "HTTP/") {
		method, rest, _ := strings.Cut(m.startLine, " ")
		target, _, _ := strings.Cut(rest, " ")
		e := &exchange{method: method, path: target, reqDir: dir}
		c.queue = append(c.queue, e)
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
	e := c.streams[stream]
	switch {
	case method != "":
		e = &exchange{method: method, path: path, reqDir: dir}
		c.streams[stream] = e
	case status != "":
		if e == nil {
			e = &exchange{reqDir: opposite(dir)}
			c.streams[stream] = e
		}
		e.status, _ = strconv.Atoi(status)
	}
	return e
}

// filtered reports whether an event is left out by the filter, and if it
// isn't, the requests of the responses it carries, to say which they
// answer when Status is set (else "").
func (f *HTTPFilter) filtered(t *exchangeTracker, ev *tracer.Event, dc decoded) (out bool, answers string) {
	var matched []string
	for _, e := range t.touched(ev, dc) {
		if !f.match(e) {
			continue
		}
		if len(f.Status) > 0 {
			matched = append(matched, e.String())
		} else {
			return false, ""
		}
	}
	if len(matched) == 0 {
		return true, ""
	}
	return false, "for " + strings.Join(matched, ", ")
}
