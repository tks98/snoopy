package output

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

func TestParseStatus(t *testing.T) {
	for s, want := range map[string]StatusRange{"404": {404, 404}, "5xx": {500, 599}, "5XX": {500, 599}, "400-499": {400, 499}} {
		if got, err := ParseStatus(s); err != nil || got != want {
			t.Errorf("%q: %v, %v", s, got, err)
		}
	}
	for _, s := range []string{"6xx", "abc", "99", "500-400", "200-700", ""} {
		if _, err := ParseStatus(s); err == nil {
			t.Errorf("%q: no error", s)
		}
	}
}

// Two exchanges on an HTTP/1.1 connection: which events each filter keeps.
func TestHTTPFilterHTTP1(t *testing.T) {
	evs := []*tracer.Event{
		event(tracer.FuncSSLWrite, "GET /health HTTP/1.1\r\nHost: x\r\n\r\n"),
		event(tracer.FuncSSLWrite, "POST /v1/charges?x=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}"),
		event(tracer.FuncSSLRead, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
		event(tracer.FuncSSLRead, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 4\r\n\r\n"),
		event(tracer.FuncSSLRead, "oops"),        // the 502's body
		event(tracer.FuncSSLWrite, "not HTTP\n"), // on another connection
	}
	evs[5].ConnID = 0xabc
	for _, c := range []struct {
		name   string
		filter HTTPFilter
		want   []int // the events shown
	}{
		{"method", HTTPFilter{Methods: []string{"post"}}, []int{1, 3, 4}},
		{"path", HTTPFilter{Paths: []string{"/v1/"}}, []int{1, 3, 4}},
		{"path, other", HTTPFilter{Paths: []string{"/health"}}, []int{0, 2}},
		{"status", HTTPFilter{Status: []StatusRange{{500, 599}}}, []int{3, 4}},
		{"method and status", HTTPFilter{Methods: []string{"GET"}, Status: []StatusRange{{500, 599}}}, nil},
	} {
		d := newDecoders(Options{Filter: &c.filter})
		var shown []int
		for i, ev := range evs {
			if !d.decode(ev).filteredOut {
				shown = append(shown, i)
			}
		}
		if !equalInts(shown, c.want) {
			t.Errorf("%s: shown %v, want %v", c.name, shown, c.want)
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// HTTP/2: by stream; a response says which request it answers.
func TestHTTPFilterHTTP2(t *testing.T) {
	client := newHTTP2Writer(true)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "GET", ":path", "/ok", ":authority", "x")})
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "GET", ":path", "/fails", ":authority", "x")})
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, EndStream: true, EndHeaders: true,
		BlockFragment: server.block(":status", "503")})
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: server.block(":status", "200")})

	var out bytes.Buffer
	p := NewBrief(&out, Options{Filter: &HTTPFilter{Status: []StatusRange{{500, 599}}}})
	for _, ev := range append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, server.buf.Bytes(), 1<<20)...) {
		if err := p.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(out.String(), "503") || !strings.Contains(out.String(), "(for GET /fails)") || strings.Contains(out.String(), "/ok") {
		t.Errorf("output:\n%s", out.String())
	}
	if p.Filtered() != 1 { // the client's call; the server's one has the 503
		t.Errorf("filtered %d", p.Filtered())
	}
}

// HAR keeps the entries that match.
func TestHTTPFilterHAR(t *testing.T) {
	var out bytes.Buffer
	h := NewHAR(&out, "test", Options{Filter: &HTTPFilter{Status: []StatusRange{{404, 404}}}})
	for _, ev := range []*tracer.Event{
		event(tracer.FuncSSLWrite, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"),
		event(tracer.FuncSSLRead, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
		event(tracer.FuncSSLWrite, "GET /b HTTP/1.1\r\nHost: x\r\n\r\n"),
		event(tracer.FuncSSLRead, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
	} {
		h.Print(ev)
	}
	h.Close()
	l := readHAR(t, out.Bytes())
	if len(l.Log.Entries) != 1 || !strings.HasSuffix(l.Log.Entries[0].Request.URL, "/b") {
		t.Errorf("entries:\n%s", out.String())
	}
}

// Two processes whose connection handles have the same value (Go's are heap
// addresses, the Java agent numbers connections from 1) have exchanges of
// their own.
func TestHTTPFilterProcesses(t *testing.T) {
	a := event(tracer.FuncGoWrite, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
	a.PID = 100
	b := event(tracer.FuncGoWrite, "POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
	b.PID = 200
	bResp := event(tracer.FuncGoRead, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
	bResp.PID = 200
	evs := []*tracer.Event{a, b, bResp}

	d := newDecoders(Options{Filter: &HTTPFilter{Methods: []string{"POST"}}})
	var shown []int
	for i, ev := range evs {
		if !d.decode(ev).filteredOut {
			shown = append(shown, i)
		}
	}
	if !equalInts(shown, []int{1, 2}) {
		t.Errorf("--method POST: shown %v, want [1 2]", shown)
	}
	d = newDecoders(Options{Filter: &HTTPFilter{Status: []StatusRange{{500, 599}}}})
	for i, ev := range evs {
		if dc := d.decode(ev); !dc.filteredOut && (i != 2 || dc.answers != "for POST /b") {
			t.Errorf("--status 5xx: event %d shown, %q", i, dc.answers)
		}
	}

	var out bytes.Buffer
	h := NewHAR(&out, "test", Options{})
	for _, ev := range evs {
		h.Print(ev)
	}
	h.Close()
	l := readHAR(t, out.Bytes())
	if len(l.Log.Entries) != 2 || l.Log.Entries[0].Response.Status != 0 || l.Log.Entries[1].Response.Status != 500 {
		t.Errorf("HAR:\n%s", out.String())
	}
}

// What's kept of a connection's streams is bounded: finished ones are let
// go, and open ones beyond maxConnStreams.
func TestExchangeStreamsBounded(t *testing.T) {
	ex := newExchangeTracker()
	req := &tracer.Event{Function: tracer.FuncSSLWrite, ConnID: 1}
	resp := &tracer.Event{Function: tracer.FuncSSLRead, ConnID: 1}
	fields := func(kv ...string) (out []hpack.HeaderField) {
		for i := 0; i < len(kv); i += 2 {
			out = append(out, hpack.HeaderField{Name: kv[i], Value: kv[i+1]})
		}
		return out
	}
	conn := func() *exConn { return ex.conns[harConnKey{tcp: 1}] }
	for i := uint32(1); i < 20000; i += 2 {
		ex.touched(req, decoded{isHTTP2: true, http2: []http2Frame{{Type: "HEADERS", Stream: i, Flags: []string{"END_STREAM"},
			Headers: fields(":method", "GET", ":path", "/x")}}})
		ex.touched(resp, decoded{isHTTP2: true, http2: []http2Frame{{Type: "HEADERS", Stream: i,
			Headers: fields(":status", "200")}}})
		// The response's last DATA, in two calls.
		ex.touched(resp, decoded{isHTTP2: true, http2: []http2Frame{{Type: "DATA", Stream: i, Flags: []string{"END_STREAM"}}}})
		if got := ex.touched(resp, decoded{isHTTP2: true, http2: []http2Frame{{Type: "DATA", Stream: i, Continued: true}}}); len(got) != 1 {
			t.Fatalf("stream %d: the rest of its DATA wasn't followed", i)
		}
	}
	if n := len(conn().streams.m); n > keepFinished {
		t.Errorf("%d finished streams kept", n)
	}
	// Streams that never finish.
	for i := uint32(1 << 20); i < 1<<20+3*maxConnStreams; i += 2 {
		ex.touched(req, decoded{isHTTP2: true, http2: []http2Frame{{Type: "HEADERS", Stream: i,
			Headers: fields(":method", "GET", ":path", "/x")}}})
	}
	if n := len(conn().streams.m); n > maxConnStreams {
		t.Errorf("%d open streams kept", n)
	}
	// HTTP/1.x requests that aren't answered.
	for i := 0; i < 3*maxQueued; i++ {
		ex.touched(req, decoded{http1: []http1Segment{{msg: &httpMessage{startLine: "GET / HTTP/1.1"}}}})
	}
	if n := len(conn().queue); n > maxQueued {
		t.Errorf("%d requests queued", n)
	}
}
