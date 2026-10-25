package output

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/http2"

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
