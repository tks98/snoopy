package output

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// requestLines prints evs with a Requests and returns the lines it wrote
// after each event.
func requestLines(t *testing.T, opts Options, evs ...*tracer.Event) []string {
	t.Helper()
	var out bytes.Buffer
	r := NewRequests(&out, opts)
	var after []string
	for i, ev := range evs {
		ev.Time = ev.Time.Add(time.Duration(i) * time.Millisecond)
		if err := r.Print(ev); err != nil {
			t.Fatal(err)
		}
		after = append(after, out.String())
	}
	return after
}

func gzipBytes(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestRequestsHTTP1(t *testing.T) {
	body := gzipBytes(`{"id":1}`)
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: " +
		itoa(len(body)) + "\r\n\r\n"
	after := requestLines(t, Options{},
		event(tracer.FuncSSLWrite, "GET /api/users?page=2 HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
		event(tracer.FuncSSLRead, "HTTP/1.1 100 Continue\r\n\r\n"),
		event(tracer.FuncSSLRead, resp+string(body[:5])),
		event(tracer.FuncSSLRead, string(body[5:])),
	)
	if after[2] != "" {
		t.Errorf("printed before the response's body ended:\n%s", after[2])
	}
	want := "03:04:05.000006 curl[42] GET https://api.example.com/api/users?page=2 HTTP/1.1 → 200, application/json, " +
		itoa(len(body)) + " bytes (gzip, 8 decoded), 3ms\n"
	if after[3] != want {
		t.Errorf("got  %q\nwant %q", after[3], want)
	}
}

// Chunked bodies end at their last chunk; a body-less response at its
// headers. A server's exchanges say it served them.
func TestRequestsChunkedAndServed(t *testing.T) {
	req := event(tracer.FuncSSLRead, "POST /login HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 3\r\n\r\nabc")
	resp := event(tracer.FuncSSLWrite, "HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n")
	end := event(tracer.FuncSSLWrite, "0\r\n\r\n")
	req2 := event(tracer.FuncSSLRead, "DELETE /cart HTTP/1.1\r\nHost: shop.example\r\n\r\n")
	resp2 := event(tracer.FuncSSLWrite, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	after := requestLines(t, Options{}, req, resp, end, req2, resp2)
	if after[1] != "" {
		t.Errorf("printed before the last chunk:\n%s", after[1])
	}
	lines := strings.Split(strings.TrimSpace(after[4]), "\n")
	if len(lines) != 2 ||
		!strings.Contains(lines[0], "curl[42] served POST https://shop.example/login HTTP/1.1 → 201, 2 bytes") ||
		!strings.Contains(lines[1], "served DELETE https://shop.example/cart HTTP/1.1 → 404, no body") {
		t.Errorf("got:\n%s", after[4])
	}
}

func TestRequestsHTTP2(t *testing.T) {
	client := newHTTP2Writer(true)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/slow")})
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/fast")})
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, EndHeaders: true,
		BlockFragment: server.block(":status", "200", "content-type", "text/plain")})
	server.fr.WriteData(3, true, []byte("fast"))
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: server.block(":status", "503")})
	evs := append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, server.buf.Bytes(), 1<<20)...)
	after := requestLines(t, Options{}, evs...)
	lines := strings.Split(strings.TrimSpace(after[len(after)-1]), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "GET https://example.com/fast HTTP/2 → 200, text/plain, 4 bytes") ||
		!strings.Contains(lines[1], "GET https://example.com/slow HTTP/2 → 503, no body") {
		t.Errorf("got:\n%s", after[len(after)-1])
	}
}

// A DATA frame with END_STREAM can be read in pieces, as Chrome reads 8 KiB
// at a time: its exchange ends with the frame's last byte, not its header.
func TestRequestsHTTP2SplitLastFrame(t *testing.T) {
	text := strings.Repeat("snoopy reads frames in pieces. ", 200)
	body := gzipBytes(text)
	client := newHTTP2Writer(true)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/page")})
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true,
		BlockFragment: server.block(":status", "200", "content-type", "text/html", "content-encoding", "gzip")})
	server.fr.WriteData(1, true, body)
	evs := append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, server.buf.Bytes(), 16)...)
	after := requestLines(t, Options{}, evs...)
	if printed := after[len(after)-2]; printed != "" {
		t.Errorf("printed before the last DATA frame ended:\n%s", printed)
	}
	want := "GET https://example.com/page HTTP/2 → 200, text/html, " + itoa(len(body)) +
		" bytes (gzip, " + itoa(len(text)) + " decoded)"
	if got := after[len(after)-1]; !strings.Contains(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// QUIC packets can arrive out of order: an HTTP/3 exchange ends once its
// response's data has all arrived, not with the packet carrying its FIN.
func TestRequestsHTTP3FINFirst(t *testing.T) {
	text := strings.Repeat("snoopy waits for the whole stream. ", 300)
	body := gzipBytes(text)
	// QPACK, no dynamic table: :method GET, :scheme https and :path / from
	// the static table, :authority as a literal; then :status 200.
	req := append([]byte{0x00, 0x00, 0xd1, 0xd7, 0xc1}, literalField(":authority", "example.com")...)
	resp := append([]byte{0x00, 0x00, 0xd9}, literalField("content-encoding", "gzip")...)
	stream := append(h3Frame(0x01, resp), h3Frame(0x00, body)...)
	third := len(stream) / 3
	packet := func(from, to int) *tracer.Event {
		return quicEvent(tracer.FuncQUICRecv, streamFrameBytes(0, uint64(from), stream[from:to], to == len(stream)))
	}
	after := requestLines(t, Options{},
		quicEvent(tracer.FuncQUICSend, streamFrameBytes(0, 0, h3Frame(0x01, req), true)),
		packet(0, third),
		packet(2*third, len(stream)), // the FIN, ahead of the middle
		packet(third, 2*third),
	)
	if after[2] != "" {
		t.Errorf("printed before the stream's data had all arrived:\n%s", after[2])
	}
	want := "GET https://example.com/ HTTP/3 → 200, " + itoa(len(body)) + " bytes (gzip, " + itoa(len(text)) + " decoded)"
	if got := after[3]; !strings.Contains(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestRequestsFilterAndRedact(t *testing.T) {
	evs := []*tracer.Event{
		event(tracer.FuncSSLWrite, "GET /ok?token=s3cr3t HTTP/1.1\r\nHost: a\r\n\r\n"),
		event(tracer.FuncSSLRead, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
		event(tracer.FuncSSLWrite, "GET /broken?token=s3cr3t HTTP/1.1\r\nHost: a\r\n\r\n"),
		event(tracer.FuncSSLRead, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"),
	}
	var out bytes.Buffer
	r := NewRequests(&out, Options{Redact: true, Filter: &HTTPFilter{Status: []StatusRange{{500, 599}}}})
	for _, ev := range evs {
		r.Print(ev)
	}
	got := out.String()
	if strings.Count(got, "\n") != 1 || !strings.Contains(got, "GET https://a/broken?token=") || strings.Contains(got, "s3cr3t") {
		t.Errorf("got:\n%s", got)
	}
	if r.Shown() != 1 || r.FilteredRequests() != 1 {
		t.Errorf("shown %d, filtered %d", r.Shown(), r.FilteredRequests())
	}
}

// A gRPC call's grpc-status, from its trailers, is shown.
func TestRequestsGRPCStatus(t *testing.T) {
	client := newHTTP2Writer(true)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true,
		BlockFragment: client.block(":method", "POST", ":scheme", "https", ":authority", "pay", ":path", "/payments.v1.Charges/Create",
			"content-type", "application/grpc")})
	client.fr.WriteData(1, true, []byte{0, 0, 0, 0, 0})
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true,
		BlockFragment: server.block(":status", "200", "content-type", "application/grpc")})
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: server.block("grpc-status", "5", "grpc-message", "no such charge")})
	evs := append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, server.buf.Bytes(), 1<<20)...)
	after := requestLines(t, Options{}, evs...)
	if got := after[len(after)-1]; !strings.Contains(got, "POST https://pay/payments.v1.Charges/Create HTTP/2 → 200, application/grpc, no body, grpc-status 5 NOT_FOUND") {
		t.Errorf("got:\n%s", got)
	}
}
