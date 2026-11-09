package output

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/http2"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

func briefLines(t *testing.T, evs ...*tracer.Event) []string {
	t.Helper()
	var buf bytes.Buffer
	b := NewBrief(&buf, Options{})
	for _, ev := range evs {
		if err := b.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	return strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
}

func TestBriefHTTP1(t *testing.T) {
	got := briefLines(t, event(tracer.FuncSSLWrite, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	want := "03:04:05.000006 curl[42] 10.0.0.2:51234 > 93.184.216.34:443 TLS 37: GET / HTTP/1.1, host example.com"
	if got[0] != want {
		t.Errorf("got  %q\nwant %q", got[0], want)
	}

	// A compressed response over two reads.
	body := testBody(20 << 10)
	gz := encode(t, body, "gzip")
	msg := fmt.Appendf(nil, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(gz))
	msg = append(msg, gz...)
	half := len(msg) - len(gz)/2
	got = briefLines(t, event(tracer.FuncSSLRead, string(msg[:half])), event(tracer.FuncSSLRead, string(msg[half:])))
	decoded := 0
	for _, line := range got {
		var n int // "(gzip)" if a piece decoded to nothing yet
		if i := strings.LastIndex(line, "(gzip, "); i >= 0 {
			if _, err := fmt.Sscanf(line[i:], "(gzip, %d decoded)", &n); err != nil {
				t.Fatalf("%q: %v", line, err)
			}
		} else if !strings.HasSuffix(line, "(gzip)") {
			t.Fatalf("no body note in %q", line)
		}
		decoded += n
	}
	if len(got) != 2 || decoded != len(body) ||
		!strings.Contains(got[0], "93.184.216.34:443 > 10.0.0.2:51234 TLS") ||
		!strings.Contains(got[0], ": HTTP/1.1 200 OK, text/html, gzip; body ") ||
		!strings.Contains(got[1], fmt.Sprintf(": body %d bytes (gzip", len(msg)-half)) {
		t.Errorf("got %q, %d of %d bytes decoded", got, decoded, len(body))
	}
}

func TestBriefHTTP2AndHTTP3(t *testing.T) {
	client := newHTTP2Writer(true)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "GET", ":authority", "example.com", ":path", "/index.html")})
	ev := event(tracer.FuncSSLWrite, client.buf.String())
	if got := briefLines(t, ev)[0]; !strings.HasSuffix(got, ": HTTP/2 HEADERS s1 GET example.com/index.html [END_STREAM]") {
		t.Errorf("HTTP/2: %q", got)
	}
	var buf bytes.Buffer
	if err := NewBrief(&buf, Options{Verbose: true}).Print(ev); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.HasSuffix(got, ": HTTP/2 preface; SETTINGS; HEADERS s1 GET example.com/index.html [END_STREAM]\n") {
		t.Errorf("HTTP/2, verbose: %q", got)
	}

	block := append([]byte{0x00, 0x00, 0xd9}, literalField("content-encoding", "br")...) // :status 200
	stream := append(h3Frame(0x01, block), h3Frame(0x00, encode(t, []byte("hello"), "br"))...)
	q := quicEvent(tracer.FuncQUICRecv, streamFrameBytes(1, 0, stream, true))
	q.Time, q.Comm = ev.Time, "chrome"
	got := briefLines(t, q)[0]
	if !strings.Contains(got, "chrome[9] peer:? > local:? QUIC ") || !strings.HasSuffix(got, ": HTTP/3 HEADERS s1 200, br; DATA s1 9 bytes (br, 5 decoded)") {
		t.Errorf("HTTP/3: %q", got)
	}
}

func TestBriefOther(t *testing.T) {
	text := event(tracer.FuncSSLRead, "hello world\nsecond line")
	bin := event(tracer.FuncSSLRead, "\x00\x01\x02\x03")
	bin.Size = 100
	unknown := event(tracer.FuncSSLWrite, "PING")
	unknown.Local, unknown.Remote = netip.AddrPort{}, netip.AddrPort{}
	long := event(tracer.FuncSSLWrite, "GET /"+strings.Repeat("a", 300)+" HTTP/1.1\r\n\r\n")

	got := briefLines(t, text, bin, unknown, long)
	for i, want := range []string{
		": hello world",
		"TLS 100: binary [truncated]",
		"local:? > peer:? TLS 4: PING",
		"aaa…",
	} {
		if !strings.HasSuffix(got[i], want) {
			t.Errorf("line %d: %q doesn't end with %q", i, got[i], want)
		}
	}
	if n := len([]rune(got[3][strings.Index(got[3], ": ")+2:])); n != maxSummary {
		t.Errorf("long summary is %d characters", n)
	}
}

// A body's calls after its first are folded into the one that ends it,
// unless verbose.
func TestBriefFoldsBodies(t *testing.T) {
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true,
		BlockFragment: server.block(":status", "200", "content-type", "text/plain")})
	head := append([]byte(nil), server.buf.Bytes()...)
	var calls [][]byte
	for i := 0; i < 5; i++ {
		server.buf.Reset()
		server.fr.WriteData(1, i == 4, bytes.Repeat([]byte("x"), 100))
		calls = append(calls, append([]byte(nil), server.buf.Bytes()...))
	}
	run := func(verbose bool) (string, *Brief) {
		var out bytes.Buffer
		b := NewBrief(&out, Options{Verbose: verbose})
		for _, data := range append([][]byte{head}, calls...) {
			if err := b.Print(event(tracer.FuncSSLRead, string(data))); err != nil {
				t.Fatal(err)
			}
		}
		return out.String(), b
	}
	got, b := run(false)
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[2], "DATA s1 100 bytes [END_STREAM] [+3 calls folded, 300 bytes]") || b.Folded() != 3 {
		t.Errorf("folded %d:\n%s", b.Folded(), got)
	}
	if got, _ := run(true); strings.Count(got, "\n") != 6 {
		t.Errorf("verbose:\n%s", got)
	}

	// HTTP/1.1, by Content-Length.
	var out bytes.Buffer
	b = NewBrief(&out, Options{})
	b.Print(event(tracer.FuncSSLRead, "HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n0123456789"))
	b.Print(event(tracer.FuncSSLRead, "0123456789"))
	b.Print(event(tracer.FuncSSLRead, "0123456789"))
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 2 || !strings.HasSuffix(lines[1], "[+1 call folded, 10 bytes]") {
		t.Errorf("HTTP/1.1:\n%s", out.String())
	}
}
