package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/net/http2"

	"github.com/tks98/snoopy/internal/tracer"
)

// HTTP/2: a response body in DATA frames (one padded) spread over calls, its
// end marked by trailers; and one whose bytes go missing.
func TestHTTP2EncodedBody(t *testing.T) {
	body := testBody(100 << 10)
	encoded := encode(t, body, "br")
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true,
		BlockFragment: server.block(":status", "200", "content-encoding", "br")})
	third := len(encoded) / 3
	server.fr.WriteData(1, false, encoded[:third])
	server.fr.WriteDataPadded(1, false, encoded[third:2*third], []byte{0, 0, 0, 0, 0, 0, 0})
	server.fr.WriteData(1, false, encoded[2*third:])
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: true,
		BlockFragment: server.block("x-trailer", "done")})
	// A stream without a Content-Encoding is left alone.
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, EndHeaders: true, BlockFragment: server.block(":status", "200")})
	server.fr.WriteData(3, true, []byte("plain"))

	for _, sizes := range [][]int{{1 << 20}, {1000}, {17, 4000}} {
		c := newHTTP2Conns(newBodyPool())
		c.start(http2Key{7, 0x1000})
		var decoded []byte
		for _, ev := range events(tracer.FuncSSLRead, server.buf.Bytes(), sizes...) {
			frames, ok, note := c.process(ev)
			if !ok {
				t.Fatalf("sizes %v: %s", sizes, note)
			}
			for _, f := range frames {
				if f.Stream == 3 && f.Body.Encoding != "" {
					t.Errorf("stream 3 decoded")
				}
				if f.Body.Err != "" {
					t.Errorf("sizes %v: %s", sizes, f.Body.Err)
				}
				decoded = append(decoded, f.Body.Decoded...)
			}
		}
		if !bytes.Equal(decoded, body) {
			t.Errorf("sizes %v: decoded %d bytes, want %d", sizes, len(decoded), len(body))
		}
		if n := len(c.pool.live); n != 0 {
			t.Errorf("sizes %v: %d bodies still being decoded", sizes, n)
		}
	}

	// Bytes of the body not captured: said once, then the rest is shown as is.
	c := newHTTP2Conns(newBodyPool())
	c.start(http2Key{7, 0x1000})
	evs := events(tracer.FuncSSLRead, server.buf.Bytes(), 2000)
	evs[1].Data = evs[1].Data[:500]
	var errs []string
	for _, ev := range evs {
		frames, _, _ := c.process(ev)
		for _, f := range frames {
			if f.Body.Err != "" {
				errs = append(errs, f.Body.Err)
			}
		}
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "weren't captured") {
		t.Errorf("errors: %q", errs)
	}
}

// HTTP/3: a response's DATA frames across packets, ended by the stream's FIN.
func TestHTTP3EncodedBody(t *testing.T) {
	body := testBody(60 << 10)
	encoded := encode(t, body, "zstd")
	// QPACK: no dynamic table, :status 200 (static entry 25), then
	// content-encoding as a literal.
	block := append([]byte{0x00, 0x00, 0xd9}, literalField("content-encoding", "zstd")...)
	stream := h3Frame(0x01, block)
	half := len(encoded) / 2
	stream = append(stream, h3Frame(0x00, encoded[:half])...)
	stream = append(stream, h3Frame(0x00, encoded[half:])...)

	c := newQUICConns(newBodyPool())
	var decoded []byte
	for off := 0; off < len(stream); off += 1200 {
		end := min(off+1200, len(stream))
		ev := quicEvent(tracer.FuncQUICRecv, streamFrameBytes(1, uint64(off), stream[off:end], end == len(stream)))
		items, ok := c.process(ev)
		if !ok {
			t.Fatal("not QUIC")
		}
		for _, it := range items {
			if it.Body.Err != "" || it.Err != "" {
				t.Errorf("%s: %s %s", it.HTTP3, it.Err, it.Body.Err)
			}
			decoded = append(decoded, it.Body.Decoded...)
		}
	}
	if !bytes.Equal(decoded, body) {
		t.Errorf("decoded %d bytes, want %d", len(decoded), len(body))
	}
}

// literalField encodes a QPACK field line with a literal name and value.
func literalField(name, value string) []byte {
	b := appendPrefixed(nil, 0x20, 3, len(name)) // 001 N=0 H=0 length(3)
	b = append(b, name...)
	b = appendPrefixed(b, 0x00, 7, len(value))
	return append(b, value...)
}

// appendPrefixed appends an integer with an n-bit prefix (RFC 7541, 5.1)
// after the given high bits.
func appendPrefixed(b []byte, high byte, n uint, v int) []byte {
	max := 1<<n - 1
	if v < max {
		return append(b, high|byte(v))
	}
	b = append(b, high|byte(max))
	for v -= max; v >= 128; v >>= 7 {
		b = append(b, byte(v&0x7f|0x80))
	}
	return append(b, byte(v))
}

// chunk frames b in the chunked transfer coding, in pieces of n bytes.
func chunk(b []byte, n int) []byte {
	var out bytes.Buffer
	for len(b) > 0 {
		k := min(n, len(b))
		fmt.Fprintf(&out, "%x;ext=1\r\n", k)
		out.Write(b[:k])
		out.WriteString("\r\n")
		b = b[k:]
	}
	out.WriteString("0\r\nX-Trailer: yes\r\n\r\n")
	return out.Bytes()
}

func TestHTTP1EncodedBody(t *testing.T) {
	body := testBody(80 << 10)
	gz, br := encode(t, body, "gzip"), encode(t, body, "br")

	// A response to HEAD has the headers but no body.
	headResp := "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1234\r\n\r\n"
	var stream bytes.Buffer
	stream.WriteString("HTTP/1.1 304 Not Modified\r\nContent-Encoding: br\r\n\r\n") // nor does a 304
	fmt.Fprintf(&stream, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(gz))
	stream.Write(gz)
	stream.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: br\r\n\r\n")
	stream.Write(chunk(br, 3000))
	stream.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain")

	for _, sizes := range [][]int{{1 << 20}, {1000}, {7, 50, 4096}} {
		c := newHTTP1Conns(newBodyPool())
		send := func(fn tracer.Function, s string) []http1Segment {
			return c.process(&tracer.Event{PID: 7, ConnID: 0x1000, Function: fn, Size: uint32(len(s)), Data: []byte(s)})
		}
		send(tracer.FuncSSLWrite, "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
		if segs := send(tracer.FuncSSLRead, headResp); len(segs) != 1 || segs[0].msg == nil {
			t.Fatalf("response to HEAD: %+v", segs)
		}
		send(tracer.FuncSSLWrite, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		var decoded []byte
		for _, ev := range events(tracer.FuncSSLRead, stream.Bytes(), sizes...) {
			for _, s := range c.process(ev) {
				if s.body.Err != "" {
					t.Errorf("sizes %v: %s", sizes, s.body.Err)
				}
				decoded = append(decoded, s.body.Decoded...)
			}
		}
		if want := append(append([]byte(nil), body...), body...); !bytes.Equal(decoded, want) {
			t.Errorf("sizes %v: decoded %d bytes, want %d", sizes, len(decoded), len(want))
		}
		if d := c.conns[http2Key{7, 0x1000}].dirs[tracer.Read]; d.state != h1Start {
			t.Errorf("sizes %v: ended in state %d", sizes, d.state)
		}
	}
}

func TestHTTP1EncodedBodyMissingBytes(t *testing.T) {
	gz := encode(t, testBody(50<<10), "gzip")
	msg := fmt.Appendf(nil, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(gz))
	msg = append(msg, gz...)
	msg = append(msg, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n"...)
	c := newHTTP1Conns(newBodyPool())
	evs := events(tracer.FuncSSLRead, msg, 4000)
	evs[2].Data = evs[2].Data[:100] // the rest wasn't captured
	var errs []string
	for _, ev := range evs {
		for _, s := range c.process(ev) {
			if s.body.Err != "" {
				errs = append(errs, s.body.Err)
			}
		}
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "weren't captured") {
		t.Errorf("errors: %q", errs)
	}
	// The next message is still found: its length counts the missing bytes.
	if d := c.conns[http2Key{7, 0x1000}].dirs[tracer.Read]; d.state != h1Start {
		t.Errorf("ended in state %d", d.state)
	}
}

func TestTextAndJSONEncodedBody(t *testing.T) {
	gz := encode(t, []byte("<html>hello, decoded world</html>"), "gzip")
	msg := fmt.Appendf(nil, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(gz))
	msg = append(msg, gz...)
	half := len(msg) - len(gz)/2

	var text, js bytes.Buffer
	tp, jp := NewText(&text, false), NewJSON(&js)
	for _, data := range [][]byte{msg[:half], msg[half:]} {
		ev := event(tracer.FuncSSLRead, string(data))
		if err := tp.Print(ev); err != nil {
			t.Fatal(err)
		}
		if err := jp.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"HTTP/1.1 200 OK", "Content-Encoding: gzip", "[gzip: ", "<html>hello, decoded world</html>"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, text.String())
		}
	}
	var decoded string
	for _, line := range strings.Split(strings.TrimSpace(js.String()), "\n") {
		var ev struct{ Body *jsonBody }
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Body == nil || ev.Body.ContentEncoding != "gzip" {
			t.Fatalf("no body in %s", line)
		}
		if ev.Body.Decoded != nil {
			decoded += *ev.Body.Decoded
		}
	}
	if decoded != "<html>hello, decoded world</html>" {
		t.Errorf("JSON decoded %q", decoded)
	}
}
