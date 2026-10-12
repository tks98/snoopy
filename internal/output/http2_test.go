package output

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/internal/tracer"
)

// http2Writer builds one direction of an HTTP/2 connection.
type http2Writer struct {
	buf bytes.Buffer
	fr  *http2.Framer
	hb  bytes.Buffer
	enc *hpack.Encoder
}

func newHTTP2Writer(client bool) *http2Writer {
	w := &http2Writer{}
	if client {
		w.buf.WriteString(http2.ClientPreface)
	}
	w.fr = http2.NewFramer(&w.buf, nil)
	w.enc = hpack.NewEncoder(&w.hb)
	w.fr.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384})
	return w
}

func (w *http2Writer) block(fields ...string) []byte {
	w.hb.Reset()
	for i := 0; i < len(fields); i += 2 {
		w.enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
	}
	return append([]byte(nil), w.hb.Bytes()...)
}

// events splits b into calls of the given sizes (the last size repeats).
func events(fn tracer.Function, b []byte, sizes ...int) []*tracer.Event {
	var out []*tracer.Event
	for i := 0; len(b) > 0; i++ {
		n := min(sizes[min(i, len(sizes)-1)], len(b))
		out = append(out, &tracer.Event{PID: 7, ConnID: 0x1000, Function: fn, Size: uint32(n), Data: b[:n]})
		b = b[n:]
	}
	return out
}

func headersOf(t *testing.T, c *http2Conns, evs []*tracer.Event) [][]string {
	t.Helper()
	var out [][]string
	for _, ev := range evs {
		frames, ok, note := c.process(ev)
		if !ok {
			t.Fatalf("not decoded: %s", note)
		}
		for _, f := range frames {
			if f.Headers != nil {
				var h []string
				for _, hf := range f.Headers {
					h = append(h, hf.Name+": "+hf.Value)
				}
				out = append(out, h)
			}
		}
	}
	return out
}

func TestHTTP2Headers(t *testing.T) {
	client := newHTTP2Writer(true)
	// The second request reuses the dynamic table entries of the first, and
	// its header block is split over a HEADERS and a CONTINUATION frame.
	req := []string{":method", "GET", ":path", "/a", ":authority", "example.com", "x-snoopy", "one"}
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: client.block(req...), EndStream: true, EndHeaders: true})
	req2 := client.block(":method", "GET", ":path", "/b", ":authority", "example.com", "x-snoopy", "one")
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: req2[:3], EndStream: true})
	client.fr.WriteContinuation(3, true, req2[3:])

	server := newHTTP2Writer(false)
	// Padding and priority fields around the header block.
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: server.block(":status", "200", "content-type", "text/plain"),
		EndHeaders: true, PadLength: 5, Priority: http2.PriorityParam{Weight: 15}})
	server.fr.WriteData(1, true, bytes.Repeat([]byte("hello "), 3000)) // spans several calls
	server.fr.WritePushPromise(http2.PushPromiseParam{StreamID: 1, PromiseID: 2, BlockFragment: server.block(":method", "GET", ":path", "/pushed"), EndHeaders: true})
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: server.block(":status", "404", "content-type", "text/plain"), EndHeaders: true, EndStream: true})

	// Clients write the 24-byte connection preface in one call; after it,
	// frames may be split anywhere.
	for _, sizes := range [][]int{{1 << 20}, {24, 1}, {30, 7, 13, 1000}, {50}} {
		c := newHTTP2Conns()
		got := headersOf(t, c, events(tracer.FuncSSLWrite, client.buf.Bytes(), sizes...))
		want := [][]string{
			{":method: GET", ":path: /a", ":authority: example.com", "x-snoopy: one"},
			{":method: GET", ":path: /b", ":authority: example.com", "x-snoopy: one"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("sizes %v, requests: got %q, want %q", sizes, got, want)
		}
		got = headersOf(t, c, events(tracer.FuncSSLRead, server.buf.Bytes(), sizes...))
		want = [][]string{
			{":status: 200", "content-type: text/plain"},
			{":method: GET", ":path: /pushed"},
			{":status: 404", "content-type: text/plain"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("sizes %v, responses: got %q, want %q", sizes, got, want)
		}
	}
}

// Bytes missing inside a DATA payload (a capture cut short by --max-size)
// don't stop decoding; anywhere else they do.
func TestHTTP2MissingBytes(t *testing.T) {
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: server.block(":status", "200"), EndHeaders: true})
	server.fr.WriteData(1, true, bytes.Repeat([]byte("x"), 20000))
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: server.block(":status", "204"), EndHeaders: true, EndStream: true})
	b := server.buf.Bytes()

	c := newHTTP2Conns()
	c.start(http2Key{7, 0x1000}) // as if the client's preface was seen
	// One call returns everything, but only the first 100 bytes are captured.
	ev := &tracer.Event{PID: 7, ConnID: 0x1000, Function: tracer.FuncSSLRead, Size: uint32(len(b)), Data: b[:100]}
	if _, ok, note := c.process(ev); ok || !strings.Contains(note, "weren't captured") {
		t.Errorf("hole across frames: ok %v, note %q", ok, note)
	}

	c = newHTTP2Conns()
	c.start(http2Key{7, 0x1000})
	dataEnd := len(b) - 9 - 1 // the last HEADERS frame: 9-byte header, 1-byte block
	evs := []*tracer.Event{
		{PID: 7, ConnID: 0x1000, Function: tracer.FuncSSLRead, Size: uint32(dataEnd), Data: b[:100]},
		{PID: 7, ConnID: 0x1000, Function: tracer.FuncSSLRead, Size: uint32(len(b) - dataEnd), Data: b[dataEnd:]},
	}
	if got := headersOf(t, c, evs); !reflect.DeepEqual(got, [][]string{{":status: 200"}, {":status: 204"}}) {
		t.Errorf("hole within DATA: got %q", got)
	}
}

func TestHTTP2NeedsConnectionStart(t *testing.T) {
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: server.block(":status", "200"), EndHeaders: true})
	c := newHTTP2Conns()
	for _, ev := range events(tracer.FuncSSLRead, server.buf.Bytes(), 1<<20) {
		if _, ok, _ := c.process(ev); ok {
			t.Error("decoded a connection whose start wasn't seen")
		}
	}
}

func TestTextHTTP2(t *testing.T) {
	client := newHTTP2Writer(true)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: client.block(":method", "GET", ":path", "/index.html"), EndStream: true, EndHeaders: true})
	var out bytes.Buffer
	p := NewText(&out, false)
	for _, ev := range events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20) {
		if err := p.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"HTTP/2 connection preface", "HTTP/2 SETTINGS stream=0", "HTTP/2 HEADERS stream=1", "[END_STREAM,END_HEADERS]", ":path: /index.html"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}
