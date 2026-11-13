package output

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"golang.org/x/net/http2"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// sseAll reads a stream in pieces of the given sizes, ending it with the
// last.
func sseAll(s *sseStream, b []byte, size int) []sseEvent {
	var out []sseEvent
	for {
		n := min(size, len(b))
		out = append(out, s.add(b[:n], n == len(b))...)
		b = b[n:]
		if len(b) == 0 {
			return out
		}
	}
}

// What an LLM API sends, in the three line endings the format allows, read
// whole and split at every size: the same events each time.
func TestSSEParse(t *testing.T) {
	parts := []string{
		": welcome\n\n", // a comment on its own: a keep-alive
		"event: message_start\ndata: {\"type\": \"message_start\"}\n\n",
		"data:no space\ndata:  two spaces\ndata\n\n", // a data field without a value adds a line
		"id: 7\nretry: 3000\nretry: soon\nevent: delta\n: a comment inside\nunknown: field\ndata: [DONE]\n\n",
		"id\ndata: x\n\n", // an id field without a value resets the ID
		"data: cut off",
	}
	// A byte order mark may start the stream, and blank lines between
	// events are nothing.
	stream := "\xef\xbb\xbf" + strings.Join(parts[:4], "") + "\n\n" + strings.Join(parts[4:], "")
	want := []sseEvent{
		{Comments: []string{"welcome"}},
		{Type: "message_start", Data: `{"type": "message_start"}`, HasData: true},
		{Data: "no space\n two spaces\n", HasData: true},
		{Type: "delta", ID: "7", HasID: true, Retry: 3000, HasRetry: true, Data: "[DONE]", HasData: true,
			Comments: []string{"a comment inside"}},
		{HasID: true, Data: "x", HasData: true},
		{Data: "cut off", HasData: true, Incomplete: true},
	}
	for name, eol := range map[string]string{"LF": "\n", "CRLF": "\r\n", "CR": "\r"} {
		in := []byte(strings.ReplaceAll(stream, "\n", eol))
		for size := 1; size <= len(in); size++ {
			got := sseAll(newSSEStream(false), in, size)
			for i := range got {
				got[i].Size = 0 // the line endings' lengths differ
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s, %d-byte pieces:\ngot  %+v\nwant %+v", name, size, got, want)
			}
		}
	}
	// Sizes count an event's bytes, its blank line included, and not the
	// byte order mark or blank lines between events.
	got := sseAll(newSSEStream(false), []byte(stream), 1<<20)
	for i := range got {
		if got[i].Size != len(parts[i]) {
			t.Errorf("event %d: size %d, want %d", i, got[i].Size, len(parts[i]))
		}
	}
}

// An event larger than maxSSEEvent is cut, the next one read as usual; bytes
// that weren't captured drop the event they were in.
func TestSSELimitsAndLostBytes(t *testing.T) {
	big := strings.Repeat("x", maxSSEEvent+100)
	s := newSSEStream(false)
	got := sseAll(s, []byte("data: "+big+"\n\ndata: next\n\n"), 4096)
	if len(got) != 2 || !got[0].Cut || len(got[0].Data) >= maxSSEEvent || got[0].Size != len(big)+8 ||
		got[1].Data != "next" || got[1].Cut {
		t.Errorf("got %d events: %v %d bytes, %+v", len(got), got[0].Cut, len(got[0].Data), got[1:])
	}

	s = newSSEStream(false)
	got = s.add([]byte("data: one\n\ndata: tw"), false)
	s.lose()
	got = append(got, s.add([]byte("o, the rest\n\ndata: three\n\n"), true)...)
	if len(got) != 2 || got[0].Data != "one" || got[1].Data != "three" {
		t.Errorf("got %+v", got)
	}
}

// gzipFlushed compresses each piece and flushes it, as a server streaming
// events through gzip does, returning what each piece was compressed to.
func gzipFlushed(pieces ...string) [][]byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	var out [][]byte
	for i, p := range pieces {
		w.Write([]byte(p))
		if i == len(pieces)-1 {
			w.Close()
		} else {
			w.Flush()
		}
		out = append(out, bytes.Clone(b.Bytes()))
		b.Reset()
	}
	return out
}

// printAll prints events with p and returns what it wrote after each.
func printAll(t *testing.T, p Printer, out *bytes.Buffer, evs ...*tracer.Event) []string {
	t.Helper()
	var after []string
	for _, ev := range evs {
		out.Reset()
		if err := p.Print(ev); err != nil {
			t.Fatal(err)
		}
		after = append(after, out.String())
	}
	return after
}

// HTTP/1.1, chunked and gzipped: each event is shown as its call arrives,
// JSON data compactly, keep-alives left out but for --verbose.
func TestTextSSEHTTP1(t *testing.T) {
	gz := gzipFlushed(
		"event: delta\ndata: {\"text\": \"Hel\"}\n\n",
		": keep-alive\n\n",
		"event: delta\ndata: {\"text\": \"lo\"}\n\nevent: delta\ndata: {\"te",
		"xt\": \"!\"}\n\n",
		"data: [DONE]\n\n",
	)
	chunk := func(b []byte) string { return fmt.Sprintf("%x\r\n%s\r\n", len(b), b) }
	calls := []string{
		"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk(gz[0]),
		chunk(gz[1]),
		chunk(gz[2]),
		chunk(gz[3]),
		chunk(gz[4]),
		"0\r\n\r\n",
	}
	evs := func() []*tracer.Event {
		out := []*tracer.Event{event(tracer.FuncSSLWrite, "GET /v1/stream HTTP/1.1\r\nHost: api.example.com\r\n\r\n")}
		for _, c := range calls {
			out = append(out, event(tracer.FuncSSLRead, c))
		}
		return out
	}

	var out bytes.Buffer
	tp := NewText(&out, Options{})
	after := printAll(t, tp, &out, evs()...)
	for i, want := range map[int][]string{
		1: {"Content-Type: text/event-stream", "SSE event delta\n" + `{"text":"Hel"}` + "\n"},
		3: {"SSE event delta\n" + `{"text":"lo"}` + "\n"},
		4: {"SSE event delta\n" + `{"text":"!"}` + "\n"},
		5: {"SSE event message\n[DONE]\n"},
		6: {"[end of the event stream]"},
	} {
		for _, w := range want {
			if !strings.Contains(after[i], w) {
				t.Errorf("call %d lacks %q:\n%s", i, w, after[i])
			}
		}
	}
	if after[2] != "" || tp.Hidden() != 1 {
		t.Errorf("the keep-alive was shown (%d hidden):\n%s", tp.Hidden(), after[2])
	}
	if strings.Contains(strings.Join(after, ""), "gzip body not decoded") {
		t.Errorf("decoding failed:\n%s", strings.Join(after, ""))
	}

	tp = NewText(&out, Options{Verbose: true})
	if after := printAll(t, tp, &out, evs()...); !strings.Contains(after[2], "SSE comment: keep-alive") {
		t.Errorf("verbose:\n%s", after[2])
	}

	// JSON: the events on the body's pieces.
	jp := NewJSON(&out, Options{})
	var got []jsonSSEEvent
	for _, line := range printAll(t, jp, &out, evs()...) {
		var ev struct{ HTTP1 []jsonHTTP1 }
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		for _, p := range ev.HTTP1 {
			got = append(got, p.SSE...)
		}
	}
	str := func(s string) *string { return &s }
	want := []jsonSSEEvent{
		{Event: "delta", Data: str(`{"text": "Hel"}`), Bytes: 36},
		{Comments: []string{"keep-alive"}, Bytes: 14},
		{Event: "delta", Data: str(`{"text": "lo"}`), Bytes: 35},
		{Event: "delta", Data: str(`{"text": "!"}`), Bytes: 34},
		{Data: str("[DONE]"), Bytes: 14},
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.Marshal(got)
		t.Errorf("JSON events: %s", gotJSON)
	}
}

// An event's data is shown up to 2 KiB unless --full, per event rather than
// per body; --redact masks secrets in it, even when it was split across
// calls; --grep finds it; --hex shows the bytes as sent.
func TestTextSSEOptions(t *testing.T) {
	long := strings.Repeat("y", 3000)
	body := "data: " + long + "\n\ndata: {\"api_key\": \"sk-ant-abcdefghijklmnopqrstuvwxyz\"}\n\n"
	head := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n" // until the connection closes
	split := len(head) + len(body) - 20
	all := head + body
	evs := func() []*tracer.Event {
		return []*tracer.Event{
			event(tracer.FuncSSLWrite, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
			event(tracer.FuncSSLRead, all[:split]),
			event(tracer.FuncSSLRead, all[split:]),
		}
	}
	calls := func(opts Options) []string {
		var out bytes.Buffer
		return printAll(t, NewText(&out, opts), &out, evs()...)
	}
	text := func(opts Options) string { return strings.Join(calls(opts), "") }
	if got := text(Options{}); !strings.Contains(got, "[… 952 more bytes; --full shows all]") ||
		!strings.Contains(got, `{"api_key":"sk-ant-abcdefghijklmnopqrstuvwxyz"}`) {
		t.Errorf("default:\n%s", got)
	}
	if got := text(Options{Full: true}); !strings.Contains(got, long+"\n") {
		t.Errorf("--full:\n%s", got)
	}
	if got := text(Options{Redact: true}); strings.Contains(got, "abcdefghijklmnop") || !strings.Contains(got, `{"api_key":"[redacted]"}`) {
		t.Errorf("--redact:\n%s", got)
	}
	if got := text(Options{Hex: true}); strings.Contains(got, "SSE event") {
		t.Errorf("--hex:\n%s", got)
	}
	// The key's name is in the first call, its value in the second.
	if got := calls(Options{Grep: regexp.MustCompile(`api_key": "sk-ant`)}); !strings.Contains(got[2], "SSE event message\n{") {
		t.Errorf("--grep:\n%s", strings.Join(got, ""))
	}
}

// HTTP/2: events in DATA frames of any size, read in calls of any size, a
// Brotli-compressed stream, and the end of the stream at its trailers.
func TestSSEHTTP2(t *testing.T) {
	events1 := "event: content_block_delta\ndata: {\"delta\": {\"text\": \"Hi\"}}\n\n" +
		":\n\n" +
		"event: content_block_delta\r\ndata: {\"delta\": {\"text\": \" there\"}}\r\n\r\n" +
		"event: message_stop\ndata: {}\n\n"
	client := newHTTP2Writer(true)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "POST", ":scheme", "https", ":authority", "api.example.com", ":path", "/v1/messages")})
	// The response, its body in DATA frames of frame bytes, compressed if
	// encoding is set.
	response := func(encoding string, frame int) []byte {
		body := []byte(events1)
		fields := []string{":status", "200", "content-type", "text/event-stream"}
		if encoding == "br" {
			var b bytes.Buffer
			w := brotli.NewWriter(&b)
			w.Write(body)
			w.Close()
			body = b.Bytes()
			fields = append(fields, "content-encoding", "br")
		}
		server := newHTTP2Writer(false)
		server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: server.block(fields...)})
		for len(body) > 0 {
			n := min(len(body), frame)
			server.fr.WriteData(1, false, body[:n])
			body = body[n:]
		}
		server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
			BlockFragment: server.block("x-done", "1")})
		return server.buf.Bytes()
	}

	for _, tc := range []struct {
		encoding    string
		frame, size int
	}{{"", 1 << 14, 1 << 20}, {"", 7, 5}, {"br", 9, 64}, {"br", 1 << 14, 3}} {
		c := newHTTP2Conns(newBodyPool(), nil)
		var got []sseEvent
		evs := append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, response(tc.encoding, tc.frame), tc.size)...)
		for _, ev := range evs {
			frames, _, note := c.process(ev)
			if note != "" {
				t.Fatal(note)
			}
			for _, f := range frames {
				if f.Body.Err != "" {
					t.Fatal(f.Body.Err)
				}
				got = append(got, f.SSE...)
			}
		}
		var types []string
		for _, e := range got {
			types = append(types, cmpOr(e.Type, ":")+" "+e.Data)
		}
		want := []string{`content_block_delta {"delta": {"text": "Hi"}}`, ": ", `content_block_delta {"delta": {"text": " there"}}`, "message_stop {}"}
		if !reflect.DeepEqual(types, want) {
			t.Errorf("%+v: %q", tc, types)
		}
		if n := len(c.conns[http2Key{7, 0x1000}].dirs[tracer.Read].sse); n != 0 {
			t.Errorf("%+v: %d streams still followed", tc, n)
		}
	}

	// --brief shows each event's call, none folded, and JSON has them.
	var out bytes.Buffer
	bp := NewBrief(&out, Options{})
	evs := append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, response("", 1<<14), 30)...)
	brief := strings.Join(printAll(t, bp, &out, evs...), "")
	if !strings.Contains(brief, `HTTP/2 DATA s1 SSE content_block_delta {"delta":{"text":"Hi"}}`) ||
		!strings.Contains(brief, "SSE message_stop {}") || bp.Folded() != 0 {
		t.Errorf("brief (%d folded):\n%s", bp.Folded(), brief)
	}
	jp := NewJSON(&out, Options{})
	n := 0
	for _, line := range printAll(t, jp, &out, evs...) {
		var ev struct{ HTTP2 []jsonHTTP2Frame }
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		for _, f := range ev.HTTP2 {
			n += len(f.SSE)
		}
	}
	if n != 4 {
		t.Errorf("JSON has %d events", n)
	}
}

// HTTP/3: a stream's packets out of order, and an event the stream's FIN
// cuts short.
func TestSSEHTTP3(t *testing.T) {
	resp := append([]byte{0x00, 0x00, 0xd9}, literalField("content-type", "text/event-stream")...)
	stream := cat(h3Frame(0x01, resp),
		h3Frame(0x00, []byte("data: {\"n\": 1}\n\ndata: {\"n\"")),
		h3Frame(0x00, []byte(": 2}\n\ndata: {\"n\": 3}\n\nevent: error\ndata: overloaded")))
	third := len(stream) / 3
	packet := func(from, to int) *tracer.Event {
		return quicEvent(tracer.FuncQUICRecv, streamFrameBytes(0, uint64(from), stream[from:to], to == len(stream)))
	}
	var out bytes.Buffer
	tp := NewText(&out, Options{})
	after := printAll(t, tp, &out, packet(0, third), packet(2*third, len(stream)), packet(third, 2*third))
	all := strings.Join(after, "")
	for _, want := range []string{"SSE event message\n{\"n\":1}\n", "SSE event message\n{\"n\":2}\n", "SSE event message\n{\"n\":3}\n",
		"SSE event error (the body ended before the event did)\noverloaded\n"} {
		if !strings.Contains(all, want) {
			t.Errorf("lacks %q:\n%s", want, all)
		}
	}
	if after[1] != "" { // the FIN came first, ahead of the middle
		t.Errorf("printed ahead of the middle:\n%s", after[1])
	}
}

// --requests: an event stream gets a line when its headers arrive, and the
// usual line, with how many events it had, when it ends.
func TestRequestsSSE(t *testing.T) {
	client := newHTTP2Writer(true)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "POST", ":scheme", "https", ":authority", "api.example.com", ":path", "/v1/chat/completions")})
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true,
		BlockFragment: server.block(":status", "200", "content-type", "text/event-stream")})
	headers := bytes.Clone(server.buf.Bytes())
	server.buf.Reset()
	server.fr.WriteData(1, false, []byte("data: {\"delta\":\"a\"}\n\n: ping\n\n"))
	server.fr.WriteData(1, false, []byte("data: {\"delta\":\"b\"}\n\n"))
	server.fr.WriteData(1, true, []byte("data: [DONE]\n\n"))
	evs := append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, headers, 1<<20)...)
	evs = append(evs, events(tracer.FuncSSLRead, server.buf.Bytes(), 30)...)
	for _, ev := range evs {
		ev.Comm = "python3"
	}
	evs[len(evs)-1].Time = evs[len(evs)-1].Time.Add(30 * time.Second)

	var out bytes.Buffer
	r := NewRequests(&out, Options{})
	for i, ev := range evs {
		ev.Time = ev.Time.Add(time.Duration(i) * time.Millisecond)
		if err := r.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	want := []string{
		"POST https://api.example.com/v1/chat/completions HTTP/2 → 200, text/event-stream, streaming, 1ms",
		"POST https://api.example.com/v1/chat/completions HTTP/2 → 200, text/event-stream, 64 bytes, 3 events, 30.",
	}
	if len(lines) != 2 || !strings.Contains(lines[0], want[0]) || !strings.Contains(lines[1], want[1]) {
		t.Errorf("got:\n%s", out.String())
	}
	if r.Shown() != 1 {
		t.Errorf("shown %d", r.Shown())
	}
}

// --requests: another response gets the early line once more of it arrives
// a second after its headers, an HTTP/1.1 stream that ends with its
// connection included; a quick one doesn't.
func TestRequestsSlowResponse(t *testing.T) {
	evs := []*tracer.Event{
		event(tracer.FuncSSLWrite, "POST /api/generate HTTP/1.1\r\nHost: localhost:11434\r\n\r\n"),
		event(tracer.FuncSSLRead, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\r\n{\"response\":\"a\"}\n"),
		event(tracer.FuncSSLRead, "{\"response\":\"b\"}\n"),
		event(tracer.FuncSSLRead, "{\"response\":\"c\"}\n"),
	}
	evs[2].Time = evs[2].Time.Add(500 * time.Millisecond)
	evs[3].Time = evs[3].Time.Add(1500 * time.Millisecond)
	after := requestLines(t, Options{}, evs...)
	if after[2] != "" {
		t.Errorf("shown as streaming too soon:\n%s", after[2])
	}
	if want := "03:04:05.000006 curl[42] POST https://localhost:11434/api/generate HTTP/1.1 → 200, application/x-ndjson, streaming, 1ms\n"; after[3] != want {
		t.Errorf("got  %q\nwant %q", after[3], want)
	}
}
