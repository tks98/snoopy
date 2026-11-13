package output

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/http2"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// WebSocket over HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220): a stream whose
// extended CONNECT got a 2xx response carries WebSocket frames in its DATA.
// The traced program is the client, as in websocket_test.go.

// take returns what a writer wrote since the last take.
func take(w *http2Writer) []byte {
	b := bytes.Clone(w.buf.Bytes())
	w.buf.Reset()
	return b
}

// wsHTTP2 returns the events of a WebSocket over HTTP/2 with permessage-
// deflate: the handshake, a compressed message from the client, a ping
// and a message in two DATA frames from the server, with a WINDOW_UPDATE,
// and the client's close. A GET on stream 3 goes on beside it.
func wsHTTP2(t *testing.T) []*tracer.Event {
	client, server := newHTTP2Writer(true), newHTTP2Writer(false)
	ev := func(fn tracer.Function, b []byte) *tracer.Event {
		return &tracer.Event{PID: 7, ConnID: 0x1000, Function: fn, Size: uint32(len(b)), Data: b}
	}
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true,
		BlockFragment: client.block(":method", "CONNECT", ":protocol", "websocket", ":scheme", "https",
			":authority", "example.com", ":path", "/chat", "sec-websocket-version", "13",
			"sec-websocket-extensions", "permessage-deflate; client_max_window_bits")})
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/other")})
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true,
		BlockFragment: server.block(":status", "200", "sec-websocket-extensions", "permessage-deflate")})
	evs := []*tracer.Event{ev(tracer.FuncSSLWrite, take(client)), ev(tracer.FuncSSLRead, take(server))}

	z := &deflater{}
	client.fr.WriteData(1, false, wsFrameBytes(wsText, true, true, wsKey, z.message(t, `{"op":"hello","token":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}`)))
	evs = append(evs, ev(tracer.FuncSSLWrite, take(client)))
	server.fr.WriteData(1, false, wsFrameBytes(wsPing, true, false, nil, []byte("hb")))
	evs = append(evs, ev(tracer.FuncSSLRead, take(server)))
	frame := wsFrameBytes(wsText, true, false, nil, []byte("hello over HTTP/2"))
	server.fr.WriteData(1, false, frame[:8])
	server.fr.WriteWindowUpdate(0, 1000)
	server.fr.WriteData(1, false, frame[8:])
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, EndStream: true, EndHeaders: true,
		BlockFragment: server.block(":status", "204")})
	evs = append(evs, ev(tracer.FuncSSLRead, take(server)))
	client.fr.WriteData(1, true, wsFrameBytes(wsClose, true, false, wsKey, append([]byte{0x03, 0xe8}, "bye"...)))
	return append(evs, ev(tracer.FuncSSLWrite, take(client)))
}

func TestWebSocketHTTP2(t *testing.T) {
	evs := wsHTTP2(t)
	got, hidden := textOf(t, Options{}, evs...)
	want := []string{
		"", "", // the handshake
		"HTTP/2 DATA stream=1 length=73\nWebSocket text length=67 [FIN,compressed]\n" +
			"[permessage-deflate: 67 bytes decoded to 65]\n{\"op\":\"hello\",\"token\":\"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"}\n\n",
		"", // the ping
		"", // checked below
		"HTTP/2 DATA stream=1 length=11 [END_STREAM]\nWebSocket close 1000 (normal closure): bye\n\n",
	}
	if !strings.Contains(got[1], ":status: 200\nsec-websocket-extensions: permessage-deflate\n") {
		t.Errorf("response:\n%s", got[1])
	}
	if hidden != 1 {
		t.Errorf("%d calls hidden, want the ping's", hidden)
	}
	for _, i := range []int{2, 3, 5} {
		if got[i] != want[i] {
			t.Errorf("call %d:\ngot  %q\nwant %q", i, got[i], want[i])
		}
	}
	// The second piece of the message, its header's rest in the first, then
	// the 204 on stream 3.
	if !strings.HasPrefix(got[4], "HTTP/2 DATA stream=1 length=8\nWebSocket text length=17 [FIN]\nhello \n"+
		"HTTP/2 DATA stream=1 length=11\nWebSocket text length=17 (continued) [FIN]\nover HTTP/2\nHTTP/2 HEADERS stream=3") {
		t.Errorf("call 4:\n%q", got[4])
	}
	got, _ = textOf(t, Options{Verbose: true}, evs...)
	if !strings.Contains(got[3], "WebSocket ping \"hb\"") || !strings.Contains(got[4], "HTTP/2 WINDOW_UPDATE") {
		t.Errorf("--verbose:\n%s%s", got[3], got[4])
	}

	lines := briefLines(t, evs...)
	if len(lines) != 5 ||
		!strings.HasSuffix(lines[2], `HTTP/2 DATA s1 WebSocket text 67 bytes (permessage-deflate, 65 decoded): {"op":"hello","token":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}`) ||
		!strings.HasSuffix(lines[3], "HTTP/2 DATA s1 WebSocket text 6 bytes: hello; DATA s1 WebSocket text (continued) 11 bytes; HEADERS s3 204 [END_STREAM]") ||
		!strings.HasSuffix(lines[4], "HTTP/2 DATA s1 WebSocket close 1000 (normal closure): bye [END_STREAM]") {
		t.Errorf("--brief:\n%s", strings.Join(lines, "\n"))
	}

	// JSON has the frames on the DATA frames' records, redacted.
	var out bytes.Buffer
	jp := NewJSON(&out, Options{Redact: true})
	after := printAll(t, jp, &out, evs...)
	var rec struct {
		HTTP2 []jsonHTTP2Frame `json:"http2"`
	}
	if err := json.Unmarshal([]byte(after[2]), &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.HTTP2) != 1 || len(rec.HTTP2[0].WebSocket) != 1 {
		t.Fatalf("JSON: %s", after[2])
	}
	f := rec.HTTP2[0].WebSocket[0]
	if f.Opcode != "text" || !f.Masked || !f.Compressed || !f.End || f.Body == nil || f.Body.Decoded == nil ||
		strings.Contains(*f.Body.Decoded, "ghp_abc") || !strings.Contains(*f.Body.Decoded, `"op":"hello"`) {
		t.Errorf("JSON: %s", after[2])
	}
	if !strings.Contains(after[5], `"opcode":"close"`) || !strings.Contains(after[5], `"close_code":1000`) {
		t.Errorf("JSON close: %s", after[5])
	}

	// --grep finds what a compressed message decompressed to.
	var buf bytes.Buffer
	tp := NewText(&buf, Options{Grep: regexp.MustCompile(`"op":"hello"`)})
	shown := 0
	for _, ev := range evs {
		buf.Reset()
		if err := tp.Print(ev); err != nil {
			t.Fatal(err)
		}
		if buf.Len() > 0 {
			shown++
		}
	}
	if shown != 1 {
		t.Errorf("--grep showed %d calls, want 1", shown)
	}

	// --requests: a line for the handshake when its response arrives, and
	// none for streaming; the GET beside it as usual.
	reqs := requestLines(t, Options{}, wsHTTP2(t)...)
	if !strings.HasSuffix(strings.TrimSpace(reqs[1]), "CONNECT https://example.com/chat HTTP/2 → 200, websocket, 1ms") {
		t.Errorf("handshake: %q", reqs[1])
	}
	if all := reqs[len(reqs)-1]; strings.Count(all, "\n") != 2 || strings.Contains(all, "streaming") ||
		!strings.Contains(all, "GET https://example.com/other HTTP/2 → 204, no body") {
		t.Errorf("--requests:\n%s", all)
	}
}

// A response other than 2xx doesn't make the stream WebSocket, nor does a
// CONNECT without :protocol; bytes of a frame header that weren't
// captured stop decoding, which shows the rest as sent.
func TestWebSocketHTTP2NotAccepted(t *testing.T) {
	for _, tc := range []struct {
		request []string
		status  string
	}{
		{[]string{":method", "CONNECT", ":protocol", "websocket", ":scheme", "https", ":authority", "example.com", ":path", "/chat"}, "403"},
		{[]string{":method", "CONNECT", ":authority", "example.com:443"}, "200"},
		{[]string{":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/chat"}, "200"},
	} {
		c := newHTTP2Conns(newBodyPool(), nil)
		client, server := newHTTP2Writer(true), newHTTP2Writer(false)
		client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: client.block(tc.request...)})
		server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: server.block(":status", tc.status)})
		server.fr.WriteData(1, false, wsFrameBytes(wsText, true, false, nil, []byte("hi")))
		for _, ev := range append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, server.buf.Bytes(), 1<<20)...) {
			frames, _, _ := c.process(ev)
			for _, f := range frames {
				if f.WS != nil {
					t.Errorf("%v %s: WebSocket", tc.request[:2], tc.status)
				}
			}
		}
	}

	client, server := newHTTP2Writer(true), newHTTP2Writer(false)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true,
		BlockFragment: client.block(":method", "CONNECT", ":protocol", "websocket", ":scheme", "https", ":authority", "example.com", ":path", "/chat")})
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: server.block(":status", "200")})
	evs := append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, server.buf.Bytes(), 1<<20)...)
	server.buf.Reset()
	// A frame whose payload goes missing, which is fine; then a DATA frame
	// with a frame header cut short by missing bytes, then one that's
	// garbage after the framing was lost.
	server.fr.WriteData(1, false, wsFrameBytes(wsBinary, true, false, nil, bytes.Repeat([]byte{7}, 100)))
	lossy := take(server)
	server.fr.WriteData(1, false, cat(wsFrameBytes(wsText, true, false, nil, []byte("ok")), wsFrameBytes(wsText, true, false, nil, []byte("hello"))))
	cut := take(server)
	server.fr.WriteData(1, false, []byte("not frames"))
	after := take(server)
	evs = append(evs,
		&tracer.Event{PID: 7, ConnID: 0x1000, Function: tracer.FuncSSLRead, Size: uint32(len(lossy)), Data: lossy[:40]},
		&tracer.Event{PID: 7, ConnID: 0x1000, Function: tracer.FuncSSLRead, Size: uint32(len(cut)), Data: cut[:14]},
		&tracer.Event{PID: 7, ConnID: 0x1000, Function: tracer.FuncSSLRead, Size: uint32(len(after)), Data: after})
	got, _ := textOf(t, Options{}, evs...)
	if !strings.Contains(got[2], "WebSocket binary length=100 [FIN]\n[29 bytes of binary data]") {
		t.Errorf("missing payload:\n%s", got[2])
	}
	if !strings.Contains(got[3], "WebSocket text length=2 [FIN]\nok\n") ||
		!strings.Contains(got[3], "[WebSocket decoding stopped for this direction of the connection: bytes of a frame header weren't captured (raise --max-size)]") {
		t.Errorf("cut header:\n%s", got[3])
	}
	if got[4] != "HTTP/2 DATA stream=1 length=10\nnot frames\n\n" {
		t.Errorf("after the framing was lost: %q", got[4])
	}

	// A frame header that doesn't parse: what follows it is shown as sent.
	server.fr.WriteData(1, false, cat(wsFrameBytes(wsText, true, false, nil, []byte("ok")), []byte("\x83\x01xtail")))
	evs[len(evs)-3] = events(tracer.FuncSSLRead, take(server), 1<<20)[0]
	got, _ = textOf(t, Options{}, evs[:len(evs)-2]...)
	if want := "HTTP/2 DATA stream=1 length=11\nWebSocket text length=2 [FIN]\nok\n" +
		"[WebSocket decoding stopped for this direction of the connection: invalid frame header 8301 (reserved opcode)]\n" +
		"[7 bytes of binary data]\n\n"; got[2] != want {
		t.Errorf("invalid header:\ngot  %q\nwant %q", got[2], want)
	}
}

// wsHTTP3 returns the events of a WebSocket over HTTP/3, with QPACK's
// static table and literals: the handshake, a compressed message from the
// client, and the server's reply in two DATA frames, out of order, and a
// ping; and the client's message's frame.
func wsHTTP3(t *testing.T) (evs []*tracer.Event, msg []byte) {
	// :method CONNECT (static 15), :scheme https (23), :protocol, :authority
	// and :path as literals; then :status 200 (25).
	req := cat([]byte{0x00, 0x00, 0xcf, 0xd7}, literalField(":protocol", "websocket"),
		literalField(":authority", "example.com"), literalField(":path", "/chat"))
	resp := cat([]byte{0x00, 0x00, 0xd9}, literalField("sec-websocket-extensions", "permessage-deflate; server_no_context_takeover"))
	z := &deflater{}
	msg = wsFrameBytes(wsText, true, true, wsKey, z.message(t, "hello over HTTP/3, hello over HTTP/3"))
	reply := wsFrameBytes(wsText, true, false, nil, []byte("hi back"))
	ping := wsFrameBytes(wsPing, true, false, nil, nil)
	evs = []*tracer.Event{
		quicEvent(tracer.FuncQUICSend, streamFrameBytes(0, 0, h3Frame(0x01, req), false)),
		quicEvent(tracer.FuncQUICRecv, streamFrameBytes(0, 0, h3Frame(0x01, resp), false)),
		quicEvent(tracer.FuncQUICSend, streamFrameBytes(0, uint64(len(h3Frame(0x01, req))), h3Frame(0x00, msg), false)),
		// The server's reply in two DATA frames, out of order, and a ping.
		quicEvent(tracer.FuncQUICRecv, streamFrameBytes(0, uint64(len(h3Frame(0x01, resp))+len(h3Frame(0x00, reply[:4]))),
			cat(h3Frame(0x00, reply[4:]), h3Frame(0x00, ping)), false)),
		quicEvent(tracer.FuncQUICRecv, streamFrameBytes(0, uint64(len(h3Frame(0x01, resp))), h3Frame(0x00, reply[:4]), false)),
	}
	return evs, msg
}

// HTTP/3: the same, with QPACK's static table and literals.
func TestWebSocketHTTP3(t *testing.T) {
	evs, msg := wsHTTP3(t)
	got, hidden := textOf(t, Options{}, evs...)
	if !strings.Contains(got[1], "HTTP/3 HEADERS stream=0\n:status: 200\n") {
		t.Errorf("response:\n%s", got[1])
	}
	if want := "HTTP/3 DATA stream=0 (" + itoa(len(msg)) + " bytes)\nWebSocket text length=" + itoa(len(msg)-6) +
		" [FIN,compressed]\n[permessage-deflate: " + itoa(len(msg)-6) + " bytes decoded to 36]\nhello over HTTP/3, hello over HTTP/3\n\n"; got[2] != want {
		t.Errorf("client's message:\ngot  %q\nwant %q", got[2], want)
	}
	if hidden != 1 {
		t.Errorf("%d calls hidden, want the out-of-order packet's", hidden)
	}
	if want := "HTTP/3 DATA stream=0 (4 bytes)\nWebSocket text length=7 [FIN]\nhi\n" +
		"HTTP/3 DATA stream=0 (5 bytes)\nWebSocket text length=7 (continued) [FIN]\n back\n\n"; got[4] != want {
		t.Errorf("server's reply:\ngot  %q\nwant %q", got[4], want)
	}

	lines := briefLines(t, evs...)
	if len(lines) != 4 || !strings.HasSuffix(lines[3], "HTTP/3 DATA s0 WebSocket text 2 bytes: hi; DATA s0 WebSocket text (continued) 5 bytes") {
		t.Errorf("--brief:\n%s", strings.Join(lines, "\n"))
	}
	var out bytes.Buffer
	after := printAll(t, NewJSON(&out, Options{}), &out, evs...)
	if !strings.Contains(after[4], `"websocket":[{"opcode":"text","fin":true,"length":7,"data_bytes":2,"payload":"hi"}]`) {
		t.Errorf("JSON: %s", after[4])
	}
	reqs := requestLines(t, Options{}, evs...)
	if !strings.HasSuffix(strings.TrimSpace(reqs[1]), "CONNECT https://example.com/chat HTTP/3 → 200, websocket, 1ms") ||
		reqs[len(reqs)-1] != reqs[1] {
		t.Errorf("--requests:\n%s", reqs[len(reqs)-1])
	}
}
