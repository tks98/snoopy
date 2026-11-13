package output

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// Unit tests build WebSocket frames (RFC 6455) here, and use RFC 6455's and
// RFC 7692's examples. The traced program is the client: it writes masked
// frames (FuncSSLWrite) and reads the server's (FuncSSLRead).

var wsKey = []byte{0x37, 0xfa, 0x21, 0x3d} // RFC 6455's examples'

// wsFrameBytes builds a frame, masked with key if it isn't nil.
func wsFrameBytes(op byte, fin, rsv1 bool, key, payload []byte) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	if rsv1 {
		b0 |= 0x40
	}
	out := []byte{b0}
	var m byte
	if key != nil {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		out = append(out, m|byte(n))
	case n < 1<<16:
		out = append(out, m|126, byte(n>>8), byte(n))
	default:
		out = binary.BigEndian.AppendUint64(append(out, m|127), uint64(n))
	}
	if key == nil {
		return append(out, payload...)
	}
	out = append(out, key...)
	for i, c := range payload {
		out = append(out, c^key[i%4])
	}
	return out
}

// wsHandshake returns a client's upgrade request and its 101 response, with
// the extensions the server accepted.
func wsHandshake(extensions string) []*tracer.Event {
	req := "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n"
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
	if extensions != "" {
		resp += "Sec-WebSocket-Extensions: " + extensions + "\r\n"
	}
	return []*tracer.Event{event(tracer.FuncSSLWrite, req), event(tracer.FuncSSLRead, resp+"\r\n")}
}

// wsDecode decodes events and returns the WebSocket frames each held, and
// why decoding stopped, if it did.
func wsDecode(t *testing.T, d decoders, evs ...*tracer.Event) (frames [][]wsFrame, errs []string) {
	t.Helper()
	for _, ev := range evs {
		dc := d.decode(ev)
		var fs []wsFrame
		var e string
		for _, s := range dc.http1 {
			if s.ws != nil {
				fs = append(fs, s.ws.Frames...)
				e = cmpOr(e, s.ws.Err)
			}
		}
		frames, errs = append(frames, fs), append(errs, e)
	}
	return frames, errs
}

func wsEvent(fn tracer.Function, b []byte) *tracer.Event {
	return event(fn, string(b))
}

// wsEvents splits b into calls of size bytes, on the connection of
// wsHandshake's events.
func wsEvents(fn tracer.Function, b []byte, size int) []*tracer.Event {
	var out []*tracer.Event
	for len(b) > 0 {
		n := min(size, len(b))
		out = append(out, wsEvent(fn, b[:n]))
		b = b[n:]
	}
	return out
}

// messages joins the frames' payloads into messages, and lists the control
// frames, as "type: payload".
func messages(frames [][]wsFrame) []string {
	var out []string
	var cur []byte
	for _, fs := range frames {
		for _, f := range fs {
			switch {
			case f.Opcode >= wsClose && f.Complete:
				out = append(out, fmt.Sprintf("%s: %s", wsOpcodeName(f.Opcode), f.Data))
			case f.Opcode < wsClose:
				cur = append(cur, f.Data...)
				if f.endsMessage() {
					if f.Compressed {
						cur = f.Body.Decoded
					}
					out = append(out, fmt.Sprintf("%s: %s", wsOpcodeName(f.Message), cur))
					cur = nil
				}
			}
		}
	}
	return out
}

// RFC 6455, section 5.7.
func TestWebSocketRFC6455Examples(t *testing.T) {
	d := newDecoders(Options{})
	wsDecode(t, d, wsHandshake("")...)
	big := bytes.Repeat([]byte{0xa5}, 65536)
	frames, errs := wsDecode(t, d,
		wsEvent(tracer.FuncSSLRead, []byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}),
		wsEvent(tracer.FuncSSLWrite, []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}),
		wsEvent(tracer.FuncSSLRead, []byte{0x01, 0x03, 0x48, 0x65, 0x6c}),
		wsEvent(tracer.FuncSSLRead, []byte{0x80, 0x02, 0x6c, 0x6f}),
		wsEvent(tracer.FuncSSLRead, []byte{0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}),
		wsEvent(tracer.FuncSSLWrite, []byte{0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}),
		wsEvent(tracer.FuncSSLRead, cat([]byte{0x82, 0x7e, 0x01, 0x00}, big[:256])),
		wsEvent(tracer.FuncSSLRead, cat([]byte{0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0}, big)),
	)
	for i, e := range errs {
		if e != "" {
			t.Fatalf("event %d: %s", i, e)
		}
	}
	got := messages(frames)
	want := []string{"text: Hello", "text: Hello", "text: Hello", "ping: Hello", "pong: Hello",
		"binary: " + string(big[:256]), "binary: " + string(big)}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got %q", got)
	}
	if f := frames[1][0]; !f.Masked || !f.Fin || f.Length != 5 {
		t.Errorf("masked frame: %+v", f)
	}
	if f := frames[3][0]; f.Opcode != wsContinuation || f.Message != wsText || f.Offset != 3 || !f.endsMessage() {
		t.Errorf("continuation frame: %+v", f)
	}
	if f := frames[7][0]; f.Length != 65536 || !f.Complete {
		t.Errorf("64-bit length: %+v", f)
	}
}

// Frames are followed however the calls split them: one byte at a time,
// several in a call, headers and payloads apart.
func TestWebSocketSplit(t *testing.T) {
	long := strings.Repeat("a long message, ", 30)
	var client, server []byte
	client = cat(client,
		wsFrameBytes(wsText, true, false, wsKey, []byte("hi")),
		wsFrameBytes(wsBinary, false, false, []byte{1, 2, 3, 4}, []byte{0, 1, 2}),
		wsFrameBytes(wsPing, true, false, []byte{5, 6, 7, 8}, []byte("ping!")), // between fragments
		wsFrameBytes(wsContinuation, true, false, []byte{9, 10, 11, 12}, []byte{3, 4, 5, 6, 7}),
		wsFrameBytes(wsText, true, false, wsKey, []byte(long)),
		wsFrameBytes(wsText, true, false, wsKey, nil),
		wsFrameBytes(wsClose, true, false, wsKey, append([]byte{0x03, 0xe8}, "bye"...)))
	server = cat(server,
		wsFrameBytes(wsText, true, false, nil, []byte(long+long)),
		wsFrameBytes(wsPong, true, false, nil, []byte("ping!")),
		wsFrameBytes(wsClose, true, false, nil, []byte{0x03, 0xe8}))
	want := []string{"text: hi", "ping: ping!", "binary: \x00\x01\x02\x03\x04\x05\x06\x07", "text: " + long, "text: ",
		"close: \x03\xe8bye", "text: " + long + long, "pong: ping!", "close: \x03\xe8"}

	for _, size := range []int{1, 2, 3, 5, 7, 14, 100, 1 << 20} {
		d := newDecoders(Options{})
		wsDecode(t, d, wsHandshake("")...)
		var evs []*tracer.Event
		evs = append(evs, wsEvents(tracer.FuncSSLWrite, client, size)...)
		evs = append(evs, wsEvents(tracer.FuncSSLRead, server, size)...)
		frames, errs := wsDecode(t, d, evs...)
		if e := strings.Join(errs, ""); e != "" {
			t.Fatalf("calls of %d bytes: %s", size, e)
		}
		if got := messages(frames); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("calls of %d bytes: got %q", size, got)
		}
		var closes []wsFrame
		for _, fs := range frames {
			for _, f := range fs {
				if f.Opcode == wsClose && f.Complete {
					closes = append(closes, f)
				}
			}
		}
		if len(closes) != 2 || closes[0].CloseCode != 1000 || closes[0].CloseReason != "bye" || closes[1].CloseCode != 1000 {
			t.Errorf("calls of %d bytes: close frames %+v", size, closes)
		}
	}
}

// RFC 7692, section 7.2.3: "Hello" compressed in a message, in a message of
// two frames, again with the window of the first, in a stored block, with
// BFINAL set, and in two blocks.
func TestWebSocketRFC7692Examples(t *testing.T) {
	d := newDecoders(Options{})
	wsDecode(t, d, wsHandshake("permessage-deflate")...)
	frames, errs := wsDecode(t, d,
		wsEvent(tracer.FuncSSLRead, []byte{0xc1, 0x07, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}),
		wsEvent(tracer.FuncSSLRead, []byte{0x41, 0x03, 0xf2, 0x48, 0xcd, 0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00}),
		wsEvent(tracer.FuncSSLRead, []byte{0xc1, 0x05, 0xf2, 0x00, 0x11, 0x00, 0x00}),
		wsEvent(tracer.FuncSSLRead, []byte{0xc1, 0x0b, 0x00, 0x05, 0x00, 0xfa, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00}),
		wsEvent(tracer.FuncSSLRead, []byte{0xc1, 0x08, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00}),
		wsEvent(tracer.FuncSSLRead, []byte{0xc1, 0x0d, 0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00}),
	)
	for i, fs := range frames {
		last := fs[len(fs)-1]
		if errs[i] != "" || !last.Compressed || last.Body.Err != "" || string(last.Body.Decoded) != "Hello" {
			t.Errorf("example %d: %+v (%s)", i, last, errs[i])
		}
	}
	// Uncompressed messages may follow compressed ones.
	frames, _ = wsDecode(t, d, wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, false, nil, []byte("plain"))))
	if f := frames[0][0]; f.Compressed || f.Body.Encoding != "" || string(f.Data) != "plain" {
		t.Errorf("uncompressed message: %+v", f)
	}
}

// deflater compresses messages as a permessage-deflate sender does: a
// flush after each, whose empty block is left out, with one compressor for
// all of them if it keeps its context.
type deflater struct {
	buf      bytes.Buffer
	w        *flate.Writer
	takeover bool
}

func (z *deflater) message(t *testing.T, s string) []byte {
	if z.w == nil || !z.takeover {
		z.w, _ = flate.NewWriter(&z.buf, flate.BestCompression)
	}
	z.buf.Reset()
	if _, err := z.w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := z.w.Flush(); err != nil {
		t.Fatal(err)
	}
	b := bytes.Clone(z.buf.Bytes())
	if !bytes.HasSuffix(b, []byte{0, 0, 0xff, 0xff}) {
		t.Fatalf("flush didn't end with an empty stored block: %x", b)
	}
	return b[:len(b)-4]
}

// With context takeover, a message can refer back into earlier ones; the
// no_context_takeover parameters say a direction's sender doesn't.
func TestWebSocketContextTakeover(t *testing.T) {
	msgs := []string{
		`{"type":"subscribe","channel":"prices","symbols":["AAPL","GOOG","MSFT"]}`,
		`{"type":"subscribe","channel":"prices","symbols":["AAPL","GOOG","AMZN"]}`,
		strings.Repeat("filler that pushes the first message out of the window ", 700),
		`{"type":"subscribe","channel":"prices","symbols":["AAPL","GOOG","MSFT"]}`,
	}
	run := func(extensions string, serverTakeover, clientTakeover bool) (client, server []string) {
		d := newDecoders(Options{})
		wsDecode(t, d, wsHandshake(extensions)...)
		zs, zc := &deflater{takeover: serverTakeover}, &deflater{takeover: clientTakeover}
		for _, m := range msgs {
			payload := zc.message(t, m)
			// The client's message in two frames, split across calls.
			frame := cat(wsFrameBytes(wsText, false, true, wsKey, payload[:len(payload)/2]),
				wsFrameBytes(wsContinuation, true, false, wsKey, payload[len(payload)/2:]))
			frames, errs := wsDecode(t, d, wsEvents(tracer.FuncSSLWrite, frame, 7)...)
			client = append(client, outcome(frames, errs))
			frames, errs = wsDecode(t, d, wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, true, nil, zs.message(t, m))))
			server = append(server, outcome(frames, errs))
		}
		return client, server
	}
	for _, c := range []struct {
		extensions                     string
		serverTakeover, clientTakeover bool
	}{
		{"permessage-deflate", true, true},
		{"permessage-deflate; server_no_context_takeover", false, true},
		{"permessage-deflate; client_no_context_takeover; server_max_window_bits=15", true, false},
		{"permessage-deflate; server_no_context_takeover; client_no_context_takeover", false, false},
	} {
		client, server := run(c.extensions, c.serverTakeover, c.clientTakeover)
		if strings.Join(client, "\n") != strings.Join(msgs, "\n") || strings.Join(server, "\n") != strings.Join(msgs, "\n") {
			t.Errorf("%s:\nclient %.80q\nserver %.80q", c.extensions, client, server)
		}
	}

	// A sender that keeps its context, where the handshake said it wouldn't,
	// can't be followed: it refers back to the first message.
	_, server := run("permessage-deflate; server_no_context_takeover", true, true)
	if server[0] != msgs[0] || !strings.HasPrefix(server[1], "error: can't decompress: flate: corrupt input") {
		t.Errorf("takeover where none was negotiated: %.80q", server)
	}
}

// outcome returns what the message that the frames end decompressed to, or
// the error.
func outcome(frames [][]wsFrame, errs []string) string {
	for i, fs := range frames {
		if errs[i] != "" {
			return "error: " + errs[i]
		}
		for _, f := range fs {
			if f.endsMessage() {
				if f.Body.Err != "" {
					return "error: " + f.Body.Err
				}
				return string(f.Body.Decoded)
			}
		}
	}
	return "no message"
}

// Bytes that weren't captured are skipped inside a frame's payload, but a
// compressed message with some missing can't be decompressed, nor, with
// context takeover, a later one that refers back to it.
func TestWebSocketMissingBytes(t *testing.T) {
	d := newDecoders(Options{})
	wsDecode(t, d, wsHandshake("permessage-deflate")...)

	text := strings.Repeat("x", 3000)
	ev := wsEvent(tracer.FuncSSLRead, cat(wsFrameBytes(wsText, true, false, nil, []byte(text)), wsFrameBytes(wsText, true, false, nil, []byte("next"))))
	ev.Data = ev.Data[:1000] // the rest wasn't captured: the end of the first frame, and the second
	_, errs := wsDecode(t, d, ev)
	if !strings.Contains(errs[0], "bytes after a frame weren't captured") {
		t.Errorf("framing lost: %q", errs[0])
	}
	// The direction is shown as sent from then on.
	dc := d.decode(wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, false, nil, []byte("later"))))
	if len(dc.http1) != 1 || dc.http1[0].ws != nil || string(dc.http1[0].raw) != "\x81\x05later" {
		t.Errorf("after the framing was lost: %+v", dc.http1)
	}

	// The client's direction is still followed.
	z := &deflater{takeover: true}
	first := z.message(t, "the same words again and again")
	second := z.message(t, "the same words again and again")
	ev = wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsText, true, true, wsKey, first))
	ev.Data = ev.Data[:len(ev.Data)-2]
	frames, errs := wsDecode(t, d, ev,
		wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsText, true, false, wsKey, []byte(text))),
		wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsText, true, true, wsKey, second)))
	if errs[0] != "" || frames[0][0].Body.Err != "bytes of the message weren't captured (raise --max-size)" {
		t.Errorf("compressed message with missing bytes: %+v %q", frames[0], errs[0])
	}
	if got := messages(frames[1:2]); len(got) != 1 || got[0] != "text: "+text {
		t.Errorf("after the missing bytes: %q", got)
	}
	if got := frames[2][0].Body.Err; got != "it refers back to an earlier message that couldn't be decompressed" {
		t.Errorf("message referring back: %q", got)
	}
}

func TestWebSocketInvalidFrames(t *testing.T) {
	for name, data := range map[string][]byte{
		"reserved opcode":      {0x83, 0x00},
		"long control frame":   cat([]byte{0x89, 0x7e, 0x00, 0x7e}, make([]byte, 126)),
		"fragmented ping":      {0x09, 0x00},
		"RSV1 without deflate": {0xc1, 0x00},
		"lone continuation":    {0x80, 0x00},
		"64-bit length's MSB":  {0x82, 0x7f, 0x80, 0, 0, 0, 0, 0, 0, 0},
	} {
		d := newDecoders(Options{})
		wsDecode(t, d, wsHandshake("")...)
		dc := d.decode(wsEvent(tracer.FuncSSLRead, cat([]byte{0x81, 0x02, 'o', 'k'}, data)))
		if len(dc.http1) != 2 || len(dc.http1[0].ws.Frames) != 1 || !strings.Contains(dc.http1[0].ws.Err, "invalid frame header") ||
			!bytes.Equal(dc.http1[1].raw, data) {
			t.Errorf("%s: %+v", name, dc.http1)
		}
	}
	// A message that starts before the last one ended.
	d := newDecoders(Options{})
	wsDecode(t, d, wsHandshake("")...)
	_, errs := wsDecode(t, d, wsEvent(tracer.FuncSSLRead, []byte{0x01, 0x01, 'a', 0x81, 0x01, 'b'}))
	if !strings.Contains(errs[0], "a new message before the last one ended") {
		t.Errorf("interleaved messages: %q", errs[0])
	}
}

// A connection that switched to WebSocket is still decoded as WebSocket
// when a call looks like it starts with HTTP/2 frames, which would have the
// HTTP/2 decoder take it for a connection that started before snoopy; and
// a new HTTP/1.x connection on the same handle is HTTP again.
func TestWebSocketNotHTTP2(t *testing.T) {
	d := newDecoders(Options{})
	wsDecode(t, d, wsHandshake("")...)
	frame := wsFrameBytes(wsBinary, true, false, nil, []byte{0x20, 0, 0, 0, 0, 0, 1})
	if !http2Aligned(frame) {
		t.Fatalf("%x doesn't look like HTTP/2", frame)
	}
	frames, errs := wsDecode(t, d, wsEvent(tracer.FuncSSLRead, frame))
	if errs[0] != "" || len(frames[0]) != 1 || frames[0][0].Length != 7 {
		t.Errorf("frame taken for HTTP/2: %+v", frames)
	}
	dc := d.decode(event(tracer.FuncSSLWrite, "GET /again HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if len(dc.http1) != 1 || dc.http1[0].msg == nil || dc.http1[0].msg.startLine != "GET /again HTTP/1.1" {
		t.Errorf("new connection on the handle: %+v", dc.http1)
	}
	// Without a 101, or with one to another protocol, frames aren't decoded.
	for _, resp := range []string{"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"} {
		d := newDecoders(Options{})
		d.decode(wsHandshake("")[0])
		d.decode(event(tracer.FuncSSLRead, resp))
		if frames, _ := wsDecode(t, d, wsEvent(tracer.FuncSSLRead, []byte{0x81, 0x01, 'x'})); len(frames[0]) != 0 {
			t.Errorf("after %q: %+v", resp, frames)
		}
	}
}

// textOf prints events with Text and returns what it printed for each.
func textOf(t *testing.T, opts Options, evs ...*tracer.Event) (out []string, hidden int) {
	t.Helper()
	var buf bytes.Buffer
	p := NewText(&buf, opts)
	for _, ev := range evs {
		buf.Reset()
		if err := p.Print(ev); err != nil {
			t.Fatal(err)
		}
		_, payload, _ := strings.Cut(buf.String(), "\n") // the call's line
		out = append(out, payload)
	}
	return out, p.Hidden()
}

func TestTextWebSocket(t *testing.T) {
	hs := wsHandshake("permessage-deflate")
	hs[1].Data = append(hs[1].Data, 0x81, 0x02, 'h', 'i') // a first message with the response
	hs[1].Size = uint32(len(hs[1].Data))
	z := &deflater{}
	long := strings.Repeat("0123456789", 300)
	evs := append(hs,
		wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsText, true, true, wsKey, z.message(t, `{"op":"hello"}`))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsPing, true, false, nil, []byte("hb"))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, false, nil, []byte(long))[:2500]),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, false, nil, []byte(long))[2500:]),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsBinary, true, false, nil, []byte{0, 1, 2, 3, 0xff})),
		wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsClose, true, false, wsKey, append([]byte{0x03, 0xe9}, "leaving"...))),
	)
	got, hidden := textOf(t, Options{}, evs...)
	want := []string{
		"", // the request
		"HTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\n" +
			"Sec-WebSocket-Extensions: permessage-deflate\n\nWebSocket text length=2 [FIN]\nhi\n\n",
		"WebSocket text length=16 [FIN,compressed]\n[permessage-deflate: 16 bytes decoded to 14]\n{\"op\":\"hello\"}\n\n",
		"", // the ping, hidden
		"WebSocket text length=3000 [FIN]\n" + long[:2048] + "\n[… 448 more bytes; --full shows all]\n\n",
		"WebSocket text length=3000 (continued) [FIN]\n[504 more bytes of text]\n\n",
		"WebSocket binary length=5 [FIN]\n[5 bytes of binary data]\n\n",
		"WebSocket close 1001 (going away): leaving\n\n",
	}
	if hidden != 1 {
		t.Errorf("%d calls hidden, want the ping's", hidden)
	}
	for i := range want {
		if i == 0 || i == 3 {
			continue
		}
		if got[i] != want[i] {
			t.Errorf("call %d:\ngot  %q\nwant %q", i, got[i], want[i])
		}
	}

	got, _ = textOf(t, Options{Verbose: true, Full: true}, evs...)
	if got[3] != "WebSocket ping \"hb\"\n\n" {
		t.Errorf("ping with --verbose: %q", got[3])
	}
	if !strings.Contains(got[4], long[:2500-4]+"\n\n") || !strings.Contains(got[6], "00000000  00 01 02 03 ff") {
		t.Errorf("--full:\n%s%s", got[4], got[6])
	}

	// A message's frames in a call are shown as one; a ping between them,
	// with --verbose, splits them.
	fragments := cat(wsFrameBytes(wsText, false, false, nil, []byte("hel")), wsFrameBytes(wsPing, true, false, nil, nil),
		wsFrameBytes(wsContinuation, false, false, nil, []byte("lo ")), wsFrameBytes(wsContinuation, true, false, nil, []byte("you")))
	evs = append(wsHandshake(""), wsEvent(tracer.FuncSSLRead, fragments))
	if got, _ := textOf(t, Options{}, evs...); got[2] != "WebSocket text length=9 in 3 frames [FIN]\nhello you\n\n" {
		t.Errorf("fragments: %q", got[2])
	}
	if got, _ := textOf(t, Options{Verbose: true}, evs...); got[2] != "WebSocket text length=3\nhel\nWebSocket ping\n"+
		"WebSocket text (continued) length=6 in 2 frames [FIN]\nlo you\n\n" {
		t.Errorf("fragments, --verbose: %q", got[2])
	}
	z = &deflater{}
	payload := z.message(t, "compressed in pieces")
	compressed := cat(wsFrameBytes(wsText, false, true, nil, payload[:4]), wsFrameBytes(wsContinuation, false, false, nil, payload[4:8]))
	evs = append(wsHandshake("permessage-deflate"), wsEvent(tracer.FuncSSLRead, compressed),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsContinuation, true, false, nil, payload[8:])))
	got, _ = textOf(t, Options{}, evs...)
	if got[2] != "WebSocket text length=8 in 2 frames [compressed]\n[8 bytes of a compressed message, decoded at its end]\n\n" ||
		got[3] != fmt.Sprintf("WebSocket continuation (text) length=%d [FIN,compressed]\n[permessage-deflate: %d bytes decoded to 20]\ncompressed in pieces\n\n", len(payload)-8, len(payload)) {
		t.Errorf("compressed fragments: %q", got[2:])
	}
	if lines := briefLines(t, evs...); !strings.HasSuffix(lines[2], "WebSocket text 8 bytes in 2 frames") ||
		!strings.HasSuffix(lines[3], fmt.Sprintf("WebSocket continuation (text) %d bytes (permessage-deflate, 20 decoded): compressed in pieces", len(payload)-8)) {
		t.Errorf("compressed fragments, --brief: %q", lines[2:])
	}

	// A frame header alone is hidden; --verbose says what it is.
	frame := wsFrameBytes(wsText, true, false, nil, []byte("split"))
	got, hidden = textOf(t, Options{}, append(wsHandshake(""), wsEvent(tracer.FuncSSLRead, frame[:1]),
		wsEvent(tracer.FuncSSLRead, frame[1:2]), wsEvent(tracer.FuncSSLRead, frame[2:]))...)
	if hidden != 2 || got[4] != "WebSocket text length=5 (continued) [FIN]\nsplit\n\n" {
		t.Errorf("split header: %d hidden, %q", hidden, got[4])
	}
	got, _ = textOf(t, Options{Verbose: true}, append(wsHandshake(""), wsEvent(tracer.FuncSSLRead, frame[:1]),
		wsEvent(tracer.FuncSSLRead, frame[1:2]))...)
	if got[2] != "WebSocket: 1 bytes of a frame header that continues in a later call\n\n" ||
		got[3] != "WebSocket text length=5 [FIN]\n\n" {
		t.Errorf("split header, --verbose: %q", got[2:])
	}
}

func TestBriefWebSocket(t *testing.T) {
	z := &deflater{}
	big := bytes.Repeat([]byte{1, 2, 3}, 4000)
	frame := wsFrameBytes(wsBinary, true, false, nil, big)
	evs := append(wsHandshake("permessage-deflate"),
		wsEvent(tracer.FuncSSLWrite, cat(wsFrameBytes(wsText, true, false, wsKey, []byte("hello\nworld")),
			wsFrameBytes(wsPing, true, false, wsKey, nil))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, true, nil, z.message(t, "compressed"))),
		wsEvent(tracer.FuncSSLRead, frame[:4000]),
		wsEvent(tracer.FuncSSLRead, frame[4000:8000]),
		wsEvent(tracer.FuncSSLRead, frame[8000:]),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsClose, true, false, nil, []byte{0x03, 0xe8})),
	)
	lines := briefLines(t, evs...)
	for i, want := range []string{
		"TLS 224: GET /chat HTTP/1.1, host example.com",
		"TLS 175: HTTP/1.1 101 Switching Protocols",
		"TLS 23: WebSocket text 11 bytes: hello",
		"TLS 14: WebSocket text 12 bytes (permessage-deflate, 10 decoded): compressed",
		"TLS 4000: WebSocket binary 3996 bytes",
		"TLS 4004: WebSocket binary (continued) 4004 bytes [+1 call folded, 4000 bytes]",
		"TLS 4: WebSocket close 1000 (normal closure)",
	} {
		if i >= len(lines) || !strings.HasSuffix(lines[i], want) {
			t.Errorf("line %d: got %q, want …%q", i, lines[min(i, len(lines)-1)], want)
		}
	}
}

func TestJSONWebSocket(t *testing.T) {
	z := &deflater{}
	evs := append(wsHandshake("permessage-deflate"),
		wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsText, true, false, wsKey, []byte(`{"password":"hunter2"}`))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, true, nil, z.message(t, `{"token":"abc"}`))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsBinary, false, false, nil, []byte{0xff, 0})),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsContinuation, true, false, nil, []byte{1})),
		wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsClose, true, false, wsKey, append([]byte{0x03, 0xe8}, "bye"...))),
	)
	frames := func(opts Options) []string {
		var buf bytes.Buffer
		j := NewJSON(&buf, opts)
		for _, ev := range evs {
			j.Print(ev)
		}
		var out []string
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			var ev struct {
				WebSocket json.RawMessage `json:"websocket"`
				HTTP1     []jsonHTTP1     `json:"http1"`
			}
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatal(err)
			}
			if ev.WebSocket != nil {
				out = append(out, string(ev.WebSocket))
			} else if len(ev.HTTP1) > 0 {
				out = append(out, fmt.Sprintf("%s end=%v", ev.HTTP1[0].Type, ev.HTTP1[0].End))
			}
		}
		return out
	}
	want := []string{
		"request end=true",
		"response end=true",
		`[{"opcode":"text","fin":true,"masked":true,"length":22,"data_bytes":22,"payload":"{\"password\":\"hunter2\"}","end":true}]`,
		`[{"opcode":"text","fin":true,"compressed":true,"length":17,"data_bytes":17,"end":true,"body":{"content_encoding":"permessage-deflate","decoded":"{\"token\":\"abc\"}"}}]`,
		`[{"opcode":"binary","length":2,"data_bytes":2,"payload_base64":"/wA="}]`,
		`[{"opcode":"continuation","message":"binary","fin":true,"length":1,"data_bytes":1,"payload":"\u0001","end":true}]`,
		`[{"opcode":"close","fin":true,"masked":true,"length":5,"data_bytes":5,"close_code":1000,"close_reason":"bye","end":true}]`,
	}
	if got := frames(Options{}); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	got := strings.Join(frames(Options{Redact: true}), "\n")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "abc") || strings.Contains(got, "payload_base64") ||
		!strings.Contains(got, `"payload":"{\"password\":\"[redacted]\"}"`) || !strings.Contains(got, `"decoded":"{\"token\":\"[redacted]\"}"`) {
		t.Errorf("--redact:\n%s", got)
	}
}

// The upgrade request is an exchange of its own, which ends with its 101
// response; what follows on the connection isn't one, and isn't a response
// streaming either, however long it goes on.
func TestRequestsWebSocket(t *testing.T) {
	evs := append(wsHandshake(""),
		wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsText, true, false, wsKey, []byte("GET / HTTP/1.1"))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, false, nil, []byte("HTTP/1.1 200 OK\r\n\r\n"))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, false, nil, []byte("later"))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsBinary, true, false, nil, make([]byte, 5000))),
	)
	for i, ev := range evs[2:] {
		ev.Time = ev.Time.Add(time.Duration(i+1) * 2 * streamingAfter)
	}
	after := requestLines(t, Options{}, evs...)
	want := "03:04:05.000006 curl[42] GET https://example.com/chat HTTP/1.1 → 101, websocket, 1ms\n"
	if after[1] != want || after[len(after)-1] != want {
		t.Errorf("got %q\nwant %q", after[1:], want)
	}
}

// --method, --path and --status keep a WebSocket connection's frames with
// the upgrade request they follow; --grep finds what's in them, decompressed
// too.
func TestFilterAndGrepWebSocket(t *testing.T) {
	z := &deflater{}
	evs := append(wsHandshake("permessage-deflate"),
		wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsText, true, false, wsKey, []byte("plain words"))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, true, nil, z.message(t, "squeezed words"))),
	)
	count := func(opts Options) int {
		var buf bytes.Buffer
		p := NewBrief(&buf, opts)
		for _, ev := range evs {
			e := *ev
			p.Print(&e)
		}
		return strings.Count(buf.String(), "\n")
	}
	for _, c := range []struct {
		opts Options
		want int
	}{
		{Options{Filter: &HTTPFilter{Paths: []string{"/chat"}}}, 4},
		{Options{Filter: &HTTPFilter{Paths: []string{"/other"}}}, 0},
		{Options{Filter: &HTTPFilter{Status: []StatusRange{{101, 101}}}}, 3},
		{Options{Grep: regexp.MustCompile("plain")}, 1},
		{Options{Grep: regexp.MustCompile("squeezed")}, 1},
	} {
		if got := count(c.opts); got != c.want {
			t.Errorf("%+v: %d lines, want %d", c.opts, got, c.want)
		}
	}
}

// A secret split between two frames of a message is masked in the second.
func TestRedactWebSocketSplit(t *testing.T) {
	evs := append(wsHandshake(""),
		wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsText, false, false, wsKey, []byte(`{"user":"a","passw`))),
		wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsContinuation, true, false, wsKey, []byte(`ord":"hunter2"}`))),
	)
	got, _ := textOf(t, Options{Redact: true}, evs...)
	if strings.Contains(got[3], "hunter2") || !strings.Contains(got[3], `ord":"[redacted]"}`) {
		t.Errorf("got %q", got[3])
	}
}

// A switch to WebSocket isn't an event stream, whatever its headers say,
// and an event stream isn't WebSocket, whatever its headers say.
func TestWebSocketNotSSE(t *testing.T) {
	d := newDecoders(Options{})
	d.decode(wsHandshake("")[0])
	d.decode(event(tracer.FuncSSLRead, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nContent-Type: text/event-stream\r\n\r\n"))
	dc := d.decode(wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, false, nil, []byte("data: x\n\n"))))
	if len(dc.http1) != 1 || dc.http1[0].ws == nil || dc.http1[0].isSSE || len(dc.http1[0].ws.Frames) != 1 {
		t.Errorf("101 with an event stream's type: %+v", dc.http1)
	}

	d = newDecoders(Options{})
	d.decode(wsHandshake("")[0])
	d.decode(event(tracer.FuncSSLRead, "HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nContent-Type: text/event-stream\r\n\r\n"))
	dc = d.decode(event(tracer.FuncSSLRead, "data: \x81\x01x\n\n"))
	if len(dc.http1) != 1 || dc.http1[0].ws != nil || !dc.http1[0].isSSE || len(dc.http1[0].sse) != 1 {
		t.Errorf("event stream with an Upgrade header: %+v", dc.http1)
	}
}
