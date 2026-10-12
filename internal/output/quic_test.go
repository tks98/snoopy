package output

import (
	"strings"
	"testing"

	"github.com/tks98/snoopy/internal/tracer"
)

// quicVar encodes a QUIC variable-length integer.
func quicVar(v uint64) []byte {
	switch {
	case v < 1<<6:
		return []byte{byte(v)}
	case v < 1<<14:
		return []byte{0x40 | byte(v>>8), byte(v)}
	default:
		return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
}

// streamFrameBytes builds a STREAM frame with offset and length.
func streamFrameBytes(id, off uint64, data []byte, fin bool) []byte {
	typ := byte(0x0e)
	if fin {
		typ |= 0x01
	}
	b := []byte{typ}
	b = append(b, quicVar(id)...)
	b = append(b, quicVar(off)...)
	b = append(b, quicVar(uint64(len(data)))...)
	return append(b, data...)
}

// h3Frame builds an HTTP/3 frame.
func h3Frame(typ uint64, payload []byte) []byte {
	b := append(quicVar(typ), quicVar(uint64(len(payload)))...)
	return append(b, payload...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func quicEvent(fn tracer.Function, data []byte) *tracer.Event {
	return &tracer.Event{PID: 9, ConnID: 0xc0de, Function: fn, Size: uint32(len(data)), Data: data}
}

// http3Of collects the HTTP/3 items of a packet as text.
func http3Of(t *testing.T, c *quicConns, data []byte) []string {
	t.Helper()
	items, ok := c.process(quicEvent(tracer.FuncQUICSend, data))
	if !ok {
		t.Fatalf("not parsed as QUIC: % x", data)
	}
	var out []string
	for _, it := range items {
		switch {
		case it.Frame != "":
		case it.Err != "":
			out = append(out, it.HTTP3+" error: "+it.Err)
		case it.Headers != nil:
			var h []string
			for _, f := range it.Headers {
				h = append(h, f.Name+"="+f.Value)
			}
			out = append(out, it.HTTP3+" "+strings.Join(h, " "))
		default:
			out = append(out, it.HTTP3+" "+string(it.Data))
		}
	}
	return out
}

func TestHTTP3(t *testing.T) {
	c := newQUICConns()
	ack := []byte{0x02, 0x05, 0x00, 0x00, 0x00} // ACK largest=5, no extra ranges

	// Control stream (client unidirectional stream 2) with SETTINGS.
	settings := h3Frame(0x04, cat(quicVar(0x01), quicVar(4096), quicVar(0x07), quicVar(16)))
	got := http3Of(t, c, cat(ack, streamFrameBytes(2, 0, cat(quicVar(0x00), settings), false)))
	if strings.Join(got, "|") != "stream: control |SETTINGS QPACK_BLOCKED_STREAMS=16 QPACK_MAX_TABLE_CAPACITY=4096" {
		t.Errorf("control: %q", got)
	}

	// A request whose header block refers to dynamic table entries that the
	// encoder stream (unidirectional stream 6) delivers later, and out of
	// order: RFC 9204's example B.2.
	enc := unhex(t, "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468")
	encStream := cat(quicVar(0x02), enc)
	got = http3Of(t, c, streamFrameBytes(0, 0, h3Frame(0x01, unhex(t, "0381 10 11")), true))
	if strings.Join(got, "|") != "HEADERS error: waiting for QPACK encoder stream data" {
		t.Errorf("blocked: %q", got)
	}
	got = http3Of(t, c, streamFrameBytes(6, 10, encStream[10:], false)) // second half first
	if len(got) != 0 {
		t.Errorf("early encoder data: %q", got)
	}
	got = http3Of(t, c, cat(streamFrameBytes(6, 0, encStream[:10], false), []byte{0x00, 0x00, 0x00})) // and padding
	if strings.Join(got, "|") != "stream: QPACK encoder |HEADERS :authority=www.example.com :path=/sample/path" {
		t.Errorf("unblocked: %q", got)
	}
	// A retransmission changes nothing.
	if got = http3Of(t, c, streamFrameBytes(6, 0, encStream[:10], false)); len(got) != 0 {
		t.Errorf("retransmission: %q", got)
	}

	// A response body in two packets, the second of which also starts
	// the next request.
	body := h3Frame(0x00, []byte("hello, quic"))
	got = http3Of(t, c, streamFrameBytes(4, 0, body[:6], false))
	if strings.Join(got, "|") != "DATA hell" {
		t.Errorf("data: %q", got)
	}
	got = http3Of(t, c, cat(streamFrameBytes(4, 6, body[6:], true), streamFrameBytes(8, 0, h3Frame(0x01, unhex(t, "0000 510b 2f69 6e64 6578 2e68 746d 6c")), true)))
	if strings.Join(got, "|") != "DATA (continued) o, quic|HEADERS :path=/index.html" {
		t.Errorf("data continued: %q", got)
	}

	// Not QUIC frames.
	if _, ok := c.process(quicEvent(tracer.FuncQUICRecv, []byte{0x17, 0x03, 0x03})); ok {
		t.Error("parsed a TLS record as QUIC")
	}
}

func TestQUICFrameSummaries(t *testing.T) {
	pkt := cat([]byte{0x01}, []byte{0x02, 0x40, 0x64, 0x00, 0x01, 0x03, 0x02, 0x01}, // PING, ACK 100 with one range
		[]byte{0x06, 0x00, 0x03, 'a', 'b', 'c'}, // CRYPTO
		[]byte{0x1e}, []byte{0x00, 0x00})        // HANDSHAKE_DONE, PADDING×2
	frames, streams, err := parseQUICFrames(pkt)
	if err != nil || len(streams) != 0 {
		t.Fatal(err, streams)
	}
	if got := strings.Join(frames, ", "); got != "PING, ACK largest=100, CRYPTO off=0 len=3, HANDSHAKE_DONE, PADDING×2" {
		t.Errorf("got %s", got)
	}
}
