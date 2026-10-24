package output

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tks98/snoopy/v2/internal/tracer"
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
	return http3OfEvent(t, c, quicEvent(tracer.FuncQUICSend, data))
}

func http3OfEvent(t *testing.T, c *quicConns, ev *tracer.Event) []string {
	t.Helper()
	items, ok := c.process(ev)
	if !ok {
		t.Fatalf("not parsed as QUIC: % x", ev.Data)
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
	c := newQUICConns(newBodyPool())
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
	frames, streams, _, err := parseQUICFrames(pkt)
	if err != nil || len(streams) != 0 {
		t.Fatal(err, streams)
	}
	if got := strings.Join(frames, ", "); got != "PING, ACK largest=100, CRYPTO off=0 len=3, HANDSHAKE_DONE, PADDING×2" {
		t.Errorf("got %s", got)
	}
}

// A connection's directions are followed by socket, across the encryption
// contexts each uses, and the QPACK table of one is bounded by the other's
// SETTINGS.
func TestQUICConnectionBySocket(t *testing.T) {
	c := newQUICConns(newBodyPool())
	local := netip.MustParseAddrPort("10.0.0.2:5000")
	ev := func(fn tracer.Function, ctx uint64, local netip.AddrPort, data []byte) *tracer.Event {
		e := quicEvent(fn, data)
		e.ConnID, e.FD, e.Local = ctx, 5, local
		return e
	}

	// The server's control stream: a table of at most 64 bytes, two entries.
	settings := cat(quicVar(0), h3Frame(0x04, cat(quicVar(0x01), quicVar(64))))
	http3OfEvent(t, c, ev(tracer.FuncQUICRecv, 0x1, local, streamFrameBytes(3, 0, settings, false)))

	// The client's encoder stream sets that capacity and inserts five
	// entries, each evicting the one before.
	enc := cat(quicVar(2), []byte{0x3f, 0x21})
	for i := range 5 {
		enc = append(enc, 0x41, 'a', 0x02, 'v', byte('0'+i))
	}
	http3OfEvent(t, c, ev(tracer.FuncQUICSend, 0xa, local, streamFrameBytes(2, 0, enc, false)))

	// After a key update, a request refers to the fifth entry: its Required
	// Insert Count of 5 is sent as 5 mod 4 + 1.
	request := streamFrameBytes(0, 0, h3Frame(0x01, []byte{0x02, 0x00, 0x80}), true)
	got := http3OfEvent(t, c, ev(tracer.FuncQUICSend, 0xb, local, request))
	if !slices.Equal(got, []string{"HEADERS a=v4"}) {
		t.Errorf("after a key update: %q", got)
	}

	// A header block whose insertions come after it in the same packet.
	got = http3OfEvent(t, c, ev(tracer.FuncQUICSend, 0xb, local, cat(
		streamFrameBytes(4, 0, h3Frame(0x01, []byte{0x03, 0x00, 0x80}), true),
		streamFrameBytes(2, uint64(len(enc)), []byte{0x41, 'b', 0x02, 'v', '5'}, false))))
	if !slices.Equal(got, []string{"HEADERS b=v5"}) {
		t.Errorf("insertion later in the packet: %q", got)
	}

	// The same fd on a new socket is a new connection.
	got = http3OfEvent(t, c, ev(tracer.FuncQUICSend, 0xc, netip.MustParseAddrPort("10.0.0.2:6000"), request))
	if !slices.Equal(got, []string{"HEADERS error: waiting for QPACK encoder stream data"}) {
		t.Errorf("new socket: %q", got)
	}
}

// A connection moving to a new socket keeps its streams; a closed one's
// keys being reused on a new socket don't.
func TestQUICMigration(t *testing.T) {
	c := newQUICConns(newBodyPool())
	now := time.Now()
	ev := func(fd int32, port uint16, ctx uint64, at time.Duration, data []byte) *tracer.Event {
		e := quicEvent(tracer.FuncQUICRecv, data)
		e.ConnID, e.FD, e.Time = ctx, fd, now.Add(at)
		e.Local = netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), port)
		return e
	}
	// A response's HEADERS frame, in two pieces.
	block := h3Frame(0x01, []byte{0x00, 0x00, 0xd9}) // :status 200, static entry 25
	first, rest := block[:2], block[2:]

	http3OfEvent(t, c, ev(5, 5000, 0xa, 0, streamFrameBytes(0, 0, first, false)))
	http3OfEvent(t, c, ev(7, 6000, 0xa, time.Second, []byte{0x1b, 1, 2, 3, 4, 5, 6, 7, 8})) // PATH_RESPONSE
	got := http3OfEvent(t, c, ev(7, 6000, 0xa, 2*time.Second, streamFrameBytes(0, uint64(len(first)), rest, true)))
	if !slices.Equal(got, []string{"HEADERS :status=200"}) {
		t.Errorf("after migrating: %q", got)
	}

	// The connection closes; a new one gets the same context on a new socket.
	http3OfEvent(t, c, ev(7, 6000, 0xa, 3*time.Second, []byte{0x1c, 0x00, 0x00, 0x00}))
	got = http3OfEvent(t, c, ev(9, 7000, 0xa, 4*time.Second, streamFrameBytes(0, 0, block, true)))
	if !slices.Equal(got, []string{"HEADERS :status=200"}) {
		t.Errorf("new connection reusing the context: %q", got)
	}
}

// A header block that refers to QPACK state from before snoopy started
// can't be decoded, and says why.
func TestHTTP3StartedBeforeSnoopy(t *testing.T) {
	c := newQUICConns(newBodyPool())
	request := streamFrameBytes(48, 0, h3Frame(0x01, []byte{0x05, 0x00, 0x80}), true)
	got := http3Of(t, c, request)
	if len(got) != 1 || !strings.Contains(got[0], "the connection probably started before snoopy") {
		t.Errorf("got %q", got)
	}
}

func TestTextQUIC(t *testing.T) {
	ack := []byte{0x02, 0x05, 0x00, 0x00, 0x00}
	block := append([]byte{0x00, 0x00, 0xd9}, literalField("content-type", "image/png")...) // :status 200
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x10")
	response := quicEvent(tracer.FuncQUICRecv, cat(ack, streamFrameBytes(0, 0, cat(h3Frame(0x01, block), h3Frame(0x00, png)), true)))
	for _, verbose := range []bool{false, true} {
		var out bytes.Buffer
		p := NewText(&out, Options{Verbose: verbose})
		for _, ev := range []*tracer.Event{quicEvent(tracer.FuncQUICSend, ack), response} {
			if err := p.Print(ev); err != nil {
				t.Fatal(err)
			}
		}
		text := out.String()
		if !strings.Contains(text, "content-type: image/png") || !strings.Contains(text, fmt.Sprintf("[%d bytes of image/png]", len(png))) {
			t.Errorf("verbose %v: no response:\n%s", verbose, text)
		}
		// The ACK-only packet, and the frames line, are only shown verbose.
		if n := strings.Count(text, "QUIC: ACK"); n != map[bool]int{false: 0, true: 2}[verbose] || p.Hidden() != map[bool]int{false: 1, true: 0}[verbose] {
			t.Errorf("verbose %v: %d frame lines, %d hidden:\n%s", verbose, n, p.Hidden(), text)
		}
	}
}

// Connections sharing a socket, as quinn's do, are told apart by their
// connection IDs, learned from their long headers and NEW_CONNECTION_ID
// frames, and their packets get the peer the connection's packets were sent
// to, which only the notices of packets sent say.
func TestQUICConnectionsOnOneSocket(t *testing.T) {
	c := newQUICConns(newBodyPool())
	servers := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:443"), netip.MustParseAddrPort("192.0.2.2:443")}
	id := func(conn, side byte) []byte { return bytes.Repeat([]byte{conn<<4 | side}, 8) }
	long := func(dcid, scid []byte) []byte {
		return cat([]byte{0xc3, 0, 0, 0, 1, byte(len(dcid))}, dcid, []byte{byte(len(scid))}, scid)
	}
	short := func(dcid []byte) []byte { return cat([]byte{0x41}, dcid, []byte{0x07}) }
	ev := func(fn tracer.Function, hdr []byte, remote netip.AddrPort, data []byte) *tracer.Event {
		e := quicEvent(fn, data)
		e.FD, e.QUICHeader, e.Remote = 5, hdr, remote
		return e
	}
	crypto := []byte{0x06, 0x00, 0x01, 0xff}               // CRYPTO off=0 len=1
	none := netip.AddrPortFrom(netip.IPv4Unspecified(), 0) // what a receive on such a socket has

	// Each connection's handshake: the client's Initial to an ID it made up,
	// and the server's reply from its own. The second connection's peer
	// is only known once its first 1-RTT packet is sent.
	for i := range byte(2) {
		initial := long(id(i, 0xe), id(i, 0xc))
		http3OfEvent(t, c, ev(tracer.FuncQUICSend, initial, none, crypto))
		if i == 0 {
			c.sent(ev(tracer.FuncQUICPacketSent, initial, servers[i], nil))
		}
		http3OfEvent(t, c, ev(tracer.FuncQUICRecv, long(id(i, 0xc), id(i, 0x5)), none, crypto))
	}
	c.sent(ev(tracer.FuncQUICPacketSent, short(id(1, 0x5)), servers[1], nil))
	// The first connection issues another ID of its own.
	issue := cat([]byte{0x18, 0x01, 0x00, 0x08}, id(0, 0xd), bytes.Repeat([]byte{0}, 16))
	sendIssue := ev(tracer.FuncQUICSend, short(id(0, 0x5)), none, issue)
	http3OfEvent(t, c, sendIssue)
	if sendIssue.Remote != servers[0] {
		t.Errorf("a send's peer: %s, want %s", sendIssue.Remote, servers[0])
	}

	// Both responses on stream 0, interleaved, the first one's last packet
	// sent to its new ID.
	bodies := [][]byte{h3Frame(0x00, []byte("hello, one")), h3Frame(0x00, []byte("hello, two"))}
	dcids := [][]byte{id(0, 0xd), id(1, 0xc)}
	want := []string{"DATA hell", "DATA hell", "DATA (continued) o, one", "DATA (continued) o, two"}
	var got []string
	for half := range 2 {
		for i := range 2 {
			b := bodies[i]
			part, off := b[:6], 0
			if half == 1 {
				part, off = b[6:], 6
			}
			e := ev(tracer.FuncQUICRecv, short(id(byte(i), 0xc)), none, streamFrameBytes(0, uint64(off), part, half == 1))
			if half == 1 {
				e.QUICHeader = short(dcids[i])
			}
			got = append(got, http3OfEvent(t, c, e)...)
			if e.Remote != servers[i] {
				t.Errorf("connection %d: peer %s, want %s", i, e.Remote, servers[i])
			}
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}

	// A packet whose ID isn't known is followed by its socket.
	e := ev(tracer.FuncQUICRecv, short(id(7, 0xc)), none, streamFrameBytes(0, 0, bodies[0], true))
	if got := http3OfEvent(t, c, e); !slices.Equal(got, []string{"DATA hello, one"}) || knownAddr(e.Remote) {
		t.Errorf("unknown connection: %q, peer %s", got, e.Remote)
	}
}

// Headers that can't be decoded, because their connection started before
// snoopy, are warned about.
func TestWarnStartedEarly(t *testing.T) {
	var warnings []string
	p := NewText(io.Discard, Options{Warn: func(msg string) { warnings = append(warnings, msg) }})
	ok := streamFrameBytes(0, 0, h3Frame(0x01, []byte{0x00, 0x00, 0xd1}), true) // :method GET, static
	if err := p.Print(quicEvent(tracer.FuncQUICSend, ok)); err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warned about a header block that decoded: %q", warnings)
	}
	// A later request, on a connection whose start wasn't seen, refers to
	// a dynamic table entry from before.
	p = NewText(io.Discard, Options{Warn: func(msg string) { warnings = append(warnings, msg) }})
	early := streamFrameBytes(48, 0, h3Frame(0x01, []byte{0x05, 0x00, 0x80}), true)
	if err := p.Print(quicEvent(tracer.FuncQUICSend, early)); err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "started before snoopy") {
		t.Errorf("warnings %q", warnings)
	}
}
