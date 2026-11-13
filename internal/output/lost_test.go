package output

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// Bytes a call is missing are put down to what left them out.
func TestMissingWhy(t *testing.T) {
	for _, tc := range []struct {
		ev   tracer.Event
		want string
	}{
		{tracer.Event{Size: 10, Data: []byte("x")}, "raise --max-size"},
		{tracer.Event{Size: 10, Data: []byte("x"), Incomplete: true}, "the ring buffer was full; see --buffer-size"},
		{tracer.Event{Size: 10, ReadError: true}, "they couldn't be read from the process's memory"},
	} {
		if got := missingWhy(&tc.ev); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.ev, got, tc.want)
		}
	}
}

// A call lost whole leaves a gap the HTTP/2 decoder runs into later: when
// calls were lost, its message says that may be why. A call lost in part
// says so itself.
func TestHTTP2LostCall(t *testing.T) {
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: server.block(":status", "200"), EndHeaders: true})
	headersEnd := server.buf.Len()
	server.fr.WriteData(1, true, bytes.Repeat([]byte("x"), 50))
	b := server.buf.Bytes()
	call := func(data []byte, size int) *tracer.Event {
		return &tracer.Event{PID: 7, ConnID: 0x1000, Function: tracer.FuncSSLRead, Size: uint32(size), Data: data}
	}

	for _, lost := range []uint64{0, 3} {
		reads := 0
		d := newDecoders(Options{Lost: func() (uint64, error) { reads++; return lost, nil }})
		d.h2.start(http2Key{7, 0x1000}, false) // as if the client's preface was seen
		d.decode(call(b[:headersEnd], headersEnd))
		// The DATA frame's header and the first 10 bytes of its payload were
		// in a call that was lost; the rest of the payload is taken for a
		// frame header.
		dc := d.decode(call(b[headersEnd+19:], len(b)-headersEnd-19))
		want := http2Stopped + "invalid frame header 787878787878787878"
		if lost > 0 {
			want += lostNote
		}
		if dc.note != want {
			t.Errorf("%d lost: note %q, want %q", lost, dc.note, want)
		}
		if reads != 1 {
			t.Errorf("%d lost: the count was read %d times", lost, reads)
		}
	}

	// Lost in part: the event says why, and the note isn't added again.
	d := newDecoders(Options{Lost: func() (uint64, error) { return 1, nil }})
	d.h2.start(http2Key{7, 0x1000}, false)
	ev := call(b[:5], len(b))
	ev.Incomplete = true
	want := http2Stopped + "bytes of a frame header weren't captured (the ring buffer was full; see --buffer-size)"
	if dc := d.decode(ev); dc.note != want {
		t.Errorf("incomplete: note %q, want %q", dc.note, want)
	}

	// Once seen above zero, the count isn't read again.
	reads := 0
	l := &lostCheck{count: func() (uint64, error) { reads++; return 1, nil }}
	for range 2 {
		if l.note() != lostNote {
			t.Error("no note")
		}
	}
	if reads != 1 {
		t.Errorf("read the count %d times", reads)
	}
	if (&lostCheck{}).note() != "" {
		t.Error("note without a count")
	}
}

// The QUIC errors that a lost packet can cause are those of a stream with a
// gap and of QPACK's table.
func TestQUICMayBeLoss(t *testing.T) {
	for err, want := range map[string]bool{
		"qpack: no dynamic table entry 3": true,
		quicWaitingQPACK:                  true,
		quicOutOfOrder:                    true,
		"headers not decoded: the connection probably started before snoopy": false,
		"given up: too many streams at once":                                 false,
		"":                                                                   false,
	} {
		if got := (quicItem{HTTP3: "HEADERS", Err: err}).mayBeLoss(); got != want {
			t.Errorf("%q: %v", err, got)
		}
	}
}
