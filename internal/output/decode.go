package output

import (
	"slices"
	"strings"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// Options sets what Text and Brief show.
type Options struct {
	// Hex prints payloads as whole hex dumps (Text only).
	Hex bool
	// Full prints whole bodies, and binary data as hex dumps, rather than
	// a body's first bytes and a line describing binary data (Text only).
	Full bool
	// Verbose also prints the calls and frames that only keep connections
	// going: HTTP/2 settings, flow control and pings, QUIC acknowledgments,
	// and the like.
	Verbose bool
	// Warn, if set, is told about what the output can't show, such as
	// headers of connections that started before snoopy. It may be told the
	// same thing more than once.
	Warn func(msg string)
}

// startedEarly is what Warn is told when headers can't be decoded.
const startedEarly = "some HTTP/2 or HTTP/3 connections started before snoopy, so their headers can't be decoded; connections opened from now on can be (restarting a program opens new ones)"

// A Hider is a Printer that leaves some events out.
type Hider interface {
	Printer
	// Hidden returns how many events were left out so far.
	Hidden() int
}

// decoders follow the protocols in events, whose messages are spread over
// many events, to find what each event carries.
type decoders struct {
	h1   *http1Conns
	h2   *http2Conns
	quic *quicConns
	warn func(string)
}

func newDecoders(warn func(string)) decoders {
	pool := newBodyPool()
	return decoders{h1: newHTTP1Conns(pool), h2: newHTTP2Conns(pool), quic: newQUICConns(pool), warn: warn}
}

// connOf returns the connection an event belongs to, for following its
// messages across calls. That's the TLS library's handle for it, except for
// TLS records captured where they're encrypted and decrypted: each direction
// has its own encryption context there, so both directions are tied
// together by their socket, when it's known.
func connOf(ev *tracer.Event) uint64 {
	if ev.Function.IsRecord() && ev.FD >= 0 {
		return 1<<63 | uint64(uint32(ev.FD))
	}
	return ev.ConnID
}

// decoded is what an event's data was found to hold.
type decoded struct {
	notice  bool // a tracer.FuncQUICPacketSent, which isn't to be printed
	isQUIC  bool
	notQUIC bool       // a QUIC packet that doesn't parse as QUIC frames
	quic    []quicItem // a QUIC packet's frames and the HTTP/3 they complete
	isHTTP2 bool
	http2   []http2Frame
	note    string         // about the HTTP/2 connection
	http1   []http1Segment // nil if not HTTP/1
}

func (d decoders) decode(ev *tracer.Event) decoded {
	if ev.Function == tracer.FuncQUICPacketSent {
		d.quic.sent(ev)
		return decoded{notice: true}
	}
	var dc decoded
	if ev.Function.IsQUIC() {
		items, ok := d.quic.process(ev)
		dc = decoded{isQUIC: true, notQUIC: !ok, quic: items}
	} else {
		dc.http2, dc.isHTTP2, dc.note = d.h2.process(ev)
		if !dc.isHTTP2 {
			dc.http1 = d.h1.process(ev)
		}
	}
	if d.warn != nil && dc.startedEarly() {
		d.warn(startedEarly)
	}
	return dc
}

// startedEarly reports whether the event's connection started before
// snoopy, so that its headers couldn't be decoded.
func (dc decoded) startedEarly() bool {
	if strings.Contains(dc.note, "started before snoopy") {
		return true
	}
	for _, f := range dc.http2 {
		if f.HeadersLost {
			return true
		}
	}
	for _, it := range dc.quic {
		if strings.Contains(it.Err, "started before snoopy") {
			return true
		}
	}
	return false
}

// housekeeping reports whether an event only carries what keeps its
// connection going, and nothing of the requests and responses on it.
func (dc decoded) housekeeping() bool {
	switch {
	case dc.note != "":
		return false
	case dc.isQUIC:
		return !dc.notQUIC && !slices.ContainsFunc(dc.quic, func(it quicItem) bool { return !it.housekeeping() })
	case dc.isHTTP2:
		return !slices.ContainsFunc(dc.http2, func(f http2Frame) bool { return !f.housekeeping() })
	}
	return false
}

// housekeeping reports whether a frame only keeps the connection going, or
// says nothing on its own: part of a header block, or a DATA frame's header
// without any of its payload.
func (f http2Frame) housekeeping() bool {
	switch f.Type {
	case "connection preface", "SETTINGS", "PING", "PRIORITY", "WINDOW_UPDATE":
		return true
	case "HEADERS", "PUSH_PROMISE", "CONTINUATION":
		return f.Headers == nil && !f.HeadersLost && f.Body.Encoding == ""
	case "DATA":
		return len(f.Data) == 0 && len(f.Body.Decoded) == 0 && f.Body.Err == ""
	}
	return false
}

// housekeeping reports whether an item only keeps the connection going: a
// QUIC frame, a stream announcing its type, SETTINGS, or a DATA frame's
// header without any of its payload.
func (it quicItem) housekeeping() bool {
	switch {
	case it.Frame != "":
		return true
	case it.Err != "":
		return false
	case strings.HasPrefix(it.HTTP3, "stream: "), it.HTTP3 == "SETTINGS", it.HTTP3 == "MAX_PUSH_ID":
		return true
	case strings.HasPrefix(it.HTTP3, "DATA"):
		return len(it.Data) == 0 && len(it.Body.Decoded) == 0 && it.Body.Err == ""
	}
	return false
}
