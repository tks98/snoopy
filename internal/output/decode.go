package output

import (
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/http2/hpack"

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
	// Redact masks what's likely secret: credentials in headers, secret
	// query parameters and JSON and form fields, and tokens of well-known
	// kinds (see redact.go). Binary data isn't shown in JSON then.
	Redact bool
	// Filter, if set, leaves out the HTTP exchanges that don't match it,
	// and everything that isn't HTTP.
	Filter *HTTPFilter
	// Warn, if set, is told about what the output can't show, such as
	// headers of connections that started before snoopy. It may be told the
	// same thing more than once.
	Warn func(msg string)
	// Proto, if set, decodes the gRPC messages of the methods it has with
	// their fields' names (--proto).
	Proto *ProtoSchemas
	// Grep, if set, leaves out the events in which it matches nothing of
	// what's shown: the data, decoded headers, decompressed bodies, gRPC
	// messages' fields; after Redact, so that it can't find what's masked.
	Grep *regexp.Regexp
	// Lost, if set, returns how many calls snoopy lost to a full ring
	// buffer (Tracer.LostEvents). A call lost whole leaves a gap in its
	// connection that the decoders can't see, so when one stops, it says
	// that lost calls may be why.
	Lost func() (uint64, error)
}

// startedEarly is what Warn is told when headers can't be decoded.
const startedEarly = "some HTTP/2 or HTTP/3 connections started before snoopy, so their headers can't be decoded; connections opened from now on can be (restarting a program opens new ones)"

// A Filterer is a Printer that leaves out the events Options.Filter doesn't
// match.
type Filterer interface {
	Printer
	// Filtered returns how many events were left out so far.
	Filtered() int
}

// A Hider is a Printer that leaves some events out.
type Hider interface {
	Printer
	// Hidden returns how many events were left out so far.
	Hidden() int
}

// decoders follow the protocols in events, whose messages are spread over
// many events, to find what each event carries.
type decoders struct {
	h1     *http1Conns
	h2     *http2Conns
	quic   *quicConns
	warn   func(string)
	redact bool
	filter *HTTPFilter
	ex     *exchangeTracker // with filter
	rs     *redactStreams   // with redact
	grep   *regexp.Regexp
	lost   *lostCheck
}

// lostCheck tells the decoders' messages whether calls were lost to a full
// ring buffer.
type lostCheck struct {
	count func() (uint64, error) // Options.Lost
	seen  bool                   // the count was above zero, and only goes up
}

// lostNote is what's added to a decoder's message about stopping when
// calls were lost.
const lostNote = "; snoopy lost calls to a full ring buffer, which may be why"

// note returns lostNote if calls were lost, or "". The count is read only
// when a decoder stops, which is rare, and not again once it's above zero.
func (l *lostCheck) note() string {
	if !l.seen && l.count != nil {
		n, err := l.count()
		l.seen = err == nil && n > 0
	}
	if l.seen {
		return lostNote
	}
	return ""
}

func newDecoders(opts Options) decoders {
	pool := newBodyPool()
	d := decoders{h1: newHTTP1Conns(pool), h2: newHTTP2Conns(pool, opts.Proto), quic: newQUICConns(pool), warn: opts.Warn,
		redact: opts.Redact, filter: opts.Filter, lost: &lostCheck{count: opts.Lost}}
	if opts.Filter != nil {
		d.ex = newExchangeTracker()
	}
	if opts.Redact {
		d.rs = newRedactStreams()
	}
	d.grep = opts.Grep
	return d
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
	data []byte // the event's data, to show as it is: redacted, with Options.Redact
	// With Options.Filter: whether the event is left out, and if it isn't,
	// which requests its responses answer, with a status filter.
	filteredOut bool
	answers     string
	notice      bool // a tracer.FuncQUICPacketSent, which isn't to be printed
	isQUIC      bool
	quicConn    quicKey    // the QUIC connection, for both directions
	notQUIC     bool       // a QUIC packet that doesn't parse as QUIC frames
	quic        []quicItem // a QUIC packet's frames and the HTTP/3 they complete
	quicEnded   []uint64   // the streams it finished (see quicConns.ended)
	isHTTP2     bool
	http2       []http2Frame
	note        string         // about the HTTP/2 connection
	http1       []http1Segment // nil if not HTTP/1
}

func (d decoders) decode(ev *tracer.Event) decoded {
	if ev.Function == tracer.FuncQUICPacketSent {
		d.quic.sent(ev)
		return decoded{notice: true}
	}
	var dc decoded
	if ev.Function.IsQUIC() {
		items, ok := d.quic.process(ev)
		dc = decoded{isQUIC: true, notQUIC: !ok, quic: items, quicConn: d.quic.last, quicEnded: d.quic.ended}
		for i, it := range dc.quic {
			if it.mayBeLoss() {
				dc.quic[i].Err += d.lost.note()
			}
		}
	} else {
		dc.http2, dc.isHTTP2, dc.note = d.h2.process(ev)
		if strings.HasPrefix(dc.note, http2Stopped) && !strings.Contains(dc.note, "ring buffer") {
			dc.note += d.lost.note()
		}
		if !dc.isHTTP2 {
			dc.http1 = d.h1.process(ev)
		}
	}
	if d.warn != nil && dc.startedEarly() {
		d.warn(startedEarly)
	}
	dc.data = ev.Data
	if d.filter != nil {
		dc.filteredOut, dc.answers = d.filter.filtered(d.ex, ev, dc, d.redact)
	}
	if d.redact {
		dc = dc.redact(d.rs, connKey(ev, dc), ev.Function.Direction())
	}
	if d.grep != nil && !dc.filteredOut && !dc.matches(d.grep) {
		dc.filteredOut = true
	}
	return dc
}

// matches reports whether re matches something of what an event shows.
func (dc decoded) matches(re *regexp.Regexp) bool {
	if re.Match(dc.data) {
		return true
	}
	headers := func(fields []hpack.HeaderField) bool {
		for _, f := range fields {
			if re.MatchString(f.Name + ": " + f.Value) {
				return true
			}
		}
		return false
	}
	for _, s := range dc.http1 {
		if re.Match(s.body.Decoded) || sseMatches(re, s.sse) {
			return true
		}
	}
	for _, f := range dc.http2 {
		if headers(f.Headers) || re.Match(f.Data) || re.Match(f.Body.Decoded) || sseMatches(re, f.SSE) {
			return true
		}
		for _, m := range f.GRPC {
			if slices.ContainsFunc(m.Fields, re.MatchString) {
				return true
			}
		}
	}
	for _, it := range dc.quic {
		if headers(it.Headers) || re.Match(it.Data) || re.Match(it.Body.Decoded) || sseMatches(re, it.SSE) {
			return true
		}
	}
	return false
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
	case len(dc.http1) > 0: // only an event stream's keep-alives
		return !slices.ContainsFunc(dc.http1, func(s http1Segment) bool { return !sseKeepAlive(s.isSSE, s.sse, s.body) })
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
		return len(f.Data) == 0 && len(f.Body.Decoded) == 0 && f.Body.Err == "" && sseEvents(f.SSE) == 0 ||
			sseKeepAlive(f.IsSSE, f.SSE, f.Body)
	}
	return false
}

// mayBeLoss reports whether an item's error is one that a QUIC packet lost
// to a full ring buffer can cause: a gap in a stream, or QPACK's table out
// of step with the encoder's.
func (it quicItem) mayBeLoss() bool {
	return strings.HasPrefix(it.Err, "qpack: ") || it.Err == quicWaitingQPACK || it.Err == quicOutOfOrder
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
		return len(it.Data) == 0 && len(it.Body.Decoded) == 0 && it.Body.Err == "" && sseEvents(it.SSE) == 0 ||
			sseKeepAlive(it.IsSSE, it.SSE, it.Body)
	}
	return false
}
