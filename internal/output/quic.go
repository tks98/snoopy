package output

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/internal/tracer"
)

// quicItem is something found in a QUIC packet: a frame, or an HTTP/3 frame
// completed by the packet's stream data.
type quicItem struct {
	// Frame summarizes a QUIC frame, e.g. "STREAM id=0 off=0 len=91 FIN".
	Frame string
	// HTTP/3, if Frame is empty.
	HTTP3   string // frame type, e.g. "HEADERS"
	Stream  uint64
	Headers []hpack.HeaderField
	Data    []byte   // DATA payload, or a summary's details
	Err     string   // why a HEADERS frame couldn't be decoded
	Body    bodyPart // what an encoded body's DATA decoded to
}

// quicConns follows the HTTP/3 traffic in QUIC packets. Packets are
// captured decrypted, one per event, and followed per direction of a
// connection, since each direction carries its own streams' data and its own
// QPACK encoder stream. A connection is its UDP socket: a direction uses
// several encryption contexts over its life (one per encryption level, and a
// new one at each key update), so the context identifies it only if the
// socket isn't known. A connection can also move to a new socket (QUIC
// connection migration), keeping its keys.
type quicConns struct {
	dirs   map[quicKey]*quicDir // several keys share one after a migration
	locals map[quicKey]netip.AddrPort
	clock  uint64
	pool   *bodyPool
}

type quicKey struct {
	pid  uint32
	fd   int32
	conn uint64 // the encryption context, if fd is -1
	send bool
}

type quicDir struct {
	streams  map[uint64]*quicStream
	qpack    qpackDecoder
	blocked  []blockedSection // HEADERS waiting for encoder stream data
	lastUsed uint64
	lastCtx  uint64    // the encryption context of the last packet
	lastTime time.Time // and when it was
	closed   bool      // a CONNECTION_CLOSE was seen
	// The QPACK_MAX_TABLE_CAPACITY this direction's sender advertised in its
	// SETTINGS, which bounds the other direction's dynamic table; -1 if not
	// seen.
	maxTableCapacity int64
	bodies           map[uint64]*bodyDecoder // by stream, for encoded bodies
	pool             *bodyPool
}

func newQUICDir(pool *bodyPool) *quicDir {
	return &quicDir{streams: map[uint64]*quicStream{}, maxTableCapacity: -1,
		bodies: map[uint64]*bodyDecoder{}, pool: pool}
}

func quicKeyOf(ev *tracer.Event) quicKey {
	send := ev.Function.Direction() == tracer.Write
	if ev.FD >= 0 {
		return quicKey{pid: ev.PID, fd: ev.FD, send: send}
	}
	return quicKey{pid: ev.PID, fd: -1, conn: ev.ConnID, send: send}
}

type blockedSection struct {
	stream uint64
	block  []byte
}

// quicStream reassembles one stream's bytes, which may arrive out of order
// and more than once, and parses HTTP/3 frames from them.
type quicStream struct {
	next     uint64            // offset of the next byte to deliver
	early    map[uint64][]byte // data that arrived ahead of next, by offset
	pending  int               // bytes in early
	buf      []byte            // delivered bytes not parsed yet
	uniType  int64             // a unidirectional stream's type once read; -1 before
	dataLeft uint64            // payload bytes still to come of the current DATA frame
	broken   bool
	finSeen  bool   // the stream's final size is known
	final    uint64 // and is this
	dataSeen bool   // a DATA frame was read
}

const (
	maxQUICDirs        = 4096
	maxQUICStreamEarly = 1 << 20 // out-of-order bytes kept per stream
	maxHTTP3Frame      = 1 << 20 // larger non-DATA frames are given up on
)

// migrationWindow is how recently a connection must have used a context for
// a new socket using it to be the connection moving there; a freed
// context's memory may be reused by a later connection.
const migrationWindow = 10 * time.Second

func newQUICConns(pool *bodyPool) *quicConns {
	return &quicConns{dirs: map[quicKey]*quicDir{}, locals: map[quicKey]netip.AddrPort{}, pool: pool}
}

// dir returns the state for an event's direction of its connection.
func (c *quicConns) dir(key quicKey, ev *tracer.Event) *quicDir {
	d := c.dirs[key]
	if l := c.locals[key]; d != nil && ev.Local.IsValid() && l.IsValid() && l != ev.Local {
		d = nil // a new socket with a closed one's fd: a new connection
	}
	if d == nil && key.fd >= 0 {
		// The first packet on this socket: an open connection moving here
		// still uses its keys.
		for k, o := range c.dirs {
			if k.pid == key.pid && k.send == key.send && k.fd >= 0 && k.fd != key.fd && !o.closed &&
				o.lastCtx == ev.ConnID && ev.Time.Sub(o.lastTime) < migrationWindow {
				d = o
				break
			}
		}
	}
	if d == nil {
		if len(c.dirs) >= maxQUICDirs {
			c.evict()
		}
		d = newQUICDir(c.pool)
	}
	c.dirs[key] = d
	if ev.Local.IsValid() {
		c.locals[key] = ev.Local
	}
	return d
}

// process returns what a QUIC packet event contains, or ok false if its data
// doesn't parse as QUIC frames.
func (c *quicConns) process(ev *tracer.Event) (items []quicItem, ok bool) {
	key := quicKeyOf(ev)
	d := c.dir(key, ev)
	c.clock++
	d.lastUsed, d.lastCtx, d.lastTime = c.clock, ev.ConnID, ev.Time
	// The other direction's SETTINGS bound this one's QPACK dynamic table.
	other := key
	other.send = !key.send
	o := c.dirs[other]
	if o != nil && (c.locals[other] != c.locals[key]) {
		o = nil // the other direction's state is from an earlier socket
	}
	if o != nil && o.maxTableCapacity >= 0 {
		d.qpack.maxEntries = int(o.maxTableCapacity / 32)
	}

	// A decrypted packet's frames end exactly where it does, unless the
	// capture was cut short; anything else isn't QUIC.
	frames, streamData, err := parseQUICFrames(ev.Data)
	if err != nil && !ev.Truncated() {
		return nil, false
	}
	for _, f := range frames {
		items = append(items, quicItem{Frame: f})
		if strings.HasPrefix(f, "CONNECTION_CLOSE") {
			d.closed = true
			if o != nil {
				o.closed = true
			}
		}
	}
	if err != nil {
		items = append(items, quicItem{Frame: "(" + err.Error() + ")"})
	}
	// A packet's frames arrive together, so a header block can use the
	// encoder stream instructions that come after it in the same packet:
	// deliver the unidirectional streams' data (control, QPACK) first.
	sort.SliceStable(streamData, func(i, j int) bool {
		return streamData[i].id&0x02 != 0 && streamData[j].id&0x02 == 0
	})
	for _, sd := range streamData {
		items = append(items, d.streamData(sd)...)
	}
	return items, true
}

func (c *quicConns) evict() {
	var oldest quicKey
	var oldestUse uint64 = 1<<64 - 1
	for k, d := range c.dirs {
		if d.lastUsed < oldestUse {
			oldest, oldestUse = k, d.lastUsed
		}
	}
	delete(c.dirs, oldest)
	delete(c.locals, oldest)
}

type streamFrame struct {
	id, offset uint64
	data       []byte
	fin        bool
}

// quicVarint decodes a QUIC variable-length integer (RFC 9000, section 16).
func quicVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3f)
	for _, x := range b[1:n] {
		v = v<<8 | uint64(x)
	}
	return v, n, true
}

var errQUICShort = errors.New("frame cut off")

// parseQUICFrames parses a decrypted packet's frames (RFC 9000, section 19)
// and returns a summary of each and the STREAM frames' data. Consecutive
// PADDING frames are summarized once.
func parseQUICFrames(b []byte) (summaries []string, streams []streamFrame, err error) {
	vars := func(n int) ([]uint64, bool) {
		out := make([]uint64, n)
		for i := range out {
			v, m, ok := quicVarint(b)
			if !ok {
				return nil, false
			}
			out[i], b = v, b[m:]
		}
		return out, true
	}
	bytesN := func(n uint64) ([]byte, bool) {
		if uint64(len(b)) < n {
			return nil, false
		}
		out := b[:n]
		b = b[n:]
		return out, true
	}
	for len(b) > 0 {
		typ, n, ok := quicVarint(b)
		if !ok {
			return summaries, streams, errQUICShort
		}
		b = b[n:]
		switch {
		case typ == 0x00: // PADDING
			count := 1
			for len(b) > 0 && b[0] == 0 {
				b, count = b[1:], count+1
			}
			summaries = append(summaries, fmt.Sprintf("PADDING×%d", count))
		case typ == 0x01:
			summaries = append(summaries, "PING")
		case typ == 0x02 || typ == 0x03: // ACK: largest, delay, range count, first range, ranges
			v, ok := vars(4)
			if !ok {
				return summaries, streams, errQUICShort
			}
			if _, ok := vars(2 * int(min(v[2], 1024))); !ok || v[2] > 1024 {
				return summaries, streams, errQUICShort
			}
			if typ == 0x03 {
				if _, ok := vars(3); !ok {
					return summaries, streams, errQUICShort
				}
			}
			summaries = append(summaries, fmt.Sprintf("ACK largest=%d", v[0]))
		case typ == 0x04: // RESET_STREAM
			v, ok := vars(3)
			if !ok {
				return summaries, streams, errQUICShort
			}
			summaries = append(summaries, fmt.Sprintf("RESET_STREAM id=%d error=%#x", v[0], v[1]))
		case typ == 0x05: // STOP_SENDING
			v, ok := vars(2)
			if !ok {
				return summaries, streams, errQUICShort
			}
			summaries = append(summaries, fmt.Sprintf("STOP_SENDING id=%d error=%#x", v[0], v[1]))
		case typ == 0x06: // CRYPTO
			v, ok := vars(2)
			if !ok {
				return summaries, streams, errQUICShort
			}
			if _, ok := bytesN(v[1]); !ok {
				return summaries, streams, errQUICShort
			}
			summaries = append(summaries, fmt.Sprintf("CRYPTO off=%d len=%d", v[0], v[1]))
		case typ == 0x07: // NEW_TOKEN
			v, ok := vars(1)
			if !ok {
				return summaries, streams, errQUICShort
			}
			if _, ok := bytesN(v[0]); !ok {
				return summaries, streams, errQUICShort
			}
			summaries = append(summaries, "NEW_TOKEN")
		case typ >= 0x08 && typ <= 0x0f: // STREAM: id, [offset], [length], data
			v, ok := vars(1)
			if !ok {
				return summaries, streams, errQUICShort
			}
			sf := streamFrame{id: v[0], fin: typ&0x01 != 0}
			if typ&0x04 != 0 {
				off, ok := vars(1)
				if !ok {
					return summaries, streams, errQUICShort
				}
				sf.offset = off[0]
			}
			if typ&0x02 != 0 {
				l, ok := vars(1)
				if !ok {
					return summaries, streams, errQUICShort
				}
				if sf.data, ok = bytesN(l[0]); !ok {
					return summaries, streams, errQUICShort
				}
			} else {
				sf.data, b = b, nil
			}
			s := fmt.Sprintf("STREAM id=%d off=%d len=%d", sf.id, sf.offset, len(sf.data))
			if sf.fin {
				s += " FIN"
			}
			summaries = append(summaries, s)
			streams = append(streams, sf)
		case typ >= 0x10 && typ <= 0x17: // flow control: MAX_DATA ... STREAMS_BLOCKED
			names := []string{"MAX_DATA", "MAX_STREAM_DATA", "MAX_STREAMS", "MAX_STREAMS", "DATA_BLOCKED",
				"STREAM_DATA_BLOCKED", "STREAMS_BLOCKED", "STREAMS_BLOCKED"}
			args := 1
			if typ == 0x11 || typ == 0x15 {
				args = 2
			}
			if _, ok := vars(args); !ok {
				return summaries, streams, errQUICShort
			}
			summaries = append(summaries, names[typ-0x10])
		case typ == 0x18: // NEW_CONNECTION_ID: seq, retire prior to, length, id, reset token
			if _, ok := vars(2); !ok || len(b) < 1 {
				return summaries, streams, errQUICShort
			}
			l := uint64(b[0])
			b = b[1:]
			if _, ok := bytesN(l + 16); !ok {
				return summaries, streams, errQUICShort
			}
			summaries = append(summaries, "NEW_CONNECTION_ID")
		case typ == 0x19: // RETIRE_CONNECTION_ID
			if _, ok := vars(1); !ok {
				return summaries, streams, errQUICShort
			}
			summaries = append(summaries, "RETIRE_CONNECTION_ID")
		case typ == 0x1a || typ == 0x1b: // PATH_CHALLENGE, PATH_RESPONSE
			if _, ok := bytesN(8); !ok {
				return summaries, streams, errQUICShort
			}
			summaries = append(summaries, map[uint64]string{0x1a: "PATH_CHALLENGE", 0x1b: "PATH_RESPONSE"}[typ])
		case typ == 0x1c || typ == 0x1d: // CONNECTION_CLOSE: error, [frame type], reason
			args := 2
			if typ == 0x1d {
				args = 1
			}
			v, ok := vars(args)
			if !ok {
				return summaries, streams, errQUICShort
			}
			l, ok := vars(1)
			if !ok {
				return summaries, streams, errQUICShort
			}
			reason, ok := bytesN(l[0])
			if !ok {
				return summaries, streams, errQUICShort
			}
			summaries = append(summaries, fmt.Sprintf("CONNECTION_CLOSE error=%#x %q", v[0], reason))
		case typ == 0x1e:
			summaries = append(summaries, "HANDSHAKE_DONE")
		case typ == 0x30 || typ == 0x31: // DATAGRAM
			if typ == 0x31 {
				l, ok := vars(1)
				if !ok {
					return summaries, streams, errQUICShort
				}
				if _, ok := bytesN(l[0]); !ok {
					return summaries, streams, errQUICShort
				}
			} else {
				b = nil
			}
			summaries = append(summaries, "DATAGRAM")
		case typ == 0xaf: // ACK_FREQUENCY (draft-ietf-quic-ack-frequency)
			if _, ok := vars(4); !ok {
				return summaries, streams, errQUICShort
			}
			summaries = append(summaries, "ACK_FREQUENCY")
		case typ == 0x1f: // IMMEDIATE_ACK (same draft)
			summaries = append(summaries, "IMMEDIATE_ACK")
		default:
			return summaries, streams, fmt.Errorf("unknown frame type %#x", typ)
		}
	}
	return summaries, streams, nil
}

// streamData delivers a STREAM frame's data and returns the HTTP/3 frames it
// completes.
func (d *quicDir) streamData(sf streamFrame) []quicItem {
	s := d.streams[sf.id]
	if s == nil {
		s = &quicStream{early: map[uint64][]byte{}, uniType: -1}
		d.streams[sf.id] = s
	}
	if s.broken {
		return nil
	}
	if sf.fin {
		s.finSeen, s.final = true, sf.offset+uint64(len(sf.data))
	}
	// Keep what's ahead, drop what's already delivered (retransmissions).
	data, off := sf.data, sf.offset
	if off < s.next {
		if off+uint64(len(data)) <= s.next {
			return nil
		}
		data, off = data[s.next-off:], s.next
	}
	if off > s.next {
		if _, dup := s.early[off]; !dup {
			s.early[off] = append([]byte(nil), data...)
			s.pending += len(data)
		}
		if s.pending > maxQUICStreamEarly {
			s.broken = true
			if dec := d.bodies[sf.id]; dec != nil {
				dec.fail(errors.New("too much of the stream arrived out of order"))
				delete(d.bodies, sf.id)
			}
			return []quicItem{{HTTP3: "(stream given up)", Stream: sf.id, Err: "too much data arrived out of order"}}
		}
		return nil
	}
	s.buf = append(s.buf, data...)
	s.next += uint64(len(data))
	for { // data that was waiting for this
		var next []byte
		var at uint64
		found := false
		for o, e := range s.early {
			if o <= s.next && o+uint64(len(e)) > s.next {
				next, at, found = e, o, true
				break
			}
		}
		for o, e := range s.early {
			if o+uint64(len(e)) <= s.next {
				delete(s.early, o)
				s.pending -= len(e)
			}
		}
		if !found {
			break
		}
		delete(s.early, at)
		s.pending -= len(next)
		next = next[s.next-at:]
		s.buf = append(s.buf, next...)
		s.next += uint64(len(next))
	}
	items := d.http3(sf.id, s)
	if dec := d.bodies[sf.id]; dec != nil && s.finSeen && s.next >= s.final {
		delete(d.bodies, sf.id)
		end := decodeBody(dec, nil, true)
		if len(end.Decoded) == 0 && end.Err == "" {
			return items
		}
		for i := len(items) - 1; i >= 0; i-- {
			if it := &items[i]; it.Stream == sf.id && it.Body.Encoding != "" {
				it.Body.Decoded = append(it.Body.Decoded, end.Decoded...)
				it.Body.Err = end.Err
				return items
			}
		}
		items = append(items, quicItem{HTTP3: "DATA (end)", Stream: sf.id, Body: end})
	}
	return items
}

// http3 parses the HTTP/3 frames in a stream's delivered bytes (RFC 9114).
// Bidirectional streams carry requests and responses; unidirectional ones
// start with their type: control, push, or QPACK's encoder and decoder
// streams.
func (d *quicDir) http3(id uint64, s *quicStream) []quicItem {
	var items []quicItem
	unidirectional := id&0x02 != 0
	if unidirectional && s.uniType < 0 {
		t, n, ok := quicVarint(s.buf)
		if !ok {
			return nil
		}
		s.uniType, s.buf = int64(t), s.buf[n:]
		name := map[int64]string{0: "control", 1: "push", 2: "QPACK encoder", 3: "QPACK decoder"}[s.uniType]
		if name == "" {
			name = fmt.Sprintf("type %#x", s.uniType)
		}
		items = append(items, quicItem{HTTP3: "stream: " + name, Stream: id})
	}
	if unidirectional {
		switch s.uniType {
		case 2: // QPACK encoder stream: instructions for our dynamic table
			if err := d.qpack.encoderStream(s.buf); err != nil {
				s.broken = true
				return append(items, quicItem{HTTP3: "QPACK encoder", Stream: id, Err: err.Error()})
			}
			s.buf = nil
			return append(items, d.retryBlocked()...)
		case 0: // control: frames, as below
		default: // the decoder stream (acknowledgments), push, unknown: skip
			s.buf = nil
			return items
		}
	}
	for len(s.buf) > 0 {
		if s.dataLeft > 0 { // more of a DATA frame
			n := min(s.dataLeft, uint64(len(s.buf)))
			items = append(items, quicItem{HTTP3: "DATA (continued)", Stream: id, Data: s.buf[:n],
				Body: decodeBody(d.bodies[id], s.buf[:n], false)})
			s.buf, s.dataLeft = s.buf[n:], s.dataLeft-n
			continue
		}
		typ, n, ok := quicVarint(s.buf)
		if !ok {
			break
		}
		length, m, ok := quicVarint(s.buf[n:])
		if !ok {
			break
		}
		header := n + m
		if typ == 0x00 { // DATA: show the payload as it arrives
			s.dataSeen = true
			avail := min(length, uint64(len(s.buf)-header))
			data := s.buf[header : header+int(avail)]
			items = append(items, quicItem{HTTP3: "DATA", Stream: id, Data: data, Body: decodeBody(d.bodies[id], data, false)})
			s.buf, s.dataLeft = s.buf[header+int(avail):], length-avail
			continue
		}
		if length > maxHTTP3Frame {
			s.broken = true
			return append(items, quicItem{HTTP3: fmt.Sprintf("frame type %#x", typ), Stream: id, Err: "too large to follow"})
		}
		if uint64(len(s.buf)-header) < length {
			break // wait for the rest
		}
		payload := s.buf[header : header+int(length)]
		s.buf = s.buf[header+int(length):]
		switch typ {
		case 0x01: // HEADERS
			items = append(items, d.headers(id, payload))
		case 0x04: // SETTINGS
			settings := http3Settings(payload)
			if v, ok := settings[0x01]; ok && s.uniType == 0 {
				d.maxTableCapacity = int64(min(v, 1<<40))
			}
			items = append(items, quicItem{HTTP3: "SETTINGS", Stream: id, Data: []byte(describeSettings(settings))})
		case 0x03, 0x05, 0x07, 0x0d:
			items = append(items, quicItem{HTTP3: map[uint64]string{3: "CANCEL_PUSH", 5: "PUSH_PROMISE", 7: "GOAWAY", 0x0d: "MAX_PUSH_ID"}[typ], Stream: id})
		default: // reserved (greasing) and unknown frames are ignored
		}
	}
	if len(s.buf) == 0 {
		s.buf = nil // let the array go
	}
	return items
}

func (d *quicDir) headers(id uint64, block []byte) quicItem {
	fields, err := d.qpack.fieldSection(block)
	if errors.Is(err, errBlocked) {
		d.blocked = append(d.blocked, blockedSection{id, append([]byte(nil), block...)})
		return quicItem{HTTP3: "HEADERS", Stream: id, Err: "waiting for QPACK encoder stream data"}
	}
	if err != nil {
		return quicItem{HTTP3: "HEADERS", Stream: id, Err: err.Error()}
	}
	item := quicItem{HTTP3: "HEADERS", Stream: id, Headers: fields}
	item.Body = d.startBody(id, fields)
	return item
}

// startBody starts decoding the body of a request or response whose
// headers give it a Content-Encoding. Headers after the body has started
// are trailers.
func (d *quicDir) startBody(id uint64, fields []hpack.HeaderField) bodyPart {
	// Header blocks waiting for QPACK data are decoded late; if the body
	// went by meanwhile, it's too late to decode it.
	if s := d.streams[id]; d.bodies[id] != nil || s != nil && s.dataSeen {
		return bodyPart{}
	}
	enc := contentEncoding(fields)
	if enc == "" {
		return bodyPart{}
	}
	dec := d.pool.start(enc)
	if dec == nil {
		return bodyPart{}
	}
	d.bodies[id] = dec
	if err := dec.failed(); err != nil {
		return bodyPart{Encoding: enc, Err: err.Error()}
	}
	return bodyPart{}
}

// retryBlocked decodes the header blocks that the encoder stream data just
// received unblocked.
func (d *quicDir) retryBlocked() []quicItem {
	var items []quicItem
	still := d.blocked[:0]
	for _, b := range d.blocked {
		fields, err := d.qpack.fieldSection(b.block)
		switch {
		case errors.Is(err, errBlocked):
			still = append(still, b)
		case err != nil:
			items = append(items, quicItem{HTTP3: "HEADERS", Stream: b.stream, Err: err.Error()})
		default:
			item := quicItem{HTTP3: "HEADERS", Stream: b.stream, Headers: fields}
			item.Body = d.startBody(b.stream, fields)
			items = append(items, item)
		}
	}
	d.blocked = still
	return items
}

// http3Settings parses a SETTINGS frame's payload.
func http3Settings(p []byte) map[uint64]uint64 {
	settings := map[uint64]uint64{}
	for len(p) > 0 {
		id, n, ok := quicVarint(p)
		if !ok {
			break
		}
		v, m, ok := quicVarint(p[n:])
		if !ok {
			break
		}
		p = p[n+m:]
		settings[id] = v
	}
	return settings
}

// describeSettings lists the settings it knows, leaving out reserved
// (greasing) and unknown ones.
func describeSettings(settings map[uint64]uint64) string {
	names := map[uint64]string{0x01: "QPACK_MAX_TABLE_CAPACITY", 0x06: "MAX_FIELD_SECTION_SIZE",
		0x07: "QPACK_BLOCKED_STREAMS", 0x08: "ENABLE_CONNECT_PROTOCOL", 0x33: "H3_DATAGRAM"}
	var out []string
	for id, v := range settings {
		if name, known := names[id]; known {
			out = append(out, fmt.Sprintf("%s=%d", name, v))
		}
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}
