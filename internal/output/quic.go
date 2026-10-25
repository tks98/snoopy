package output

import (
	"cmp"
	"container/heap"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/v2/internal/tracer"
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
	// For DATA: the body's content type, if known, and how many of its
	// bytes came before these.
	ContentType string
	Offset      int64
}

// quicConns follows the HTTP/3 traffic in QUIC packets. Packets are
// captured decrypted, one per event, and followed per direction of a
// connection, since each direction carries its own streams' data and its own
// QPACK encoder stream. A connection is its UDP socket: a direction uses
// several encryption contexts over its life (one per encryption level, and a
// new one at each key update), so the context identifies it only if the
// socket isn't known. A connection can also move to a new socket (QUIC
// connection migration), keeping its keys. Connections sharing a socket are
// told apart by their connection IDs (see cidConns).
type quicConns struct {
	// last is the connection of the last packet processed, as both of its
	// directions know it (send unset).
	last   quicKey
	dirs   map[quicKey]*quicDir // several keys share one after a migration
	locals map[quicKey]netip.AddrPort
	cids   *cidConns
	clock  uint64
	pool   *bodyPool
}

type quicKey struct {
	pid  uint32
	fd   int32  // -1 if unknown, cidFD for a connection known by its IDs
	conn uint64 // the encryption context if fd is -1, the cidConn's id if cidFD
	send bool
}

const cidFD = -2

type quicDir struct {
	streams  map[uint64]*quicStream
	qpack    qpackDecoder
	blocked  []blockedSection // HEADERS waiting for encoder stream data
	lastUsed uint64
	lastCtx  uint64    // the encryption context of the last packet
	lastTime time.Time // and when it was
	closed   bool      // a CONNECTION_CLOSE was seen
	// The connection's start was seen: the first request's stream, or a
	// unidirectional stream's type, which comes at its start. Header blocks
	// can refer to QPACK encoder stream data sent at any time before them.
	startSeen bool
	// The QPACK_MAX_TABLE_CAPACITY this direction's sender advertised in its
	// SETTINGS, which bounds the other direction's dynamic table; -1 if not
	// seen.
	maxTableCapacity int64
	bodies           map[uint64]*bodyDecoder // by stream, for encoded bodies
	pool             *bodyPool
	done             doneStreams
	held             int    // bytes held for streams: their early and buf, with overhead
	blockedBytes     int    // in blocked
	clock            uint64 // for evicting the least recently used stream
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

// doneStreams remembers the streams done with, finished or given up, so
// that retransmitted data doesn't start them over. Each kind of stream (the
// low two bits of its ID) is opened in order, and streams mostly end in
// about the order they start, so that's mostly a count of each kind below
// which all are done.
type doneStreams struct {
	below [4]uint64           // stream numbers (ID >> 2) below these are done
	ids   map[uint64]struct{} // and these, above them
}

func (s *doneStreams) has(id uint64) bool {
	if id>>2 < s.below[id&3] {
		return true
	}
	_, ok := s.ids[id]
	return ok
}

func (s *doneStreams) add(id uint64) {
	k := id & 3
	if id>>2 < s.below[k] {
		return
	}
	if s.ids == nil {
		s.ids = map[uint64]struct{}{}
	}
	s.ids[id] = struct{}{}
	for {
		next := s.below[k]<<2 | k
		if _, ok := s.ids[next]; !ok {
			break
		}
		delete(s.ids, next)
		s.below[k]++
	}
	if len(s.ids) > maxQUICDone {
		// Streams whose end wasn't seen hold the counts back. Count every
		// stream up to the last one done as done: one not seen yet below
		// that is all but certain to have been missed.
		for id := range s.ids {
			s.below[id&3] = max(s.below[id&3], id>>2+1)
		}
		clear(s.ids)
	}
}

// offsetHeap is a min-heap of the offsets of a stream's early data.
type offsetHeap []uint64

func (h offsetHeap) Len() int           { return len(h) }
func (h offsetHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h offsetHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *offsetHeap) Push(x any)        { *h = append(*h, x.(uint64)) }
func (h *offsetHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
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
	earlyAt  offsetHeap        // early's offsets
	pending  int               // bytes in early, with earlyOverhead for each piece
	buf      []byte            // delivered bytes not parsed yet
	uniType  int64             // a unidirectional stream's type once read; -1 before
	dataLeft uint64            // payload bytes still to come of the current DATA frame
	broken   bool
	finSeen  bool   // the stream's final size is known
	final    uint64 // and is this
	dataSeen bool   // a DATA frame was read
	body     bodyInfo
	lastUsed uint64
}

// held returns the bytes held for the stream, counted against maxQUICDirHeld.
func (s *quicStream) held() int {
	return len(s.buf) + s.pending
}

const (
	maxQUICDirs        = 4096
	maxQUICStreamEarly = 1 << 20   // out-of-order bytes kept per stream
	maxHTTP3Frame      = 1 << 20   // larger non-DATA frames are given up on
	maxBlocked         = 64        // header blocks kept waiting for encoder stream data
	maxBlockedBytes    = 256 << 10 // and their bytes, per direction
	// Streams followed at once per direction. Peers allow about 100
	// requests at a time (MAX_STREAMS), and open a few unidirectional
	// streams.
	maxQUICStreams = 256
	// Bytes held per direction for its streams: out-of-order data and
	// frames not complete yet. Four streams' worth of maxQUICStreamEarly.
	maxQUICDirHeld = 4 << 20
	// Streams remembered as done past the counts in doneStreams; a few
	// bytes each.
	maxQUICDone = 4096
	// What each piece of out-of-order data counts for in pending, besides
	// its bytes, for the memory it takes to keep: else a peer could send
	// millions of 1-byte pieces.
	earlyOverhead = 64
)

// migrationWindow is how recently a connection must have used a context for
// a new socket using it to be the connection moving there; a freed
// context's memory may be reused by a later connection.
const migrationWindow = 10 * time.Second

func newQUICConns(pool *bodyPool) *quicConns {
	return &quicConns{dirs: map[quicKey]*quicDir{}, locals: map[quicKey]netip.AddrPort{}, cids: newCIDConns(), pool: pool}
}

// dir returns the state for an event's direction of its connection.
func (c *quicConns) dir(key quicKey, ev *tracer.Event) *quicDir {
	d := c.dirs[key]
	if key.fd == cidFD {
		if d == nil {
			if len(c.dirs) >= maxQUICDirs {
				c.evict()
			}
			d = newQUICDir(c.pool)
			c.dirs[key] = d
		}
		return d
	}
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
	cc := c.cids.of(ev)
	if cc != nil {
		key = quicKey{pid: ev.PID, fd: cidFD, conn: cc.id, send: key.send}
	}
	c.last = key
	c.last.send = false
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
		d.qpack.maxCapacity, d.qpack.maxKnown = o.maxTableCapacity, true
	}

	// A decrypted packet's frames end exactly where it does, unless the
	// capture was cut short, or a frame type is new (an extension snoopy
	// doesn't know yet), after which the rest can't be parsed: what came
	// before is kept, unless nothing did, which isn't QUIC.
	frames, streamData, issued, err := parseQUICFrames(ev.Data)
	var unknown unknownFrameError
	partial := errors.As(err, &unknown) && len(frames) > 0
	if err != nil && !ev.Truncated() && !partial {
		return nil, false
	}
	if cc != nil {
		c.cids.learn(ev, cc, issued)
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

// unknownFrameError is a frame type parseQUICFrames doesn't know, whose
// length it can't tell, so the rest of the packet can't be parsed.
type unknownFrameError uint64

func (e unknownFrameError) Error() string {
	return fmt.Sprintf("unknown frame type %#x; the rest of the packet isn't shown", uint64(e))
}

// parseQUICFrames parses a decrypted packet's frames (RFC 9000, section 19)
// and returns a summary of each, the STREAM frames' data and the connection
// IDs issued in NEW_CONNECTION_ID frames. Consecutive PADDING frames are
// summarized once.
func parseQUICFrames(b []byte) (summaries []string, streams []streamFrame, issued [][]byte, err error) {
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
			return summaries, streams, issued, errQUICShort
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
				return summaries, streams, issued, errQUICShort
			}
			if _, ok := vars(2 * int(min(v[2], 1024))); !ok || v[2] > 1024 {
				return summaries, streams, issued, errQUICShort
			}
			if typ == 0x03 {
				if _, ok := vars(3); !ok {
					return summaries, streams, issued, errQUICShort
				}
			}
			summaries = append(summaries, fmt.Sprintf("ACK largest=%d", v[0]))
		case typ == 0x04: // RESET_STREAM
			v, ok := vars(3)
			if !ok {
				return summaries, streams, issued, errQUICShort
			}
			summaries = append(summaries, fmt.Sprintf("RESET_STREAM id=%d error=%#x", v[0], v[1]))
		case typ == 0x05: // STOP_SENDING
			v, ok := vars(2)
			if !ok {
				return summaries, streams, issued, errQUICShort
			}
			summaries = append(summaries, fmt.Sprintf("STOP_SENDING id=%d error=%#x", v[0], v[1]))
		case typ == 0x06: // CRYPTO
			v, ok := vars(2)
			if !ok {
				return summaries, streams, issued, errQUICShort
			}
			if _, ok := bytesN(v[1]); !ok {
				return summaries, streams, issued, errQUICShort
			}
			summaries = append(summaries, fmt.Sprintf("CRYPTO off=%d len=%d", v[0], v[1]))
		case typ == 0x07: // NEW_TOKEN
			v, ok := vars(1)
			if !ok {
				return summaries, streams, issued, errQUICShort
			}
			if _, ok := bytesN(v[0]); !ok {
				return summaries, streams, issued, errQUICShort
			}
			summaries = append(summaries, "NEW_TOKEN")
		case typ >= 0x08 && typ <= 0x0f: // STREAM: id, [offset], [length], data
			v, ok := vars(1)
			if !ok {
				return summaries, streams, issued, errQUICShort
			}
			sf := streamFrame{id: v[0], fin: typ&0x01 != 0}
			if typ&0x04 != 0 {
				off, ok := vars(1)
				if !ok {
					return summaries, streams, issued, errQUICShort
				}
				sf.offset = off[0]
			}
			if typ&0x02 != 0 {
				l, ok := vars(1)
				if !ok {
					return summaries, streams, issued, errQUICShort
				}
				if sf.data, ok = bytesN(l[0]); !ok {
					return summaries, streams, issued, errQUICShort
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
				return summaries, streams, issued, errQUICShort
			}
			summaries = append(summaries, names[typ-0x10])
		case typ == 0x18: // NEW_CONNECTION_ID: seq, retire prior to, length, id, reset token
			if _, ok := vars(2); !ok || len(b) < 1 {
				return summaries, streams, issued, errQUICShort
			}
			l := uint64(b[0])
			b = b[1:]
			idAndToken, ok := bytesN(l + 16)
			if !ok {
				return summaries, streams, issued, errQUICShort
			}
			issued = append(issued, idAndToken[:l])
			summaries = append(summaries, "NEW_CONNECTION_ID")
		case typ == 0x19: // RETIRE_CONNECTION_ID
			if _, ok := vars(1); !ok {
				return summaries, streams, issued, errQUICShort
			}
			summaries = append(summaries, "RETIRE_CONNECTION_ID")
		case typ == 0x1a || typ == 0x1b: // PATH_CHALLENGE, PATH_RESPONSE
			if _, ok := bytesN(8); !ok {
				return summaries, streams, issued, errQUICShort
			}
			summaries = append(summaries, map[uint64]string{0x1a: "PATH_CHALLENGE", 0x1b: "PATH_RESPONSE"}[typ])
		case typ == 0x1c || typ == 0x1d: // CONNECTION_CLOSE: error, [frame type], reason
			args := 2
			if typ == 0x1d {
				args = 1
			}
			v, ok := vars(args)
			if !ok {
				return summaries, streams, issued, errQUICShort
			}
			l, ok := vars(1)
			if !ok {
				return summaries, streams, issued, errQUICShort
			}
			reason, ok := bytesN(l[0])
			if !ok {
				return summaries, streams, issued, errQUICShort
			}
			summaries = append(summaries, fmt.Sprintf("CONNECTION_CLOSE error=%#x %q", v[0], reason))
		case typ == 0x1e:
			summaries = append(summaries, "HANDSHAKE_DONE")
		case typ == 0x30 || typ == 0x31: // DATAGRAM
			if typ == 0x31 {
				l, ok := vars(1)
				if !ok {
					return summaries, streams, issued, errQUICShort
				}
				if _, ok := bytesN(l[0]); !ok {
					return summaries, streams, issued, errQUICShort
				}
			} else {
				b = nil
			}
			summaries = append(summaries, "DATAGRAM")
		case typ == 0xaf: // ACK_FREQUENCY (draft-ietf-quic-ack-frequency)
			if _, ok := vars(4); !ok {
				return summaries, streams, issued, errQUICShort
			}
			summaries = append(summaries, "ACK_FREQUENCY")
		case typ == 0x1f: // IMMEDIATE_ACK (same draft)
			summaries = append(summaries, "IMMEDIATE_ACK")
		default:
			return summaries, streams, issued, unknownFrameError(typ)
		}
	}
	return summaries, streams, issued, nil
}

// streamData delivers a STREAM frame's data and returns the HTTP/3 frames it
// completes.
func (d *quicDir) streamData(sf streamFrame) []quicItem {
	var items []quicItem
	s := d.streams[sf.id]
	if s == nil {
		if d.done.has(sf.id) {
			return nil // a retransmission, or the stream was given up
		}
		if len(d.streams) >= maxQUICStreams {
			items = d.evictStreams()
		}
		s = &quicStream{early: map[uint64][]byte{}, uniType: -1}
		d.streams[sf.id] = s
	}
	d.clock++
	s.lastUsed = d.clock
	before := s.held()
	items = append(items, d.deliver(sf, s)...)
	d.held += s.held() - before
	switch {
	case s.broken, s.finSeen && s.next >= s.final:
		d.forget(sf.id, s, errors.New("the stream was given up"))
	case d.held > maxQUICDirHeld:
		d.forget(sf.id, s, errors.New("too much data waiting across the connection's streams"))
		items = append(items, quicItem{HTTP3: "(stream given up)", Stream: sf.id,
			Err: "too much data waiting across the connection's streams"})
	}
	return items
}

// forget stops following a stream, which is done with: finished, or given
// up for err, which its body's decoder is told if it's still going.
func (d *quicDir) forget(id uint64, s *quicStream, err error) {
	if dec := d.bodies[id]; dec != nil {
		dec.fail(err)
		delete(d.bodies, id)
	}
	d.held -= s.held()
	delete(d.streams, id)
	d.done.add(id)
}

// evictStreams gives up on the least recently used eighth of the streams,
// to make room for more, except for the unidirectional streams opened
// first: the control and QPACK streams, which last as long as the
// connection.
func (d *quicDir) evictStreams() []quicItem {
	ids := make([]uint64, 0, len(d.streams))
	for id := range d.streams {
		if id&0x02 == 0 || id >= 16 {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(a, b uint64) int { return cmp.Compare(d.streams[a].lastUsed, d.streams[b].lastUsed) })
	var items []quicItem
	for _, id := range ids[:min(len(ids), max(maxQUICStreams/8, 1))] {
		d.forget(id, d.streams[id], errors.New("given up: too many streams at once"))
		items = append(items, quicItem{HTTP3: "(stream given up)", Stream: id, Err: "too many streams at once"})
	}
	return items
}

// deliver reassembles a STREAM frame's data and returns the HTTP/3 frames it
// completes.
func (d *quicDir) deliver(sf streamFrame, s *quicStream) []quicItem {
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
		if len(data) == 0 {
			return nil // nothing to keep: a FIN alone, noted above
		}
		if _, dup := s.early[off]; !dup {
			s.early[off] = append([]byte(nil), data...)
			heap.Push(&s.earlyAt, off)
			s.pending += len(data) + earlyOverhead
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
	for len(s.earlyAt) > 0 && s.earlyAt[0] <= s.next { // data that was waiting for this
		at := heap.Pop(&s.earlyAt).(uint64)
		e := s.early[at]
		delete(s.early, at)
		s.pending -= len(e) + earlyOverhead
		if end := at + uint64(len(e)); end > s.next {
			s.buf = append(s.buf, e[s.next-at:]...)
			s.next = end
		}
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
	if id == 0 {
		d.startSeen = true
	}
	if unidirectional && s.uniType < 0 {
		t, n, ok := quicVarint(s.buf)
		if !ok {
			return nil
		}
		s.uniType, s.buf = int64(t), s.buf[n:]
		d.startSeen = true
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
			items = append(items, s.data("DATA (continued)", id, s.buf[:n], d.bodies[id]))
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
			items = append(items, s.data("DATA", id, data, d.bodies[id]))
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
			items = append(items, d.headers(id, payload)...)
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

// data returns the item for a piece of a DATA frame's payload.
func (s *quicStream) data(typ string, id uint64, data []byte, dec *bodyDecoder) quicItem {
	item := quicItem{HTTP3: typ, Stream: id, Data: data, Body: decodeBody(dec, data, false),
		ContentType: s.body.contentType, Offset: s.body.seen}
	s.body.seen += int64(len(data))
	return item
}

func (d *quicDir) headers(id uint64, block []byte) []quicItem {
	fields, err := d.qpack.fieldSection(block)
	if errors.Is(err, errBlocked) {
		for len(d.blocked) > 0 && (len(d.blocked) >= maxBlocked || d.blockedBytes+len(block) > maxBlockedBytes) {
			d.blockedBytes -= len(d.blocked[0].block)
			d.blocked = append(d.blocked[:0], d.blocked[1:]...)
		}
		if len(block) <= maxBlockedBytes {
			d.blocked = append(d.blocked, blockedSection{id, append([]byte(nil), block...)})
			d.blockedBytes += len(block)
		}
		if !d.startSeen {
			return []quicItem{{HTTP3: "HEADERS", Stream: id,
				Err: "headers not decoded: the connection probably started before snoopy"}}
		}
		return []quicItem{{HTTP3: "HEADERS", Stream: id, Err: "waiting for QPACK encoder stream data"}}
	}
	return d.decodedItems(id, fields, err)
}

// decodedItems returns the items for a field section that fieldSection
// returned fields and err for.
func (d *quicDir) decodedItems(id uint64, fields []hpack.HeaderField, err error) []quicItem {
	if err != nil && !errors.Is(err, errFieldsCut) {
		return []quicItem{{HTTP3: "HEADERS", Stream: id, Err: err.Error()}}
	}
	items := []quicItem{d.decoded(id, fields)}
	if err != nil {
		items = append(items, quicItem{HTTP3: "HEADERS", Stream: id, Err: err.Error()})
	}
	return items
}

// decoded returns the item for a decoded header block, and starts following
// the body it heads.
func (d *quicDir) decoded(id uint64, fields []hpack.HeaderField) quicItem {
	item := quicItem{HTTP3: "HEADERS", Stream: id, Headers: fields}
	if s := d.streams[id]; s != nil && !s.dataSeen {
		s.body.contentType = contentType(fields)
	}
	item.Body = d.startBody(id, fields)
	return item
}

// startBody starts decoding the body of a request or response whose
// headers give it a Content-Encoding. Headers after the body has started
// are trailers.
func (d *quicDir) startBody(id uint64, fields []hpack.HeaderField) bodyPart {
	// Header blocks waiting for QPACK data are decoded late; if the body
	// went by meanwhile, it's too late to decode it.
	if s := d.streams[id]; d.bodies[id] != nil || s != nil && s.dataSeen || s == nil && d.done.has(id) {
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
	d.blockedBytes = 0
	for _, b := range d.blocked {
		fields, err := d.qpack.fieldSection(b.block)
		if errors.Is(err, errBlocked) {
			still = append(still, b)
			d.blockedBytes += len(b.block)
			continue
		}
		items = append(items, d.decodedItems(b.stream, fields, err)...)
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
