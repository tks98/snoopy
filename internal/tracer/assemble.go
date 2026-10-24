package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// rawHeader mirrors struct event_header in bpf/snoopy.c. Each ring buffer
// record is a header followed by ChunkLen bytes of payload (and possibly
// unused space).
type rawHeader struct {
	TimestampNs   uint64
	LatencyNs     uint64
	ConnID        uint64
	Pid           uint32
	Tid           uint32
	Size          uint32
	Captured      uint32
	ChunkOffset   uint32
	ChunkLen      uint32
	Fd            int32
	Family        uint16
	Lport         uint16
	Rport         uint16
	Fn            uint8
	Flags         uint8
	Laddr         [16]byte
	Raddr         [16]byte
	QuicHeaderLen uint8
	QuicHeader    [47]byte
	Comm          [16]byte
	_             [4]byte
}

// Address families as reported in rawHeader.Family.
const (
	afInet  = 2
	afInet6 = 10
)

// addresses returns the socket's local and remote address, if known.
func (h *rawHeader) addresses() (local, remote netip.AddrPort) {
	var l, r netip.Addr
	switch h.Family {
	case afInet:
		l = netip.AddrFrom4([4]byte(h.Laddr[:4]))
		r = netip.AddrFrom4([4]byte(h.Raddr[:4]))
	case afInet6:
		l = netip.AddrFrom16(h.Laddr).Unmap()
		r = netip.AddrFrom16(h.Raddr).Unmap()
	default:
		return local, remote
	}
	return netip.AddrPortFrom(l, h.Lport), netip.AddrPortFrom(r, h.Rport)
}

const flagReadError = 1 // EVENT_FLAG_READ_ERROR

var headerSize = binary.Size(rawHeader{})

type chunk struct {
	rawHeader
	data []byte
}

// decodeHeader decodes a record's rawHeader, which has to be headerSize
// bytes or more, field by field: binary.Decode's reflection was a good part
// of what snoopy spent under load. TestDecodeHeader checks they agree.
func decodeHeader(b []byte) rawHeader {
	e := binary.NativeEndian
	h := rawHeader{
		TimestampNs:   e.Uint64(b[0:]),
		LatencyNs:     e.Uint64(b[8:]),
		ConnID:        e.Uint64(b[16:]),
		Pid:           e.Uint32(b[24:]),
		Tid:           e.Uint32(b[28:]),
		Size:          e.Uint32(b[32:]),
		Captured:      e.Uint32(b[36:]),
		ChunkOffset:   e.Uint32(b[40:]),
		ChunkLen:      e.Uint32(b[44:]),
		Fd:            int32(e.Uint32(b[48:])),
		Family:        e.Uint16(b[52:]),
		Lport:         e.Uint16(b[54:]),
		Rport:         e.Uint16(b[56:]),
		Fn:            b[58],
		Flags:         b[59],
		QuicHeaderLen: b[92],
	}
	copy(h.Laddr[:], b[60:76])
	copy(h.Raddr[:], b[76:92])
	copy(h.QuicHeader[:], b[93:140])
	copy(h.Comm[:], b[140:156])
	return h
}

func parseChunk(record []byte) (chunk, error) {
	var c chunk
	if len(record) < headerSize {
		return c, fmt.Errorf("short record: %d bytes", len(record))
	}
	c.rawHeader = decodeHeader(record)
	if int(c.ChunkLen) > len(record)-headerSize {
		return c, fmt.Errorf("chunk length %d exceeds record", c.ChunkLen)
	}
	c.data = record[headerSize : headerSize+int(c.ChunkLen)]
	return c, nil
}

// assembler joins the chunks of each call back into one Event.
//
// The BPF program writes all chunks of a call in order from a single program
// run, stopping at the first chunk the ring buffer has no room for. Calls on
// one thread are sequential, so at most one call per thread is in flight and
// a missing chunk can only be at the end of a call.
type assembler struct {
	pending map[uint32]*partial // by thread ID
	clock   func(monoNs uint64) time.Time
}

type partial struct {
	ev       *Event
	ts       uint64
	captured uint32
	seen     time.Time
}

func newAssembler(clock func(uint64) time.Time) *assembler {
	return &assembler{pending: map[uint32]*partial{}, clock: clock}
}

// add consumes one chunk and returns any events it completes.
func (a *assembler) add(c chunk, now time.Time) []*Event {
	var done []*Event

	p := a.pending[c.Tid]
	if p != nil && p.ts != c.TimestampNs {
		// A new call started on this thread before the previous one was
		// complete, so the rest of the previous one was dropped.
		p.ev.Incomplete = true
		done = append(done, p.ev)
		delete(a.pending, c.Tid)
		p = nil
	}

	if p == nil {
		if c.ChunkOffset != 0 {
			// The start of this call was lost; drop what's left of it.
			return done
		}
		p = &partial{ev: a.newEvent(c), ts: c.TimestampNs, captured: c.Captured}
		a.pending[c.Tid] = p
	}
	p.seen = now

	if c.ChunkOffset != uint32(len(p.ev.Data)) {
		p.ev.Incomplete = true
	} else {
		p.ev.Data = append(p.ev.Data, c.data...)
	}
	if c.Flags&flagReadError != 0 {
		p.ev.ReadError = true
	}

	if p.ev.ReadError || p.ev.Incomplete || uint32(len(p.ev.Data)) >= p.captured {
		done = append(done, p.ev)
		delete(a.pending, c.Tid)
	}
	return done
}

// expire returns calls that have waited for their remaining chunks for
// longer than maxAge; those chunks were dropped.
func (a *assembler) expire(now time.Time, maxAge time.Duration) []*Event {
	var done []*Event
	for tid, p := range a.pending {
		if now.Sub(p.seen) >= maxAge {
			p.ev.Incomplete = true
			done = append(done, p.ev)
			delete(a.pending, tid)
		}
	}
	return done
}

func (a *assembler) newEvent(c chunk) *Event {
	comm := c.Comm[:]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	local, remote := c.addresses()
	var quicHeader []byte
	if n := min(int(c.QuicHeaderLen), len(c.QuicHeader)); n > 0 {
		quicHeader = bytes.Clone(c.QuicHeader[:n])
	}
	return &Event{
		QUICHeader: quicHeader,
		Local:      local,
		Remote:     remote,
		Time:       a.clock(c.TimestampNs),
		Latency:    time.Duration(c.LatencyNs),
		Function:   Function(c.Fn),
		PID:        c.Pid,
		TID:        c.Tid,
		Comm:       string(comm),
		ConnID:     c.ConnID,
		FD:         c.Fd,
		Size:       c.Size,
		Data:       make([]byte, 0, c.Captured),
	}
}
