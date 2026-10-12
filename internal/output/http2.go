package output

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/internal/tracer"
)

// http2Frame is one HTTP/2 frame, or part of a DATA frame, found in an event.
type http2Frame struct {
	Type      string
	Stream    uint32
	Length    int      // the frame's payload length
	Flags     []string // e.g. END_STREAM
	Continued bool     // more of a DATA frame that started in an earlier event
	Data      []byte   // DATA payload in this event (padding included)
	// Headers is the decoded header block, on the HEADERS, PUSH_PROMISE or
	// CONTINUATION frame that completes it.
	Headers []hpack.HeaderField
}

// http2Conns decodes the HTTP/2 connections seen in events. HPACK
// compresses each side's headers against a table built up over the whole
// connection, so decoding starts with the connection preface, and stops for
// a direction if bytes of it go missing.
type http2Conns struct {
	conns map[http2Key]*http2Conn
	clock uint64 // for evicting the least recently used connection
}

type http2Key struct {
	pid  uint32
	conn uint64
}

type http2Conn struct {
	dirs     [2]http2Dir // by tracer.Direction
	lastUsed uint64
}

// http2Dir is one direction of a connection, as a byte stream of frames.
type http2Dir struct {
	dec        *hpack.Decoder
	buf        []byte // unparsed bytes, starting at a frame header
	dataLeft   int    // payload bytes still to come of the current DATA frame
	dataStream uint32
	block      []byte // header block being assembled
	broken     bool
}

const (
	maxHTTP2Conns   = 4096
	maxHTTP2Pending = 1 << 20 // larger frames than this are given up on
)

func newHTTP2Conns() *http2Conns {
	return &http2Conns{conns: map[http2Key]*http2Conn{}}
}

// process returns the frames in an event of a connection whose start was
// seen, and ok. ok is false for other connections, and for a direction
// whose decoding has stopped; note, if not empty, says why it just stopped.
func (c *http2Conns) process(ev *tracer.Event) (frames []http2Frame, ok bool, note string) {
	key := http2Key{ev.PID, ev.ConnID}
	data := ev.Data
	conn := c.conns[key]
	if bytes.HasPrefix(data, []byte(http2Preface)) {
		conn = c.start(key) // a new connection, possibly reusing the handle
		data = data[len(http2Preface):]
		frames = append(frames, http2Frame{Type: "connection preface"})
	}
	if conn == nil {
		return nil, false, ""
	}
	c.clock++
	conn.lastUsed = c.clock
	d := &conn.dirs[ev.Function.Direction()]
	if d.broken {
		return nil, false, ""
	}

	missing := max(int(ev.Size)-len(ev.Data), 0) // truncated, dropped or unreadable
	more, err := d.add(data, missing)
	if err != nil {
		d.broken = true
		d.buf, d.block = nil, nil
		return nil, false, "HTTP/2 decoding stopped for this direction of the connection: " + err.Error()
	}
	return append(frames, more...), true, ""
}

func (c *http2Conns) start(key http2Key) *http2Conn {
	if _, ok := c.conns[key]; !ok && len(c.conns) >= maxHTTP2Conns {
		var oldest http2Key
		var oldestUse uint64 = 1<<64 - 1
		for k, v := range c.conns {
			if v.lastUsed < oldestUse {
				oldest, oldestUse = k, v.lastUsed
			}
		}
		delete(c.conns, oldest)
	}
	conn := &http2Conn{}
	for i := range conn.dirs {
		dec := hpack.NewDecoder(4096, nil)
		// The peer's SETTINGS may allow a larger table; we only listen.
		dec.SetAllowedMaxDynamicTableSize(1 << 24)
		conn.dirs[i].dec = dec
	}
	c.conns[key] = conn
	return conn
}

// add parses the bytes of one call: data, followed by missing bytes that
// weren't captured. Missing bytes are fine within the payload of a DATA
// frame, which isn't needed to follow the connection; anywhere else, the
// framing or the header table is lost.
func (d *http2Dir) add(data []byte, missing int) ([]http2Frame, error) {
	var frames []http2Frame
	d.buf = append(d.buf, data...)
	for {
		if d.dataLeft > 0 {
			n := min(d.dataLeft, len(d.buf))
			if n > 0 {
				frames = append(frames, http2Frame{Type: "DATA", Stream: d.dataStream, Continued: true, Data: d.buf[:n]})
				d.buf, d.dataLeft = d.buf[n:], d.dataLeft-n
			}
			if d.dataLeft > 0 { // all captured bytes used up
				if missing > d.dataLeft {
					return frames, errors.New("bytes after a DATA frame weren't captured (raise --max-size)")
				}
				d.dataLeft -= missing
				return frames, nil
			}
			continue
		}
		if len(d.buf) < 9 {
			if missing > 0 {
				return frames, errors.New("bytes of a frame header weren't captured (raise --max-size)")
			}
			return frames, nil
		}
		length := int(d.buf[0])<<16 | int(d.buf[1])<<8 | int(d.buf[2])
		typ, flags := d.buf[3], d.buf[4]
		stream := binary.BigEndian.Uint32(d.buf[5:9])
		if !validHTTP2Frame(typ, flags, length, stream) {
			return frames, fmt.Errorf("invalid frame header %x", d.buf[:9])
		}
		f := http2Frame{Type: http2FrameTypes[typ], Stream: stream, Length: length, Flags: http2FlagNames(typ, flags)}
		if typ == 0 { // DATA: show the payload as it arrives
			n := min(length, len(d.buf)-9)
			f.Data = d.buf[9 : 9+n]
			frames = append(frames, f)
			d.buf, d.dataLeft, d.dataStream = d.buf[9+n:], length-n, stream
			continue
		}
		if len(d.buf) < 9+length {
			if missing > 0 {
				return frames, fmt.Errorf("bytes of a %s frame weren't captured (raise --max-size)", f.Type)
			}
			if len(d.buf) > maxHTTP2Pending {
				return frames, fmt.Errorf("%s frame of %d bytes is too large to follow", f.Type, length)
			}
			return frames, nil
		}
		payload := d.buf[9 : 9+length]
		d.buf = d.buf[9+length:]
		if err := d.headerBlock(&f, typ, flags, payload); err != nil {
			return frames, err
		}
		frames = append(frames, f)
	}
}

// headerBlock collects the header block fragments of HEADERS, PUSH_PROMISE
// and CONTINUATION frames, and decodes the block once it's complete.
func (d *http2Dir) headerBlock(f *http2Frame, typ, flags byte, p []byte) error {
	const (
		endHeaders = 0x4
		padded     = 0x8
		priority   = 0x20
	)
	switch typ {
	case 1, 5: // HEADERS, PUSH_PROMISE
		if flags&padded != 0 {
			if len(p) < 1 || int(p[0]) > len(p)-1 {
				return fmt.Errorf("bad padding in %s frame", f.Type)
			}
			p = p[1 : len(p)-int(p[0])]
		}
		skip := 0
		if typ == 1 && flags&priority != 0 {
			skip = 5
		} else if typ == 5 {
			skip = 4 // promised stream ID
		}
		if len(p) < skip {
			return fmt.Errorf("%s frame too short", f.Type)
		}
		d.block = append(d.block[:0], p[skip:]...)
	case 9: // CONTINUATION
		d.block = append(d.block, p...)
	default:
		return nil
	}
	if flags&endHeaders == 0 {
		return nil
	}
	fields, err := d.dec.DecodeFull(d.block)
	d.block = d.block[:0]
	if err != nil {
		return fmt.Errorf("can't decode header block: %v", err)
	}
	f.Headers = fields
	return nil
}
