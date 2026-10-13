package output

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

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
	// For a body with a Content-Encoding: what this frame's part of it
	// decoded to, or why it couldn't be.
	Body bodyPart
}

// bodyPart is what a piece of a message body decoded to.
type bodyPart struct {
	Encoding string // the body's Content-Encoding; empty if it has none
	Decoded  []byte
	Err      string
}

// decodeBody passes a piece of a body to its decoder, ending the body if
// last is set.
func decodeBody(dec *bodyDecoder, piece []byte, last bool) bodyPart {
	if dec == nil {
		return bodyPart{}
	}
	part := bodyPart{Encoding: dec.encoding, Decoded: dec.write(piece)}
	if last {
		part.Decoded = append(part.Decoded, dec.end()...)
	}
	if err := dec.failed(); err != nil {
		if dec.reported { // said so already: show the rest as sent
			return bodyPart{}
		}
		part.Err, dec.reported = err.Error(), true
	}
	return part
}

// contentEncoding returns a message's Content-Encoding, if its headers
// start one with a body: not an interim (1xx) response.
func contentEncoding(fields []hpack.HeaderField) string {
	var encoding string
	for _, f := range fields {
		switch f.Name {
		case ":status":
			if strings.HasPrefix(f.Value, "1") {
				return ""
			}
		case "content-encoding":
			encoding = f.Value
		}
	}
	return encoding
}

// http2Conns decodes the HTTP/2 connections seen in events. HPACK
// compresses each side's headers against a table built up over the whole
// connection, so decoding starts with the connection preface, and stops for
// a direction if bytes of it go missing.
type http2Conns struct {
	conns map[http2Key]*http2Conn
	clock uint64 // for evicting the least recently used connection
	pool  *bodyPool
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
	dec      *hpack.Decoder
	buf      []byte // unparsed bytes, starting at a frame header
	dataLeft int    // payload bytes still to come of the current DATA frame
	data     dataFrame
	block    []byte // header block being assembled
	// The HEADERS frame the block started with: its stream, and whether it
	// ends the stream.
	blockStream    uint32
	blockEndStream bool
	broken         bool
	bodies         map[uint32]*bodyDecoder // by stream, for encoded bodies
}

// dataFrame is the DATA frame being read, to find its body bytes: a padded
// frame's payload starts with the padding length and ends with padding.
type dataFrame struct {
	stream    uint32
	length    int  // payload length
	off       int  // payload bytes read so far
	pad       int  // padding length, -1 until read
	endStream bool // END_STREAM
}

// bodyBytes returns the body bytes in the next piece of the frame's payload.
func (f *dataFrame) bodyBytes(piece []byte) []byte {
	start := f.off
	f.off += len(piece)
	if f.pad == 0 {
		return piece
	}
	if f.pad < 0 && start == 0 && len(piece) > 0 {
		f.pad = int(piece[0])
	}
	lo, hi := max(start, 1), min(f.off, f.length-f.pad)
	if lo >= hi {
		return nil
	}
	return piece[lo-start : hi-start]
}

const (
	maxHTTP2Conns   = 4096
	maxHTTP2Pending = 1 << 20 // larger frames than this are given up on
)

func newHTTP2Conns(pool *bodyPool) *http2Conns {
	return &http2Conns{conns: map[http2Key]*http2Conn{}, pool: pool}
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
	more, err := d.add(data, missing, c.pool)
	if err != nil {
		d.broken = true
		d.buf, d.block = nil, nil
		d.endBodies(err)
		return nil, false, "HTTP/2 decoding stopped for this direction of the connection: " + err.Error()
	}
	return append(frames, more...), true, ""
}

func (c *http2Conns) start(key http2Key) *http2Conn {
	if old, ok := c.conns[key]; ok {
		old.close()
	} else if len(c.conns) >= maxHTTP2Conns {
		var oldest http2Key
		var oldestUse uint64 = 1<<64 - 1
		for k, v := range c.conns {
			if v.lastUsed < oldestUse {
				oldest, oldestUse = k, v.lastUsed
			}
		}
		c.conns[oldest].close()
		delete(c.conns, oldest)
	}
	conn := &http2Conn{}
	for i := range conn.dirs {
		dec := hpack.NewDecoder(4096, nil)
		// The peer's SETTINGS may allow a larger table; we only listen.
		dec.SetAllowedMaxDynamicTableSize(1 << 24)
		conn.dirs[i].dec = dec
		conn.dirs[i].bodies = map[uint32]*bodyDecoder{}
	}
	c.conns[key] = conn
	return conn
}

// close gives up on the bodies still being decoded.
func (conn *http2Conn) close() {
	for i := range conn.dirs {
		conn.dirs[i].endBodies(errors.New("connection no longer followed"))
	}
}

func (d *http2Dir) endBodies(err error) {
	for stream, dec := range d.bodies {
		dec.fail(err)
		delete(d.bodies, stream)
	}
}

// add parses the bytes of one call: data, followed by missing bytes that
// weren't captured. Missing bytes are fine within the payload of a DATA
// frame, which isn't needed to follow the connection; anywhere else, the
// framing or the header table is lost.
func (d *http2Dir) add(data []byte, missing int, pool *bodyPool) ([]http2Frame, error) {
	var frames []http2Frame
	d.buf = append(d.buf, data...)
	for {
		if d.dataLeft > 0 {
			n := min(d.dataLeft, len(d.buf))
			if n > 0 {
				f := http2Frame{Type: "DATA", Stream: d.data.stream, Continued: true, Data: d.buf[:n]}
				d.buf, d.dataLeft = d.buf[n:], d.dataLeft-n
				f.Body = d.dataBody(f.Data)
				frames = append(frames, f)
			}
			if d.dataLeft > 0 { // all captured bytes used up
				if missing > d.dataLeft {
					return frames, errors.New("bytes after a DATA frame weren't captured (raise --max-size)")
				}
				if dec := d.bodies[d.data.stream]; dec != nil && missing > 0 {
					dec.fail(errors.New("bytes of the body weren't captured (raise --max-size)"))
					if p := decodeBody(dec, nil, false); p.Err != "" {
						if n := len(frames); n > 0 && frames[n-1].Stream == d.data.stream {
							frames[n-1].Body.Encoding, frames[n-1].Body.Err = p.Encoding, p.Err
						} else {
							frames = append(frames, http2Frame{Type: "DATA", Stream: d.data.stream, Continued: true, Body: p})
						}
					}
				}
				d.dataLeft -= missing
				d.data.off += missing
				if d.dataLeft == 0 && d.data.endStream {
					delete(d.bodies, d.data.stream)
				}
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
			const endStream, padded = 0x1, 0x8
			n := min(length, len(d.buf)-9)
			f.Data = d.buf[9 : 9+n]
			d.buf, d.dataLeft = d.buf[9+n:], length-n
			d.data = dataFrame{stream: stream, length: length, endStream: flags&endStream != 0}
			if flags&padded != 0 {
				d.data.pad = -1
			}
			f.Body = d.dataBody(f.Data)
			frames = append(frames, f)
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
		if err := d.headerBlock(&f, typ, flags, payload, pool); err != nil {
			return frames, err
		}
		if typ == 3 { // RST_STREAM
			if dec := d.bodies[stream]; dec != nil {
				dec.fail(errors.New("the stream was reset"))
				delete(d.bodies, stream)
			}
		}
		frames = append(frames, f)
	}
}

// dataBody decodes the body bytes in a piece of the current DATA frame's
// payload, if the body has a Content-Encoding.
func (d *http2Dir) dataBody(piece []byte) bodyPart {
	stream := d.data.stream
	body := d.data.bodyBytes(piece)
	dec := d.bodies[stream]
	last := d.data.off >= d.data.length && d.data.endStream
	if last {
		delete(d.bodies, stream)
	}
	return decodeBody(dec, body, last)
}

// headerBlock collects the header block fragments of HEADERS, PUSH_PROMISE
// and CONTINUATION frames, and decodes the block once it's complete.
func (d *http2Dir) headerBlock(f *http2Frame, typ, flags byte, p []byte, pool *bodyPool) error {
	const (
		endStream  = 0x1
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
		d.blockStream, d.blockEndStream = 0, false
		if typ == 1 {
			d.blockStream, d.blockEndStream = f.Stream, flags&endStream != 0
		}
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
	if stream := d.blockStream; stream != 0 {
		dec := d.bodies[stream]
		if dec == nil { // not trailers
			if enc := contentEncoding(fields); enc != "" && !d.blockEndStream {
				if dec := pool.start(enc); dec != nil {
					d.bodies[stream] = dec
					if err := dec.failed(); err != nil {
						f.Body = bodyPart{Encoding: enc, Err: err.Error()}
					}
				}
			}
		} else if d.blockEndStream { // trailers end the body
			delete(d.bodies, stream)
			f.Body = decodeBody(dec, nil, true)
		}
	}
	return nil
}
