package output

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/tks98/snoopy/internal/tracer"
)

// http1Conns follows the HTTP/1.x messages on connections, to undo their
// bodies' Content-Encoding: a body is framed by Content-Length or the
// chunked transfer coding, or runs to the end of the connection, and comes
// spread over many calls.
type http1Conns struct {
	conns map[http2Key]*http1Conn
	clock uint64
	pool  *bodyPool
}

type http1Conn struct {
	dirs     [2]http1Dir // by tracer.Direction
	headSent bool        // the last request was HEAD, so its response has no body
	lastUsed uint64
}

// What the next bytes of a direction are.
const (
	h1Start   = iota // a message's start line (or not HTTP/1: not followed)
	h1Head           // more of a header block
	h1Length         // body bytes, left of them to come
	h1Chunked        // a chunked body
	h1ToClose        // body bytes until the connection closes
	h1Gone           // not HTTP/1 anymore (switched protocols, a tunnel)
)

// Where a chunked body is.
const (
	chunkSize    = iota // in a chunk-size line
	chunkData           // in a chunk's data, left of it to come
	chunkDataEnd        // in the CRLF after a chunk's data
	chunkTrailer        // in the trailer section, after the last chunk
)

type http1Dir struct {
	state int
	head  []byte // a header block so far
	left  int64  // body or chunk bytes still to come
	chunk int
	line  []byte // a chunk-size or trailer line so far
	body  *bodyDecoder
}

// http1Segment is a part of an event's data: a start line and headers, or
// bytes of a body as sent (chunked framing included) with what they decoded
// to.
type http1Segment struct {
	msg    *httpMessage
	raw    []byte
	inBody bool // raw is (part of) a message body
	body   bodyPart
}

const (
	maxHTTP1Conns = 4096
	maxHTTP1Head  = 64 << 10
	maxChunkLine  = 4 << 10
)

func newHTTP1Conns(pool *bodyPool) *http1Conns {
	return &http1Conns{conns: map[http2Key]*http1Conn{}, pool: pool}
}

// process splits an event's data into segments, decoding encoded bodies.
// It returns nil for connections it doesn't follow, whose data starts with
// neither a message nor more of one.
func (c *http1Conns) process(ev *tracer.Event) []http1Segment {
	key := http2Key{ev.PID, ev.ConnID}
	conn := c.conns[key]
	if conn == nil {
		if !startsHTTP1(ev.Data) {
			return nil
		}
		if len(c.conns) >= maxHTTP1Conns {
			c.evict()
		}
		conn = &http1Conn{}
		c.conns[key] = conn
	}
	c.clock++
	conn.lastUsed = c.clock
	d := &conn.dirs[ev.Function.Direction()]
	segs := conn.add(d, ev.Data, c.pool)
	if missing := int(ev.Size) - len(ev.Data); missing > 0 {
		if dec := d.lose(missing); dec != nil {
			if p := decodeBody(dec, nil, false); p.Err != "" {
				segs = append(segs, http1Segment{body: p})
			}
		}
	}
	return segs
}

func (c *http1Conns) evict() {
	var oldest http2Key
	var oldestUse uint64 = 1<<64 - 1
	for k, conn := range c.conns {
		if conn.lastUsed < oldestUse {
			oldest, oldestUse = k, conn.lastUsed
		}
	}
	for i := range c.conns[oldest].dirs {
		c.conns[oldest].dirs[i].endBody(errors.New("connection no longer followed"))
	}
	delete(c.conns, oldest)
}

func startsHTTP1(b []byte) bool {
	return http1Request.Match(b) || http1Response.Match(b)
}

var http1StartPrefix = regexp.MustCompile(`^(H(T(T(P(/(1(\.([01]( \d{0,3})?)?)?)?)?)?)?)?|[A-Z]{1,10}( \S*( H?T?T?P?/?1?\.?[01]?)?)?)$`)

// startLinePrefix reports whether b, a call's data, could be the first part
// of a start line that the next call completes.
func startLinePrefix(b []byte) bool {
	return len(b) < 256 && http1StartPrefix.Match(b)
}

func (conn *http1Conn) add(d *http1Dir, data []byte, pool *bodyPool) []http1Segment {
	var segs []http1Segment
	for len(data) > 0 {
		switch d.state {
		case h1Start:
			if !startsHTTP1(data) {
				if startLinePrefix(data) { // the start line continues in the next call
					d.head, d.state = append(d.head[:0], data...), h1Head
				}
				// Otherwise lost track of the messages; wait for the next one.
				return append(segs, http1Segment{raw: data})
			}
			end := headEnd(data)
			if end < 0 {
				m, _ := parseHTTP1(data)
				d.head = append(d.head[:0], data...)
				d.state = h1Head
				return append(segs, http1Segment{msg: &m})
			}
			m, _ := parseHTTP1(data[:end])
			segs = append(segs, http1Segment{msg: &m})
			conn.startBody(d, m, pool)
			data = data[end:]
		case h1Head:
			old := len(d.head)
			d.head = append(d.head, data...)
			end := headEnd(d.head)
			if end < 0 {
				if len(d.head) > maxHTTP1Head {
					d.head, d.state = nil, h1Start
				}
				return append(segs, http1Segment{raw: data})
			}
			segs = append(segs, http1Segment{raw: data[:end-old]})
			m, ok := parseHTTP1(d.head[:end])
			d.head = nil
			if !ok { // a start line's beginning, it seemed
				d.state = h1Start
				return segs
			}
			conn.startBody(d, m, pool)
			data = data[end-old:]
		case h1Length:
			n := min(int64(len(data)), d.left)
			d.left -= n
			segs = append(segs, http1Segment{raw: data[:n], inBody: true, body: decodeBody(d.body, data[:n], d.left == 0)})
			if d.left == 0 {
				d.body, d.state = nil, h1Start
			}
			data = data[n:]
		case h1Chunked:
			n, body, done, ok := d.chunked(data)
			seg := http1Segment{raw: data[:n], inBody: true, body: decodeBody(d.body, body, done && ok)}
			if !ok {
				// Lost track of the framing; wait for the next message.
				d.endBody(errors.New("bad chunked framing"))
				if seg.body.Encoding != "" {
					seg.body.Err = "bad chunked framing"
				}
				done = true
			}
			segs = append(segs, seg)
			if done {
				d.body, d.state = nil, h1Start
			}
			data = data[n:]
		case h1ToClose:
			return append(segs, http1Segment{raw: data, inBody: true, body: decodeBody(d.body, data, false)})
		default: // h1Gone
			return append(segs, http1Segment{raw: data})
		}
	}
	return segs
}

// headEnd returns where the header block at the start of b ends, after its
// blank line, or -1.
func headEnd(b []byte) int {
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return i + 4
	}
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		return i + 2
	}
	return -1
}

// startBody sets up for the body, if any, that follows a message's headers
// (RFC 9112, section 6).
func (conn *http1Conn) startBody(d *http1Dir, m httpMessage, pool *bodyPool) {
	header := func(name string) string {
		for _, h := range m.headers {
			if strings.EqualFold(strings.TrimSpace(h[0]), name) {
				return h[1]
			}
		}
		return ""
	}
	d.state = h1Start
	chunked := strings.Contains(strings.ToLower(header("Transfer-Encoding")), "chunked")
	length, lengthErr := strconv.ParseInt(header("Content-Length"), 10, 64)
	if response, ok := strings.CutPrefix(m.startLine, "HTTP/"); ok {
		_, rest, _ := strings.Cut(response, " ")
		status, _ := strconv.Atoi(strings.TrimSpace(rest[:min(3, len(rest))]))
		switch {
		case status == 101: // switching protocols, e.g. to WebSocket
			d.state = h1Gone
			conn.dirs[tracer.Read], conn.dirs[tracer.Write] = http1Dir{state: h1Gone}, http1Dir{state: h1Gone}
			return
		case status < 200 || status == 204 || status == 304 || conn.headSent:
			return // no body
		case chunked:
			d.state = h1Chunked
		case lengthErr == nil:
			d.state, d.left = h1Length, length
		default:
			d.state = h1ToClose
		}
	} else {
		method, _, _ := strings.Cut(m.startLine, " ")
		conn.headSent = method == "HEAD"
		switch {
		case method == "CONNECT": // a tunnel follows
			d.state = h1Gone
			return
		case chunked:
			d.state = h1Chunked
		case lengthErr == nil:
			d.state, d.left = h1Length, length
		}
	}
	if d.state == h1Length && d.left <= 0 {
		d.state = h1Start
		return
	}
	d.chunk, d.line = chunkSize, nil
	if d.state != h1Start {
		d.body = pool.start(header("Content-Encoding"))
	}
}

// chunked reads chunked framing from b: it returns how many bytes it used,
// the body bytes among them, and whether the body ended; ok is false if the
// framing is broken.
func (d *http1Dir) chunked(b []byte) (n int, body []byte, done, ok bool) {
	// Body bytes are copied out only if there's framing between them.
	var parts [][]byte
	for n < len(b) {
		switch d.chunk {
		case chunkData:
			k := int(min(int64(len(b)-n), d.left))
			parts = append(parts, b[n:n+k])
			n += k
			if d.left -= int64(k); d.left == 0 {
				d.chunk = chunkDataEnd
			}
			continue
		}
		i := bytes.IndexByte(b[n:], '\n')
		if i < 0 {
			d.line = append(d.line, b[n:]...)
			return len(b), join(parts), false, len(d.line) <= maxChunkLine
		}
		line := strings.TrimSpace(string(append(d.line, b[n:n+i]...)))
		d.line = nil
		n += i + 1
		switch d.chunk {
		case chunkSize:
			size, _, _ := strings.Cut(line, ";") // chunk extensions
			v, err := strconv.ParseInt(strings.TrimSpace(size), 16, 64)
			if err != nil || v < 0 {
				return n, join(parts), true, false
			}
			if v == 0 {
				d.chunk = chunkTrailer
			} else {
				d.chunk, d.left = chunkData, v
			}
		case chunkDataEnd:
			if line != "" {
				return n, join(parts), true, false
			}
			d.chunk = chunkSize
		case chunkTrailer:
			if line == "" {
				return n, join(parts), true, true
			}
		}
	}
	return n, join(parts), false, true
}

func join(parts [][]byte) []byte {
	if len(parts) == 1 {
		return parts[0]
	}
	return bytes.Join(parts, nil)
}

// lose accounts for bytes of the direction that weren't captured, and
// returns the body decoder it stopped, if any.
func (d *http1Dir) lose(n int) *bodyDecoder {
	dec := d.body
	switch d.state {
	case h1Length:
		d.endBody(errors.New("bytes of the body weren't captured (raise --max-size)"))
		if d.left -= int64(n); d.left <= 0 {
			d.state, d.body = h1Start, nil
		}
	case h1Chunked, h1Head:
		d.endBody(errors.New("bytes of the body weren't captured (raise --max-size)"))
		d.state, d.head, d.body = h1Start, nil, nil // the framing is lost
	case h1ToClose:
		d.endBody(errors.New("bytes of the body weren't captured (raise --max-size)"))
	default:
		return nil
	}
	return dec
}

func (d *http1Dir) endBody(err error) {
	if d.body != nil {
		d.body.fail(err)
	}
}
