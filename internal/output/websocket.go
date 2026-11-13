package output

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// WebSocket (RFC 6455) is followed on HTTP/1.1 connections that switch to
// it: after a 101 response with "Upgrade: websocket", each direction is a
// stream of frames, which can be split across calls or come several to a
// call. On HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220), a stream whose extended
// CONNECT for WebSocket got a 2xx response is the same, in its DATA frames'
// payloads: each direction of a wsConn is then a direction of the stream.
// A client's frames are masked, and unmasked here. Messages compressed with
// permessage-deflate (RFC 7692), when the handshake negotiated it, are
// decompressed when their last frame ends. A connection whose handshake
// wasn't seen, because it started before snoopy, is shown as raw data.

// WebSocket opcodes.
const (
	wsContinuation = 0x0
	wsText         = 0x1
	wsBinary       = 0x2
	wsClose        = 0x8
	wsPing         = 0x9
	wsPong         = 0xa
)

const (
	permessageDeflate = "permessage-deflate"
	// DEFLATE's largest window, which a sender that keeps its compression
	// context from message to message may refer back into.
	wsWindow = 32 << 10
	// A control frame's largest payload.
	maxWSControl = 125
	// The most of a compressed message kept to decompress at its end,
	// which can decompress to more than maxDecodedBody already.
	maxWSDeflated = 4 << 20
)

// deflateEnd ends a compressed message's payload for decompressing: the
// empty stored block that the sender's flush ended it with, which it left
// out (RFC 7692, section 7.2.1), and then a final empty block, so the
// decompressor ends cleanly.
var deflateEnd = []byte{0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff}

// wsFrame is a WebSocket frame, or the part of one, found in an event.
type wsFrame struct {
	Opcode byte
	Fin    bool
	Masked bool
	// Compressed is set on the frames of a message compressed with
	// permessage-deflate: RSV1 on its first frame.
	Compressed bool
	Length     int64 // the payload's length
	Continued  bool  // the frame's header was in an earlier event
	Complete   bool  // the frame's payload ends in this event
	// Message is, for a data frame, the type of the message it's part of:
	// wsText or wsBinary.
	Message byte
	// Data is the frame's payload bytes in this event, unmasked (and still
	// compressed if the message is). A control frame's is its whole payload,
	// on the event that completes it.
	Data []byte
	// Offset is how many bytes of the message's payload came before Data.
	Offset int64
	// Body is, on the frame that ends a compressed message, what the message
	// decompressed to, or why it couldn't be.
	Body bodyPart
	// A complete close frame's status code (0 if it has none) and reason.
	CloseCode   int
	CloseReason string
}

// wsPart is the WebSocket in an event's data.
type wsPart struct {
	Frames []wsFrame
	// Partial is how many bytes of a frame header at the end continue in a
	// later event.
	Partial int
	// Err says why decoding stopped for this direction of the connection.
	Err string
	// Rest is, on HTTP/2 and HTTP/3, the bytes from where the framing was
	// lost on, shown as sent. (HTTP/1.x shows them as a raw segment.)
	Rest []byte
}

// wsConn follows a WebSocket connection's frames, in both directions.
type wsConn struct {
	dirs [2]wsDir // by tracer.Direction
}

// wsDir is one direction of a WebSocket connection, as a stream of frames.
type wsDir struct {
	deflate  bool // permessage-deflate was negotiated
	takeover bool // and this direction's sender keeps its context
	otherExt bool // extensions snoopy doesn't know of were negotiated
	stopped  bool // the framing was lost

	hdr     []byte  // a frame header so far
	inFrame bool    // reading a frame's payload
	f       wsFrame // that frame's header
	key     [4]byte // and masking key
	got     int64   // payload bytes of it so far
	ctrl    []byte  // a control frame's payload so far

	// The message being read: its type (0 between messages), whether it's
	// compressed, and how many bytes of its payload came so far.
	msg           byte
	msgCompressed bool
	msgSeen       int64
	deflated      []byte // a compressed message's payload so far
	msgErr        string // why a compressed message can't be decompressed
	// window is the end of what this direction's messages decompressed to,
	// which the next one can refer back into if the sender keeps its
	// context; windowLost is set once a message couldn't be decompressed.
	window     []byte
	windowLost bool
}

// newWSConn returns a decoder for a connection that switched protocols with
// a 101 response sent in direction server with these headers, or nil if it
// didn't switch to WebSocket. The response's Sec-WebSocket-Extensions say
// which extensions the server accepted.
func newWSConn(headers [][2]string, server tracer.Direction) *wsConn {
	var websocket bool
	var extensions []string
	for _, h := range headers {
		switch strings.ToLower(strings.TrimSpace(h[0])) {
		case "upgrade":
			for _, p := range strings.Split(h[1], ",") {
				websocket = websocket || strings.EqualFold(strings.TrimSpace(p), "websocket")
			}
		case "sec-websocket-extensions":
			extensions = append(extensions, h[1])
		}
	}
	if !websocket {
		return nil
	}
	return newWSStream(extensions, server)
}

// newWSStream returns a decoder for a WebSocket connection whose handshake's
// response, sent in direction server, accepted these extensions (its
// Sec-WebSocket-Extensions values): on HTTP/1.1 a 101, on HTTP/2 and HTTP/3
// a 2xx response to an extended CONNECT.
func newWSStream(extensions []string, server tracer.Direction) *wsConn {
	c := &wsConn{}
	for _, ext := range strings.Split(strings.Join(extensions, ","), ",") {
		params := strings.Split(ext, ";")
		switch name := strings.ToLower(strings.TrimSpace(params[0])); {
		case name == "":
		case name == permessageDeflate && !c.dirs[0].deflate:
			for i := range c.dirs {
				c.dirs[i].deflate, c.dirs[i].takeover = true, true
			}
			for _, p := range params[1:] {
				param, _, _ := strings.Cut(p, "=")
				switch strings.ToLower(strings.TrimSpace(param)) {
				case "server_no_context_takeover":
					c.dirs[server].takeover = false
				case "client_no_context_takeover":
					c.dirs[opposite(server)].takeover = false
				}
			}
		default: // may use the RSV bits for something else
			for i := range c.dirs {
				c.dirs[i].otherExt = true
			}
		}
	}
	return c
}

// wsConnect reports whether a request's header fields are an extended
// CONNECT for WebSocket, on HTTP/2 (RFC 8441, section 4) or HTTP/3 (RFC
// 9220).
func wsConnect(fields []hpack.HeaderField) bool {
	method, _ := headerField(fields, ":method")
	protocol, _ := headerField(fields, ":protocol")
	return method == "CONNECT" && strings.EqualFold(protocol, "websocket")
}

// wsAccept returns the decoder for a stream whose extended CONNECT for
// WebSocket got a response with these header fields, sent in direction
// server; nil if it didn't accept it: only a 2xx response does.
func wsAccept(fields []hpack.HeaderField, server tracer.Direction) *wsConn {
	if status, _ := headerField(fields, ":status"); len(status) != 3 || status[0] != '2' {
		return nil
	}
	var extensions []string
	for _, f := range fields {
		if f.Name == "sec-websocket-extensions" {
			extensions = append(extensions, f.Value)
		}
	}
	return newWSStream(extensions, server)
}

// negotiated returns d, a direction whose frames were read before the
// handshake's response (see wsEarly), with the extensions that n, the same
// direction as the response set it up, has.
func (d wsDir) negotiated(n wsDir) wsDir {
	d.deflate, d.takeover, d.otherExt = n.deflate, n.takeover, n.otherExt
	return d
}

// webSocket reports whether an event is on a connection that switched to
// WebSocket, and doesn't start a new HTTP/2 one reusing its handle. HTTP/2
// is then left out: it takes a call that starts with what looks like its
// frames for a connection that started before snoopy, as a WebSocket
// frame of 9 bytes now and then does.
func (d decoders) webSocket(ev *tracer.Event) bool {
	key := http2Key{ev.PID, connOf(ev)}
	conn := d.h1.conns[key]
	return conn != nil && conn.ws != nil && d.h2.conns[key] == nil && !bytes.HasPrefix(ev.Data, []byte(http2Preface))
}

// atFrame reports whether a direction is between frames, or not followed
// anymore: where an HTTP/1.x message would start a new connection reusing
// the TLS library's handle. No valid frame starts like one.
func (c *wsConn) atFrame(dir tracer.Direction) bool {
	d := &c.dirs[dir]
	return d.stopped || !d.inFrame && len(d.hdr) == 0
}

// decode decodes the next bytes of a direction, for HTTP/1.1 and for
// HTTP/2's and HTTP/3's streams alike: the frames in them, and if the
// framing is lost in them, why and the bytes from there on (Err and Rest).
// It returns nil once the framing was lost before: the bytes are then only
// data.
func (c *wsConn) decode(dir tracer.Direction, data []byte) *wsPart {
	d := &c.dirs[dir]
	if d.stopped {
		return nil
	}
	frames, rest, err := d.add(data)
	part := &wsPart{Frames: frames}
	if !d.inFrame {
		part.Partial = len(d.hdr)
	}
	if err != nil {
		part.Err, part.Rest = d.stop(err), rest
	}
	return part
}

// skip accounts for n bytes of a direction that weren't captured, which
// followed what part (nil if none) holds of the call; why says why (see
// missingWhy). They can be skipped in a frame's payload; anywhere else, the
// framing is lost. It returns part, or a new one if part is nil, or nil if
// the framing was lost before.
func (c *wsConn) skip(dir tracer.Direction, part *wsPart, n int, why string) *wsPart {
	d := &c.dirs[dir]
	if d.stopped {
		return part
	}
	if part == nil {
		part = &wsPart{}
	}
	frames, err := d.lose(n, why, part.Frames)
	part.Frames = frames
	if err != nil {
		part.Err, part.Partial = d.stop(err), 0
	}
	return part
}

// segments decodes the next bytes of an HTTP/1.1 connection's direction: as
// frames, and as raw bytes once the framing is lost.
func (c *wsConn) segments(dir tracer.Direction, data []byte) []http1Segment {
	part := c.decode(dir, data)
	if part == nil {
		return []http1Segment{{raw: data}}
	}
	segs := []http1Segment{{ws: part}}
	if len(part.Rest) > 0 {
		segs = append(segs, http1Segment{raw: part.Rest})
		part.Rest = nil
	}
	return segs
}

// lose accounts for n bytes of an HTTP/1.1 connection's direction that
// weren't captured, which followed segs (see skip).
func (c *wsConn) lose(dir tracer.Direction, segs []http1Segment, n int, why string) []http1Segment {
	var part *wsPart
	if k := len(segs); k > 0 && segs[k-1].ws != nil {
		part = segs[k-1].ws
	}
	if p := c.skip(dir, part, n, why); p != nil && part == nil {
		segs = append(segs, http1Segment{ws: p})
	}
	return segs
}

func (d *wsDir) stop(err error) string {
	d.stopped = true
	d.hdr, d.ctrl, d.deflated, d.window = nil, nil, nil, nil
	return "WebSocket decoding stopped for this direction of the connection: " + err.Error()
}

// add parses the bytes of one call. rest is what's left of them when the
// framing is lost, from the frame header that didn't parse on.
func (d *wsDir) add(data []byte) (frames []wsFrame, rest []byte, err error) {
	cur := -1 // the index in frames of the frame being read
	for len(data) > 0 {
		if !d.inFrame {
			n, err := d.header(data)
			if err != nil {
				return frames, data, err
			}
			data = data[n:]
			if !d.inFrame { // the header continues in the next call
				break
			}
			frames = append(frames, d.frame(false))
			cur = len(frames) - 1
		} else if cur < 0 {
			frames = append(frames, d.frame(true))
			cur = len(frames) - 1
		}
		n := int(min(int64(len(data)), d.f.Length-d.got))
		d.payload(&frames[cur], data[:n])
		data = data[n:]
		if d.got == d.f.Length {
			d.finish(&frames[cur])
			cur = -1
		}
	}
	return frames, nil, nil
}

// header reads a frame header from data, which may complete one that an
// earlier call started, and returns how many bytes of data it used. Once
// the header is complete, the frame's payload is next (inFrame).
func (d *wsDir) header(data []byte) (int, error) {
	used := 0
	for {
		need := 2
		if len(d.hdr) >= 2 {
			switch d.hdr[1] & 0x7f { // a 16- or 64-bit length follows
			case 126:
				need += 2
			case 127:
				need += 8
			}
			if d.hdr[1]&0x80 != 0 {
				need += 4 // the masking key
			}
		}
		if len(d.hdr) == need {
			break
		}
		n := min(need-len(d.hdr), len(data)-used)
		if n == 0 {
			return used, nil
		}
		d.hdr = append(d.hdr, data[used:used+n]...)
		used += n
	}
	h := d.hdr
	d.hdr = d.hdr[:0]
	f := wsFrame{Opcode: h[0] & 0x0f, Fin: h[0]&0x80 != 0, Masked: h[1]&0x80 != 0}
	switch n := h[1] & 0x7f; n {
	case 126:
		f.Length = int64(binary.BigEndian.Uint16(h[2:]))
	case 127:
		n := binary.BigEndian.Uint64(h[2:])
		if n >= 1<<63 {
			return 0, fmt.Errorf("invalid frame header %x (length too large)", h)
		}
		f.Length = int64(n)
	default:
		f.Length = int64(n)
	}
	if f.Masked {
		copy(d.key[:], h[len(h)-4:])
	}
	rsv := h[0] & 0x70
	isData := f.Opcode < wsClose
	var why string
	switch {
	case f.Opcode > wsBinary && f.Opcode != wsClose && f.Opcode != wsPing && f.Opcode != wsPong:
		why = "reserved opcode"
	case !isData && (!f.Fin || f.Length > maxWSControl):
		why = "a control frame fragmented or longer than 125 bytes"
	case rsv != 0 && !d.otherExt && (rsv != 0x40 || !d.deflate || f.Opcode == wsContinuation || !isData):
		why = "reserved bits set"
	case f.Opcode == wsContinuation && d.msg == 0:
		why = "a continuation frame without a message to continue"
	case isData && f.Opcode != wsContinuation && d.msg != 0:
		why = "a new message before the last one ended"
	}
	if why != "" {
		return 0, fmt.Errorf("invalid frame header %x (%s)", h, why)
	}
	if f.Opcode == wsText || f.Opcode == wsBinary {
		d.msg, d.msgSeen = f.Opcode, 0
		d.msgCompressed = d.deflate && rsv&0x40 != 0
		d.deflated, d.msgErr = nil, ""
	}
	if isData {
		f.Message, f.Compressed = d.msg, d.msgCompressed
	}
	d.f, d.inFrame, d.got = f, true, 0
	return used, nil
}

// frame returns the item for the frame being read, in the call at hand.
func (d *wsDir) frame(continued bool) wsFrame {
	f := d.f
	f.Continued = continued
	if f.Opcode < wsClose {
		f.Offset = d.msgSeen
	}
	return f
}

// payload reads the next bytes of the frame's payload, for f, the frame's
// item in this call.
func (d *wsDir) payload(f *wsFrame, b []byte) {
	if d.f.Masked && len(b) > 0 {
		u := make([]byte, len(b))
		at := int(d.got % 4)
		for i, c := range b {
			u[i] = c ^ d.key[(at+i)%4]
		}
		b = u
	}
	d.got += int64(len(b))
	if d.f.Opcode >= wsClose {
		d.ctrl = append(d.ctrl, b...)
		return
	}
	f.Data = b
	d.msgSeen += int64(len(b))
	if d.msgCompressed && d.msgErr == "" {
		if len(d.deflated)+len(b) > maxWSDeflated {
			d.msgErr, d.deflated = fmt.Sprintf("compressed message larger than %d MiB", maxWSDeflated>>20), nil
		} else {
			d.deflated = append(d.deflated, b...)
		}
	}
}

// finish ends the frame being read, whose item in this call is f.
func (d *wsDir) finish(f *wsFrame) {
	f.Complete, d.inFrame = true, false
	switch {
	case d.f.Opcode >= wsClose:
		f.Data, d.ctrl = d.ctrl, nil
		if f.Opcode == wsClose && len(f.Data) >= 2 {
			f.CloseCode, f.CloseReason = int(binary.BigEndian.Uint16(f.Data)), string(f.Data[2:])
		}
	case d.f.Fin:
		if d.msgCompressed {
			f.Body = d.inflate()
		}
		d.msg, d.msgCompressed, d.deflated = 0, false, nil
	}
}

// inflate decompresses the message that just ended. With context
// takeover, the sender's window carries over from message to message, so
// the end of what earlier ones decompressed to is the decompressor's
// dictionary; and once a message couldn't be decompressed, the next ones
// may refer back into what's missing, which the decompressor finds (a
// distance further back than its dictionary goes).
func (d *wsDir) inflate() bodyPart {
	part := bodyPart{Encoding: permessageDeflate}
	if d.msgErr != "" {
		part.Err, d.window, d.windowLost = d.msgErr, nil, d.takeover
		return part
	}
	var dict []byte
	if d.takeover {
		dict = d.window
	}
	r := flate.NewReaderDict(io.MultiReader(bytes.NewReader(d.deflated), bytes.NewReader(deflateEnd)), dict)
	out, err := io.ReadAll(io.LimitReader(r, maxDecodedBody+1))
	if err == nil && len(out) > maxDecodedBody {
		out, err = out[:maxDecodedBody], errBodyTooLarge
	}
	part.Decoded = out
	if err != nil {
		part.Err = "can't decompress: " + err.Error()
		var corrupt flate.CorruptInputError
		if d.windowLost && errors.As(err, &corrupt) {
			part.Err = "it refers back to an earlier message that couldn't be decompressed"
		}
		d.window, d.windowLost = nil, d.takeover
		return part
	}
	if d.takeover {
		d.window = keepWindow(d.window, out)
	}
	return part
}

// keepWindow returns the last wsWindow bytes of window followed by out.
func keepWindow(window, out []byte) []byte {
	if len(out) >= wsWindow {
		return append([]byte(nil), out[len(out)-wsWindow:]...)
	}
	window = append(window, out...)
	if extra := len(window) - wsWindow; extra > 0 {
		window = window[:copy(window, window[extra:])]
	}
	return window
}

// lose skips n bytes of the frame being read that weren't captured, for
// the reason why; frames are the call's frames so far.
func (d *wsDir) lose(n int, why string, frames []wsFrame) ([]wsFrame, error) {
	switch {
	case !d.inFrame:
		return frames, fmt.Errorf("bytes of a frame header weren't captured (%s)", why)
	case int64(n) > d.f.Length-d.got:
		return frames, fmt.Errorf("bytes after a frame weren't captured (%s)", why)
	case d.f.Opcode >= wsClose:
		return frames, fmt.Errorf("bytes of a control frame weren't captured (%s)", why)
	}
	d.got += int64(n)
	d.msgSeen += int64(n)
	if d.msgCompressed && d.msgErr == "" {
		d.msgErr, d.deflated = fmt.Sprintf("bytes of the message weren't captured (%s)", why), nil
	}
	if d.got == d.f.Length {
		if k := len(frames); k == 0 || frames[k-1].Complete {
			frames = append(frames, d.frame(true))
		}
		d.finish(&frames[len(frames)-1])
	}
	return frames, nil
}

// startsMessage reports whether the frame is a message's first, with its
// header in this event.
func (f wsFrame) startsMessage() bool {
	return (f.Opcode == wsText || f.Opcode == wsBinary) && !f.Continued
}

// endsMessage reports whether the frame's payload ends in this event and
// ends a message, or is a control frame's.
func (f wsFrame) endsMessage() bool {
	return f.Complete && f.Fin
}

// housekeeping reports whether the frame only keeps the connection going
// (a ping or a pong), or says nothing on its own: a data frame's header
// without any of its payload.
func (f wsFrame) housekeeping() bool {
	switch f.Opcode {
	case wsPing, wsPong:
		return true
	case wsClose:
		return !f.Complete
	}
	return !f.Complete && len(f.Data) == 0
}

// housekeeping reports whether a segment's WebSocket frames only keep the
// connection going; false if it has none.
func (p *wsPart) housekeeping() bool {
	if p == nil || p.Err != "" {
		return false
	}
	for _, f := range p.Frames {
		if !f.housekeeping() {
			return false
		}
	}
	return true
}

// noteLost adds the lost-calls note (see lostCheck) to why decoding
// stopped, if it did, and bytes went missing for some other reason than a
// full ring buffer, which it says already.
func noteLost(segs []http1Segment, l *lostCheck) {
	for _, s := range segs {
		if s.ws != nil && s.ws.Err != "" && !strings.Contains(s.ws.Err, "ring buffer") {
			s.ws.Err += l.note()
		}
	}
}

var wsOpcodes = map[byte]string{wsContinuation: "continuation", wsText: "text", wsBinary: "binary",
	wsClose: "close", wsPing: "ping", wsPong: "pong"}

func wsOpcodeName(op byte) string {
	if name, ok := wsOpcodes[op]; ok {
		return name
	}
	return fmt.Sprintf("opcode %#x", op)
}

// wsCloseCodes names the status codes of RFC 6455, section 7.4.1, and
// those registered with IANA since.
var wsCloseCodes = map[int]string{
	1000: "normal closure", 1001: "going away", 1002: "protocol error", 1003: "unsupported data",
	1007: "invalid payload data", 1008: "policy violation", 1009: "message too big",
	1010: "mandatory extension", 1011: "internal error", 1012: "service restart",
	1013: "try again later", 1014: "bad gateway",
}

// describe sums up a control frame on one line.
func (f wsFrame) describe() string {
	name := wsOpcodeName(f.Opcode)
	switch {
	case !f.Complete:
		return fmt.Sprintf("%s length=%d", name, f.Length)
	case f.Opcode == wsClose && f.CloseCode == 0:
		return "close (no status code)"
	case f.Opcode == wsClose:
		s := fmt.Sprintf("close %d", f.CloseCode)
		if n := wsCloseCodes[f.CloseCode]; n != "" {
			s += " (" + n + ")"
		}
		if f.CloseReason != "" {
			s += ": " + f.CloseReason
		}
		return s
	case len(f.Data) == 0:
		return name
	case utf8.Valid(f.Data):
		return fmt.Sprintf("%s %q", name, f.Data)
	}
	return fmt.Sprintf("%s 0x%x", name, f.Data)
}

// wsRuns groups the frames to show into runs: a message's data frames in
// an event are shown as one (some libraries send a frame per write, and
// more to end a compressed message), a control frame on its own. Unless
// verbose, pings and pongs are left out.
func wsRuns(frames []wsFrame, verbose bool) [][]wsFrame {
	var runs [][]wsFrame
	for _, f := range frames {
		if !verbose && f.housekeeping() {
			continue
		}
		if n := len(runs); n > 0 && f.Opcode < wsClose && !f.startsMessage() {
			if last := runs[n-1]; last[0].Opcode < wsClose && !last[len(last)-1].endsMessage() {
				runs[n-1] = append(last, f)
				continue
			}
		}
		runs = append(runs, []wsFrame{f})
	}
	return runs
}

// wsMessage is what a run of a message's data frames carries.
type wsMessage struct {
	name   string // its type, and whether it started in an earlier event
	length int64  // the frames' payload lengths
	data   []byte // their payload bytes in the event
	offset int64  // the message's payload bytes before data
	ends   bool
	body   bodyPart // for a compressed message, on the run that ends it
}

func newWSMessage(run []wsFrame) wsMessage {
	first, last := run[0], run[len(run)-1]
	m := wsMessage{name: wsOpcodeName(first.Message), offset: first.Offset, ends: last.endsMessage(), body: last.Body}
	if len(run) == 1 && first.Opcode == wsContinuation { // a fragment
		m.name = "continuation (" + m.name + ")"
	}
	if first.Continued || len(run) > 1 && first.Opcode == wsContinuation {
		m.name += " (continued)"
	}
	for _, f := range run {
		m.length += f.Length
		m.data = append(m.data, f.Data...)
	}
	if len(run) == 1 {
		m.data = first.Data
	}
	return m
}

// wsTitle is a run of data frames' line in the text output: the frame's
// type, length and flags, or for several, the message's.
func wsTitle(run []wsFrame) string {
	first, last := run[0], run[len(run)-1]
	var line string
	if len(run) == 1 {
		line = fmt.Sprintf("%s length=%d", wsOpcodeName(first.Opcode), first.Length)
		if first.Opcode == wsContinuation {
			line = fmt.Sprintf("continuation (%s) length=%d", wsOpcodeName(first.Message), first.Length)
		}
		if first.Continued {
			line += " (continued)"
		}
	} else {
		m := newWSMessage(run)
		line = fmt.Sprintf("%s length=%d in %d frames", m.name, m.length, len(run))
	}
	var flags []string
	if last.Fin {
		flags = append(flags, "FIN")
	}
	if first.Compressed {
		flags = append(flags, "compressed")
	}
	if len(flags) > 0 {
		line += " [" + strings.Join(flags, ",") + "]"
	}
	return line
}

// writeWebSocket prints an event's WebSocket frames: data frames' payloads
// as bodies are (text up to maxBodyShown bytes into a message, binary data
// described), compressed messages once decompressed, control frames on a
// line each. Pings and pongs are left out unless Options.Verbose is set.
func (t *Text) writeWebSocket(b *strings.Builder, p *wsPart) {
	if len(p.Frames) == 0 && p.Partial > 0 {
		b.WriteString(t.dim(fmt.Sprintf("WebSocket: %d bytes of a frame header that continues in a later call", p.Partial)) + "\n")
	}
	for _, run := range wsRuns(p.Frames, t.opts.Verbose) {
		if f := run[0]; f.Opcode >= wsClose {
			paint := t.dim // pings and pongs
			if f.Opcode == wsClose {
				paint = t.title
			}
			b.WriteString(paint("WebSocket "+escapeText([]byte(f.describe()))) + "\n")
			continue
		}
		b.WriteString(t.title("WebSocket "+wsTitle(run)) + "\n")
		m := newWSMessage(run)
		switch {
		case !run[0].Compressed:
			if len(m.data) > 0 {
				t.writeBody(b, m.data, "", m.offset, "")
			}
		case m.body.Err != "":
			b.WriteString(t.warn(fmt.Sprintf("[%s message not decoded: %s]", permessageDeflate, m.body.Err)) + "\n")
		case m.ends:
			t.writeBody(b, m.body.Decoded, "", 0, fmt.Sprintf("%s: %d bytes decoded to", permessageDeflate, m.offset+int64(len(m.data))))
		case len(m.data) > 0:
			b.WriteString(t.dim(fmt.Sprintf("[%d bytes of a compressed message, decoded at its end]", len(m.data))) + "\n")
		}
	}
	if p.Err != "" {
		b.WriteString(t.warn("["+p.Err+"]") + "\n")
	}
	if len(p.Rest) > 0 {
		t.writeBody(b, p.Rest, "", 0, "")
	}
}

// briefWebSocket describes an event's WebSocket frames: a message's size
// and the first line of its text, a control frame as in the text output.
// Unless verbose, pings and pongs are left out.
func briefWebSocket(p *wsPart, verbose bool) string {
	var parts []string
	for _, run := range wsRuns(p.Frames, verbose) {
		if run[0].Opcode >= wsClose {
			parts = append(parts, run[0].describe())
			continue
		}
		m := newWSMessage(run)
		s := fmt.Sprintf("%s %d bytes", m.name, len(m.data))
		if len(run) > 1 {
			s += fmt.Sprintf(" in %d frames", len(run))
		}
		text, offset := m.data, m.offset
		if run[0].Compressed {
			s += bodyNote(m.body)
			text, offset = m.body.Decoded, 0
		}
		if offset == 0 && len(text) > 0 && isText(text) {
			s += ": " + briefData(text)
		}
		parts = append(parts, s)
	}
	if p.Err != "" {
		parts = append(parts, p.Err)
	}
	if len(parts) == 0 {
		return "WebSocket, part of a frame"
	}
	return "WebSocket " + strings.Join(parts, "; ")
}

// bodyRefs adds the messages the frames carry to refs, for --brief's
// folding (see bodyRefs in fold.go), and says whether that's all the event
// carries: not if it starts a message, whose first call is shown.
func (p *wsPart) bodyRefs(key bodyKey, refs []bodyRef, onlyBody bool) ([]bodyRef, bool) {
	if p.Err != "" {
		onlyBody = false
	}
	for _, f := range p.Frames {
		switch {
		case f.housekeeping():
		case f.Opcode >= wsClose:
			onlyBody = false
		default:
			refs = append(refs, bodyRef{key, len(f.Data), f.endsMessage()})
			onlyBody = onlyBody && !f.startsMessage()
		}
	}
	return refs, onlyBody
}

// matches reports whether re matches the payload of a frame, as shown.
func (p *wsPart) matches(re *regexp.Regexp) bool {
	if p == nil {
		return false
	}
	for _, f := range p.Frames {
		if !f.Compressed && re.Match(f.Data) || re.Match(f.Body.Decoded) || re.MatchString(f.CloseReason) {
			return true
		}
	}
	return re.Match(p.Rest)
}

// redact returns a copy of the frames with secrets masked in their
// payloads: data frames' as the bytes of a stream that restarts with each
// message, under the keys data and decoded (for compressed messages, as
// decompressed), and control frames' each on its own.
func (p *wsPart) redact(r *redactStreams, data, decoded redactKey) *wsPart {
	if p == nil {
		return nil
	}
	out := *p
	out.Frames = make([]wsFrame, len(p.Frames))
	for i, f := range p.Frames {
		if f.startsMessage() {
			r.reset(data)
			r.reset(decoded)
		}
		switch {
		case f.Opcode >= wsClose:
			f.Data = redactText(f.Data)
			f.CloseReason = string(redactText([]byte(f.CloseReason)))
		case !f.Compressed:
			f.Data = r.text(data, f.Data)
		}
		f.Body.Decoded = r.text(decoded, f.Body.Decoded)
		out.Frames[i] = f
	}
	out.Rest = redactText(p.Rest)
	return &out
}

// jsonWSFrame is a WebSocket frame, or the part of one, in an event.
type jsonWSFrame struct {
	Opcode string `json:"opcode"` // text, binary, continuation, close, ping, pong
	// For a continuation frame, the type of its message.
	Message    string `json:"message,omitempty"`
	Fin        bool   `json:"fin,omitempty"`
	Masked     bool   `json:"masked,omitempty"`
	Compressed bool   `json:"compressed,omitempty"`
	Length     int64  `json:"length"`
	Continued  bool   `json:"continued,omitempty"`
	DataBytes  int    `json:"data_bytes,omitempty"`
	// The payload in this event, unmasked: as a string if it's valid UTF-8,
	// otherwise base64 (left out with --redact). Not for compressed
	// messages, whose decompressed payload is in Body.
	Payload       *string `json:"payload,omitempty"`
	PayloadBase64 []byte  `json:"payload_base64,omitempty"`
	CloseCode     int     `json:"close_code,omitempty"`
	CloseReason   string  `json:"close_reason,omitempty"`
	// Set on the frame whose payload ends its message, or a control frame's.
	End  bool      `json:"end,omitempty"`
	Body *jsonBody `json:"body,omitempty"`
}

// jsonWebSocket returns the WebSocket frames among an event's segments,
// and why decoding stopped, if it did.
func jsonWebSocket(segs []http1Segment, redact bool) (frames []jsonWSFrame, stopped string) {
	for _, s := range segs {
		if s.ws != nil {
			frames = append(frames, jsonWSFrames(s.ws, redact)...)
			stopped = cmpOr(stopped, s.ws.Err)
		}
	}
	return frames, stopped
}

// jsonWSFrames returns the frames of a part, for JSON; nil for none.
func jsonWSFrames(p *wsPart, redact bool) (frames []jsonWSFrame) {
	if p != nil {
		for _, f := range p.Frames {
			jf := jsonWSFrame{Opcode: wsOpcodeName(f.Opcode), Fin: f.Fin, Masked: f.Masked, Compressed: f.Compressed,
				Length: f.Length, Continued: f.Continued, DataBytes: len(f.Data), End: f.endsMessage(),
				CloseCode: f.CloseCode, CloseReason: f.CloseReason, Body: newJSONBody(f.Body)}
			if f.Opcode == wsContinuation {
				jf.Message = wsOpcodeName(f.Message)
			}
			if f.Opcode != wsClose && !f.Compressed && len(f.Data) > 0 {
				switch {
				case utf8.Valid(f.Data):
					s := string(f.Data)
					jf.Payload = &s
				case !redact:
					jf.PayloadBase64 = f.Data
				}
			}
			frames = append(frames, jf)
		}
	}
	return frames
}
