package output

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// HAR collects the HTTP requests and responses it's given into a HAR 1.2
// log (http://www.softwareishard.com/blog/har-12-spec/), which browsers'
// developer tools and other HAR viewers open, and writes it when it's
// closed: HAR is one JSON document, not a stream. Requests and responses
// are paired in order on an HTTP/1.x connection, and by stream on HTTP/2
// and HTTP/3. Bodies are shown decompressed, up to maxHARBody each.
type HAR struct {
	mu      sync.Mutex // Print, WriteFile and Close may run at once
	dirty   bool       // entries changed since the last WriteFile
	w       io.Writer
	dec     decoders
	version string
	entries []*harEntry
	conns   map[harConnKey]*harConn
	filter  *HTTPFilter
	redact  bool
	// maxKept is how many entries are kept, bodies and all, for the log:
	// maxHAREntries, or 0 for Requests, which only needs each one's end.
	maxKept int
	// done, if set, is called once for each exchange whose response has
	// ended: an HTTP/2 or HTTP/3 stream's end or reset, or an HTTP/1.x
	// response's last body byte.
	done func(*harEntry)
	// progress, if set, is called after each event that carried a
	// response's headers or some of its body but didn't end it, with the
	// event's time.
	progress func(*harEntry, time.Time)
	touched  []*harEntry // by the event being printed, for progress
}

// maxHARBody bounds how much of a body a HAR entry keeps, and maxHAREntries
// how many entries; later ones are followed, to pair what follows, but not
// kept.
const (
	maxHARBody    = 4 << 20
	maxHAREntries = 100000
	maxHARConns   = 4096
)

// harConnKey is a connection (see connKey).
type harConnKey struct {
	pid  uint32
	tcp  uint64  // the TLS connection (connOf), for HTTP/1.x and HTTP/2
	quic quicKey // for HTTP/3
}

// harConn is what's open on a connection: HTTP/1.x requests waiting for
// their responses, in order, and the exchange each direction's bytes belong
// to; or HTTP/2's and HTTP/3's exchanges, by stream.
type harConn struct {
	queue   []*harEntry
	current map[tracer.Direction]*harEntry
	streams streams[*harEntry]
}

type harEntry struct {
	start, end time.Time
	version    string // "HTTP/1.1", "HTTP/2", "HTTP/3"
	reqDir     tracer.Direction
	req, resp  harMessage
	process    string
	pid        uint32
	container  string
	server     netip.AddrPort
	conn       string
	respAt     time.Time // when the response's headers arrived
	kept       bool      // in HAR.entries
	ended      bool      // done was called for it
	reset      bool      // its stream was reset
	announced  bool      // Requests printed it as streaming
	// tunnel is, for an HTTP/2 or HTTP/3 CONNECT that a 2xx response
	// accepted, what its stream carries since: the extended CONNECT's
	// :protocol (e.g. websocket), else "tunnel".
	tunnel string
	// ws is what's kept of the WebSocket messages or server-sent events
	// that follow the request (har_websocket.go).
	ws *harWS
}

type harMessage struct {
	seen      bool
	method    string
	target    string // request target, or :path
	authority string // Host, or :authority
	scheme    string
	status    int
	reason    string
	version   string
	headers   [][2]string
	body      []byte // as decoded
	bodySize  int    // as sent, HTTP/1.1's chunked framing included
	length    int    // the body's own bytes (Content-Length's), framing left out
	decoded   int    // the body's length decoded, if it has a Content-Encoding, kept or not
	encoding  string // its Content-Encoding, if any
	events    int    // server-sent events in a text/event-stream body
	truncated bool
}

// NewHAR returns a printer that writes a HAR log to w when it's closed.
// version is snoopy's, for the log's creator. Of opts, only Redact and
// Filter apply, both to whole entries: secrets are masked in whole bodies,
// however they were split across calls.
func NewHAR(w io.Writer, version string, opts Options) *HAR {
	h := &HAR{w: w, version: version, conns: map[harConnKey]*harConn{}, filter: opts.Filter, redact: opts.Redact,
		maxKept: maxHAREntries}
	opts.Warn, opts.Filter, opts.Redact = nil, nil, false
	h.dec = newDecoders(opts)
	return h
}

func (h *HAR) Print(ev *tracer.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	dc := h.dec.decode(ev)
	if dc.notice {
		return nil
	}
	key := connKey(ev, dc)
	c := h.conns[key]
	if c == nil {
		if len(h.conns) >= maxHARConns {
			clear(h.conns) // what's open on them stays as it is in its entries
		}
		c = &harConn{current: map[tracer.Direction]*harEntry{}}
		h.conns[key] = c
	}
	dir := ev.Function.Direction()
	h.dirty = true
	switch {
	case dc.isQUIC:
		for _, it := range dc.quic {
			switch {
			case it.HTTP3 == "HEADERS" && it.Headers != nil:
				h.headers(c, ev, dir, it.Stream, it.Headers, "HTTP/3")
			case strings.HasPrefix(it.HTTP3, "DATA"):
				h.data(c, ev, dir, it.Stream, it.Data, it.Body, it.SSE, it.WS)
			}
		}
	case dc.isHTTP2:
		for _, f := range dc.http2 {
			switch {
			case f.Headers != nil:
				h.headers(c, ev, dir, uint64(f.Stream), f.Headers, "HTTP/2")
				if f.IsSSE { // trailers ending an event stream
					h.data(c, ev, dir, uint64(f.Stream), nil, bodyPart{}, f.SSE, nil)
				}
			case f.Type == "DATA":
				h.data(c, ev, dir, uint64(f.Stream), f.Data, f.Body, f.SSE, f.WS)
			}
		}
	default:
		for _, s := range dc.http1 {
			switch {
			case s.ws != nil:
				if e := c.current[dir]; e != nil {
					e.webSocket(ev.Time, dir, s.ws)
				}
			case s.msg != nil:
				h.http1Message(c, ev, dir, s.msg, s.lateRequest)
			case s.inBody || s.body.Encoding != "":
				if e := c.current[dir]; e != nil {
					e.add(dir, s.raw, s.payload, s.body)
					e.side(dir).events += sseEvents(s.sse)
					e.sse(ev.Time, s.sse)
					e.end = ev.Time
					h.touch(e, dir)
					if dir != e.reqDir && sseDone(s.sse) {
						h.ended(e)
					}
				}
			}
			if e := c.current[dir]; s.ends && e != nil && dir != e.reqDir {
				h.ended(e)
			}
		}
	}
	// A response's end ends its exchange.
	for _, end := range streamEnds(dc) {
		if e := c.streams.get(end.id); e != nil && (end.reset || dir != e.reqDir) {
			c.streams.finish(end.id)
			e.reset = end.reset
			h.ended(e)
		}
	}
	if h.progress != nil {
		for _, e := range h.touched {
			if !e.ended {
				h.progress(e, ev.Time)
			}
		}
		h.touched = h.touched[:0]
	}
	return nil
}

// touch notes that an event carried part of an exchange's response, for
// progress.
func (h *HAR) touch(e *harEntry, dir tracer.Direction) {
	if h.progress != nil && dir != e.reqDir && !slices.Contains(h.touched, e) {
		h.touched = append(h.touched, e)
	}
}

// ended tells done, once, that an exchange's response has ended.
func (h *HAR) ended(e *harEntry) {
	if !e.ended && h.done != nil {
		e.ended = true
		h.done(e)
	}
}

// newEntry starts an entry for a request (or a response whose request
// wasn't seen) of ev's.
func (h *HAR) newEntry(ev *tracer.Event, version string, reqDir tracer.Direction) *harEntry {
	e := &harEntry{start: ev.Time, end: ev.Time, version: version, reqDir: reqDir,
		process: ev.Comm, pid: ev.PID, container: cmpOr(ev.ContainerName, shortID(ev.ContainerID)),
		conn: fmt.Sprintf("%#x", ev.ConnID)}
	// The server's end: the peer if the traced program sent the request,
	// else itself.
	if reqDir == tracer.Write {
		e.server = ev.Remote
	} else {
		e.server = ev.Local
	}
	if len(h.entries) < h.maxKept {
		h.entries = append(h.entries, e)
		e.kept = true
	}
	return e
}

// add adds bytes of a message's body, sent in direction dir: raw as sent,
// payload the body's bytes among them (without chunked framing). They're
// counted, and kept if the entry is.
func (e *harEntry) add(dir tracer.Direction, raw, payload []byte, part bodyPart) {
	m := e.side(dir)
	if e.kept {
		m.add(raw, payload, part)
		return
	}
	m.bodySize += len(raw)
	m.length += len(payload)
	m.count(part)
}

// count counts what a part of the body decoded to, if it's encoded.
func (m *harMessage) count(part bodyPart) {
	if part.Encoding != "" {
		m.encoding = part.Encoding
		m.decoded += len(part.Decoded)
	}
}

// side returns the message of the exchange that bytes sent in direction
// dir belong to.
func (e *harEntry) side(dir tracer.Direction) *harMessage {
	if dir == e.reqDir {
		return &e.req
	}
	return &e.resp
}

func (h *HAR) http1Message(c *harConn, ev *tracer.Event, dir tracer.Direction, m *httpMessage, late bool) {
	if strings.HasPrefix(m.startLine, "HTTP/") { // a response
		version, status, _ := strings.Cut(m.startLine, " ")
		code, reason, _ := strings.Cut(status, " ")
		n, _ := strconv.Atoi(code)
		if n >= 100 && n < 200 && n != 101 {
			return // an interim response; the final one is still to come
		}
		var e *harEntry
		if len(c.queue) > 0 {
			e, c.queue = c.queue[0], c.queue[1:]
		}
		if e == nil {
			e = h.newEntry(ev, version, opposite(dir))
		}
		e.resp = harMessage{seen: true, status: n, reason: reason, version: version, headers: m.headers}
		e.end, e.respAt = ev.Time, ev.Time
		c.current[dir] = e
		h.touch(e, dir)
		return
	}
	method, rest, _ := strings.Cut(m.startLine, " ")
	target, version, _ := strings.Cut(rest, " ")
	if e := c.current[opposite(dir)]; late && e != nil && !e.req.seen && e.reqDir == dir {
		// The request of the 101 before it, whose call returned later.
		e.req = harMessage{seen: true, method: method, target: target, version: version, headers: m.headers, scheme: "https",
			authority: headerValue(m.headers, "host")}
		c.current[dir] = e
		return
	}
	e := h.newEntry(ev, version, dir)
	e.req = harMessage{seen: true, method: method, target: target, version: version, headers: m.headers, scheme: "https"}
	for _, hd := range m.headers {
		if strings.EqualFold(hd[0], "host") {
			e.req.authority = hd[1]
		}
	}
	c.queue = append(c.queue, e)
	if len(c.queue) > maxQueued {
		c.queue = c.queue[1:]
	}
	c.current[dir] = e
}

func (h *HAR) headers(c *harConn, ev *tracer.Event, dir tracer.Direction, stream uint64, fields []hpack.HeaderField, version string) {
	var method, path, authority, scheme, status string
	var headers [][2]string
	for _, f := range fields {
		switch f.Name {
		case ":method":
			method = f.Value
		case ":path":
			path = f.Value
		case ":authority":
			authority = f.Value
		case ":scheme":
			scheme = f.Value
		case ":status":
			status = f.Value
		}
		headers = append(headers, [2]string{f.Name, f.Value})
	}
	e := c.streams.get(stream)
	switch {
	case method != "":
		e = h.newEntry(ev, version, dir)
		e.req = harMessage{seen: true, method: method, target: path, authority: authority, scheme: cmpOr(scheme, "https"),
			version: version, headers: headers}
		c.streams.set(stream, e)
	case status != "":
		n, _ := strconv.Atoi(status)
		if n >= 100 && n < 200 && n != 101 {
			return
		}
		if e == nil {
			e = h.newEntry(ev, version, opposite(dir))
			c.streams.set(stream, e)
		}
		e.resp = harMessage{seen: true, status: n, version: version, headers: headers}
		e.end, e.respAt = ev.Time, ev.Time
		h.touch(e, dir)
		if e.req.method == "CONNECT" && n >= 200 && n < 300 {
			// The stream is a tunnel now, as a 101 makes an HTTP/1.1
			// connection another protocol's: the exchange is done.
			e.tunnel = cmpOr(headerValue(e.req.headers, ":protocol"), "tunnel")
			h.ended(e)
		}
	case e != nil: // trailers
		m := e.side(dir)
		m.headers = append(m.headers, headers...)
		e.end = ev.Time
	}
}

func (h *HAR) data(c *harConn, ev *tracer.Event, dir tracer.Direction, stream uint64, data []byte, part bodyPart, events []sseEvent, ws *wsPart) {
	e := c.streams.get(stream)
	if e == nil {
		return
	}
	if ws != nil { // a WebSocket's frames, which are its messages, not a body
		e.webSocket(ev.Time, dir, ws)
		return
	}
	e.add(dir, data, data, part)
	e.side(dir).events += sseEvents(events)
	e.sse(ev.Time, events)
	e.end = ev.Time
	h.touch(e, dir)
	if dir != e.reqDir && sseDone(events) {
		h.ended(e)
	}
}

// add adds bytes of the message's body as sent, and what they decoded to
// if the body has a Content-Encoding.
func (m *harMessage) add(raw, payload []byte, part bodyPart) {
	m.bodySize += len(raw)
	m.length += len(payload)
	m.count(part)
	piece := payload
	if part.Encoding != "" {
		piece = part.Decoded
	}
	if room := maxHARBody - len(m.body); room < len(piece) {
		piece = piece[:max(room, 0)]
		m.truncated = true
	}
	m.body = append(m.body, piece...)
}

// redacted returns a copy of the message with secrets masked, in its whole
// body.
func (m harMessage) redacted() *harMessage {
	m.target = redactTarget(m.target)
	headers := make([][2]string, len(m.headers))
	for i, hd := range m.headers {
		headers[i] = [2]string{hd[0], redactHeader(hd[0], hd[1])}
	}
	m.headers, m.body = headers, redactText(m.body)
	return &m
}

// url returns the URL an entry's request (req, which may be redacted)
// was for: from its authority (or Host), or else the server's address.
func (e *harEntry) url(req *harMessage) url.URL {
	u := url.URL{Scheme: cmpOr(req.scheme, "https"), Host: req.authority}
	if u.Host == "" && e.server.IsValid() {
		u.Host = e.server.String()
	}
	target := cmpOr(req.target, "/")
	if parsed, err := url.ParseRequestURI(target); err == nil && parsed.IsAbs() {
		u = *parsed // an absolute target, as to a proxy
	} else {
		path, query, _ := strings.Cut(target, "?")
		u.Path, u.RawQuery = path, query
	}
	return u
}

func opposite(d tracer.Direction) tracer.Direction {
	if d == tracer.Write {
		return tracer.Read
	}
	return tracer.Write
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Close writes the log to the writer NewHAR was given, if any.
func (h *HAR) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.w == nil {
		return nil
	}
	return h.encode(h.w)
}

// WriteFile writes the log to path, if it changed since the last time:
// to a temporary file in its directory first, renamed over it, so that
// path always holds a whole log, even if snoopy is killed while writing.
func (h *HAR) WriteFile(path string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.dirty {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // if it wasn't renamed
	bw := bufio.NewWriter(f)
	err = h.encode(bw)
	err = errors.Join(err, bw.Flush(), f.Chmod(0o644), f.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	h.dirty = false
	return nil
}

// encode writes the log as one JSON document. h.mu is held.
func (h *HAR) encode(w io.Writer) error {
	type nv struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	headers := func(hs [][2]string) []nv {
		out := []nv{}
		for _, hd := range hs {
			out = append(out, nv{hd[0], hd[1]})
		}
		return out
	}
	header := func(hs [][2]string, name string) string {
		for _, hd := range hs {
			if strings.EqualFold(hd[0], name) {
				return hd[1]
			}
		}
		return ""
	}
	cookies := func(hs [][2]string, name string) []nv {
		out := []nv{}
		for _, hd := range hs {
			if !strings.EqualFold(hd[0], name) {
				continue
			}
			for _, c := range strings.Split(hd[1], ";") {
				n, v, ok := strings.Cut(strings.TrimSpace(c), "=")
				if ok {
					out = append(out, nv{n, v})
				}
				if name == "set-cookie" {
					break // the rest are attributes
				}
			}
		}
		return out
	}
	type content struct {
		Size     int    `json:"size"`
		MimeType string `json:"mimeType"`
		Text     string `json:"text,omitempty"`
		Encoding string `json:"encoding,omitempty"`
		Comment  string `json:"comment,omitempty"`
	}
	body := func(m *harMessage) content {
		c := content{Size: len(m.body), MimeType: header(m.headers, "content-type")}
		if utf8.Valid(m.body) {
			c.Text = string(m.body)
		} else {
			c.Text, c.Encoding = base64.StdEncoding.EncodeToString(m.body), "base64"
		}
		if m.truncated {
			c.Comment = fmt.Sprintf("only the first %d bytes kept", maxHARBody)
		}
		return c
	}
	type entry struct {
		Started  string         `json:"startedDateTime"`
		Time     float64        `json:"time"`
		Request  map[string]any `json:"request"`
		Response map[string]any `json:"response"`
		Cache    struct{}       `json:"cache"`
		Timings  map[string]any `json:"timings"`
		ServerIP string         `json:"serverIPAddress,omitempty"`
		Conn     string         `json:"connection,omitempty"`
		Process  string         `json:"_process"`
		PID      uint32         `json:"_pid"`
		Comment  string         `json:"comment,omitempty"`
		Contain  string         `json:"_container,omitempty"`
		// Chrome's (see har_websocket.go).
		ResourceType string              `json:"_resourceType,omitempty"`
		WSMessages   *[]harWSMessageJSON `json:"_webSocketMessages,omitempty"`
		SSEMessages  []harSSEEventJSON   `json:"_eventSourceMessages,omitempty"`
	}
	var entries []entry
	for _, e := range h.entries {
		req, resp := &e.req, &e.resp
		if h.filter != nil && !h.filter.match(&exchange{method: req.method, path: req.target, status: resp.status}) {
			continue
		}
		if h.redact {
			req, resp = req.redacted(), resp.redacted()
		}
		u := e.url(req)
		var query []nv
		for k, vs := range u.Query() {
			for _, v := range vs {
				query = append(query, nv{k, v})
			}
		}
		if query == nil {
			query = []nv{}
		}
		request := map[string]any{
			"method": cmpOr(req.method, "GET"), "url": u.String(), "httpVersion": cmpOr(req.version, e.version),
			"cookies": cookies(req.headers, "cookie"), "headers": headers(req.headers), "queryString": query,
			"headersSize": -1, "bodySize": req.bodySize,
		}
		if req.bodySize > 0 || len(req.body) > 0 {
			c := body(req)
			pd := map[string]any{"mimeType": c.MimeType, "text": c.Text}
			if c.Encoding != "" { // postData has no encoding of its own
				pd["comment"] = "base64"
			}
			request["postData"] = pd
		}
		response := map[string]any{
			"status": resp.status, "statusText": resp.reason, "httpVersion": cmpOr(resp.version, e.version),
			"cookies": cookies(resp.headers, "set-cookie"), "headers": headers(resp.headers), "content": body(resp),
			"redirectURL": header(resp.headers, "location"), "headersSize": -1, "bodySize": resp.bodySize,
		}
		ms := float64(e.end.Sub(e.start)) / float64(time.Millisecond)
		out := entry{
			Started: e.start.Format(time.RFC3339Nano), Time: ms, Request: request, Response: response,
			Timings: map[string]any{"send": 0, "wait": ms, "receive": 0},
			Conn:    e.conn, Process: e.process, PID: e.pid, Contain: e.container,
		}
		if e.server.IsValid() {
			out.ServerIP = e.server.Addr().String()
		}
		switch {
		case !req.seen:
			out.Comment = "the request was sent before snoopy started, or wasn't captured"
		case !resp.seen:
			out.Comment = "no response was seen"
		}
		messages, events, notes := e.ws.json(h.redact)
		if e.isWebSocket() {
			out.ResourceType = "websocket"
			if messages == nil {
				messages = []harWSMessageJSON{}
			}
			out.WSMessages = &messages
		}
		out.SSEMessages = events
		if out.Comment != "" {
			notes = append([]string{out.Comment}, notes...)
		}
		out.Comment = strings.Join(notes, "; ")
		entries = append(entries, out)
	}
	if entries == nil {
		entries = []entry{}
	}
	log := map[string]any{"log": map[string]any{
		"version": "1.2",
		"creator": map[string]string{"name": "snoopy", "version": h.version},
		"entries": entries,
	}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
