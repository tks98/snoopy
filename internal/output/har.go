package output

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
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
	w       io.Writer
	dec     decoders
	version string
	entries []*harEntry
	conns   map[harConnKey]*harConn
	filter  *HTTPFilter
}

// maxHARBody bounds how much of a body a HAR entry keeps, and maxHAREntries
// how many entries; later ones are counted, not kept.
const (
	maxHARBody    = 4 << 20
	maxHAREntries = 100000
	maxHARConns   = 4096
)

type harConnKey struct {
	tcp  uint64  // the TLS connection (connOf), for HTTP/1.x and HTTP/2
	quic quicKey // for HTTP/3
}

// harConn is what's open on a connection: HTTP/1.x requests waiting for
// their responses, in order, and the exchange each direction's bytes belong
// to; or HTTP/2's and HTTP/3's exchanges, by stream.
type harConn struct {
	queue   []*harEntry
	current map[tracer.Direction]*harEntry
	streams map[uint64]*harEntry
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
	bodySize  int    // as sent
	truncated bool
}

// NewHAR returns a printer that writes a HAR log to w when it's closed.
// version is snoopy's, for the log's creator. Of opts, only Redact and
// Filter apply, the filter to whole entries.
func NewHAR(w io.Writer, version string, opts Options) *HAR {
	filter := opts.Filter
	opts.Warn, opts.Filter = nil, nil // the filter applies to whole entries
	return &HAR{w: w, dec: newDecoders(opts), version: version, conns: map[harConnKey]*harConn{}, filter: filter}
}

func (h *HAR) Print(ev *tracer.Event) error {
	dc := h.dec.decode(ev)
	if dc.notice {
		return nil
	}
	key := harConnKey{tcp: connOf(ev)}
	if dc.isQUIC {
		key = harConnKey{quic: dc.quicConn}
	}
	c := h.conns[key]
	if c == nil {
		if len(h.conns) >= maxHARConns {
			clear(h.conns) // what's open on them stays as it is in its entries
		}
		c = &harConn{current: map[tracer.Direction]*harEntry{}, streams: map[uint64]*harEntry{}}
		h.conns[key] = c
	}
	dir := ev.Function.Direction()
	switch {
	case dc.isQUIC:
		for _, it := range dc.quic {
			switch {
			case it.HTTP3 == "HEADERS" && it.Headers != nil:
				h.headers(c, ev, dir, it.Stream, it.Headers, "HTTP/3")
			case strings.HasPrefix(it.HTTP3, "DATA"):
				h.data(c, ev, dir, it.Stream, it.Data, it.Body)
			}
		}
	case dc.isHTTP2:
		for _, f := range dc.http2 {
			switch {
			case f.Headers != nil:
				h.headers(c, ev, dir, uint64(f.Stream), f.Headers, "HTTP/2")
			case f.Type == "DATA":
				h.data(c, ev, dir, uint64(f.Stream), f.Data, f.Body)
			}
		}
	default:
		for _, s := range dc.http1 {
			switch {
			case s.msg != nil:
				h.http1Message(c, ev, dir, s.msg)
			case s.inBody || s.body.Encoding != "":
				if e := c.current[dir]; e != nil {
					e.side(dir).add(s.raw, s.body)
					e.end = ev.Time
				}
			}
		}
	}
	return nil
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
	if len(h.entries) < maxHAREntries {
		h.entries = append(h.entries, e)
	}
	return e
}

// side returns the message of the exchange that bytes sent in direction
// dir belong to.
func (e *harEntry) side(dir tracer.Direction) *harMessage {
	if dir == e.reqDir {
		return &e.req
	}
	return &e.resp
}

func (h *HAR) http1Message(c *harConn, ev *tracer.Event, dir tracer.Direction, m *httpMessage) {
	if strings.HasPrefix(m.startLine, "HTTP/") { // a response
		var e *harEntry
		for len(c.queue) > 0 && e == nil {
			e, c.queue = c.queue[0], c.queue[1:]
		}
		version, status, _ := strings.Cut(m.startLine, " ")
		code, reason, _ := strings.Cut(status, " ")
		n, _ := strconv.Atoi(code)
		if n >= 100 && n < 200 && n != 101 {
			if e != nil { // an interim response; the final one is still to come
				c.queue = append([]*harEntry{e}, c.queue...)
			}
			return
		}
		if e == nil {
			e = h.newEntry(ev, version, opposite(dir))
		}
		e.resp = harMessage{seen: true, status: n, reason: reason, version: version, headers: m.headers}
		e.end = ev.Time
		c.current[dir] = e
		return
	}
	method, rest, _ := strings.Cut(m.startLine, " ")
	target, version, _ := strings.Cut(rest, " ")
	e := h.newEntry(ev, version, dir)
	e.req = harMessage{seen: true, method: method, target: target, version: version, headers: m.headers, scheme: "https"}
	for _, hd := range m.headers {
		if strings.EqualFold(hd[0], "host") {
			e.req.authority = hd[1]
		}
	}
	c.queue = append(c.queue, e)
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
	e := c.streams[stream]
	switch {
	case method != "":
		e = h.newEntry(ev, version, dir)
		e.req = harMessage{seen: true, method: method, target: path, authority: authority, scheme: cmpOr(scheme, "https"),
			version: version, headers: headers}
		c.streams[stream] = e
	case status != "":
		n, _ := strconv.Atoi(status)
		if n >= 100 && n < 200 && n != 101 {
			return
		}
		if e == nil {
			e = h.newEntry(ev, version, opposite(dir))
			c.streams[stream] = e
		}
		e.resp = harMessage{seen: true, status: n, version: version, headers: headers}
		e.end = ev.Time
	case e != nil: // trailers
		m := e.side(dir)
		m.headers = append(m.headers, headers...)
		e.end = ev.Time
	}
}

func (h *HAR) data(c *harConn, ev *tracer.Event, dir tracer.Direction, stream uint64, data []byte, part bodyPart) {
	e := c.streams[stream]
	if e == nil {
		return
	}
	e.side(dir).add(data, part)
	e.end = ev.Time
}

// add adds bytes of the message's body as sent, and what they decoded to
// if the body has a Content-Encoding.
func (m *harMessage) add(raw []byte, part bodyPart) {
	m.bodySize += len(raw)
	piece := raw
	if part.Encoding != "" {
		piece = part.Decoded
	}
	if room := maxHARBody - len(m.body); room < len(piece) {
		piece = piece[:max(room, 0)]
		m.truncated = true
	}
	m.body = append(m.body, piece...)
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

// Close writes the log.
func (h *HAR) Close() error {
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
	}
	var entries []entry
	for _, e := range h.entries {
		req, resp := &e.req, &e.resp
		if h.filter != nil && !h.filter.match(&exchange{method: req.method, path: req.target, status: resp.status}) {
			continue
		}
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
	enc := json.NewEncoder(h.w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
