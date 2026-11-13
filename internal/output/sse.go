package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Server-sent events (text/event-stream, from the HTML standard) are how
// most LLM APIs stream their answers, and how many other servers push
// updates: a response body that stays open, made of lines, each event a few
// "field: value" lines (event, data, id, retry) ended by a blank line. Lines
// starting with a colon are comments, which servers send every so often to
// keep the connection open. The body may come over HTTP/1.1 (usually
// chunked), HTTP/2 or HTTP/3, and be compressed; events are read from the
// body as decoded, and can be split across calls or share one.
//
// Events are shown as sent rather than as a browser's EventSource
// dispatches them: one without data, or with only comments, is shown too.

// maxSSEEvent bounds how much of an event is kept: its data, comments and
// fields. The rest of a larger one is counted, not kept.
const maxSSEEvent = 1 << 20

// sseEvent is an event a piece of a body completed.
type sseEvent struct {
	Type     string // the event field; empty if it had none ("message", to EventSource)
	ID       string
	HasID    bool
	Retry    int // the retry field, in milliseconds
	HasRetry bool
	Data     string // the data fields' values, joined by newlines
	HasData  bool
	Comments []string // without their colon
	Size     int      // the event's bytes in the body, its blank line included
	// Cut is set on an event larger than maxSSEEvent, of which only that
	// much is kept; Incomplete on one the body ended in, before its blank
	// line.
	Cut        bool
	Incomplete bool
}

// commentOnly reports whether an event is only comments: a keep-alive.
func (e sseEvent) commentOnly() bool {
	return e.Type == "" && !e.HasID && !e.HasRetry && !e.HasData
}

// isEventStream reports whether a content type is text/event-stream.
func isEventStream(contentType string) bool {
	return strings.EqualFold(mediaType(contentType), "text/event-stream")
}

// sseStream reads the events of one body.
type sseStream struct {
	encoded bool // the body has a Content-Encoding: events are read from what it decodes to
	stopped bool // decoding the body stopped, so the rest can't be read
	started bool // the body's first bytes were read, past a byte order mark
	bom     int  // bytes of a byte order mark read so far
	line    []byte
	crEnded bool // the last line ended with CR: an LF next is part of its end
	resync  bool // bytes went missing: skip to the next blank line
	ev      sseEvent
	data    []byte
	kept    int  // bytes kept of the event, counted against maxSSEEvent
	any     bool // the event has a field or comment so far
}

func newSSEStream(encoded bool) *sseStream {
	return &sseStream{encoded: encoded}
}

// feed reads the next piece of the body: payload, its bytes as sent, and
// part, what they decoded to if the body has a Content-Encoding. last is set
// on the piece that ends the body. It returns the events the piece
// completes, and whether it was read as events, which it isn't once the
// body's decoding has stopped: it's then shown as sent.
func (s *sseStream) feed(payload []byte, part bodyPart, last bool) ([]sseEvent, bool) {
	if s == nil || s.stopped {
		return nil, false
	}
	b := payload
	if s.encoded {
		b = part.Decoded
		if part.Err != "" || part.Encoding == "" {
			s.stopped = true // what was decoded is read; the rest can't be
		}
	}
	return s.add(b, last && !s.stopped), true
}

// add reads the next bytes of the stream, ending it if last is set.
func (s *sseStream) add(b []byte, last bool) []sseEvent {
	var out []sseEvent
	// A byte order mark may start the stream, and be split between calls.
	for bom := "\xef\xbb\xbf"; !s.started && len(b) > 0; {
		if b[0] != bom[s.bom] {
			s.started = true
			break
		}
		b = b[1:]
		if s.bom++; s.bom == len(bom) {
			s.started = true
		}
	}
	for len(b) > 0 {
		if s.crEnded {
			s.crEnded = false
			if b[0] == '\n' { // CRLF, split between calls
				b = b[1:]
				s.ev.Size++
				continue
			}
		}
		i := bytes.IndexAny(b, "\r\n")
		if i < 0 {
			s.appendLine(b)
			s.ev.Size += len(b)
			break
		}
		s.appendLine(b[:i])
		s.ev.Size += i + 1
		s.crEnded = b[i] == '\r'
		b = b[i+1:]
		if ev, ok := s.endLine(); ok {
			out = append(out, ev)
		}
	}
	if last {
		if len(s.line) > 0 { // a last line without its line break
			if ev, ok := s.endLine(); ok {
				out = append(out, ev)
			}
		}
		if s.any && !s.resync {
			ev := s.dispatch()
			ev.Incomplete = true
			out = append(out, ev)
		}
		s.clear()
	}
	return out
}

// appendLine adds bytes to the line being read, up to maxSSEEvent of the
// event's.
func (s *sseStream) appendLine(p []byte) {
	if room := maxSSEEvent - s.kept - len(s.line); room < len(p) {
		p = p[:max(room, 0)]
		if !s.resync {
			s.ev.Cut = true
		}
	}
	s.line = append(s.line, p...)
}

// endLine reads the line that just ended, and returns the event it ends, if
// it's blank.
func (s *sseStream) endLine() (sseEvent, bool) {
	line := s.line
	s.line = s.line[:0]
	if s.resync {
		if len(line) == 0 {
			s.resync = false
			s.clear()
		}
		return sseEvent{}, false
	}
	if len(line) == 0 {
		if !s.any { // blank lines between events
			s.clear()
			return sseEvent{}, false
		}
		return s.dispatch(), true
	}
	s.kept += len(line)
	if line[0] == ':' {
		s.ev.Comments = append(s.ev.Comments, string(bytes.TrimPrefix(line[1:], []byte(" "))))
		s.any = true
		return sseEvent{}, false
	}
	name, value, _ := bytes.Cut(line, []byte(":"))
	value = bytes.TrimPrefix(value, []byte(" "))
	switch string(name) {
	case "event":
		s.ev.Type, s.any = string(value), true
	case "data":
		s.data = append(append(s.data, value...), '\n')
		s.ev.HasData, s.any = true, true
	case "id":
		if bytes.IndexByte(value, 0) < 0 { // the standard ignores an id with NUL in it
			s.ev.ID, s.ev.HasID, s.any = string(value), true, true
		}
	case "retry":
		if n, err := strconv.Atoi(string(value)); err == nil && len(value) > 0 && value[0] >= '0' && value[0] <= '9' {
			s.ev.Retry, s.ev.HasRetry, s.any = n, true, true
		}
	default: // other fields are ignored
	}
	return sseEvent{}, false
}

// dispatch returns the event read so far, and starts the next.
func (s *sseStream) dispatch() sseEvent {
	ev := s.ev
	ev.Data = string(bytes.TrimSuffix(s.data, []byte("\n")))
	s.clear()
	return ev
}

func (s *sseStream) clear() {
	s.ev = sseEvent{}
	s.data = s.data[:0]
	if cap(s.data) > 64<<10 { // let a large event's array go
		s.data = nil
	}
	s.kept, s.any = 0, false
}

// lose accounts for bytes of the body that weren't captured: the event
// they were part of is dropped, and reading starts again after the next
// blank line.
func (s *sseStream) lose() {
	if s == nil {
		return
	}
	s.clear()
	s.line, s.crEnded, s.resync = s.line[:0], false, true
}

// sseEvents counts the events that aren't only comments.
func sseEvents(events []sseEvent) int {
	n := 0
	for _, e := range events {
		if !e.commentOnly() {
			n++
		}
	}
	return n
}

// sseKeepAlive reports whether a piece of an event stream only carries
// comments, as servers send to keep the connection open.
func sseKeepAlive(isSSE bool, events []sseEvent, part bodyPart) bool {
	return isSSE && part.Err == "" && len(events) > 0 && sseEvents(events) == 0
}

// compactJSON returns b without the spaces between its tokens if it's a
// JSON object or array, else nil.
func compactJSON(b []byte) []byte {
	t := bytes.TrimLeft(b, " \t\r\n")
	if len(t) == 0 || t[0] != '{' && t[0] != '[' {
		return nil
	}
	var out bytes.Buffer
	if json.Compact(&out, b) != nil {
		return nil
	}
	return out.Bytes()
}

// sseTitle is the line an event is shown under.
func sseTitle(e sseEvent) string {
	s := "SSE event " + escapeText([]byte(cmpOr(e.Type, "message")))
	if e.HasID {
		id := escapeText([]byte(e.ID))
		if id == "" || strings.ContainsAny(id, " ,") {
			id = strconv.Quote(e.ID)
		}
		s += ", id " + id
	}
	if e.HasRetry {
		s += fmt.Sprintf(", retry %dms", e.Retry)
	}
	if e.Incomplete {
		s += " (the body ended before the event did)"
	}
	return s
}

// writeSSE prints the server-sent events that a piece of a body completed:
// piece as sent, starting offset bytes into the body, and part, what it
// decoded to if the body has a Content-Encoding; ends is set if the piece
// ends the body. Each event's data is shown up to maxBodyShown bytes, unless
// Options.Full is set, JSON without its spaces. Comments are shown with
// Options.Verbose.
func (t *Text) writeSSE(b *strings.Builder, events []sseEvent, piece []byte, offset int64, part bodyPart, contentType string, ends bool) {
	if part.Err != "" { // says why decoding stopped, and shows the piece as sent
		t.writeBodyPart(b, piece, offset, part, contentType)
	}
	comments := func(e sseEvent) {
		if t.opts.Verbose {
			for _, c := range e.Comments {
				b.WriteString(t.dim("SSE comment: "+escapeText([]byte(c))) + "\n")
			}
		}
	}
	for _, e := range events {
		if e.commentOnly() {
			comments(e)
			continue
		}
		b.WriteString(t.title(sseTitle(e)) + "\n")
		comments(e)
		data := []byte(e.Data)
		if c := compactJSON(data); c != nil {
			data = c
		}
		if len(data) > 0 {
			limit := len(data)
			if !t.opts.Full {
				limit = maxBodyShown
			}
			t.writeLimited(b, data, limit)
		}
		if e.Cut {
			b.WriteString(t.dim(fmt.Sprintf("[an event of %d bytes; only its first %d KiB are kept]", e.Size, maxSSEEvent>>10)) + "\n")
		}
	}
	if len(events) > 0 || part.Err != "" {
		return
	}
	n := len(piece)
	if part.Encoding != "" {
		n = len(part.Decoded)
	}
	switch {
	case n > 0:
		b.WriteString(t.dim(fmt.Sprintf("[%d bytes of an event, shown when it ends]", n)) + "\n")
	case ends:
		b.WriteString(t.dim("[end of the event stream]") + "\n")
	case part.Encoding != "" && len(piece) > 0:
		b.WriteString(t.dim(fmt.Sprintf("[%s: %d bytes, no output]", part.Encoding, len(piece))) + "\n")
	}
}

// briefSSE describes the events in a piece of a body, or returns "" if it
// completed none (comments aside).
func briefSSE(events []sseEvent) string {
	var parts []string
	for _, e := range events {
		if e.commentOnly() {
			continue
		}
		p := cmpOr(e.Type, "message")
		if e.HasData {
			data := []byte(e.Data)
			if len(data) > 4*maxSummary { // it's clipped anyway
				data = data[:4*maxSummary]
			} else if c := compactJSON(data); c != nil {
				data = c
			}
			p += " " + string(data)
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return ""
	}
	return "SSE " + strings.Join(parts, "; ")
}

// jsonSSEEvent is an event in the JSON output; see docs/usage.md.
type jsonSSEEvent struct {
	Event      string   `json:"event,omitempty"`
	ID         *string  `json:"id,omitempty"`
	Retry      *int     `json:"retry,omitempty"`
	Data       *string  `json:"data,omitempty"`
	Comments   []string `json:"comments,omitempty"`
	Bytes      int      `json:"bytes"`
	Truncated  bool     `json:"truncated,omitempty"`
	Incomplete bool     `json:"incomplete,omitempty"`
}

func jsonSSE(events []sseEvent) []jsonSSEEvent {
	var out []jsonSSEEvent
	for _, e := range events {
		j := jsonSSEEvent{Event: e.Type, Comments: e.Comments, Bytes: e.Size, Truncated: e.Cut, Incomplete: e.Incomplete}
		if e.HasID {
			j.ID = &e.ID
		}
		if e.HasRetry {
			j.Retry = &e.Retry
		}
		if e.HasData {
			j.Data = &e.Data
		}
		out = append(out, j)
	}
	return out
}

// redactSSE returns copies of events with secrets masked in their data,
// IDs and comments. Each event is whole, so nothing is split across calls.
func redactSSE(events []sseEvent) []sseEvent {
	if events == nil {
		return nil
	}
	out := make([]sseEvent, len(events))
	for i, e := range events {
		e.Data = string(redactText([]byte(e.Data)))
		e.ID = string(redactText([]byte(e.ID)))
		e.Comments = redactLines(e.Comments)
		out[i] = e
	}
	return out
}

// sseMatches reports whether re matches something of what events show.
func sseMatches(re *regexp.Regexp, events []sseEvent) bool {
	return slices.ContainsFunc(events, func(e sseEvent) bool {
		return re.MatchString(e.Data) || re.MatchString(e.Type) || slices.ContainsFunc(e.Comments, re.MatchString)
	})
}
