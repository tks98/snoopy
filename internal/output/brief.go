package output

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"
	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/internal/tracer"
)

// Brief prints one line per event, like tcpdump: the time, the process, where
// the data went, the protocol and size, and what the data holds.
//
//	06:27:36.512901 curl[5565] 192.168.5.15:41794 > 172.66.147.243:443 TLS 74: GET / HTTP/1.1, host example.com
type Brief struct {
	w    io.Writer
	h1   *http1Conns
	h2   *http2Conns
	quic *quicConns

	dim, title, write, read, warn func(a ...any) string
}

// maxSummary bounds a line's summary, in characters.
const maxSummary = 200

// NewBrief returns a Brief printer. Colors follow color.NoColor.
func NewBrief(w io.Writer) *Brief {
	s := func(attrs ...color.Attribute) func(a ...any) string {
		return color.New(attrs...).SprintFunc()
	}
	pool := newBodyPool()
	return &Brief{
		w:     w,
		h1:    newHTTP1Conns(pool),
		h2:    newHTTP2Conns(pool),
		quic:  newQUICConns(pool),
		dim:   s(color.Faint),
		title: s(color.Bold),
		write: s(color.FgCyan),
		read:  s(color.FgGreen),
		warn:  s(color.FgYellow),
	}
}

func (b *Brief) Print(ev *tracer.Event) error {
	paint, proto := b.read, "TLS"
	if ev.Function.Direction() == tracer.Write {
		paint = b.write
	}
	if ev.Function.IsQUIC() {
		proto = "QUIC"
	}
	line := fmt.Sprintf("%s %s %s %s %d", b.dim(ev.Time.Format("15:04:05.000000")),
		b.title(fmt.Sprintf("%s[%d]", ev.Comm, ev.PID)), paint(endpoints(ev)), proto, ev.Size)
	if s := clip(b.summary(ev)); s != "" {
		line += ": " + s
	}
	switch {
	case ev.ReadError:
		line += " " + b.warn("[unreadable]")
	case ev.Incomplete:
		line += " " + b.warn("[incomplete]")
	case ev.Truncated():
		line += " " + b.warn("[truncated]")
	}
	_, err := io.WriteString(b.w, line+"\n")
	return err
}

// summary describes what an event's data holds.
func (b *Brief) summary(ev *tracer.Event) string {
	if ev.Function.IsQUIC() {
		items, ok := b.quic.process(ev)
		if !ok {
			return "packet that doesn't parse as QUIC"
		}
		return briefQUIC(items)
	}
	frames, isHTTP2, note := b.h2.process(ev)
	if isHTTP2 {
		return briefHTTP2(frames)
	}
	if note != "" {
		return note
	}
	if segs := b.h1.process(ev); segs != nil {
		return briefHTTP1(segs)
	}
	return briefData(ev.Data)
}

func briefQUIC(items []quicItem) string {
	var frames, parts []string
	for _, it := range items {
		switch {
		case it.Frame != "":
			frames = append(frames, it.Frame)
		case strings.HasPrefix(it.HTTP3, "stream:"): // a stream's type: noise here
		case it.Err != "":
			parts = append(parts, fmt.Sprintf("%s s%d: %s", it.HTTP3, it.Stream, it.Err))
		case it.Headers != nil:
			parts = append(parts, fmt.Sprintf("%s s%d %s%s", it.HTTP3, it.Stream, briefFields(it.Headers), bodyNote(it.Body)))
		case strings.HasPrefix(it.HTTP3, "DATA"):
			parts = append(parts, fmt.Sprintf("DATA s%d %d bytes%s", it.Stream, len(it.Data), bodyNote(it.Body)))
		default:
			parts = append(parts, it.HTTP3)
		}
	}
	if len(parts) == 0 {
		return "QUIC " + strings.Join(frames, ", ")
	}
	return "HTTP/3 " + strings.Join(parts, "; ")
}

func briefHTTP2(frames []http2Frame) string {
	if len(frames) == 0 {
		return "HTTP/2, part of a frame"
	}
	type run struct {
		text  string
		count int
	}
	var runs []run
	for _, f := range frames {
		var p string
		switch {
		case f.Type == "connection preface":
			p = "preface"
		case f.Headers != nil:
			p = fmt.Sprintf("%s s%d %s", f.Type, f.Stream, briefFields(f.Headers))
		case f.Type == "DATA":
			p = fmt.Sprintf("DATA s%d %d bytes%s", f.Stream, len(f.Data), bodyNote(f.Body))
		case f.Stream != 0 && f.Type != "CONTINUATION":
			p = fmt.Sprintf("%s s%d", f.Type, f.Stream)
		default:
			p = f.Type
		}
		if f.Headers == nil && f.Body.Encoding != "" && f.Type != "DATA" {
			p += bodyNote(f.Body)
		}
		if slices.Contains(f.Flags, "END_STREAM") {
			p += " [END_STREAM]"
		}
		// Runs of the same frame, e.g. WINDOW_UPDATEs, are counted.
		if n := len(runs); n > 0 && runs[n-1].text == p {
			runs[n-1].count++
			continue
		}
		runs = append(runs, run{p, 1})
	}
	parts := make([]string, len(runs))
	for i, r := range runs {
		parts[i] = r.text
		if r.count > 1 {
			parts[i] += fmt.Sprintf(" ×%d", r.count)
		}
	}
	return "HTTP/2 " + strings.Join(parts, "; ")
}

// briefFields describes a header block: a request's method and URL, a
// response's status and content type, or else how many fields it has.
func briefFields(fields []hpack.HeaderField) string {
	get := func(name string) string {
		for _, f := range fields {
			if f.Name == name {
				return f.Value
			}
		}
		return ""
	}
	if m := get(":method"); m != "" {
		return m + " " + get(":authority") + get(":path")
	}
	if s := get(":status"); s != "" {
		parts := []string{s}
		for _, name := range []string{"content-type", "content-encoding"} {
			if v := get(name); v != "" {
				parts = append(parts, v)
			}
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%d fields", len(fields))
}

func briefHTTP1(segs []http1Segment) string {
	var parts []string
	body, bodyBytes := bodyPart{}, -1
	flushBody := func() {
		if bodyBytes >= 0 {
			parts = append(parts, fmt.Sprintf("body %d bytes%s", bodyBytes, bodyNote(body)))
			body, bodyBytes = bodyPart{}, -1
		}
	}
	for _, s := range segs {
		switch {
		case s.msg != nil:
			flushBody()
			parts = append(parts, briefMessage(s.msg))
		case !s.inBody:
			if len(s.raw) > 0 { // the rest of a header block, or not HTTP
				parts = append(parts, briefData(s.raw))
			} else if s.body.Err != "" { // bytes of a body lost
				parts = append(parts, "body"+bodyNote(s.body))
			}
		default:
			if bodyBytes < 0 {
				bodyBytes = 0
			}
			bodyBytes += len(s.raw)
			body.Encoding = s.body.Encoding
			body.Decoded = append(body.Decoded, s.body.Decoded...)
			if s.body.Err != "" {
				body.Err = s.body.Err
			}
		}
	}
	flushBody()
	return strings.Join(parts, "; ")
}

// briefMessage describes an HTTP/1.x message's start: its start line,
// and the host for a request or the content type for a response.
func briefMessage(m *httpMessage) string {
	header := func(name string) string {
		for _, h := range m.headers {
			if strings.EqualFold(strings.TrimSpace(h[0]), name) {
				return h[1]
			}
		}
		return ""
	}
	parts := []string{m.startLine}
	if !strings.HasPrefix(m.startLine, "HTTP/") {
		if h := header("Host"); h != "" {
			parts = append(parts, "host "+h)
		}
	} else {
		for _, name := range []string{"Content-Type", "Content-Encoding"} {
			if v := header(name); v != "" {
				parts = append(parts, v)
			}
		}
	}
	return strings.Join(parts, ", ")
}

// briefData describes data that isn't HTTP: its first line if it's
// text.
func briefData(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if !isText(data) {
		return "binary"
	}
	first, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimSpace(first)
}

// bodyNote says what an encoded body's piece decoded to.
func bodyNote(p bodyPart) string {
	switch {
	case p.Encoding == "":
		return ""
	case p.Err != "":
		return fmt.Sprintf(" (%s, not decoded: %s)", p.Encoding, p.Err)
	case len(p.Decoded) == 0: // e.g. only the end of the encoding
		return " (" + p.Encoding + ")"
	default:
		return fmt.Sprintf(" (%s, %d decoded)", p.Encoding, len(p.Decoded))
	}
}

// clip makes a summary safe to print on one line, and not too long.
func clip(s string) string {
	s = strings.Join(strings.Fields(escapeText([]byte(s))), " ")
	if utf8.RuneCountInString(s) <= maxSummary {
		return s
	}
	r := []rune(s)
	return string(r[:maxSummary-1]) + "…"
}
