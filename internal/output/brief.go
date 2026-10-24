package output

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"
	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// Brief prints one line per event, like tcpdump: the time, the process, where
// the data went, the protocol and size, and what the data holds.
//
//	06:27:36.512901 curl[5565] 192.168.5.15:41794 > 172.66.147.243:443 TLS 74: GET / HTTP/1.1, host example.com
type Brief struct {
	w      io.Writer
	opts   Options
	dec    decoders
	hidden int

	dim, title, write, read, warn func(a ...any) string
}

// maxSummary bounds a line's summary, in characters.
const maxSummary = 200

// NewBrief returns a Brief printer. Of the options, only Verbose applies.
// Colors follow color.NoColor.
func NewBrief(w io.Writer, opts Options) *Brief {
	s := func(attrs ...color.Attribute) func(a ...any) string {
		return color.New(attrs...).SprintFunc()
	}
	return &Brief{
		w:     w,
		opts:  opts,
		dec:   newDecoders(opts),
		dim:   s(color.Faint),
		title: s(color.Bold),
		write: s(color.FgCyan),
		read:  s(color.FgGreen),
		warn:  s(color.FgYellow),
	}
}

// Hidden returns how many events were left out because they only kept a
// connection going.
func (b *Brief) Hidden() int { return b.hidden }

func (b *Brief) Print(ev *tracer.Event) error {
	dc := b.dec.decode(ev)
	if dc.notice {
		return nil
	}
	if !b.opts.Verbose && dc.housekeeping() {
		b.hidden++
		return nil
	}
	paint, proto := b.read, "TLS"
	if ev.Function.Direction() == tracer.Write {
		paint = b.write
	}
	if ev.Function.IsQUIC() {
		proto = "QUIC"
	}
	process := fmt.Sprintf("%s[%d]", ev.Comm, ev.PID)
	if ev.ContainerName != "" {
		process = ev.ContainerName + " " + process
	}
	line := fmt.Sprintf("%s %s %s %s %d", b.dim(ev.Time.Format("15:04:05.000000")),
		b.title(process), paint(endpoints(ev)), proto, ev.Size)
	if s := clip(b.summary(ev, dc)); s != "" {
		line += ": " + s
	}
	if dc.isHTTP2 && dc.note != "" {
		line += " " + b.warn("[started before snoopy; headers not decoded]")
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
func (b *Brief) summary(ev *tracer.Event, dc decoded) string {
	switch {
	case dc.notQUIC:
		return "packet that doesn't parse as QUIC"
	case dc.isQUIC:
		return briefQUIC(dc.quic, b.opts.Verbose)
	case dc.isHTTP2:
		return briefHTTP2(dc.http2, b.opts.Verbose)
	case dc.note != "":
		return dc.note
	case dc.http1 != nil:
		return briefHTTP1(dc.http1)
	}
	return briefData(dc.data)
}

// briefQUIC describes the HTTP/3 frames in a packet, or else its QUIC
// frames. Unless verbose, HTTP/3 frames that only keep the connection going
// are left out.
func briefQUIC(items []quicItem, verbose bool) string {
	var frames, parts []string
	for _, it := range items {
		switch {
		case it.Frame != "":
			frames = append(frames, it.Frame)
		case strings.HasPrefix(it.HTTP3, "stream:"): // a stream's type: noise here
		case !verbose && it.housekeeping():
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

// briefHTTP2 describes HTTP/2 frames. Unless verbose, frames that only keep
// the connection going are left out.
func briefHTTP2(frames []http2Frame, verbose bool) string {
	if len(frames) == 0 {
		return "HTTP/2, part of a frame"
	}
	type run struct {
		text  string
		count int
	}
	var runs []run
	for _, f := range frames {
		if !verbose && f.housekeeping() {
			continue
		}
		var p string
		switch {
		case f.Type == "connection preface":
			p = "preface"
		case f.Headers != nil:
			p = fmt.Sprintf("%s s%d %s", f.Type, f.Stream, briefFields(f.Headers))
		case f.HeadersLost:
			p = fmt.Sprintf("%s s%d (not decoded)", f.Type, f.Stream)
		case f.Type == "DATA" && len(f.GRPC) > 0:
			p = fmt.Sprintf("DATA s%d gRPC %d message", f.Stream, len(f.GRPC))
			if len(f.GRPC) > 1 {
				p += "s"
			}
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
	if len(runs) == 0 {
		return "HTTP/2 settings and flow control"
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
	// A gRPC call's status, in its trailers, or with the response's
	// headers if it has no messages.
	grpc := ""
	if s := get("grpc-status"); s != "" {
		grpc = strings.TrimSpace("grpc-status " + s + " " + grpcStatusName(s))
	}
	if s := get(":status"); s != "" {
		parts := []string{s}
		for _, name := range []string{"content-type", "content-encoding"} {
			if v := get(name); v != "" {
				parts = append(parts, v)
			}
		}
		if grpc != "" {
			parts = append(parts, grpc)
		}
		return strings.Join(parts, ", ")
	}
	if grpc != "" {
		return grpc
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
