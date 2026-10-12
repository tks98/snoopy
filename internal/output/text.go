// Package output formats traced TLS events as text, JSON or pcap.
package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/tks98/snoopy/internal/tracer"
)

// Printer writes events somewhere.
type Printer interface {
	Print(ev *tracer.Event) error
}

// Text prints events for humans: a header line per call followed by the
// payload, pretty-printed if it is HTTP/1.x or HTTP/2 and hex-dumped if it
// is binary.
type Text struct {
	w   io.Writer
	hex bool
	h2  *http2Conns

	dim, title, fn, write, read, header, warn func(a ...any) string
}

// NewText returns a Text printer. If hex is set, payloads are always
// hex-dumped. Colors follow color.NoColor.
func NewText(w io.Writer, hex bool) *Text {
	s := func(attrs ...color.Attribute) func(a ...any) string {
		return color.New(attrs...).SprintFunc()
	}
	return &Text{
		w:      w,
		hex:    hex,
		h2:     newHTTP2Conns(),
		dim:    s(color.Faint),
		title:  s(color.Bold),
		fn:     s(color.FgHiMagenta, color.Bold),
		write:  s(color.FgCyan),
		read:   s(color.FgGreen),
		header: s(color.FgHiBlue),
		warn:   s(color.FgYellow),
	}
}

func (t *Text) Print(ev *tracer.Event) error {
	var b strings.Builder

	// 12:01:02.345678 curl (pid 2422) SSL_write → 93.184.216.34:443  77 bytes  311µs
	fmt.Fprintf(&b, "%s %s %s %s",
		t.dim(ev.Time.Format("15:04:05.000000")),
		t.title(ev.Comm),
		t.dim(processLabel(ev)),
		t.fn(ev.Function.String()),
	)
	arrow, paint := "←", t.read
	if ev.Function.Direction() == tracer.Write {
		arrow, paint = "→", t.write
	}
	peer := "peer"
	if ev.Remote.IsValid() {
		peer = ev.Remote.String()
	}
	fmt.Fprintf(&b, " %s  %d bytes  %s", paint(arrow+" "+peer), ev.Size, t.dim(formatLatency(ev.Latency)))

	var extra []string
	if ev.FD >= 0 {
		extra = append(extra, fmt.Sprintf("fd %d", ev.FD))
	}
	extra = append(extra, fmt.Sprintf("conn %#x", ev.ConnID))
	if ev.ContainerID != "" {
		extra = append(extra, "container "+shortID(ev.ContainerID))
	}
	fmt.Fprintf(&b, "  %s\n", t.dim(strings.Join(extra, ", ")))

	frames, isHTTP2, note := t.h2.process(ev)
	if note != "" {
		fmt.Fprintln(&b, t.warn("["+note+"]"))
	}
	if isHTTP2 && !t.hex {
		t.writeHTTP2(&b, frames, len(ev.Data))
	} else {
		t.writePayload(&b, ev.Data)
	}

	switch {
	case ev.ReadError:
		fmt.Fprintln(&b, t.warn("[payload could not be read from the process's memory]"))
	case ev.Incomplete:
		fmt.Fprintln(&b, t.warn(fmt.Sprintf("[incomplete: only %d of %d bytes arrived; the ring buffer was full]", len(ev.Data), ev.Size)))
	case ev.Truncated():
		fmt.Fprintln(&b, t.warn(fmt.Sprintf("[truncated: captured %d of %d bytes; raise with --max-size]", len(ev.Data), ev.Size)))
	}
	b.WriteString("\n")

	_, err := io.WriteString(t.w, b.String())
	return err
}

func (t *Text) writePayload(b *strings.Builder, data []byte) {
	if len(data) == 0 {
		return
	}
	if t.hex {
		b.WriteString(hexdump(data) + "\n")
		return
	}
	if m, ok := parseHTTP1(data); ok {
		b.WriteString(t.title(escapeText([]byte(m.startLine))) + "\n")
		for _, h := range m.headers {
			fmt.Fprintf(b, "%s: %s\n", t.header(escapeText([]byte(h[0]))), escapeText([]byte(h[1])))
		}
		if len(m.body) > 0 {
			b.WriteString("\n")
			t.writeBody(b, m.body)
		}
		return
	}
	t.writeBody(b, data)
}

// writeHTTP2 prints the frames of an HTTP/2 connection, with their decoded
// headers.
func (t *Text) writeHTTP2(b *strings.Builder, frames []http2Frame, captured int) {
	if len(frames) == 0 && captured > 0 {
		b.WriteString(t.dim(fmt.Sprintf("HTTP/2: %d bytes of a frame that continues in a later call", captured)) + "\n")
	}
	for _, f := range frames {
		line := "HTTP/2 " + f.Type
		switch {
		case f.Type == "connection preface":
		case f.Continued:
			line += fmt.Sprintf(" stream=%d (continued)", f.Stream)
		default:
			line += fmt.Sprintf(" stream=%d length=%d", f.Stream, f.Length)
		}
		if len(f.Flags) > 0 {
			line += " [" + strings.Join(f.Flags, ",") + "]"
		}
		if f.Headers != nil {
			b.WriteString(t.title(line) + "\n")
		} else {
			b.WriteString(t.dim(line) + "\n")
		}
		for _, h := range f.Headers {
			fmt.Fprintf(b, "%s: %s\n", t.header(escapeText([]byte(h.Name))), escapeText([]byte(h.Value)))
		}
		if len(f.Data) > 0 {
			t.writeBody(b, f.Data)
		}
	}
}

func (t *Text) writeBody(b *strings.Builder, data []byte) {
	if isText(data) {
		text := escapeText(data)
		b.WriteString(text)
		if !strings.HasSuffix(text, "\n") {
			b.WriteString("\n")
		}
		return
	}
	if frames := summarizeHTTP2(data); frames != nil {
		b.WriteString(t.dim("HTTP/2: "+strings.Join(frames, "; ")) + "\n")
	}
	b.WriteString(hexdump(data) + "\n")
}

func processLabel(ev *tracer.Event) string {
	if ev.PID == ev.TID {
		return fmt.Sprintf("(pid %d)", ev.PID)
	}
	return fmt.Sprintf("(pid %d, tid %d)", ev.PID, ev.TID)
}

func formatLatency(d time.Duration) string {
	switch {
	case d < time.Microsecond:
		return d.String()
	case d < time.Millisecond:
		return d.Round(time.Microsecond).String()
	default:
		return d.Round(10 * time.Microsecond).String()
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
