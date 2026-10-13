// Package output formats traced TLS events as text, JSON or pcap.
package output

import (
	"fmt"
	"io"
	"net/netip"
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
	w    io.Writer
	hex  bool
	h1   *http1Conns
	h2   *http2Conns
	quic *quicConns

	dim, title, fn, write, read, header, warn func(a ...any) string
}

// NewText returns a Text printer. If hex is set, payloads are always
// hex-dumped. Colors follow color.NoColor.
func NewText(w io.Writer, hex bool) *Text {
	s := func(attrs ...color.Attribute) func(a ...any) string {
		return color.New(attrs...).SprintFunc()
	}
	pool := newBodyPool()
	return &Text{
		w:      w,
		hex:    hex,
		h1:     newHTTP1Conns(pool),
		h2:     newHTTP2Conns(pool),
		quic:   newQUICConns(pool),
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

	// 12:01:02.345678 curl (pid 2422) SSL_write 10.0.0.2:51234 > 93.184.216.34:443  77 bytes  311µs
	fmt.Fprintf(&b, "%s %s %s %s",
		t.dim(ev.Time.Format("15:04:05.000000")),
		t.title(ev.Comm),
		t.dim(processLabel(ev)),
		t.fn(ev.Function.String()),
	)
	paint := t.read
	if ev.Function.Direction() == tracer.Write {
		paint = t.write
	}
	fmt.Fprintf(&b, " %s  %d bytes  %s", paint(endpoints(ev)), ev.Size, t.dim(formatLatency(ev.Latency)))

	var extra []string
	if ev.FD >= 0 {
		extra = append(extra, fmt.Sprintf("fd %d", ev.FD))
	}
	extra = append(extra, fmt.Sprintf("conn %#x", ev.ConnID))
	if ev.ContainerID != "" {
		extra = append(extra, "container "+shortID(ev.ContainerID))
	}
	fmt.Fprintf(&b, "  %s\n", t.dim(strings.Join(extra, ", ")))

	if ev.Function.IsQUIC() {
		if items, ok := t.quic.process(ev); ok && !t.hex {
			t.writeQUIC(&b, items)
		} else {
			b.WriteString(hexdump(ev.Data) + "\n")
		}
	} else {
		frames, isHTTP2, note := t.h2.process(ev)
		if note != "" {
			fmt.Fprintln(&b, t.warn("["+note+"]"))
		}
		var segs []http1Segment
		if !isHTTP2 {
			segs = t.h1.process(ev)
		}
		switch {
		case isHTTP2 && !t.hex:
			t.writeHTTP2(&b, frames, len(ev.Data))
		case decodesBody(segs) && !t.hex:
			t.writeHTTP1(&b, segs)
		default:
			t.writePayload(&b, ev.Data)
		}
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

// writeHTTP1 prints HTTP/1.x messages whose bodies are being decoded.
func (t *Text) writeHTTP1(b *strings.Builder, segs []http1Segment) {
	for i, s := range segs {
		switch {
		case s.msg != nil:
			b.WriteString(t.title(escapeText([]byte(s.msg.startLine))) + "\n")
			for _, h := range s.msg.headers {
				fmt.Fprintf(b, "%s: %s\n", t.header(escapeText([]byte(h[0]))), escapeText([]byte(h[1])))
			}
			if s.msg.complete && i+1 < len(segs) {
				b.WriteString("\n")
			}
		case s.body.Encoding != "":
			t.writeBodyPart(b, s.raw, s.body)
		case len(s.raw) > 0:
			t.writeBody(b, s.raw)
		}
	}
}

func decodesBody(segs []http1Segment) bool {
	for _, s := range segs {
		if s.body.Encoding != "" {
			return true
		}
	}
	return false
}

// writeBodyPart prints a piece of an encoded body as what it decoded to, or
// as sent if it couldn't be decoded.
func (t *Text) writeBodyPart(b *strings.Builder, raw []byte, part bodyPart) {
	if part.Err != "" {
		b.WriteString(t.warn(fmt.Sprintf("[%s body not decoded: %s]", part.Encoding, part.Err)) + "\n")
		if len(raw) > 0 {
			t.writeBody(b, raw)
		}
		return
	}
	if len(part.Decoded) == 0 { // e.g. only the end of the encoding
		b.WriteString(t.dim(fmt.Sprintf("[%s: %d bytes, no output]", part.Encoding, len(raw))) + "\n")
		return
	}
	b.WriteString(t.dim(fmt.Sprintf("[%s: %d bytes decoded to %d]", part.Encoding, len(raw), len(part.Decoded))) + "\n")
	t.writeBody(b, part.Decoded)
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
		switch {
		case f.Body.Encoding != "":
			t.writeBodyPart(b, f.Data, f.Body)
		case len(f.Data) > 0:
			t.writeBody(b, f.Data)
		}
	}
}

// writeQUIC prints a QUIC packet's frames on one line, then the HTTP/3
// frames its stream data completed.
func (t *Text) writeQUIC(b *strings.Builder, items []quicItem) {
	var frames []string
	for _, it := range items {
		if it.Frame != "" {
			frames = append(frames, it.Frame)
		}
	}
	b.WriteString(t.dim("QUIC: "+strings.Join(frames, ", ")) + "\n")
	for _, it := range items {
		if it.Frame != "" {
			continue
		}
		line := fmt.Sprintf("HTTP/3 %s stream=%d", it.HTTP3, it.Stream)
		switch {
		case it.Err != "":
			b.WriteString(t.warn(line+": "+it.Err) + "\n")
		case it.Headers != nil:
			b.WriteString(t.title(line) + "\n")
			for _, h := range it.Headers {
				fmt.Fprintf(b, "%s: %s\n", t.header(escapeText([]byte(h.Name))), escapeText([]byte(h.Value)))
			}
			if it.Body.Encoding != "" {
				t.writeBodyPart(b, nil, it.Body)
			}
		case it.HTTP3 == "SETTINGS":
			b.WriteString(t.dim(line+" "+string(it.Data)) + "\n")
		default:
			if it.Data != nil {
				line += fmt.Sprintf(" (%d bytes)", len(it.Data))
			}
			b.WriteString(t.dim(line) + "\n")
			switch {
			case it.Body.Encoding != "":
				t.writeBodyPart(b, it.Data, it.Body)
			case len(it.Data) > 0:
				t.writeBody(b, it.Data)
			}
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

// endpoints says where an event's data went, from sender to receiver, as
// tcpdump writes it. An end that isn't known is "local" (the traced
// process's socket) or "peer".
func endpoints(ev *tracer.Event) string {
	local, remote := "local", "peer"
	if knownAddr(ev.Local) {
		local = ev.Local.String()
	}
	if knownAddr(ev.Remote) {
		remote = ev.Remote.String()
	}
	if ev.Function.Direction() == tracer.Write {
		return local + " > " + remote
	}
	return remote + " > " + local
}

// knownAddr reports whether an address is known. An unconnected UDP socket
// (Firefox's QUIC) has 0.0.0.0:0 as its remote address.
func knownAddr(a netip.AddrPort) bool {
	return a.IsValid() && (!a.Addr().IsUnspecified() || a.Port() != 0)
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
