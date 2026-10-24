// Package output formats traced TLS events as text, JSON or pcap.
package output

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fatih/color"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// Printer writes events somewhere.
type Printer interface {
	Print(ev *tracer.Event) error
}

// Text prints events for humans: a header line per call followed by the
// payload, decoded if it is HTTP, and hex-dumped if it is binary.
type Text struct {
	w      io.Writer
	opts   Options
	dec    decoders
	hidden int

	dim, title, fn, write, read, header, warn func(a ...any) string
}

// How much of the data is shown, without Options.Full.
const (
	maxBodyShown = 2048 // bytes of a body, or of a call's data that isn't HTTP
	maxHexShown  = 256  // bytes of binary data that isn't a body
)

// NewText returns a Text printer. Colors follow color.NoColor.
func NewText(w io.Writer, opts Options) *Text {
	s := func(attrs ...color.Attribute) func(a ...any) string {
		return color.New(attrs...).SprintFunc()
	}
	return &Text{
		w:      w,
		opts:   opts,
		dec:    newDecoders(opts.Warn),
		dim:    s(color.Faint),
		title:  s(color.Bold),
		fn:     s(color.FgHiMagenta, color.Bold),
		write:  s(color.FgCyan),
		read:   s(color.FgGreen),
		header: s(color.FgHiBlue),
		warn:   s(color.FgYellow),
	}
}

// Hidden returns how many events were left out because they only kept a
// connection going.
func (t *Text) Hidden() int { return t.hidden }

func (t *Text) Print(ev *tracer.Event) error {
	dc := t.dec.decode(ev)
	if dc.notice {
		return nil
	}
	if !t.opts.Verbose && dc.housekeeping() {
		t.hidden++
		return nil
	}
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
	switch {
	case ev.ContainerName != "":
		extra = append(extra, "container "+ev.ContainerName)
	case ev.ContainerID != "":
		extra = append(extra, "container "+shortID(ev.ContainerID))
	}
	fmt.Fprintf(&b, "  %s\n", t.dim(strings.Join(extra, ", ")))

	if dc.note != "" {
		fmt.Fprintln(&b, t.warn("["+dc.note+"]"))
	}
	switch {
	case t.opts.Hex:
		if len(ev.Data) > 0 {
			b.WriteString(hexdump(ev.Data) + "\n")
		}
	case dc.isQUIC && !dc.notQUIC:
		t.writeQUIC(&b, dc.quic)
	case dc.isHTTP2:
		t.writeHTTP2(&b, dc.http2, len(ev.Data))
	case dc.http1 != nil:
		t.writeHTTP1(&b, dc.http1)
	default:
		t.writeData(&b, ev.Data)
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

// writeHTTP1 prints HTTP/1.x messages, and data that isn't HTTP/1.x on a
// connection that was.
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
			t.writeBodyPart(b, s.raw, s.offset, s.body, s.contentType)
		case s.inBody:
			t.writeBody(b, s.raw, s.contentType, s.offset, "")
		case len(s.raw) > 0:
			t.writeData(b, s.raw)
		}
	}
}

// writeBodyPart prints a piece of an encoded body as what it decoded to, or
// as sent if it couldn't be decoded. offset is where the piece starts in the
// body as sent.
func (t *Text) writeBodyPart(b *strings.Builder, raw []byte, offset int64, part bodyPart, contentType string) {
	if part.Err != "" {
		b.WriteString(t.warn(fmt.Sprintf("[%s body not decoded: %s]", part.Encoding, part.Err)) + "\n")
		if len(raw) > 0 {
			t.writeBody(b, raw, contentType, offset, "")
		}
		return
	}
	if len(part.Decoded) == 0 { // e.g. only the end of the encoding
		b.WriteString(t.dim(fmt.Sprintf("[%s: %d bytes, no output]", part.Encoding, len(raw))) + "\n")
		return
	}
	t.writeBody(b, part.Decoded, contentType, part.Offset, fmt.Sprintf("%s: %d bytes decoded to", part.Encoding, len(raw)))
}

// writeBody prints a piece of a message body that starts offset bytes into
// it. Unless Options.Full is set, text is shown up to maxBodyShown bytes into
// the body, and the rest of it, and binary data, are only described. decoded,
// if not empty, says what the piece was decoded from, e.g. "gzip: 300 bytes
// decoded to".
func (t *Text) writeBody(b *strings.Builder, data []byte, contentType string, offset int64, decoded string) {
	text := isText(data)
	if t.opts.Full || text && offset < maxBodyShown {
		if decoded != "" {
			b.WriteString(t.dim(fmt.Sprintf("[%s %d]", decoded, len(data))) + "\n")
		}
		switch {
		case !text:
			b.WriteString(hexdump(data) + "\n")
		case t.opts.Full:
			t.writeLimited(b, data, len(data))
		default:
			t.writeLimited(b, data, int(maxBodyShown-offset))
		}
		return
	}
	what := mediaType(contentType)
	if what == "" {
		what = "binary data"
		if text {
			what = "text"
		}
	}
	desc := fmt.Sprintf("%d bytes of %s", len(data), what)
	if offset > 0 {
		desc = fmt.Sprintf("%d more bytes of %s", len(data), what)
	}
	if decoded != "" {
		desc = decoded + " " + desc
	}
	b.WriteString(t.dim("["+desc+"]") + "\n")
}

// writeData prints data that isn't known to be a message body: text, and
// binary data as a hex dump, each up to a limit unless Options.Full is set.
func (t *Text) writeData(b *strings.Builder, data []byte) {
	if len(data) == 0 {
		return
	}
	if isText(data) {
		limit := len(data)
		if !t.opts.Full {
			limit = maxBodyShown
		}
		t.writeLimited(b, data, limit)
		return
	}
	if t.opts.Full || len(data) <= maxHexShown {
		b.WriteString(hexdump(data) + "\n")
		return
	}
	b.WriteString(hexdump(data[:maxHexShown]) + "\n")
	b.WriteString(t.dim(fmt.Sprintf("[… %d more bytes; --full shows all]", len(data)-maxHexShown)) + "\n")
}

// writeLimited prints text, or its first limit bytes, ending at a line
// break if there's one in the second half, and says how much was left out.
func (t *Text) writeLimited(b *strings.Builder, data []byte, limit int) {
	shown := data
	if len(data) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(data[cut]) { // don't split a character
			cut--
		}
		if i := bytes.LastIndexByte(data[:cut], '\n'); i >= limit/2 {
			cut = i + 1
		}
		shown = data[:cut]
	}
	text := escapeText(shown)
	b.WriteString(text)
	if !strings.HasSuffix(text, "\n") && text != "" {
		b.WriteString("\n")
	}
	if len(shown) < len(data) {
		b.WriteString(t.dim(fmt.Sprintf("[… %d more bytes; --full shows all]", len(data)-len(shown))) + "\n")
	}
}

// mediaType returns a Content-Type's type, without its parameters.
func mediaType(contentType string) string {
	typ, _, _ := strings.Cut(contentType, ";")
	return strings.TrimSpace(typ)
}

// writeHTTP2 prints the frames of an HTTP/2 connection, with their decoded
// headers.
func (t *Text) writeHTTP2(b *strings.Builder, frames []http2Frame, captured int) {
	if len(frames) == 0 && captured > 0 {
		b.WriteString(t.dim(fmt.Sprintf("HTTP/2: %d bytes of a frame that continues in a later call", captured)) + "\n")
	}
	for _, f := range frames {
		if !t.opts.Verbose && f.housekeeping() {
			continue
		}
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
		switch {
		case f.Headers != nil:
			b.WriteString(t.title(line) + "\n")
		case f.HeadersLost:
			b.WriteString(t.title(line) + t.dim(" (headers not decoded)") + "\n")
		default:
			b.WriteString(t.dim(line) + "\n")
		}
		for _, h := range f.Headers {
			value := escapeText([]byte(h.Value))
			if name := grpcStatusName(h.Value); h.Name == "grpc-status" && name != "" {
				value += " (" + name + ")"
			}
			fmt.Fprintf(b, "%s: %s\n", t.header(escapeText([]byte(h.Name))), value)
		}
		switch {
		case f.IsGRPC:
			t.writeGRPC(b, f)
		case f.Body.Encoding != "":
			t.writeBodyPart(b, f.Data, f.Offset, f.Body, f.ContentType)
		case len(f.Data) > 0:
			t.writeBody(b, f.Data, f.ContentType, f.Offset, "")
		}
	}
}

// maxGRPCLines is how many lines of a gRPC message's fields are shown,
// unless Options.Full is set.
const maxGRPCLines = 40

// writeGRPC prints the gRPC messages a DATA frame completed, as their
// protobuf fields.
func (t *Text) writeGRPC(b *strings.Builder, f http2Frame) {
	if len(f.GRPC) == 0 && len(f.Data) > 0 {
		b.WriteString(t.dim(fmt.Sprintf("[%d bytes of a gRPC message]", len(f.Data))) + "\n")
	}
	for _, m := range f.GRPC {
		line := fmt.Sprintf("gRPC message, %d bytes", m.Length)
		if m.Compressed {
			line += ", compressed"
		}
		b.WriteString(t.title(line) + "\n")
		if m.Err != "" {
			b.WriteString(t.dim("["+m.Err+"]") + "\n")
			continue
		}
		if len(m.Fields) == 0 {
			b.WriteString(t.dim("(no fields)") + "\n")
		}
		for i, l := range m.Fields {
			if i == maxGRPCLines && !t.opts.Full {
				b.WriteString(t.dim(fmt.Sprintf("[%d more lines; --full shows them]", len(m.Fields)-i)) + "\n")
				break
			}
			b.WriteString(escapeText([]byte(l)) + "\n")
		}
	}
}

// writeQUIC prints the HTTP/3 frames a QUIC packet's stream data completed,
// after the packet's QUIC frames on one line if Options.Verbose is set.
func (t *Text) writeQUIC(b *strings.Builder, items []quicItem) {
	if t.opts.Verbose {
		var frames []string
		for _, it := range items {
			if it.Frame != "" {
				frames = append(frames, it.Frame)
			}
		}
		b.WriteString(t.dim("QUIC: "+strings.Join(frames, ", ")) + "\n")
	}
	for _, it := range items {
		if it.Frame != "" || !t.opts.Verbose && it.housekeeping() {
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
				t.writeBodyPart(b, nil, 0, it.Body, "")
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
				t.writeBodyPart(b, it.Data, it.Offset, it.Body, it.ContentType)
			case len(it.Data) > 0:
				t.writeBody(b, it.Data, it.ContentType, it.Offset, "")
			}
		}
	}
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
