package output

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// isText reports whether b reads as text: valid UTF-8 with few control
// characters. A rune cut off at the end of a truncated capture is allowed.
func isText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	bad := 0
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			if !utf8.FullRune(b[i:]) {
				i = len(b) // cut-off rune at the end
				continue
			}
			bad++
		case unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' && r != '\f' && r != '\v':
			bad++
		}
		i += size
	}
	return bad*20 <= len(b) // at most 5%
}

// escapeText makes text safe to print on a terminal: control characters
// other than newlines and tabs are shown as \xNN, carriage returns before a
// newline are dropped.
func escapeText(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r == '\r' && i+1 < len(b) && b[i+1] == '\n':
		case r == '\n' || r == '\t':
			sb.WriteRune(r)
		case r == utf8.RuneError && size <= 1, unicode.IsControl(r):
			for _, c := range b[i : i+size] {
				fmt.Fprintf(&sb, `\x%02x`, c)
			}
		default:
			sb.Write(b[i : i+size])
		}
		i += size
	}
	return sb.String()
}

func hexdump(b []byte) string {
	return strings.TrimSuffix(hex.Dump(b), "\n")
}

var (
	http1Request  = regexp.MustCompile(`^[A-Z]{3,10} \S+ HTTP/1\.[01]\r?\n`)
	http1Response = regexp.MustCompile(`^HTTP/1\.[01] \d{3}[ \r\n]`)
)

// httpMessage is an HTTP/1.x message split into its parts.
type httpMessage struct {
	startLine string
	headers   [][2]string
	body      []byte
	complete  bool // whether the end of the header block was captured
}

// parseHTTP1 parses the start of an HTTP/1.x request or response.
func parseHTTP1(b []byte) (httpMessage, bool) {
	if !http1Request.Match(b) && !http1Response.Match(b) {
		return httpMessage{}, false
	}
	var m httpMessage
	head := b
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		head, m.body, m.complete = b[:i], b[i+4:], true
	} else if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		head, m.body, m.complete = b[:i], b[i+2:], true
	}
	if !isText(head) {
		return httpMessage{}, false
	}
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	m.startLine = lines[0]
	for _, line := range lines[1:] {
		name, value, _ := strings.Cut(line, ":")
		m.headers = append(m.headers, [2]string{name, strings.TrimSpace(value)})
	}
	return m, true
}

const http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

var http2FrameTypes = []string{
	"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
	"PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION",
}

// summarizeHTTP2 describes the HTTP/2 frames in b, or returns nil if b
// doesn't look like a sequence of frames. Frame headers are only nine bytes,
// so to avoid describing random binary data, every frame must be valid for
// its type and at least one must be complete; the last may be cut off.
func summarizeHTTP2(b []byte) []string {
	var out []string
	complete := 0
	if rest, ok := bytes.CutPrefix(b, []byte(http2Preface)); ok {
		out = append(out, "connection preface")
		complete++
		b = rest
	}
	for len(b) >= 9 {
		length := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		typ, flags := b[3], b[4]
		stream := binary.BigEndian.Uint32(b[5:9])
		if !validHTTP2Frame(typ, flags, length, stream) {
			return nil
		}
		desc := fmt.Sprintf("%s stream=%d length=%d", http2FrameTypes[typ], stream, length)
		if f := http2Flags(typ, flags); f != "" {
			desc += " " + f
		}
		if 9+length > len(b) {
			if complete == 0 {
				return nil
			}
			return append(out, desc+" (cut off)")
		}
		out = append(out, desc)
		complete++
		b = b[9+length:]
	}
	if complete == 0 {
		return nil
	}
	if len(b) > 0 {
		out = append(out, fmt.Sprintf("%d bytes of the next frame", len(b)))
	}
	return out
}

// http2FlagMasks are the flags defined for each frame type; senders must
// leave the others unset (RFC 9113, section 4.1).
var http2FlagMasks = []byte{0x09, 0x2d, 0x00, 0x00, 0x01, 0x0c, 0x01, 0x00, 0x00, 0x04}

func validHTTP2Frame(typ, flags byte, length int, stream uint32) bool {
	if int(typ) >= len(http2FrameTypes) || flags&^http2FlagMasks[typ] != 0 || stream&(1<<31) != 0 {
		return false
	}
	switch typ {
	case 0, 1, 3, 5, 9: // DATA, HEADERS, RST_STREAM, PUSH_PROMISE, CONTINUATION
		if stream == 0 {
			return false
		}
	case 4, 6, 7: // SETTINGS, PING, GOAWAY
		if stream != 0 {
			return false
		}
	}
	switch typ {
	case 2: // PRIORITY
		return length == 5
	case 3, 8: // RST_STREAM, WINDOW_UPDATE
		return length == 4
	case 4: // SETTINGS
		return length%6 == 0
	case 6: // PING
		return length == 8
	case 7: // GOAWAY
		return length >= 8
	}
	return true
}

func http2Flags(typ, flags byte) string {
	var names []string
	add := func(bit byte, name string) {
		if flags&bit != 0 {
			names = append(names, name)
		}
	}
	switch typ {
	case 0: // DATA
		add(0x1, "END_STREAM")
	case 1: // HEADERS
		add(0x1, "END_STREAM")
		add(0x4, "END_HEADERS")
	case 4, 6: // SETTINGS, PING
		add(0x1, "ACK")
	case 9: // CONTINUATION
		add(0x4, "END_HEADERS")
	}
	if len(names) == 0 {
		return ""
	}
	return "[" + strings.Join(names, ",") + "]"
}
