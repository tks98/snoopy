package output

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http2/hpack"
)

// gRPC runs over HTTP/2: a call's request and response are streams of
// messages, each a compressed flag, a 4-byte length and that many bytes of
// (usually) protobuf, laid end to end across the stream's DATA frames, and
// its status comes in the response's trailers. Without the service's
// schema, messages are shown the way protoc --decode_raw shows them: field
// numbers and their values.

// grpcMessage is a message a DATA frame completed.
type grpcMessage struct {
	Length     int  // as framed, compressed if Compressed
	Compressed bool // with the stream's grpc-encoding
	// Fields is the message decoded as protobuf, one line per field, nested
	// messages indented; nil if it isn't protobuf, or wasn't decoded.
	Fields []string
	Err    string // why it wasn't decoded, if it wasn't
}

const (
	maxGRPCMessage = 4 << 20 // larger ones are skipped, not decoded
	maxProtoDepth  = 16
)

// grpcStream reassembles one stream direction's messages.
type grpcStream struct {
	encoding string // grpc-encoding
	buf      []byte // bytes of the message under way, from its prefix
	skip     int    // bytes still to skip of a message too large to decode
}

// isGRPC reports whether a content type is gRPC's (application/grpc,
// application/grpc+proto, ...), but not gRPC-Web's, which is framed
// differently.
func isGRPC(contentType string) bool {
	typ := mediaType(contentType)
	return typ == "application/grpc" || strings.HasPrefix(typ, "application/grpc+")
}

func grpcEncoding(fields []hpack.HeaderField) string {
	for _, f := range fields {
		if f.Name == "grpc-encoding" {
			return strings.ToLower(strings.TrimSpace(f.Value))
		}
	}
	return ""
}

// add takes in the next body bytes of the stream and returns the messages
// they complete.
func (s *grpcStream) add(p []byte) []grpcMessage {
	var out []grpcMessage
	for len(p) > 0 {
		if s.skip > 0 {
			n := min(s.skip, len(p))
			s.skip -= n
			p = p[n:]
			continue
		}
		if len(s.buf) < 5 {
			n := min(5-len(s.buf), len(p))
			s.buf = append(s.buf, p[:n]...)
			p = p[n:]
			if len(s.buf) < 5 {
				break
			}
		}
		compressed := s.buf[0]&1 != 0
		length := int(binary.BigEndian.Uint32(s.buf[1:5]))
		if length > maxGRPCMessage {
			out = append(out, grpcMessage{Length: length, Compressed: compressed,
				Err: fmt.Sprintf("more than %d bytes, not decoded", maxGRPCMessage)})
			s.buf, s.skip = s.buf[:0], length
			continue
		}
		n := min(5+length-len(s.buf), len(p))
		s.buf = append(s.buf, p[:n]...)
		p = p[n:]
		if len(s.buf) < 5+length {
			break
		}
		out = append(out, s.message(compressed, s.buf[5:]))
		s.buf = s.buf[:0]
	}
	return out
}

func (s *grpcStream) message(compressed bool, b []byte) grpcMessage {
	m := grpcMessage{Length: len(b), Compressed: compressed}
	if compressed {
		var err error
		if b, err = decompressGRPC(s.encoding, b); err != nil {
			m.Err = err.Error()
			return m
		}
	}
	if fields, ok := decodeProtobuf(b, 0); ok {
		m.Fields = fields
	} else {
		m.Err = "not protobuf"
	}
	return m
}

// grpcZstd is the decoder for zstd messages, shared since making one is
// costly. Its window is limited as bodies' are, and its output to
// maxGRPCMessage: a frame's header can otherwise ask for gigabytes.
// DecodeAll can be used by several goroutines at once.
var grpcZstd = sync.OnceValues(func() (*zstd.Decoder, error) {
	return zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxWindow(zstdMaxWindow), zstd.WithDecoderMaxMemory(maxGRPCMessage))
})

// decompressGRPC decompresses a message with one of gRPC's encodings
// (grpc-encoding), up to maxGRPCMessage bytes.
func decompressGRPC(encoding string, b []byte) ([]byte, error) {
	var r io.Reader
	var err error
	switch encoding {
	case "gzip":
		r, err = gzip.NewReader(bytes.NewReader(b))
	case "deflate": // zlib, as in HTTP
		r, err = zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			r, err = flate.NewReader(bytes.NewReader(b)), nil
		}
	case "zstd":
		d, err := grpcZstd()
		if err != nil {
			return nil, fmt.Errorf("zstd: %v", err)
		}
		out, err := d.DecodeAll(b, nil)
		if errors.Is(err, zstd.ErrDecoderSizeExceeded) {
			return nil, fmt.Errorf("more than %d bytes decompressed, not decoded", maxGRPCMessage)
		}
		if err != nil {
			return nil, fmt.Errorf("zstd: %v", err)
		}
		return out, nil
	case "", "identity":
		return nil, fmt.Errorf("compressed, but the stream has no grpc-encoding")
	default:
		return nil, fmt.Errorf("compressed with %s, which snoopy doesn't decompress", encoding)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %v", encoding, err)
	}
	out, err := io.ReadAll(io.LimitReader(r, maxGRPCMessage+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", encoding, err)
	}
	if len(out) > maxGRPCMessage {
		return nil, fmt.Errorf("more than %d bytes decompressed, not decoded", maxGRPCMessage)
	}
	return out, nil
}

// decodeProtobuf decodes b as a protobuf message without its schema, as
// protoc --decode_raw does, and reports whether it is one: every byte
// accounted for by well-formed fields. A length-delimited field is shown as
// a string if it's printable text, else as a nested message if it parses
// as one, else as bytes.
func decodeProtobuf(b []byte, depth int) ([]string, bool) {
	if depth >= maxProtoDepth {
		return nil, false
	}
	var lines []string
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, false
		}
		b = b[n:]
		field, wire := key>>3, key&7
		if field == 0 || field > 1<<29-1 {
			return nil, false
		}
		name := strconv.FormatUint(field, 10)
		switch wire {
		case 0: // varint
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, false
			}
			b = b[n:]
			lines = append(lines, fmt.Sprintf("%s: %d", name, v))
		case 1: // 64 bits
			if len(b) < 8 {
				return nil, false
			}
			v := binary.LittleEndian.Uint64(b)
			b = b[8:]
			lines = append(lines, fmt.Sprintf("%s: 0x%016x%s", name, v, floatNote(math.Float64frombits(v))))
		case 5: // 32 bits
			if len(b) < 4 {
				return nil, false
			}
			v := binary.LittleEndian.Uint32(b)
			b = b[4:]
			lines = append(lines, fmt.Sprintf("%s: 0x%08x%s", name, v, floatNote(float64(math.Float32frombits(v)))))
		case 2: // length-delimited
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return nil, false
			}
			v := b[n : n+int(l)]
			b = b[n+int(l):]
			if printable(v) {
				lines = append(lines, fmt.Sprintf("%s: %s", name, strconv.Quote(string(v))))
			} else if nested, ok := decodeProtobuf(v, depth+1); ok && len(v) > 0 {
				lines = append(lines, name+" {")
				for _, l := range nested {
					lines = append(lines, "  "+l)
				}
				lines = append(lines, "}")
			} else {
				lines = append(lines, fmt.Sprintf("%s: %s", name, quoteBytes(v)))
			}
		default: // groups (3, 4) are long deprecated; 6 and 7 aren't wire types
			return nil, false
		}
	}
	return lines, true
}

// floatNote shows a 64- or 32-bit value as the float it may be, when that's
// a plausible one.
func floatNote(f float64) string {
	if f == 0 || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) < 1e-6 || math.Abs(f) > 1e15 {
		return ""
	}
	return " (" + strconv.FormatFloat(f, 'g', -1, 64) + " as a float)"
}

func printable(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return len(b) == 0
	}
	for _, r := range string(b) {
		if r < ' ' && r != '\n' && r != '\t' && r != '\r' || r == 0x7f {
			return false
		}
	}
	return true
}

// quoteBytes shows bytes as an escaped string, its first 64 if it's longer.
func quoteBytes(b []byte) string {
	const max = 64
	s := strconv.Quote(string(b[:min(len(b), max)]))
	if len(b) > max {
		s += fmt.Sprintf(" (%d bytes)", len(b))
	}
	return s
}

// grpcStatusNames are gRPC's status codes' names, for grpc-status.
var grpcStatusNames = []string{"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED",
	"NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION",
	"ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED"}

// grpcStatusName returns a grpc-status value's name, or "".
func grpcStatusName(value string) string {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 0 || n >= len(grpcStatusNames) {
		return ""
	}
	return grpcStatusNames[n]
}
