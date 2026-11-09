package output

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// JSON prints one JSON object per line (NDJSON).
type JSON struct {
	enc      *json.Encoder
	dec      decoders
	redact   bool
	filtered int
}

// Filtered returns how many events Options.Filter left out so far.
func (j *JSON) Filtered() int { return j.filtered }

// NewJSON returns a printer of NDJSON. Of opts, only Warn, Redact and Filter
// apply.
func NewJSON(w io.Writer, opts Options) *JSON {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSON{enc: enc, dec: newDecoders(opts), redact: opts.Redact}
}

// jsonEvent is the documented JSON schema; see docs/usage.md.
type jsonEvent struct {
	Time        time.Time `json:"time"`
	Function    string    `json:"function"`
	Library     string    `json:"library"`
	Direction   string    `json:"direction"`
	ProcessName string    `json:"process_name"`
	PID         uint32    `json:"pid"`
	TID         uint32    `json:"tid"`
	ContainerID string    `json:"container_id,omitempty"`
	Container   string    `json:"container_name,omitempty"`
	ConnID      string    `json:"conn_id"`
	FD          *int32    `json:"fd,omitempty"`
	LocalAddr   string    `json:"local_addr,omitempty"`
	RemoteAddr  string    `json:"remote_addr,omitempty"`
	LatencyNs   int64     `json:"latency_ns"`
	Size        uint32    `json:"size"`
	Captured    int       `json:"captured"`
	Truncated   bool      `json:"truncated,omitempty"`
	Incomplete  bool      `json:"incomplete,omitempty"`
	ReadError   bool      `json:"read_error,omitempty"`
	// Exactly one of Data (valid UTF-8) or DataBase64 (anything else) is
	// set when bytes were captured.
	Data       *string `json:"data,omitempty"`
	DataBase64 []byte  `json:"data_base64,omitempty"`
	// With --status: which requests the event's responses answer.
	Answers string `json:"answers,omitempty"`
	// Set with --redact, which masks secrets in what's shown, and leaves
	// data that isn't text out.
	Redacted bool `json:"redacted,omitempty"`
	// The HTTP/2 frames in the data. A connection that started before
	// snoopy is followed from a call that starts with a frame, and its
	// headers can't be decoded.
	HTTP2      []jsonHTTP2Frame `json:"http2,omitempty"`
	HTTP2Error string           `json:"http2_error,omitempty"`
	// For QUIC packets: the frames, and the HTTP/3 frames they completed.
	QUICFrames []string         `json:"quic_frames,omitempty"`
	HTTP3      []jsonHTTP3Frame `json:"http3,omitempty"`
	// For HTTP/1.x: the messages and body bytes in the data, and what the
	// bytes of an encoded body in it decoded to.
	HTTP1 []jsonHTTP1 `json:"http1,omitempty"`
	Body  *jsonBody   `json:"body,omitempty"`
}

// jsonHTTP1 is a piece of HTTP/1.x in an event: a request's or response's
// start line and headers, or bytes of a body. End is set on the piece that
// completes its message: headers with no body after them, or a body's last
// bytes.
type jsonHTTP1 struct {
	// "request", "response", "body", or "headers": the rest of a header
	// block an earlier event started.
	Type    string       `json:"type"`
	Method  string       `json:"method,omitempty"`
	Target  string       `json:"target,omitempty"`
	Version string       `json:"version,omitempty"`
	Status  int          `json:"status,omitempty"`
	Reason  string       `json:"reason,omitempty"`
	Headers []jsonHeader `json:"headers,omitempty"`
	// Set when the header block's end wasn't in the captured bytes.
	HeadersIncomplete bool `json:"headers_incomplete,omitempty"`
	Bytes             int  `json:"bytes,omitempty"` // a body's, without chunked framing
	End               bool `json:"end,omitempty"`
}

// jsonHTTP1Pieces returns an event's HTTP/1.x messages and body bytes,
// with secrets masked if redact is set.
func jsonHTTP1Pieces(segs []http1Segment, redact bool) []jsonHTTP1 {
	var out []jsonHTTP1
	for _, s := range segs {
		switch {
		case s.msg != nil:
			m := s.msg
			p := jsonHTTP1{HeadersIncomplete: !m.complete, End: s.ends}
			if version, status, ok := strings.Cut(m.startLine, " "); ok && strings.HasPrefix(version, "HTTP/") {
				code, reason, _ := strings.Cut(status, " ")
				p.Type, p.Version, p.Reason = "response", version, reason
				p.Status, _ = strconv.Atoi(code)
			} else {
				method, rest, _ := strings.Cut(m.startLine, " ")
				target, version, _ := strings.Cut(rest, " ")
				if redact {
					target = redactTarget(target)
				}
				p.Type, p.Method, p.Target, p.Version = "request", method, target, version
			}
			for _, h := range m.headers {
				value := h[1]
				if redact {
					value = redactHeader(h[0], value)
				}
				p.Headers = append(p.Headers, jsonHeader{h[0], value})
			}
			out = append(out, p)
		case s.inBody:
			if n := len(out); n > 0 && out[n-1].Type == "body" && !out[n-1].End {
				out[n-1].Bytes += len(s.payload) // one piece per body per event
				out[n-1].End = s.ends
				continue
			}
			out = append(out, jsonHTTP1{Type: "body", Bytes: len(s.payload), End: s.ends})
		case s.ends:
			// The end of a header block an earlier call started.
			out = append(out, jsonHTTP1{Type: "headers", End: true})
		}
	}
	return out
}

// jsonBody is what a piece of a body with a Content-Encoding decoded to.
type jsonBody struct {
	ContentEncoding string  `json:"content_encoding"`
	Decoded         *string `json:"decoded,omitempty"`
	DecodedBase64   []byte  `json:"decoded_base64,omitempty"`
	Error           string  `json:"error,omitempty"`
}

func newJSONBody(p bodyPart) *jsonBody {
	if p.Encoding == "" {
		return nil
	}
	jb := &jsonBody{ContentEncoding: p.Encoding, Error: p.Err}
	if len(p.Decoded) > 0 {
		if utf8.Valid(p.Decoded) {
			s := string(p.Decoded)
			jb.Decoded = &s
		} else {
			jb.DecodedBase64 = p.Decoded
		}
	}
	return jb
}

type jsonHTTP3Frame struct {
	Type      string       `json:"type"`
	Stream    uint64       `json:"stream"`
	DataBytes int          `json:"data_bytes,omitempty"`
	Headers   []jsonHeader `json:"headers,omitempty"`
	Error     string       `json:"error,omitempty"`
	Body      *jsonBody    `json:"body,omitempty"`
}

type jsonHTTP2Frame struct {
	Type      string       `json:"type"`
	Stream    uint32       `json:"stream"`
	Length    int          `json:"length,omitempty"`
	Flags     []string     `json:"flags,omitempty"`
	Continued bool         `json:"continued,omitempty"`
	DataBytes int          `json:"data_bytes,omitempty"`
	Headers   []jsonHeader `json:"headers,omitempty"`
	// A header block that couldn't be decoded, because the connection
	// started before snoopy.
	HeadersNotDecoded bool      `json:"headers_not_decoded,omitempty"`
	Body              *jsonBody `json:"body,omitempty"`
	// The gRPC messages a DATA frame completed.
	GRPC []jsonGRPCMessage `json:"grpc_messages,omitempty"`
}

type jsonGRPCMessage struct {
	Bytes      int      `json:"bytes"`
	Compressed bool     `json:"compressed,omitempty"`
	Protobuf   []string `json:"protobuf,omitempty"` // as protoc --decode_raw shows it, a line per field
	Error      string   `json:"error,omitempty"`
}

type jsonHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (j *JSON) Print(ev *tracer.Event) error {
	// Decoding can fill in a QUIC packet's peer (see cidConns).
	dc := j.dec.decode(ev)
	if dc.notice {
		return nil
	}
	if dc.filteredOut {
		j.filtered++
		return nil
	}
	out := jsonEvent{
		Time:        ev.Time,
		Function:    ev.Function.String(),
		Library:     ev.Function.Library().String(),
		Direction:   ev.Function.Direction().String(),
		ProcessName: ev.Comm,
		PID:         ev.PID,
		TID:         ev.TID,
		ContainerID: ev.ContainerID,
		Container:   ev.ContainerName,
		ConnID:      fmt.Sprintf("%#x", ev.ConnID),
		LatencyNs:   ev.Latency.Nanoseconds(),
		Size:        ev.Size,
		Captured:    len(ev.Data),
		Truncated:   ev.Truncated(),
		Incomplete:  ev.Incomplete,
		ReadError:   ev.ReadError,
	}
	if ev.FD >= 0 {
		fd := ev.FD
		out.FD = &fd
	}
	if ev.Local.IsValid() {
		out.LocalAddr = ev.Local.String()
	}
	if ev.Remote.IsValid() {
		out.RemoteAddr = ev.Remote.String()
	}
	out.Redacted = j.redact
	out.Answers = strings.TrimPrefix(dc.answers, "for ")
	if len(dc.data) > 0 {
		switch {
		case utf8.Valid(dc.data):
			s := string(dc.data)
			out.Data = &s
		case !j.redact: // HTTP/2's and HTTP/3's headers are compressed in it
			out.DataBase64 = dc.data
		}
	}
	if dc.isQUIC {
		for _, it := range dc.quic {
			if it.Frame != "" {
				out.QUICFrames = append(out.QUICFrames, it.Frame)
				continue
			}
			jf := jsonHTTP3Frame{Type: it.HTTP3, Stream: it.Stream, DataBytes: len(it.Data), Error: it.Err, Body: newJSONBody(it.Body)}
			for _, h := range it.Headers {
				jf.Headers = append(jf.Headers, jsonHeader{h.Name, h.Value})
			}
			out.HTTP3 = append(out.HTTP3, jf)
		}
		return j.enc.Encode(out)
	}
	if !dc.isHTTP2 {
		out.HTTP2Error = dc.note
		out.HTTP1 = jsonHTTP1Pieces(dc.http1, j.redact)
		// Encoded bodies' pieces in the event, decoded, as one.
		var body bodyPart
		for _, s := range dc.http1 {
			if s.body.Encoding != "" {
				body.Encoding = s.body.Encoding
				body.Decoded = append(body.Decoded, s.body.Decoded...)
				body.Err = cmp.Or(body.Err, s.body.Err)
			}
		}
		out.Body = newJSONBody(body)
	}
	for _, f := range dc.http2 {
		jf := jsonHTTP2Frame{Type: f.Type, Stream: f.Stream, Length: f.Length, Flags: f.Flags, Continued: f.Continued,
			DataBytes: len(f.Data), HeadersNotDecoded: f.HeadersLost, Body: newJSONBody(f.Body)}
		for _, h := range f.Headers {
			jf.Headers = append(jf.Headers, jsonHeader{h.Name, h.Value})
		}
		for _, m := range f.GRPC {
			jf.GRPC = append(jf.GRPC, jsonGRPCMessage{Bytes: m.Length, Compressed: m.Compressed, Protobuf: m.Fields, Error: m.Err})
		}
		out.HTTP2 = append(out.HTTP2, jf)
	}
	return j.enc.Encode(out)
}
