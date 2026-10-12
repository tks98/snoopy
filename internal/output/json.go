package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"github.com/tks98/snoopy/internal/tracer"
)

// JSON prints one JSON object per line (NDJSON).
type JSON struct {
	enc  *json.Encoder
	h2   *http2Conns
	quic *quicConns
}

func NewJSON(w io.Writer) *JSON {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSON{enc: enc, h2: newHTTP2Conns(), quic: newQUICConns()}
}

// jsonEvent is the documented JSON schema; see README.md.
type jsonEvent struct {
	Time        time.Time `json:"time"`
	Function    string    `json:"function"`
	Library     string    `json:"library"`
	Direction   string    `json:"direction"`
	ProcessName string    `json:"process_name"`
	PID         uint32    `json:"pid"`
	TID         uint32    `json:"tid"`
	ContainerID string    `json:"container_id,omitempty"`
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
	// The HTTP/2 frames in the data, for connections whose start was seen.
	HTTP2      []jsonHTTP2Frame `json:"http2,omitempty"`
	HTTP2Error string           `json:"http2_error,omitempty"`
	// For QUIC packets: the frames, and the HTTP/3 frames they completed.
	QUICFrames []string         `json:"quic_frames,omitempty"`
	HTTP3      []jsonHTTP3Frame `json:"http3,omitempty"`
}

type jsonHTTP3Frame struct {
	Type      string       `json:"type"`
	Stream    uint64       `json:"stream"`
	DataBytes int          `json:"data_bytes,omitempty"`
	Headers   []jsonHeader `json:"headers,omitempty"`
	Error     string       `json:"error,omitempty"`
}

type jsonHTTP2Frame struct {
	Type      string       `json:"type"`
	Stream    uint32       `json:"stream"`
	Length    int          `json:"length,omitempty"`
	Flags     []string     `json:"flags,omitempty"`
	Continued bool         `json:"continued,omitempty"`
	DataBytes int          `json:"data_bytes,omitempty"`
	Headers   []jsonHeader `json:"headers,omitempty"`
}

type jsonHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (j *JSON) Print(ev *tracer.Event) error {
	out := jsonEvent{
		Time:        ev.Time,
		Function:    ev.Function.String(),
		Library:     ev.Function.Library().String(),
		Direction:   ev.Function.Direction().String(),
		ProcessName: ev.Comm,
		PID:         ev.PID,
		TID:         ev.TID,
		ContainerID: ev.ContainerID,
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
	if len(ev.Data) > 0 {
		if utf8.Valid(ev.Data) {
			s := string(ev.Data)
			out.Data = &s
		} else {
			out.DataBase64 = ev.Data
		}
	}
	if ev.Function.IsQUIC() {
		items, _ := j.quic.process(ev)
		for _, it := range items {
			if it.Frame != "" {
				out.QUICFrames = append(out.QUICFrames, it.Frame)
				continue
			}
			jf := jsonHTTP3Frame{Type: it.HTTP3, Stream: it.Stream, DataBytes: len(it.Data), Error: it.Err}
			for _, h := range it.Headers {
				jf.Headers = append(jf.Headers, jsonHeader{h.Name, h.Value})
			}
			out.HTTP3 = append(out.HTTP3, jf)
		}
		return j.enc.Encode(out)
	}
	frames, _, note := j.h2.process(ev)
	out.HTTP2Error = note
	for _, f := range frames {
		jf := jsonHTTP2Frame{Type: f.Type, Stream: f.Stream, Length: f.Length, Flags: f.Flags, Continued: f.Continued, DataBytes: len(f.Data)}
		for _, h := range f.Headers {
			jf.Headers = append(jf.Headers, jsonHeader{h.Name, h.Value})
		}
		out.HTTP2 = append(out.HTTP2, jf)
	}
	return j.enc.Encode(out)
}
