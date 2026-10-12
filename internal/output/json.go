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
	enc *json.Encoder
}

func NewJSON(w io.Writer) *JSON {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSON{enc: enc}
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
	return j.enc.Encode(out)
}
