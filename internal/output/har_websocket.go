package output

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// A WebSocket connection's messages, and a text/event-stream's events, are
// written on the entry of the request they follow as Chrome's DevTools
// writes them, which its HAR import and other HAR viewers read: an array
// _webSocketMessages, and _resourceType "websocket", on the upgrade
// request's entry (an HTTP/1.1 GET answered by a 101, or an HTTP/2 or
// HTTP/3 extended CONNECT answered by a 2xx, whose stream's DATA carries
// the frames), and _eventSourceMessages on an event stream's. See
// devtools-frontend's front_end/models/har/Log.ts, which builds them, and
// the DevTools protocol's Network.WebSocketFrame, which they come from:
// each is a whole message (not a frame), its data the text of a text
// message (opcode 1) and base64 for any other opcode, its time in seconds
// since the epoch.
//
// As in DevTools, only data messages are listed: compressed ones as they
// decompressed to, fragmented ones once, at the event that ends them.
// Pings and pongs are left out, and a close frame is said in the entry's
// comment. A message still incomplete when the log is written is left out
// of it, until it ends.

// The most of the messages and events an entry keeps: their count, and
// their data's bytes; and the most of one message's data. Later ones are
// counted, in the entry's comment.
const (
	maxHARMessages     = 100000
	maxHARMessageBytes = 4 * maxHARBody
	maxHARMessage      = maxHARBody
)

// harWS is what an entry keeps of the WebSocket connection or event stream
// that follows its request.
type harWS struct {
	messages []harWSMessage
	events   []harSSEEvent
	bytes    int // of the messages' and events' data kept
	// The message being read in each direction (by tracer.Direction), until
	// its last frame: its data so far; how many of its bytes were captured,
	// of how many its frames said; and whether some didn't fit.
	pending [2]struct {
		started   bool
		data      []byte
		got, want int64
		cut       bool
	}
	left, cut, gaps, undecoded int      // messages or events left out, cut, missing bytes, not decompressed
	closes                     []string // close frames, as "sent: 1000 (normal closure)"
	stopped                    string   // why decoding stopped, if it did
}

type harWSMessage struct {
	sent   bool
	time   time.Time
	opcode byte
	data   []byte
}

type harSSEEvent struct {
	time           time.Time
	name, id, data string
}

// fits reports whether a message or event of n bytes can still be kept,
// and counts it if not.
func (w *harWS) fits(n int) bool {
	if len(w.messages)+len(w.events) >= maxHARMessages || w.bytes+n > maxHARMessageBytes {
		w.left++
		return false
	}
	w.bytes += n
	return true
}

// webSocket adds the WebSocket frames of an event, sent in direction dir,
// to the entry of the request that switched the connection to WebSocket.
func (e *harEntry) webSocket(at time.Time, dir tracer.Direction, p *wsPart) {
	if !e.kept || p == nil {
		return
	}
	e.end = at // the entry lasts as long as its connection
	if e.ws == nil {
		e.ws = &harWS{}
	}
	w := e.ws
	sent := dir == e.reqDir
	if p.Err != "" && w.stopped == "" {
		w.stopped = p.Err
	}
	pm := &w.pending[dir]
	for _, f := range p.Frames {
		if f.Opcode >= wsClose {
			if f.Opcode == wsClose && f.Complete && len(w.closes) < 2 {
				w.closes = append(w.closes, map[bool]string{true: "sent", false: "received"}[sent]+": "+strings.TrimPrefix(f.describe(), "close "))
			}
			continue
		}
		if f.startsMessage() {
			pm.started, pm.data, pm.got, pm.want, pm.cut = true, nil, 0, 0, false
		}
		if !pm.started {
			continue // a message that began before what was decoded
		}
		if !f.Continued {
			pm.want += f.Length
		}
		pm.got += int64(len(f.Data))
		if !f.Compressed {
			piece := f.Data
			if room := maxHARMessage - len(pm.data); len(piece) > room {
				piece, pm.cut = piece[:max(room, 0)], true
			}
			pm.data = append(pm.data, piece...)
		}
		if !f.endsMessage() {
			continue
		}
		data := pm.data
		if f.Compressed {
			data = f.Body.Decoded
			if f.Body.Err != "" {
				w.undecoded++
			}
			if len(data) > maxHARMessage {
				data, pm.cut = data[:maxHARMessage], true
			}
		}
		if pm.got != pm.want && f.Body.Err == "" {
			w.gaps++ // a compressed message's are said by its Body.Err
		}
		if pm.cut {
			w.cut++
		}
		if w.fits(len(data)) {
			w.messages = append(w.messages, harWSMessage{sent: sent, time: at, opcode: f.Message, data: data})
		}
		pm.started, pm.data = false, nil
	}
}

// sse adds the server-sent events a response's bytes completed.
func (e *harEntry) sse(at time.Time, events []sseEvent) {
	if !e.kept || len(events) == 0 {
		return
	}
	if e.ws == nil {
		e.ws = &harWS{}
	}
	w := e.ws
	for _, ev := range events {
		if ev.commentOnly() {
			continue
		}
		if ev.Cut {
			w.cut++
		}
		if w.fits(len(ev.Data)) {
			w.events = append(w.events, harSSEEvent{time: at, name: cmpOr(ev.Type, "message"), id: ev.ID, data: ev.Data})
		}
	}
}

// harWSMessageJSON is a message in _webSocketMessages.
type harWSMessageJSON struct {
	Type   string  `json:"type"` // send or receive
	Time   float64 `json:"time"` // seconds since the epoch
	Opcode int     `json:"opcode"`
	Data   string  `json:"data"`
}

// harSSEEventJSON is an event in _eventSourceMessages.
type harSSEEventJSON struct {
	Time      float64 `json:"time"`
	EventName string  `json:"eventName"`
	EventID   string  `json:"eventId"`
	Data      string  `json:"data"`
}

func epochSeconds(t time.Time) float64 {
	return float64(t.UnixNano()) / 1e9
}

// isWebSocket reports whether an entry's response switched its connection
// to WebSocket, or, for an extended CONNECT on HTTP/2 or HTTP/3 (RFC 8441
// and 9220), its stream.
func (e *harEntry) isWebSocket() bool {
	if e.tunnel != "" {
		return strings.EqualFold(e.tunnel, "websocket")
	}
	if e.resp.status != 101 {
		return false
	}
	for _, hd := range e.resp.headers {
		if strings.EqualFold(strings.TrimSpace(hd[0]), "upgrade") && strings.Contains(strings.ToLower(hd[1]), "websocket") {
			return true
		}
	}
	return false
}

// json returns an entry's WebSocket messages and server-sent events for
// the log, and what its comment says of them. With redact, secrets are
// masked in each message's text, and binary messages' data is left out,
// as in the JSON output.
func (w *harWS) json(redact bool) (messages []harWSMessageJSON, events []harSSEEventJSON, notes []string) {
	if w == nil {
		return nil, nil, nil
	}
	for _, m := range w.messages {
		jm := harWSMessageJSON{Type: "receive", Time: epochSeconds(m.time), Opcode: int(m.opcode)}
		if m.sent {
			jm.Type = "send"
		}
		switch {
		case m.opcode == wsText && redact:
			jm.Data = string(redactText(m.data))
		case m.opcode == wsText:
			jm.Data = string(m.data)
		case !redact:
			jm.Data = base64.StdEncoding.EncodeToString(m.data)
		}
		messages = append(messages, jm)
	}
	for _, ev := range w.events {
		data := ev.data
		if redact {
			data = string(redactText([]byte(data)))
		}
		events = append(events, harSSEEventJSON{Time: epochSeconds(ev.time), EventName: ev.name, EventID: ev.id, Data: data})
	}
	what := "messages"
	if len(w.events) > 0 {
		what = "events"
	}
	if w.left > 0 {
		notes = append(notes, fmt.Sprintf("%d later %s left out (only %d, or %d MiB, kept)", w.left, what, maxHARMessages, maxHARMessageBytes>>20))
	}
	if w.cut > 0 {
		notes = append(notes, fmt.Sprintf("%d %s cut short (only the first %d bytes of each kept)", w.cut, what, maxHARMessage))
	}
	if w.gaps > 0 {
		notes = append(notes, fmt.Sprintf("%d messages with bytes that weren't captured", w.gaps))
	}
	if w.undecoded > 0 {
		notes = append(notes, fmt.Sprintf("%d %s messages not decoded", w.undecoded, permessageDeflate))
	}
	for _, c := range w.closes {
		if redact {
			c = string(redactText([]byte(c)))
		}
		notes = append(notes, "close "+c)
	}
	if w.stopped != "" {
		notes = append(notes, w.stopped)
	}
	return messages, events, notes
}
