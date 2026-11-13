package output

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// harWSEntry is the part of an entry that WebSocket messages and
// server-sent events add, as Chrome's DevTools writes it.
type harWSEntry struct {
	ResourceType string `json:"_resourceType"`
	Response     struct {
		Status int `json:"status"`
	} `json:"response"`
	Time     float64 `json:"time"`
	Comment  string  `json:"comment"`
	Messages *[]struct {
		Type   string  `json:"type"`
		Time   float64 `json:"time"`
		Opcode int     `json:"opcode"`
		Data   *string `json:"data"`
	} `json:"_webSocketMessages"`
	Events []struct {
		Time      float64 `json:"time"`
		EventName string  `json:"eventName"`
		EventID   *string `json:"eventId"`
		Data      string  `json:"data"`
	} `json:"_eventSourceMessages"`
}

func harWSEntries(t *testing.T, b []byte) []harWSEntry {
	t.Helper()
	readHAR(t, b) // the rest of the log is as for any entry
	var l struct {
		Log struct {
			Entries []harWSEntry `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatalf("%v:\n%s", err, b)
	}
	return l.Log.Entries
}

// harOf prints the events to a HAR printer, the nth a millisecond after
// the first, and returns the log.
func harOf(t *testing.T, opts Options, evs ...*tracer.Event) []byte {
	t.Helper()
	var out bytes.Buffer
	h := NewHAR(&out, "test", opts)
	for i, ev := range evs {
		ev.Time = ev.Time.Add(time.Duration(i) * time.Millisecond)
		if err := h.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// A connection's messages are listed on the upgrade request's entry: whole
// messages, however they were framed and split across calls, compressed
// ones decompressed; pings and pongs left out, the close in the comment.
func TestHARWebSocket(t *testing.T) {
	z := &deflater{takeover: true}
	hello := wsFrameBytes(wsText, false, false, wsKey, []byte("hel"))
	hello = append(hello, wsFrameBytes(wsPing, true, false, wsKey, []byte("p"))...) // between fragments
	hello = append(hello, wsFrameBytes(wsContinuation, true, false, wsKey, []byte("lo"))...)
	evs := append(wsHandshake("permessage-deflate"), wsEvents(tracer.FuncSSLWrite, hello, 3)...)
	evs = append(evs,
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsBinary, true, false, nil, []byte{0, 1, 0xff})),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, true, nil, z.message(t, `{"price": 42}`))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsPong, true, false, nil, []byte("p"))),
		wsEvent(tracer.FuncSSLWrite, wsFrameBytes(wsClose, true, false, wsKey, append([]byte{0x03, 0xe8}, "bye"...))),
	)
	entries := harWSEntries(t, harOf(t, Options{}, evs...))
	if len(entries) != 1 {
		t.Fatalf("%d entries", len(entries))
	}
	e := entries[0]
	if e.ResourceType != "websocket" || e.Response.Status != 101 || e.Messages == nil {
		t.Fatalf("%+v", e)
	}
	start := float64(evs[0].Time.UnixNano()) / 1e9
	var got []string
	for _, m := range *e.Messages {
		got = append(got, m.Type+" "+itoa(m.Opcode)+" "+*m.Data)
		if m.Time <= start || m.Time > start+1 {
			t.Errorf("time %f, the request's %f", m.Time, start)
		}
	}
	want := []string{
		"send 1 hello",
		"receive 2 " + base64.StdEncoding.EncodeToString([]byte{0, 1, 0xff}),
		`receive 1 {"price": 42}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("messages:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The message ends at the last of its calls, and the entry at the close.
	if (*e.Messages)[0].Time != float64(evs[2+(len(hello)+2)/3-1].Time.UnixNano())/1e9 {
		t.Errorf("the first message's time %f", (*e.Messages)[0].Time)
	}
	if e.Comment != "close sent: 1000 (normal closure): bye" || e.Time < float64(len(evs)-1) {
		t.Errorf("comment %q, time %f", e.Comment, e.Time)
	}
}

// An upgrade with no messages yet has an empty list; other entries have
// none.
func TestHARWebSocketEmpty(t *testing.T) {
	evs := append([]*tracer.Event{
		event(tracer.FuncSSLWrite, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		event(tracer.FuncSSLRead, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
	}, wsHandshake("")...)
	b := harOf(t, Options{}, evs...)
	entries := harWSEntries(t, b)
	if len(entries) != 2 || entries[0].Messages != nil || entries[0].ResourceType != "" ||
		entries[1].Messages == nil || len(*entries[1].Messages) != 0 || entries[1].ResourceType != "websocket" {
		t.Errorf("%s", b)
	}
}

// --redact masks secrets in text messages, as a whole, however they were
// split, and in a close's reason; binary messages' data is left out.
func TestHARWebSocketRedact(t *testing.T) {
	secret := "Authorization: Bearer abcdefghijklmnop"
	frames := cat(wsFrameBytes(wsText, false, false, wsKey, []byte(secret[:25])),
		wsFrameBytes(wsContinuation, true, false, wsKey, []byte(secret[25:])))
	evs := append(wsHandshake(""), wsEvents(tracer.FuncSSLWrite, frames, 5)...)
	evs = append(evs,
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsBinary, true, false, nil, []byte("token=abcdefghijklmnop"))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsClose, true, false, nil, append([]byte{0x03, 0xe8}, "Bearer abcdefghijklmnop"...))))
	b := harOf(t, Options{Redact: true}, evs...)
	if bytes.Contains(b, []byte("abcdefghijklmnop")) || bytes.Contains(b, []byte(base64.StdEncoding.EncodeToString([]byte("token=abcdefghijklmnop")))) {
		t.Fatalf("a secret in the log:\n%s", b)
	}
	ms := *harWSEntries(t, b)[0].Messages
	if len(ms) != 2 || *ms[0].Data != "Authorization: Bearer [redacted]" || *ms[1].Data != "" {
		t.Errorf("%s", b)
	}
}

// An entry keeps up to maxHARMessage bytes of a message, and
// maxHARMessageBytes of them all; it says what it left out, and which
// messages had bytes that weren't captured.
func TestHARWebSocketLimits(t *testing.T) {
	evs := wsHandshake("")
	big := bytes.Repeat([]byte("x"), maxHARMessage+10)
	evs = append(evs, wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, false, nil, big)))
	for range maxHARMessageBytes / maxHARMessage {
		evs = append(evs, wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, false, nil, big[:maxHARMessage])))
	}
	// A message whose middle wasn't captured.
	gap := wsFrameBytes(wsText, true, false, nil, []byte("0123456789"))
	ev := wsEvent(tracer.FuncSSLRead, gap[:5])
	ev.Size = uint32(len(gap)) // the rest of the call wasn't captured
	evs = append(evs, ev)
	e := harWSEntries(t, harOf(t, Options{}, evs...))[0]
	ms := *e.Messages
	if len(ms) != maxHARMessageBytes/maxHARMessage || len(*ms[0].Data) != maxHARMessage {
		t.Errorf("%d messages, the first of %d bytes", len(ms), len(*ms[0].Data))
	}
	want := "2 later messages left out (only 100000, or 16 MiB, kept); 1 messages cut short (only the first 4194304 bytes of each kept); " +
		"1 messages with bytes that weren't captured"
	if e.Comment != want {
		t.Errorf("comment %q\nwant    %q", e.Comment, want)
	}
}

// A log written while a connection is open has its messages so far, not
// one still incomplete.
func TestHARWebSocketWriteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.har")
	h := NewHAR(nil, "test", Options{})
	for _, ev := range append(wsHandshake(""),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, true, false, nil, []byte("one"))),
		wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsText, false, false, nil, []byte("tw")))) {
		h.Print(ev)
	}
	if err := h.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if ms := *harWSEntries(t, b)[0].Messages; len(ms) != 1 || *ms[0].Data != "one" {
		t.Errorf("%s", b)
	}
	h.Print(wsEvent(tracer.FuncSSLRead, wsFrameBytes(wsContinuation, true, false, nil, []byte("o"))))
	if err := h.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if ms := *harWSEntries(t, b)[0].Messages; len(ms) != 2 || *ms[1].Data != "two" {
		t.Errorf("%s", b)
	}
}

// An event stream's events are listed as Chrome lists them, with the
// body as it was; keep-alives are left out.
func TestHAREventSource(t *testing.T) {
	evs := []*tracer.Event{
		event(tracer.FuncSSLWrite, "GET /v1/stream HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
		event(tracer.FuncSSLRead, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nevent: delta\nid: 7\ndata: a\ndata: b\n\n: keep-alive\n\n"),
		event(tracer.FuncSSLRead, "data: [DONE]\n\n"),
	}
	b := harOf(t, Options{}, evs...)
	e := harWSEntries(t, b)[0]
	if e.ResourceType != "" || e.Messages != nil || len(e.Events) != 2 {
		t.Fatalf("%s", b)
	}
	if ev := e.Events[0]; ev.EventName != "delta" || *ev.EventID != "7" || ev.Data != "a\nb" {
		t.Errorf("%+v", ev)
	}
	if ev := e.Events[1]; ev.EventName != "message" || *ev.EventID != "" || ev.Data != "[DONE]" ||
		ev.Time != float64(evs[2].Time.UnixNano())/1e9 {
		t.Errorf("%+v", ev)
	}
	if !strings.Contains(readHAR(t, b).Log.Entries[0].Response.Content.Text, ": keep-alive") {
		t.Errorf("the body changed:\n%s", b)
	}
}

// WebSocket over HTTP/2 and HTTP/3: the extended CONNECT's entry has the
// stream's messages, and its DATA isn't a body; the GET beside it is an
// entry of its own.
func TestHARWebSocketStreams(t *testing.T) {
	type message struct{ typ, data string }
	check := func(name string, b []byte, n int, want []message, comment string) {
		t.Helper()
		entries := harWSEntries(t, b)
		if len(entries) != n {
			t.Fatalf("%s: %d entries:\n%s", name, len(entries), b)
		}
		e := entries[0]
		if e.ResourceType != "websocket" || e.Response.Status != 200 || e.Messages == nil || e.Comment != comment {
			t.Fatalf("%s: %+v", name, e)
		}
		if l := readHAR(t, b).Log.Entries[0]; l.Request.Method != "CONNECT" || l.Response.Content.Text != "" || l.Response.BodySize != 0 {
			t.Errorf("%s: %+v", name, l)
		}
		var got []message
		for _, m := range *e.Messages {
			if m.Opcode != wsText {
				t.Errorf("%s: opcode %d", name, m.Opcode)
			}
			got = append(got, message{m.Type, *m.Data})
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: messages %q\nwant %q", name, got, want)
		}
		for _, e := range entries[1:] {
			if e.Messages != nil || e.ResourceType != "" {
				t.Errorf("%s: %+v", name, e)
			}
		}
	}
	check("HTTP/2", harOf(t, Options{Redact: true}, wsHTTP2(t)...), 2, []message{
		{"send", `{"op":"hello","token":"[redacted]"}`}, {"receive", "hello over HTTP/2"}},
		"close sent: 1000 (normal closure): bye")
	evs, _ := wsHTTP3(t)
	check("HTTP/3", harOf(t, Options{}, evs...), 1, []message{
		{"send", "hello over HTTP/3, hello over HTTP/3"}, {"receive", "hi back"}}, "")
}

// An event stream's events are all listed, after an OpenAI-style [DONE]
// too, which ends the exchange for --requests.
func TestHAREventSourceAfterDone(t *testing.T) {
	evs := []*tracer.Event{
		event(tracer.FuncSSLWrite, "POST /v1/chat/completions HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
		event(tracer.FuncSSLRead, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: {\"a\":1}\n\ndata: [DONE]\n\n"),
		event(tracer.FuncSSLRead, "event: usage\ndata: {\"tokens\":3}\n\n"),
	}
	e := harWSEntries(t, harOf(t, Options{}, evs...))[0]
	var got []string
	for _, ev := range e.Events {
		got = append(got, ev.EventName+" "+ev.Data)
	}
	if want := []string{`message {"a":1}`, "message [DONE]", `usage {"tokens":3}`}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("events %q\nwant %q", got, want)
	}
}
