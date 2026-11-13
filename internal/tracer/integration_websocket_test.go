//go:build integration

// This file is package tracer_test, not tracer, so that it can decode what
// it captures with internal/output, which imports tracer.
package tracer_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tks98/snoopy/v2/internal/discover"
	"github.com/tks98/snoopy/v2/internal/output"
	"github.com/tks98/snoopy/v2/internal/tracer"
)

// TestWebSocket traces a WebSocket client and server written with
// coder/websocket (testdata/wsgo, a module of its own, which the Go
// toolchain downloads), with permessage-deflate and context takeover, and
// checks that snoopy's JSON output has each message, decompressed, from
// both ends of both directions.
func TestWebSocket(t *testing.T) {
	// As in testdata/wsgo/main.go.
	short := strings.Repeat("snoopy decodes WebSocket messages. ", 8)
	long := strings.Repeat("a long message that compresses well, ", 2000)
	traceWebSocket(t, "wsgo", nil, nil, short, short, long, "fragment one, fragment two", "\x00\x01\x02 binary")
}

// TestWebSocketStreams does the same for WebSocket over a stream of an
// HTTP/2 connection (RFC 8441) and of an HTTP/3 one (RFC 9220), with
// net/http and quic-go (testdata/wsstreams, which frames WebSocket itself).
func TestWebSocketStreams(t *testing.T) {
	// As in testdata/wsstreams/main.go.
	short := strings.Repeat("snoopy decodes WebSocket over HTTP/2 and HTTP/3. ", 8)
	long := strings.Repeat("a long message that compresses well, ", 2000)
	for _, tc := range []struct {
		name string
		env  []string
	}{{"h2", []string{"GODEBUG=http2xconnect=1"}}, {"h3", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			traceWebSocket(t, "wsstreams", []string{tc.name}, tc.env, short, short, long, "fragment one, fragment two", "\x00\x01\x02 binary")
		})
	}
}

// traceWebSocket builds the test program in testdata/name, runs it with
// args and env added to the environment, while tracing it, and checks that
// it sent and received the messages, each compressed, and a close with
// the status 1000 and the reason "done".
func traceWebSocket(t *testing.T, name string, args, env []string, messages ...string) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		if os.Getenv("SNOOPY_TEST_STRICT") == "1" {
			t.Fatal("go not installed (and SNOOPY_TEST_STRICT=1)")
		}
		t.Skip("go not installed")
	}
	program := filepath.Join(t.TempDir(), name)
	build := exec.Command(goTool, "build", "-o", program, ".")
	build.Dir = filepath.Join("testdata", name)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v: %s", name, err, out)
	}
	targets, err := discover.Inspect(program)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := tracer.New(tracer.Options{Comm: name})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	for _, target := range targets {
		if _, err := tr.Attach(target, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := tr.AttachSyscalls(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var events []*tracer.Event
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- tr.Run(ctx, func(ev *tracer.Event) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	cmd := exec.Command(program, args...)
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer // quic-go warns there about UDP buffer sizes
	cmd.Stderr = &stderr
	if out, err := cmd.Output(); err != nil || string(out) != "ok\n" {
		t.Fatalf("%s: %v: %s%s", name, err, out, stderr.Bytes())
	}

	want := map[string]int{}
	for _, m := range messages {
		want[m] += 4 // the client's write, the server's read, and the echo's write and read
	}
	var got map[string]int
	var stats wsStats
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		mu.Lock()
		evs := slices.Clone(events)
		mu.Unlock()
		var errs []string
		got, stats, errs = decodeWebSocket(t, evs)
		if len(errs) > 0 {
			t.Fatalf("decoding failed: %q (%+v)", errs, stats)
		}
		// The close frame is the client's, written and read; the handshake's
		// response is written and read; context takeover compresses every
		// message.
		if fmt.Sprint(got) == fmt.Sprint(want) && stats.closes >= 2 && stats.upgrades == 2 && stats.compressed == 4*len(messages) {
			// The HAR log has the same messages, on the two ends' entries
			// of the upgrade request.
			if got, entries := harWebSocket(t, evs); fmt.Sprint(got) != fmt.Sprint(want) || entries != 2 {
				t.Errorf("HAR: %d WebSocket entries, messages by length %v", entries, lengths(got))
			}
			return
		}
	}
	t.Errorf("messages by length: got %v, want %v (%+v)", lengths(got), lengths(want), stats)
}

// lengths counts messages by length, to show: the messages are long.
func lengths(m map[string]int) map[int]int {
	out := map[int]int{}
	for k, v := range m {
		out[len(k)] = v
	}
	return out
}

// harWebSocket writes events to a HAR log as snoopy --har does and returns
// the WebSocket messages it lists, counted, and how many entries are
// WebSocket connections.
func harWebSocket(t *testing.T, evs []*tracer.Event) (msgs map[string]int, entries int) {
	t.Helper()
	var buf bytes.Buffer
	h := output.NewHAR(&buf, "test", output.Options{})
	for _, ev := range evs {
		if err := h.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Log struct {
			Entries []struct {
				ResourceType string `json:"_resourceType"`
				Messages     []struct {
					Type   string `json:"type"`
					Opcode int    `json:"opcode"`
					Data   string `json:"data"`
				} `json:"_webSocketMessages"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	msgs = map[string]int{}
	for _, e := range log.Log.Entries {
		if e.ResourceType != "websocket" {
			continue
		}
		entries++
		for _, m := range e.Messages {
			data := m.Data
			if m.Opcode != 1 {
				b, err := base64.StdEncoding.DecodeString(m.Data)
				if err != nil {
					t.Fatalf("message data not base64: %v", err)
				}
				data = string(b)
			}
			msgs[data]++
		}
	}
	return msgs, entries
}

// wsStats counts close frames with status 1000 and the reason "done", 101
// responses (or, on HTTP/2 and HTTP/3, 200 responses), and compressed
// messages.
type wsStats struct{ closes, upgrades, compressed int }

// decodeWebSocket prints events as snoopy --json does and returns the
// WebSocket messages they hold, counted, what else it counts, and why
// decoding failed, if it did: on HTTP/1.1 connections, and on HTTP/2 and
// HTTP/3 streams.
func decodeWebSocket(t *testing.T, evs []*tracer.Event) (msgs map[string]int, stats wsStats, errs []string) {
	t.Helper()
	// Events from different CPUs can arrive out of order; each connection's
	// calls are one after the other.
	slices.SortStableFunc(evs, func(a, b *tracer.Event) int { return a.Time.Compare(b.Time) })
	var buf bytes.Buffer
	j := output.NewJSON(&buf, output.Options{})
	for _, ev := range evs {
		if err := j.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	type frame struct {
		Opcode      string  `json:"opcode"`
		Payload     *string `json:"payload"`
		End         bool    `json:"end"`
		CloseCode   int     `json:"close_code"`
		CloseReason string  `json:"close_reason"`
		Body        *struct {
			Decoded *string `json:"decoded"`
			Error   string  `json:"error"`
		} `json:"body"`
	}
	type stream struct {
		Stream  uint64 `json:"stream"`
		Headers []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
		WebSocket      []frame `json:"websocket"`
		WebSocketError string  `json:"websocket_error"`
	}
	msgs = map[string]int{}
	pending := map[string]string{} // by connection, direction and stream
	sc := bufio.NewScanner(&buf)
	sc.Buffer(nil, 4<<20)
	for sc.Scan() {
		var ev struct {
			ConnID    string `json:"conn_id"`
			Direction string `json:"direction"`
			HTTP1     []struct {
				Status int `json:"status"`
			} `json:"http1"`
			WebSocket      []frame  `json:"websocket"`
			WebSocketError string   `json:"websocket_error"`
			HTTP2          []stream `json:"http2"`
			HTTP3          []stream `json:"http3"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		for _, p := range ev.HTTP1 {
			if p.Status == 101 {
				stats.upgrades++
			}
		}
		streams := append([]stream{{WebSocket: ev.WebSocket, WebSocketError: ev.WebSocketError}}, append(ev.HTTP2, ev.HTTP3...)...)
		for _, s := range streams {
			for _, h := range s.Headers {
				if h.Name == ":status" && h.Value == "200" {
					stats.upgrades++
				}
			}
			if s.WebSocketError != "" {
				errs = append(errs, s.WebSocketError)
			}
			key := fmt.Sprintf("%s %s %d", ev.ConnID, ev.Direction, s.Stream)
			for _, f := range s.WebSocket {
				switch {
				case f.Opcode == "close":
					if f.End && f.CloseCode == 1000 && f.CloseReason == "done" {
						stats.closes++
					}
				case f.Opcode == "ping" || f.Opcode == "pong":
				case f.Body != nil && f.Body.Error != "":
					errs = append(errs, f.Body.Error)
				case f.Body != nil && f.Body.Decoded != nil:
					msgs[*f.Body.Decoded]++
					stats.compressed++
					delete(pending, key)
				default:
					if f.Payload != nil {
						pending[key] += *f.Payload
					}
					if f.End {
						msgs[pending[key]]++
						delete(pending, key)
					}
				}
			}
		}
	}
	return msgs, stats, errs
}
