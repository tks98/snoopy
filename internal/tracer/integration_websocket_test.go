//go:build integration

// This file is package tracer_test, not tracer, so that it can decode what
// it captures with internal/output, which imports tracer.
package tracer_test

import (
	"bufio"
	"bytes"
	"context"
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
	program := filepath.Join(t.TempDir(), "wsgo")
	build := exec.Command(goTool, "build", "-o", program, ".")
	build.Dir = "testdata/wsgo"
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build WebSocket program: %v: %s", err, out)
	}
	targets, err := discover.Inspect(program)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := tracer.New(tracer.Options{Comm: "wsgo"})
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

	if out, err := exec.Command(program).CombinedOutput(); err != nil || string(out) != "ok\n" {
		t.Fatalf("WebSocket program: %v: %s", err, out)
	}

	// As in testdata/wsgo/main.go.
	short := strings.Repeat("snoopy decodes WebSocket messages. ", 8)
	long := strings.Repeat("a long message that compresses well, ", 2000)
	want := map[string]int{}
	for _, m := range []string{short, short, long, "fragment one, fragment two", "\x00\x01\x02 binary"} {
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
		// The close frame is the client's, written and read; the 101
		// response is written and read; context takeover compresses every
		// message.
		if fmt.Sprint(got) == fmt.Sprint(want) && stats.closes >= 2 && stats.upgrades == 2 && stats.compressed == 20 {
			return
		}
	}
	// Only lengths: the messages are long.
	lengths := func(m map[string]int) map[int]int {
		out := map[int]int{}
		for k, v := range m {
			out[len(k)] = v
		}
		return out
	}
	t.Errorf("messages by length: got %v, want %v (%+v)", lengths(got), lengths(want), stats)
}

// wsStats counts close frames with status 1000 and the reason "done", 101
// responses, and compressed messages.
type wsStats struct{ closes, upgrades, compressed int }

// decodeWebSocket prints events as snoopy --json does and returns the
// WebSocket messages they hold, counted, what else it counts, and why
// decoding failed, if it did.
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
	msgs = map[string]int{}
	pending := map[string]string{} // by connection and direction
	sc := bufio.NewScanner(&buf)
	sc.Buffer(nil, 4<<20)
	for sc.Scan() {
		var ev struct {
			ConnID    string `json:"conn_id"`
			Direction string `json:"direction"`
			HTTP1     []struct {
				Status int `json:"status"`
			} `json:"http1"`
			WebSocket      []frame `json:"websocket"`
			WebSocketError string  `json:"websocket_error"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.WebSocketError != "" {
			errs = append(errs, ev.WebSocketError)
		}
		for _, p := range ev.HTTP1 {
			if p.Status == 101 {
				stats.upgrades++
			}
		}
		key := ev.ConnID + " " + ev.Direction
		for _, f := range ev.WebSocket {
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
	return msgs, stats, errs
}
