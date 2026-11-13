//go:build integration

package tracer_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
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

// TestSSEHTTP3 traces the quic-go test program (testdata/quicgo) reading
// server-sent events over HTTP/3 from its own server, plain and gzipped,
// with an event large enough to take several QUIC packets, and checks what
// snoopy's JSON and --requests output make of them: every event, each with
// the packet it arrived in, as it arrived, and a line for the stream at its
// headers and at its end.
func TestSSEHTTP3(t *testing.T) {
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
	program := filepath.Join(t.TempDir(), "quicgo")
	build := exec.Command(goTool, "build", "-o", program, ".")
	build.Dir = "testdata/quicgo"
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build quic-go program: %v: %s", err, out)
	}
	targets, err := discover.Inspect(program)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := tracer.New(tracer.Options{Comm: "quicgo"})
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

	// The server, under a name --comm doesn't match, so that only the
	// client's side is traced.
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := fmt.Sprint(l.LocalAddr().(*net.UDPAddr).Port)
	l.Close()
	server := filepath.Join(t.TempDir(), "qgserver")
	if err := os.Symlink(program, server); err != nil {
		t.Fatal(err)
	}
	srv := exec.Command(server, "server", port)
	stdout, err := srv.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "listening\n" {
		t.Fatalf("quic-go server: %q, %v", line, err)
	}

	// As testdata/quicgo's events handler sends them.
	big := strings.Repeat("x", 5000)
	want := []string{
		`message_start {"type": "message_start"}`,
		`delta {"index": 0, "text": "word0"}`,
		`delta {"index": 1, "text": "word1"}`,
		`delta {"index": 2, "text": "word2"}`,
		"big " + big,
		`delta {"index": 3, "text": "word3"}`,
		"done [DONE]",
	}
	for _, gzip := range []string{"0", "1"} {
		path := "/events?n=4&gap=250ms&big=5000&gzip=" + gzip
		out, err := exec.Command(program, "client", port, path).CombinedOutput()
		if err != nil || !bytes.HasPrefix(out, []byte("200 OK text/event-stream\n")) || !bytes.Contains(out, []byte("[DONE]")) {
			t.Fatalf("quic-go client: %v: %s", err, out)
		}
		var got []sseSeen
		var lines []string
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			mu.Lock()
			evs := slices.Clone(events)
			mu.Unlock()
			got, lines = decodeSSE(t, evs, path)
			if len(got) >= len(want) && len(lines) >= 2 {
				break
			}
		}
		var shown []string
		for _, e := range got {
			shown = append(shown, e.event+" "+e.data)
		}
		if !slices.Equal(shown, want) {
			t.Fatalf("gzip=%s: events:\n%.300q", gzip, shown)
		}
		// Each delta is shown when its packet arrives, not at the end.
		for i := 2; i < len(got); i++ {
			if got[i].event == "delta" && got[i].at.Sub(got[i-2].at) < 150*time.Millisecond {
				t.Errorf("gzip=%s: events %d and %d arrived %v apart", gzip, i-2, i, got[i].at.Sub(got[i-2].at))
			}
		}
		// Uncompressed, the big event comes in packets of its own, and is
		// shown with its last.
		if gzip == "0" && got[4].callBytes >= len(big) {
			t.Errorf("the big event came in one call of %d bytes", got[4].callBytes)
		}
		if len(lines) != 2 || !strings.Contains(lines[0], ", streaming, ") || !strings.Contains(lines[1], ", 7 events, ") {
			t.Errorf("gzip=%s: --requests:\n%s", gzip, strings.Join(lines, "\n"))
		}
		mu.Lock()
		events = nil
		mu.Unlock()
	}
}

// sseSeen is an event in snoopy's JSON output, with the time of the call
// it came with and that call's HTTP/3 DATA bytes.
type sseSeen struct {
	event, data string
	at          time.Time
	callBytes   int
}

// decodeSSE prints events as snoopy --json does and returns the
// server-sent events of the response to a request for path, and the lines
// --requests prints for it.
func decodeSSE(t *testing.T, evs []*tracer.Event, path string) ([]sseSeen, []string) {
	t.Helper()
	slices.SortStableFunc(evs, func(a, b *tracer.Event) int { return a.Time.Compare(b.Time) })
	var buf, req bytes.Buffer
	j := output.NewJSON(&buf, output.Options{})
	r := output.NewRequests(&req, output.Options{})
	for _, ev := range evs {
		if err := j.Print(ev); err != nil {
			t.Fatal(err)
		}
		if err := r.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	var out []sseSeen
	stream, found := -1, false
	sc := bufio.NewScanner(&buf)
	sc.Buffer(nil, 4<<20)
	for sc.Scan() {
		var ev struct {
			Time  time.Time `json:"time"`
			HTTP3 []struct {
				Type    string `json:"type"`
				Stream  int    `json:"stream"`
				Bytes   int    `json:"data_bytes"`
				Headers []struct {
					Name, Value string
				} `json:"headers"`
				SSE []struct {
					Event string  `json:"event"`
					Data  *string `json:"data"`
				} `json:"sse_events"`
			} `json:"http3"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		callBytes := 0
		for _, f := range ev.HTTP3 {
			if f.Type == "DATA" || f.Type == "DATA (continued)" {
				callBytes += f.Bytes
			}
		}
		for _, f := range ev.HTTP3 {
			for _, h := range f.Headers {
				if h.Name == ":path" && h.Value == path {
					stream, found = f.Stream, true
				}
			}
			if !found || f.Stream != stream {
				continue
			}
			for _, e := range f.SSE {
				if e.Data != nil { // not the keep-alive comment
					out = append(out, sseSeen{e.Event, *e.Data, ev.Time, callBytes})
				}
			}
		}
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(req.String()), "\n") {
		if strings.Contains(line, path+" HTTP/3") {
			lines = append(lines, line)
		}
	}
	return out, lines
}
