//go:build integration

package tracer_test

import (
	"bufio"
	"bytes"
	"context"
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

// TestQuicGoDialAddr traces the quic-go test program's client dialing with
// quic.DialAddrEarly, which gives its connection a zero-length connection
// ID: the server's short headers are then only the flags and the packet
// number, 2 to 5 bytes. Both directions must still be captured and decoded,
// which --requests's line for the request shows: it needs the request's
// headers, sent, and the response's, received.
func TestQuicGoDialAddr(t *testing.T) {
	program, port, snapshot := traceQuicGo(t)
	path := "/zero-length-id"
	cmd := exec.Command(program, "client", port, path)
	cmd.Env = append(os.Environ(), "QUICGO_DIAL=addr")
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("200 OK served "+path)) {
		t.Fatalf("quic-go client: %v: %s", err, out)
	}
	body := "served " + path + " on " + port
	var lines []string
	var short, response bool
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		evs := snapshot(false)
		short, response = false, false
		for _, ev := range evs {
			if ev.Function != tracer.FuncGoQUICRecv {
				continue
			}
			// A short header with no connection ID: flags and a packet number
			// of 1 to 4 bytes.
			if h := ev.QUICHeader; len(h) >= 2 && len(h) <= 5 && h[0]&0x80 == 0 {
				short = true
			}
			if bytes.Contains(ev.Data, []byte(body)) {
				response = true
			}
		}
		lines = quicGoRequests(t, evs, path)
		if short && response && len(lines) == 1 {
			break
		}
	}
	if !short {
		t.Error("no received packet with a zero-length connection ID")
	}
	if !response {
		t.Errorf("the response, %q, wasn't captured", body)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], " 200") {
		t.Errorf("--requests:\n%s", strings.Join(lines, "\n"))
	}
}

// quicGoRequests returns the lines --requests prints for events, the ones
// for requests for path.
func quicGoRequests(t *testing.T, evs []*tracer.Event, path string) []string {
	t.Helper()
	slices.SortStableFunc(evs, func(a, b *tracer.Event) int { return a.Time.Compare(b.Time) })
	var req bytes.Buffer
	r := output.NewRequests(&req, output.Options{})
	for _, ev := range evs {
		if err := r.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(req.String()), "\n") {
		if strings.Contains(line, path+" HTTP/3") {
			lines = append(lines, line)
		}
	}
	return lines
}

// traceQuicGo builds the quic-go test program (testdata/quicgo), traces
// programs named quicgo, and starts the program's server under another
// name, so that only clients are traced. It returns the program, the
// server's port on 127.0.0.1, and a function that returns the events seen
// so far, and forgets them if reset is set.
func traceQuicGo(t *testing.T) (program, port string, snapshot func(reset bool) []*tracer.Event) {
	t.Helper()
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
	program = filepath.Join(t.TempDir(), "quicgo")
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
	t.Cleanup(func() { tr.Close() })
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
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})

	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port = fmt.Sprint(l.LocalAddr().(*net.UDPAddr).Port)
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
	return program, port, func(reset bool) []*tracer.Event {
		mu.Lock()
		defer mu.Unlock()
		evs := slices.Clone(events)
		if reset {
			events = nil
		}
		return evs
	}
}
