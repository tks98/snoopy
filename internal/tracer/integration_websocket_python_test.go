//go:build integration

package tracer_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tks98/snoopy/v2/internal/discover"
	"github.com/tks98/snoopy/v2/internal/tracer"
)

// TestWebSocketPython is TestWebSocket with another implementation: the
// Python websockets library (testdata/wspy), through OpenSSL, with
// permessage-deflate, context takeover and windows of 1 KiB
// (server_max_window_bits and client_max_window_bits 10), which snoopy's
// 32 KiB of history has to cover, and a message sent as three frames.
func TestWebSocketPython(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	missing := func(why string) {
		if os.Getenv("SNOOPY_TEST_STRICT") == "1" {
			t.Fatal(why + " (and SNOOPY_TEST_STRICT=1)")
		}
		t.Skip(why)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		missing("python3 not installed")
	}
	if err := exec.Command(python, "-c", "import websockets").Run(); err != nil {
		missing("Python's websockets not installed (python3-websockets)")
	}

	// The server's certificate: httptest's.
	srv := httptest.NewTLSServer(nil)
	cert := srv.TLS.Certificates[0]
	srv.Close()
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o644); err != nil {
		t.Fatal(err)
	}

	all, _, err := discover.Find(discover.Options{NoScan: true})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := tracer.New(tracer.Options{Comm: "python3"})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	for _, target := range all {
		if target.Library != discover.OpenSSL {
			continue
		}
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

	if out, err := exec.Command(python, "testdata/wspy/wspy.py", certFile, keyFile).CombinedOutput(); err != nil || string(out) != "ok\n" {
		t.Fatalf("WebSocket program: %v: %s", err, out)
	}

	// As in testdata/wspy/wspy.py.
	short := strings.Repeat("snoopy decodes WebSocket messages. ", 8)
	var long strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&long, "message %d of a long one, with a window of 1 KiB; ", i)
	}
	want := map[string]int{}
	for _, m := range []string{short, short, long.String(), "fragment one, fragment two, fragment three"} {
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
		// The client's close frame and the server's reply, which repeats
		// it, are each written and read; every message is compressed.
		if fmt.Sprint(got) == fmt.Sprint(want) && stats.closes >= 2 && stats.upgrades == 2 && stats.compressed == 16 {
			return
		}
	}
	lengths := func(m map[string]int) map[int]int {
		out := map[int]int{}
		for k, v := range m {
			out[len(k)] = v
		}
		return out
	}
	t.Errorf("messages by length: got %v, want %v (%+v)", lengths(got), lengths(want), stats)
}
