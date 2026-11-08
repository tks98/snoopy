//go:build integration

package tracer

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tks98/snoopy/v2/internal/discover"
)

// SNOOPY_TEST_LEGACY_UPROBES=1 runs the tests attaching a perf-based link
// per probe, as kernels before 6.6 do, on any kernel.
func init() {
	legacyUprobesForTests = os.Getenv("SNOOPY_TEST_LEGACY_UPROBES") == "1"
}

// Both ways of attaching, uprobe_multi links and a perf-based link per
// probe, capture the same calls: per process, for a Go program (this
// test's), whose calls run on many threads (the first kernels with
// uprobe_multi only saw the main thread's), and for every process, for
// curl's libssl.
func TestUprobeModes(t *testing.T) {
	requireRoot(t)
	// Both, whatever SNOOPY_TEST_LEGACY_UPROBES says.
	defer func(forced bool) { legacyUprobesForTests = forced }(legacyUprobesForTests)
	legacyUprobesForTests = false
	curl := requireTool(t, "curl")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	goTargets, err := discover.Inspect(exe)
	if err != nil {
		t.Fatal(err)
	}
	var libssl []discover.Target
	for _, target := range systemTargets(t, discover.OpenSSL) {
		if strings.Contains(target.Path, "libssl.so") {
			libssl = append(libssl, target)
		}
	}
	if len(goTargets) != 1 || goTargets[0].Go == nil || len(libssl) == 0 {
		missing(t, "no Go target (%d) or system libssl (%d)", len(goTargets), len(libssl))
	}
	gi := goTargets[0].Go
	goProbes := len(gi.Read.Returns) + len(gi.Write.Returns) + 2

	for _, mode := range []struct {
		name   string
		legacy bool
	}{{"multi", false}, {"legacy", true}} {
		t.Run(mode.name, func(t *testing.T) {
			tr, err := New(Options{PID: os.Getpid(), PerProcess: true, LegacyUprobes: mode.legacy})
			if err != nil {
				t.Fatal(err)
			}
			if !mode.legacy && !tr.UprobeMulti() {
				tr.Close()
				// CI's runners' kernels have them: that's where the default
				// way is tested.
				missing(t, "the kernel has no uprobe_multi links, or one whose PID filtering isn't fixed")
			}
			if mode.legacy && tr.UprobeMulti() {
				t.Error("UprobeMulti with LegacyUprobes")
			}
			start := time.Now()
			if _, err := tr.Attach(goTargets[0], os.Getpid()); err != nil {
				t.Fatal(err)
			}
			for _, target := range libssl {
				if _, err := tr.Attach(target, 0); err != nil {
					t.Fatalf("%s: %v", target.Path, err)
				}
			}
			attachTime := time.Since(start)
			if err := tr.AttachSyscalls(); err != nil {
				t.Fatal(err)
			}

			// A link per probe, or per program: for Go, the RETs' program and
			// each method's entry (no QUIC here); for libssl, the return
			// probes' and each function's entry.
			tr.mu.Lock()
			goLinks := len(tr.procs[os.Getpid()].links)
			sslLinks := 0
			for _, f := range tr.files {
				sslLinks += len(f.links)
			}
			tr.mu.Unlock()
			wantGo := goProbes
			if !mode.legacy {
				wantGo = 3
			}
			if goLinks != wantGo {
				t.Errorf("%d links for the Go program's %d probes, want %d", goLinks, goProbes, wantGo)
			}
			if !mode.legacy && sslLinks > 5*len(libssl) {
				t.Errorf("%d links for %d libssl files, want at most 5 each", sslLinks, len(libssl))
			}
			t.Logf("%d links for %d Go probes, %d for libssl; attached in %v", goLinks, goProbes, sslLinks, attachTime)

			events := &eventLog{added: make(chan struct{}, 1)}
			done := make(chan error, 1)
			ctx, cancel := context.WithCancel(context.Background())
			go func() { done <- tr.Run(ctx, events.add) }()

			srv, _ := newServer(t)
			resp, err := srv.Client().Post(srv.URL+"/modes-go-"+mode.name, "text/plain", strings.NewReader("ping"))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if out, err := exec.Command(curl, "-sk", "--http1.1", srv.URL+"/modes-curl-"+mode.name).CombinedOutput(); err != nil {
				t.Fatalf("curl: %v: %s", err, out)
			}

			waitFor(t, events, "Go client write", func(ev *Event) bool {
				return ev.Function == FuncGoWrite && contains("POST /modes-go-"+mode.name)(ev)
			})
			waitFor(t, events, "Go client read", func(ev *Event) bool {
				return ev.Function == FuncGoRead && contains("served /modes-go-"+mode.name)(ev)
			})
			waitFor(t, events, "curl's SSL_write", func(ev *Event) bool {
				return ev.Function == FuncSSLWrite && contains("GET /modes-curl-"+mode.name)(ev)
			})
			waitFor(t, events, "curl's SSL_read", func(ev *Event) bool {
				return ev.Function == FuncSSLRead && contains("served /modes-curl-"+mode.name)(ev)
			})

			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
			start = time.Now()
			if err := tr.Close(); err != nil {
				t.Error(err)
			}
			t.Logf("closed in %v", time.Since(start))
		})
	}
}
