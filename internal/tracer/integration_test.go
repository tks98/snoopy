//go:build integration

// Integration tests load the BPF program into the running kernel and trace
// real TLS clients against an in-process server. They need root:
//
//	go test -c -tags integration -o tracer.test ./internal/tracer
//	sudo ./tracer.test -test.v
//
// Tests for clients that aren't installed (curl, python3, gnutls-cli, an NSS
// toolchain) are skipped.
package tracer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tks98/snoopy/internal/discover"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func requireTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not installed", name)
	}
	return path
}

// eventLog collects every event, so tests can wait for events in any order:
// events from different CPUs need not arrive in the order they happened.
type eventLog struct {
	mu     sync.Mutex
	events []*Event
	added  chan struct{}
}

func (l *eventLog) add(ev *Event) {
	l.mu.Lock()
	l.events = append(l.events, ev)
	l.mu.Unlock()
	select {
	case l.added <- struct{}{}:
	default:
	}
}

func (l *eventLog) find(match func(*Event) bool) *Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ev := range l.events {
		if match(ev) {
			return ev
		}
	}
	return nil
}

// dump logs every event received so far, to show what arrived instead.
func (l *eventLog) dump(t *testing.T) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	t.Logf("%d events received:", len(l.events))
	for _, ev := range l.events {
		data := ev.Data
		if len(data) > 64 {
			data = data[:64]
		}
		t.Logf("  %v pid=%d tid=%d conn=%#x fd=%d size=%d incomplete=%v %q",
			ev.Function, ev.PID, ev.TID, ev.ConnID, ev.FD, ev.Size, ev.Incomplete, data)
	}
}

// startTracer attaches to the given library kinds and collects events.
func startTracer(t *testing.T, opts Options, targets []discover.Target) *eventLog {
	t.Helper()
	tr, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	attached := 0
	for _, target := range targets {
		if _, err := tr.Attach(target); err != nil {
			t.Logf("attach %s %s: %v", target.Library, target.Path, err)
			continue
		}
		attached++
	}
	if attached == 0 {
		tr.Close()
		t.Skip("no matching TLS library to attach to")
	}
	if err := tr.AttachSyscalls(); err != nil {
		t.Fatal(err)
	}

	events := &eventLog{added: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx, events.add) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		tr.Close()
	})
	return events
}

func systemTargets(t *testing.T, lib discover.Library) []discover.Target {
	t.Helper()
	all, _, err := discover.Find(discover.Options{NoScan: true})
	if err != nil {
		t.Fatal(err)
	}
	var out []discover.Target
	for _, target := range all {
		if target.Library == lib {
			out = append(out, target)
		}
	}
	return out
}

// waitFor returns the first event, received so far or later, that matches.
func waitFor(t *testing.T, events *eventLog, desc string, match func(*Event) bool) *Event {
	t.Helper()
	timeout := time.After(20 * time.Second)
	for {
		if ev := events.find(match); ev != nil {
			return ev
		}
		select {
		case <-events.added:
		case <-time.After(100 * time.Millisecond):
		case <-timeout:
			events.dump(t)
			t.Fatalf("timed out waiting for %s", desc)
		}
	}
}

func contains(s string) func(*Event) bool {
	return func(ev *Event) bool { return bytes.Contains(ev.Data, []byte(s)) }
}

func newServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "served %s with %d body bytes", r.URL.Path, n)
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return srv, port
}

func checkConnection(t *testing.T, ev *Event, server string) {
	t.Helper()
	if ev.FD < 0 {
		t.Errorf("%s: no fd", ev.Function)
	}
	want := netip.MustParseAddrPort(server)
	if ev.Remote != want && ev.Local != want {
		t.Errorf("%s: addresses %s -> %s, want one to be %s", ev.Function, ev.Local, ev.Remote, want)
	}
}

func TestGoCryptoTLS(t *testing.T) {
	requireRoot(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	targets, err := discover.Inspect(exe)
	if err != nil {
		t.Fatal(err)
	}
	events := startTracer(t, Options{PID: os.Getpid()}, targets)

	srv, _ := newServer(t)
	resp, err := srv.Client().Post(srv.URL+"/go-test", "text/plain", strings.NewReader("ping"))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	server := srv.Listener.Addr().String()
	write := waitFor(t, events, "client write", func(ev *Event) bool {
		return ev.Function == FuncGoWrite && contains("POST /go-test HTTP/1.1")(ev)
	})
	checkConnection(t, write, server)
	waitFor(t, events, "server read", func(ev *Event) bool {
		return ev.Function == FuncGoRead && contains("POST /go-test HTTP/1.1")(ev)
	})
	read := waitFor(t, events, "client read", func(ev *Event) bool {
		return ev.Function == FuncGoRead && contains("served /go-test with 4 body bytes")(ev)
	})
	checkConnection(t, read, server)
	if read.Latency <= 0 || read.PID != uint32(os.Getpid()) {
		t.Errorf("bad event metadata: %+v", read)
	}
}

func TestOpenSSL(t *testing.T) {
	requireRoot(t)
	curl := requireTool(t, "curl")
	events := startTracer(t, Options{Comm: "curl"}, systemTargets(t, discover.OpenSSL))
	srv, _ := newServer(t)

	if out, err := exec.Command(curl, "-sk", "--http1.1", srv.URL+"/curl-test").CombinedOutput(); err != nil {
		t.Fatalf("curl: %v: %s", err, out)
	}
	write := waitFor(t, events, "SSL_write", func(ev *Event) bool {
		return ev.Function == FuncSSLWrite && contains("GET /curl-test HTTP/1.1")(ev)
	})
	checkConnection(t, write, srv.Listener.Addr().String())
	if write.Comm != "curl" {
		t.Errorf("comm %q", write.Comm)
	}
	waitFor(t, events, "SSL_read", func(ev *Event) bool {
		return ev.Function == FuncSSLRead && contains("served /curl-test")(ev)
	})
}

func TestOpenSSLLargePayload(t *testing.T) {
	requireRoot(t)
	curl := requireTool(t, "curl")
	events := startTracer(t, Options{Comm: "curl", MaxCapture: MaxCaptureLimit}, systemTargets(t, discover.OpenSSL))
	srv, _ := newServer(t)

	body := make([]byte, 200<<10)
	rand.Read(body)
	file := filepath.Join(t.TempDir(), "body")
	os.WriteFile(file, body, 0o600)
	if out, err := exec.Command(curl, "-sk", "--http1.1", "--data-binary", "@"+file, srv.URL+"/upload").CombinedOutput(); err != nil {
		t.Fatalf("curl: %v: %s", err, out)
	}

	// curl sends the request in several writes of up to 64 KiB, each
	// captured as multiple ring buffer chunks. One thread makes them, so
	// they arrive in order. Newer curl versions (8.18) put the headers and
	// the start of the body in the same write.
	var stream, got []byte
	deadline := time.Now().Add(20 * time.Second)
	for len(got) < len(body) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		stream = stream[:0]
		events.mu.Lock()
		for _, ev := range events.events {
			if ev.Function != FuncSSLWrite && ev.Function != FuncSSLWriteEx {
				continue
			}
			if ev.Truncated() || ev.Incomplete {
				t.Errorf("partial capture: size %d, captured %d, incomplete %v", ev.Size, len(ev.Data), ev.Incomplete)
			}
			stream = append(stream, ev.Data...)
		}
		events.mu.Unlock()
		_, got, _ = bytes.Cut(stream, []byte("\r\n\r\n"))
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("captured %d bytes that differ from the %d sent", len(got), len(body))
	}
}

func TestOpenSSLEx(t *testing.T) {
	requireRoot(t)
	python := requireTool(t, "python3")
	events := startTracer(t, Options{Comm: "python3"}, systemTargets(t, discover.OpenSSL))
	_, port := newServer(t)

	script := `
import socket, ssl, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", int(sys.argv[1]))))
s.sendall(b"GET /python-test HTTP/1.0\r\nHost: x\r\n\r\n")
while s.recv(4096): pass
`
	if out, err := exec.Command(python, "-c", script, port).CombinedOutput(); err != nil {
		t.Fatalf("python: %v: %s", err, out)
	}
	// Python 3.10+ uses SSL_write_ex; older versions SSL_write.
	waitFor(t, events, "python write", func(ev *Event) bool {
		return (ev.Function == FuncSSLWriteEx || ev.Function == FuncSSLWrite) && contains("GET /python-test")(ev)
	})
}

func TestGnuTLS(t *testing.T) {
	requireRoot(t)
	gnutls := requireTool(t, "gnutls-cli")
	events := startTracer(t, Options{}, systemTargets(t, discover.GnuTLS))
	_, port := newServer(t)

	cmd := exec.Command(gnutls, "--insecure", "--logfile=/dev/null", "-p", port, "127.0.0.1")
	cmd.Stdin = strings.NewReader("GET /gnutls-test HTTP/1.0\r\nHost: x\r\n\r\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("gnutls-cli: %v: %s", err, out) // exits non-zero when the server closes
	}
	waitFor(t, events, "gnutls_record_send", func(ev *Event) bool {
		return ev.Function == FuncGnuTLSSend && contains("GET /gnutls-test")(ev)
	})
	waitFor(t, events, "gnutls_record_recv", func(ev *Event) bool {
		return ev.Function == FuncGnuTLSRecv && contains("served /gnutls-test")(ev)
	})
}

func TestNSS(t *testing.T) {
	requireRoot(t)
	cc := requireTool(t, "cc")
	pkgConfig := requireTool(t, "pkg-config")
	flags, err := exec.Command(pkgConfig, "--cflags", "--libs", "nss").Output()
	if err != nil {
		t.Skip("NSS development files not installed")
	}
	client := filepath.Join(t.TempDir(), "nssclient")
	args := append([]string{"testdata/nssclient.c", "-o", client}, strings.Fields(string(flags))...)
	if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
		t.Fatalf("build NSS client: %v: %s", err, out)
	}

	events := startTracer(t, Options{Comm: "nssclient"}, systemTargets(t, discover.NSS))
	_, port := newServer(t)
	if out, err := exec.Command(client, port, "/nss-test").CombinedOutput(); err != nil {
		t.Fatalf("nssclient: %v: %s", err, out)
	}
	waitFor(t, events, "PR_Write", func(ev *Event) bool {
		return ev.Function == FuncPRWrite && contains("GET /nss-test")(ev)
	})
	waitFor(t, events, "PR_Read", func(ev *Event) bool {
		return ev.Function == FuncPRRead && contains("served /nss-test")(ev)
	})
}

// Without kernel BTF the CO-RE socket lookup is compiled out; everything
// else must still work.
func TestWithoutKernelBTF(t *testing.T) {
	requireRoot(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	targets, err := discover.Inspect(exe)
	if err != nil {
		t.Fatal(err)
	}
	events := startTracer(t, Options{PID: os.Getpid(), ignoreKernelBTF: true}, targets)

	srv, _ := newServer(t)
	resp, err := srv.Client().Get(srv.URL + "/no-btf")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	ev := waitFor(t, events, "client write", func(ev *Event) bool {
		return ev.Function == FuncGoWrite && contains("GET /no-btf")(ev)
	})
	if ev.Remote.IsValid() {
		t.Errorf("addresses resolved without BTF: %s", ev.Remote)
	}
	if ev.FD < 0 {
		t.Error("fd missing")
	}
}

// newHTTPSProxy starts an HTTPS proxy that handles CONNECT, so clients
// tunnel TLS to the target through TLS to the proxy.
func newHTTPSProxy(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer up.Close()
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go io.Copy(up, br)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

// A TLS write tunneled through an HTTPS proxy makes a nested TLS write to
// the proxy; both must be reported, the outer one with the plaintext.
func TestNestedGo(t *testing.T) {
	requireRoot(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	targets, err := discover.Inspect(exe)
	if err != nil {
		t.Fatal(err)
	}
	events := startTracer(t, Options{PID: os.Getpid()}, targets)

	srv, _ := newServer(t)
	proxy := newHTTPSProxy(t, srv.TLS)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "https", Host: proxy}),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get(srv.URL + "/nested-go")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	write := waitFor(t, events, "tunneled write", func(ev *Event) bool {
		return ev.Function == FuncGoWrite && contains("GET /nested-go HTTP/1.1")(ev)
	})
	// The tunneled connection goes over the socket to the proxy.
	checkConnection(t, write, proxy)
	waitFor(t, events, "tunneled read", func(ev *Event) bool {
		return ev.Function == FuncGoRead && contains("served /nested-go")(ev) && ev.PID == write.PID && ev.ConnID == write.ConnID
	})
}

// When a Go function's stack check fails, runtime.morestack grows the stack
// and restarts the function from its first instruction. With TLS over TLS,
// an outer Read seen twice left a call behind that was then paired with the
// inner Read's return. Read from fresh goroutines at increasing stack depths,
// so that for some reads the outer Read is the call that grows the stack.
func TestGoStackGrowth(t *testing.T) {
	requireRoot(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	targets, err := discover.Inspect(exe)
	if err != nil {
		t.Fatal(err)
	}
	events := startTracer(t, Options{PID: os.Getpid()}, targets)

	srv, _ := newServer(t)
	host := srv.Listener.Addr().String()
	outer, err := tls.Dial("tcp", newHTTPSProxy(t, srv.TLS), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	fmt.Fprintf(outer, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	resp, err := http.ReadResponse(bufio.NewReader(outer), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %s", resp.Status)
	}
	inner := tls.Client(outer, &tls.Config{InsecureSkipVerify: true})
	defer inner.Close()

	const rounds = 512 // about 16 KiB of stack in steps smaller than a frame of the read path
	buf := make([]byte, 4096)
	for i := range rounds {
		path := fmt.Sprintf("/stack-%d", i)
		if _, err := fmt.Fprintf(inner, "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", path); err != nil {
			t.Fatal(err)
		}
		done := make(chan error)
		go atDepth(i, func() {
			var got []byte
			for !bytes.Contains(got, []byte("served "+path+" ")) {
				n, err := inner.Read(buf)
				if err != nil {
					done <- err
					return
				}
				got = append(got, buf[:n]...)
			}
			done <- nil
		})
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}

	write := waitFor(t, events, "tunneled write", func(ev *Event) bool {
		return ev.Function == FuncGoWrite && contains("GET /stack-0 HTTP/1.1")(ev)
	})
	// Every response must show up as a read on the tunneled connection.
	var missing []int
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		missing = missing[:0]
		for i := range rounds {
			served := contains(fmt.Sprintf("served /stack-%d ", i))
			if events.find(func(ev *Event) bool {
				return ev.Function == FuncGoRead && ev.ConnID == write.ConnID && served(ev)
			}) == nil {
				missing = append(missing, i)
			}
		}
		if len(missing) == 0 || time.Now().After(deadline) {
			break
		}
	}
	if len(missing) > 0 {
		served := contains(fmt.Sprintf("served /stack-%d ", missing[0]))
		events.mu.Lock()
		for _, ev := range events.events {
			if ev.Function == FuncGoRead && served(ev) {
				t.Logf("round %d: %v conn=%#x size=%d %q", missing[0], ev.Function, ev.ConnID, ev.Size, ev.Data)
			}
		}
		events.mu.Unlock()
		t.Errorf("%d of %d tunneled reads not reported on the tunneled connection (conn=%#x), e.g. round %d",
			len(missing), rounds, write.ConnID, missing[0])
	}
}

// atDepth calls f with n more stack frames in use.
//
//go:noinline
func atDepth(n int, f func()) {
	if n > 0 {
		atDepth(n-1, f)
		return
	}
	f()
}

func TestNestedOpenSSL(t *testing.T) {
	requireRoot(t)
	curl := requireTool(t, "curl")
	events := startTracer(t, Options{Comm: "curl"}, systemTargets(t, discover.OpenSSL))
	srv, _ := newServer(t)
	proxy := newHTTPSProxy(t, srv.TLS)

	// --noproxy '' keeps a no_proxy variable from bypassing the proxy.
	out, err := exec.Command(curl, "-sk", "--http1.1", "--noproxy", "", "--proxy", "https://"+proxy, "--proxy-insecure", srv.URL+"/nested-curl").CombinedOutput()
	if err != nil {
		t.Fatalf("curl: %v: %s", err, out)
	}
	write := waitFor(t, events, "tunneled SSL_write", func(ev *Event) bool {
		return ev.Function == FuncSSLWrite && contains("GET /nested-curl HTTP/1.1")(ev)
	})
	checkConnection(t, write, proxy)
	waitFor(t, events, "tunneled SSL_read", func(ev *Event) bool {
		return ev.Function == FuncSSLRead && contains("served /nested-curl")(ev)
	})
}

// --comm and the reported name are the process's, even when the calling
// thread has a name of its own.
func TestThreadName(t *testing.T) {
	requireRoot(t)
	python := requireTool(t, "python3")
	events := startTracer(t, Options{Comm: "python3"}, systemTargets(t, discover.OpenSSL))
	_, port := newServer(t)

	script := `
import ctypes, socket, ssl, sys, threading
def run():
    ctypes.CDLL(None).prctl(15, b"tls-worker", 0, 0, 0)  # PR_SET_NAME
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", int(sys.argv[1]))))
    s.sendall(b"GET /thread-name HTTP/1.0\r\nHost: x\r\n\r\n")
    while s.recv(4096): pass
t = threading.Thread(target=run)
t.start()
t.join()
`
	if out, err := exec.Command(python, "-c", script, port).CombinedOutput(); err != nil {
		t.Fatalf("python: %v: %s", err, out)
	}
	ev := waitFor(t, events, "write from a named thread", contains("GET /thread-name"))
	if ev.Comm != "python3" {
		t.Errorf("process name %q", ev.Comm)
	}
	if ev.PID == ev.TID {
		t.Error("expected the write to come from a thread")
	}
}
