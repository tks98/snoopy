//go:build integration

// Integration tests load the BPF program into the running kernel and trace
// real TLS clients against an in-process server. They need root:
//
//	go test -c -tags integration -o tracer.test ./internal/tracer
//	sudo ./tracer.test -test.v
//
// Tests for clients that aren't installed (curl, python3, gnutls-cli, an NSS,
// wolfSSL, Mbed TLS or s2n-tls toolchain) are skipped.
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

	"github.com/tks98/snoopy/v2/internal/discover"
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
		t.Logf("  %v pid=%d tid=%d conn=%#x fd=%d %s > %s size=%d incomplete=%v header=%x %q",
			ev.Function, ev.PID, ev.TID, ev.ConnID, ev.FD, ev.Local, ev.Remote, ev.Size, ev.Incomplete, ev.QUICHeader, data)
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
	return runTracer(t, tr)
}

// runTracer collects a tracer's events until the test ends, then closes it.
func runTracer(t *testing.T, tr *Tracer) *eventLog {
	t.Helper()
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

// With PID, the processes it starts are traced too, and no others.
func TestPIDFollowsChildren(t *testing.T) {
	requireRoot(t)
	curl := requireTool(t, "curl")
	srv, _ := newServer(t)
	// The process traced: a shell that runs curl once told to (": " keeps
	// the shell from replacing itself with curl).
	sh := exec.Command("sh", "-c", `read x; "$0" -sk --http1.1 "$1"; :`, curl, srv.URL+"/child")
	stdin, err := sh.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sh.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sh.Process.Kill(); sh.Wait() })
	events := startTracer(t, Options{PID: sh.Process.Pid}, systemTargets(t, discover.OpenSSL))

	if out, err := exec.Command(curl, "-sk", "--http1.1", srv.URL+"/other").CombinedOutput(); err != nil {
		t.Fatalf("curl: %v: %s", err, out)
	}
	stdin.Write([]byte("\n"))
	stdin.Close()
	if err := sh.Wait(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, events, "the shell's curl", contains("GET /child HTTP/1.1"))
	if events.find(contains("GET /other")) != nil {
		t.Error("traced a curl that the shell didn't start")
	}
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

func TestWolfSSL(t *testing.T) {
	testCClient(t, discover.WolfSSL, "wolfsslclient", FuncWolfSSLWrite, FuncWolfSSLRead, "-lwolfssl")
}

func TestMbedTLS(t *testing.T) {
	testCClient(t, discover.MbedTLS, "mbedtlsclient", FuncMbedTLSWrite, FuncMbedTLSRead,
		"-lmbedtls", "-lmbedx509", "-lmbedcrypto")
}

// s2n-tls isn't packaged by most distributions; the test runs if it's
// installed, e.g. built from source into /usr/local.
func TestS2N(t *testing.T) {
	testCClient(t, discover.S2N, "s2nclient", FuncS2NSend, FuncS2NRecv, "-ls2n")
}

// testCClient builds testdata/<name>.c, a client that sends a GET request
// through the library, and checks that both the request and the response
// are captured along with the socket's addresses. It skips the test if the
// library's development files aren't installed.
func testCClient(t *testing.T, lib discover.Library, name string, write, read Function, ldflags ...string) {
	t.Helper()
	requireRoot(t)
	cc := requireTool(t, "cc")
	client := filepath.Join(t.TempDir(), name)
	args := append([]string{"testdata/" + name + ".c", "-o", client}, ldflags...)
	if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
		if bytes.Contains(out, []byte("No such file or directory")) || bytes.Contains(out, []byte("cannot find -l")) {
			t.Skipf("%s development files not installed", lib)
		}
		t.Fatalf("build %s: %v: %s", name, err, out)
	}

	events := startTracer(t, Options{Comm: name}, systemTargets(t, lib))
	srv, port := newServer(t)
	path := "/" + name
	if out, err := exec.Command(client, port, path).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", name, err, out)
	}
	server := srv.Listener.Addr().String()
	sent := waitFor(t, events, write.String(), func(ev *Event) bool {
		return ev.Function == write && contains("GET "+path+" HTTP/1.0")(ev)
	})
	checkConnection(t, sent, server)
	received := waitFor(t, events, read.String(), func(ev *Event) bool {
		return ev.Function == read && contains("served "+path+" ")(ev)
	})
	checkConnection(t, received, server)
	if sent.ConnID != received.ConnID {
		t.Errorf("request on connection %#x, response on %#x", sent.ConnID, received.ConnID)
	}
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

// A program started after the tracer, using a library nothing has attached
// to yet (a private copy of libssl), is found through its exec and traced.
func TestNewProcess(t *testing.T) {
	requireRoot(t)
	curl := requireTool(t, "curl")
	// A copy of the system's libssl (not, say, a browser with BoringSSL).
	var libssl string
	for _, target := range systemTargets(t, discover.OpenSSL) {
		if strings.HasPrefix(filepath.Base(target.Path), "libssl.so") {
			libssl = target.Path
			break
		}
	}
	if libssl == "" {
		t.Skip("no system libssl")
	}
	libDir := t.TempDir()
	lib, err := os.ReadFile(libssl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(libDir, filepath.Base(libssl)), lib, 0o755); err != nil {
		t.Fatal(err)
	}

	tr, err := New(Options{Comm: "curl"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.AttachSyscalls(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var attached []string
	stop, err := tr.WatchNewProcesses(discover.NewWatcher(nil), nil, func(target discover.Target, funcs []string, err error) {
		mu.Lock()
		defer mu.Unlock()
		attached = append(attached, fmt.Sprintf("%s %s %v %v", target.Library, target.Path, funcs, err))
	})
	if err != nil {
		t.Fatal(err)
	}
	events := runTracer(t, tr)
	t.Cleanup(stop) // runs before runTracer's cleanup closes the tracer

	// Answer late, so the response arrives after the copy was attached.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		fmt.Fprintf(w, "served %s late", r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	cmd := exec.Command(curl, "-sk", "--http1.1", srv.URL+"/new-process")
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+libDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("curl: %v: %s", err, out)
	}
	ev := waitFor(t, events, "SSL_read from the private libssl", func(ev *Event) bool {
		return ev.Function == FuncSSLRead && contains("served /new-process late")(ev)
	})
	checkConnection(t, ev, srv.Listener.Addr().String())

	mu.Lock()
	defer mu.Unlock()
	t.Logf("attached: %q", attached)
	found := false
	for _, a := range attached {
		found = found || strings.Contains(a, libDir)
	}
	if !found {
		t.Errorf("the private libssl in %s wasn't attached to", libDir)
	}
}

// TestRustls needs a Rust toolchain, and building the client takes a while,
// so it only runs with SNOOPY_TEST_RUSTLS=1.
// rustls under tokio, with its default crypto provider (aws-lc-rs) and with
// ring: seen where the provider encrypts and decrypts each record, over TLS
// 1.3 and 1.2, with AES-GCM and ChaCha20-Poly1305.
func TestRustlsAsync(t *testing.T) {
	requireRoot(t)
	if os.Getenv("SNOOPY_TEST_RUSTLS") != "1" {
		t.Skip("set SNOOPY_TEST_RUSTLS=1 to build the rustls client with cargo and run this test")
	}
	cargo := requireTool(t, "cargo")
	providers := []struct {
		name       string
		features   []string
		send, recv Function
	}{
		{"aws-lc", nil, FuncRecordSend, FuncRecordRecv},
		{"ring", []string{"--no-default-features", "--features", "ring"}, FuncRingSend, FuncRingRecv},
	}
	clients := map[string]string{}
	var targets []discover.Target
	for _, p := range providers {
		dir := "testdata/rustlsasync/target/" + p.name
		args := append([]string{"build", "--release", "--quiet", "--manifest-path", "testdata/rustlsasync/Cargo.toml",
			"--target-dir", dir}, p.features...)
		if out, err := exec.Command(cargo, args...).CombinedOutput(); err != nil {
			t.Fatalf("build rustls client with %s: %v: %s", p.name, err, out)
		}
		client, err := filepath.Abs(dir + "/release/rustlsasync")
		if err != nil {
			t.Fatal(err)
		}
		found, err := discover.Inspect(client)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 || found[0].Rust == nil || !found[0].Rust.AtRecords() {
			t.Fatalf("%s's AEAD functions not found: %+v", p.name, found)
		}
		clients[p.name] = client
		targets = append(targets, found...)
	}
	events := startTracer(t, Options{Comm: "rustlsasync"}, targets)
	srv, port := newServer(t)
	server := srv.Listener.Addr().String()

	for _, p := range providers {
		for _, v := range []struct {
			name    string
			options []string
		}{
			{"tls13", nil},
			{"tls12", []string{"tls12"}},
			{"tls13-chacha", []string{"chacha"}},
			{"tls12-chacha", []string{"tls12", "chacha"}},
		} {
			name := p.name + "-" + v.name
			path := "/async-" + name
			out, err := exec.Command(clients[p.name], append([]string{port, path}, v.options...)...).CombinedOutput()
			if err != nil || !bytes.Contains(out, []byte("served "+path)) {
				t.Fatalf("rustlsasync %s: %v: %s", name, err, out)
			}
			// The connection's first write goes out before its socket is
			// known; it is held back until the socket notice fills it in.
			write := waitFor(t, events, name+" request", func(ev *Event) bool {
				return ev.Function == p.send && contains("GET "+path+" HTTP/1.1")(ev)
			})
			checkConnection(t, write, server)
			read := waitFor(t, events, name+" response", func(ev *Event) bool {
				return ev.Function == p.recv && contains("served "+path)(ev)
			})
			checkConnection(t, read, server)
			// Only application data: no handshake messages, no TLS 1.3
			// content type left at the end.
			if !bytes.HasPrefix(write.Data, []byte("GET ")) || !bytes.HasSuffix(write.Data, []byte("\r\n\r\n")) {
				t.Errorf("%s request: %q", name, write.Data)
			}
			if !bytes.HasPrefix(read.Data, []byte("HTTP/1.1 200 OK")) {
				t.Errorf("%s response: %q", name, read.Data)
			}
		}
	}
	// Records only: the Writer isn't probed too, or writes would show twice.
	if ev := events.find(func(ev *Event) bool { return ev.Function == FuncRustlsWrite || ev.Function == FuncRustlsRead }); ev != nil {
		t.Errorf("%s probed as well", ev.Function)
	}
}

// HTTP/3 over quinn, with rustls's aws-lc-rs and ring providers: seen
// where the provider encrypts and decrypts each QUIC packet. The server is
// the same program under another name, so only the client is traced.
func TestQuinnHTTP3(t *testing.T) {
	requireRoot(t)
	if os.Getenv("SNOOPY_TEST_RUSTLS") != "1" {
		t.Skip("set SNOOPY_TEST_RUSTLS=1 to build the quinn client with cargo and run this test")
	}
	cargo := requireTool(t, "cargo")
	providers := []struct {
		name       string
		features   []string
		send, recv Function
	}{
		{"aws-lc", nil, FuncAwsLCQUICSend, FuncAwsLCQUICRecv},
		{"ring", []string{"--no-default-features", "--features", "ring"}, FuncRingQUICSend, FuncRingQUICRecv},
	}
	clients := map[string]string{}
	var targets []discover.Target
	for _, p := range providers {
		dir := "testdata/quinnh3/target/" + p.name
		args := append([]string{"build", "--release", "--quiet", "--manifest-path", "testdata/quinnh3/Cargo.toml",
			"--target-dir", dir}, p.features...)
		if out, err := exec.Command(cargo, args...).CombinedOutput(); err != nil {
			t.Fatalf("build quinn client with %s: %v: %s", p.name, err, out)
		}
		client, err := filepath.Abs(dir + "/release/quinnh3")
		if err != nil {
			t.Fatal(err)
		}
		found, err := discover.Inspect(client)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 || found[0].Rust == nil || !found[0].Rust.AtRecords() {
			t.Fatalf("%s's AEAD functions not found: %+v", p.name, found)
		}
		clients[p.name] = client
		targets = append(targets, found...)
	}
	events := startTracer(t, Options{Comm: "quinnh3"}, targets)

	for _, p := range providers {
		// Two servers, which the client reaches at once over one socket.
		ports := []string{quinnServer(t, clients[p.name]), quinnServer(t, clients[p.name])}

		path := "/h3-" + p.name
		out, err := exec.Command(clients[p.name], "client", strings.Join(ports, ","), path).CombinedOutput()
		if err != nil || bytes.Count(out, []byte("200 OK served "+path)) != 2 {
			t.Fatalf("quinn client with %s: %v: %s", p.name, err, out)
		}
		var reads []*Event
		for _, port := range ports {
			server := "127.0.0.1:" + port
			// The response body is plain in its DATA frame; the request's
			// headers are QPACK-encoded, so only its packet is looked for.
			read := waitFor(t, events, p.name+" response from "+port, func(ev *Event) bool {
				return ev.Function == p.recv && contains("served "+path+" on "+port)(ev)
			})
			// The socket isn't connected, so a send's peer is only in a
			// notice of where a packet went, whose header (as sent) has
			// its connection's ID for the server; output follows the
			// connection by it (cidConns). quinn's IDs are 8 bytes.
			sent := waitFor(t, events, p.name+" packet sent to "+port, func(ev *Event) bool {
				return ev.Function == FuncQUICPacketSent && ev.PID == read.PID && ev.Remote.String() == server &&
					len(ev.QUICHeader) > 9 && ev.QUICHeader[0]&0x80 == 0 // after the handshake
			})
			write := waitFor(t, events, p.name+" request to "+port, func(ev *Event) bool {
				return ev.Function == p.send && ev.PID == read.PID && len(ev.QUICHeader) > 9 &&
					bytes.Equal(ev.QUICHeader[1:9], sent.QUICHeader[1:9])
			})
			if read.FD < 0 || read.FD != write.FD || sent.FD != write.FD || read.Local != write.Local {
				t.Errorf("%s: response on fd %d at %s, request on fd %d at %s, sent on fd %d",
					port, read.FD, read.Local, write.FD, write.Local, sent.FD)
			}
			for _, ev := range []*Event{read, write} {
				if len(ev.QUICHeader) < 9 || ev.QUICHeader[0]&0x80 != 0 {
					t.Errorf("%s: %s's header: % x", port, ev.Function, ev.QUICHeader)
				}
			}
			reads = append(reads, read)
		}
		if reads[0].FD != reads[1].FD {
			t.Errorf("the client used two sockets: fds %d and %d", reads[0].FD, reads[1].FD)
		}
	}
}

// HTTP/3 over quic-go: seen where Go's AEADs encrypt and decrypt each
// packet. Like quinn, quic-go runs a client's connections over one socket
// that isn't connected, so the client reaches two servers at once.
func TestQuicGoHTTP3(t *testing.T) {
	requireRoot(t)
	goTool := requireTool(t, "go")
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
	if len(targets) != 1 || targets[0].Go == nil || len(targets[0].Go.Opens) == 0 {
		t.Fatalf("Go's AEADs not found: %+v", targets)
	}
	events := startTracer(t, Options{Comm: "quicgo"}, targets)

	var ports []string
	for range 2 {
		port := freeUDPPort(t)
		server := filepath.Join(t.TempDir(), "qgserver") // not a "quicgo" prefix, which --comm would match
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
		ports = append(ports, port)
	}

	path := "/quic-go"
	out, err := exec.Command(program, "client", strings.Join(ports, ","), path).CombinedOutput()
	if err != nil || bytes.Count(out, []byte("200 OK served "+path)) != 2 {
		t.Fatalf("quic-go client: %v: %s", err, out)
	}
	var reads []*Event
	for _, port := range ports {
		server := "127.0.0.1:" + port
		read := waitFor(t, events, "response from "+port, func(ev *Event) bool {
			return ev.Function == FuncGoQUICRecv && contains("served "+path+" on "+port)(ev)
		})
		// As with quinn (TestQuinnHTTP3), the peer is in a notice of where a
		// packet went, whose header has the server's connection ID: 4 bytes,
		// quic-go's default.
		sent := waitFor(t, events, "packet sent to "+port, func(ev *Event) bool {
			return ev.Function == FuncQUICPacketSent && ev.PID == read.PID && ev.Remote.String() == server &&
				len(ev.QUICHeader) > 5 && ev.QUICHeader[0]&0x80 == 0
		})
		write := waitFor(t, events, "request to "+port, func(ev *Event) bool {
			return ev.Function == FuncGoQUICSend && ev.PID == read.PID && len(ev.QUICHeader) > 5 &&
				bytes.Equal(ev.QUICHeader[1:5], sent.QUICHeader[1:5])
		})
		if read.FD < 0 || read.FD != write.FD || sent.FD != write.FD {
			t.Errorf("%s: response on fd %d, request on fd %d, sent on fd %d", port, read.FD, write.FD, sent.FD)
		}
		reads = append(reads, read)
	}
	if reads[0].FD != reads[1].FD {
		t.Errorf("the client used two sockets: fds %d and %d", reads[0].FD, reads[1].FD)
	}
}

// quinnServer starts the quinn test program as an HTTP/3 server, under
// another name than the client's, and returns its port on 127.0.0.1.
func quinnServer(t *testing.T, program string) string {
	t.Helper()
	port := freeUDPPort(t)
	server := filepath.Join(t.TempDir(), "quinnsrv")
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
		t.Fatalf("quinn server: %q, %v", line, err)
	}
	return port
}

// curl's HTTP/3, through ngtcp2's crypto library. Ubuntu's curl has no
// HTTP/3 and Fedora's does, so SNOOPY_TEST_CURL_HTTP3 is the root of a
// system with one: / on Fedora, or a Fedora root filesystem, which curl is
// run chrooted in. The server is the quinn test program, built with cargo.
func TestCurlHTTP3(t *testing.T) {
	requireRoot(t)
	root := os.Getenv("SNOOPY_TEST_CURL_HTTP3")
	if root == "" {
		t.Skip("set SNOOPY_TEST_CURL_HTTP3 to the root of a system whose curl has HTTP/3 to run this test")
	}
	cargo := requireTool(t, "cargo")
	build := exec.Command(cargo, "build", "--release", "--quiet", "--manifest-path", "testdata/quinnh3/Cargo.toml",
		"--target-dir", "testdata/quinnh3/target/aws-lc")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build quinn server: %v: %s", err, out)
	}
	program, err := filepath.Abs("testdata/quinnh3/target/aws-lc/release/quinnh3")
	if err != nil {
		t.Fatal(err)
	}
	var libs []string
	for _, pattern := range []string{"usr/lib64/libngtcp2_crypto_*.so.*", "usr/lib/*/libngtcp2_crypto_*.so.*"} {
		found, _ := filepath.Glob(filepath.Join(root, pattern))
		libs = append(libs, found...)
	}
	var targets []discover.Target
	for _, lib := range libs {
		found, err := discover.Inspect(lib)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, found...)
	}
	if len(targets) == 0 || targets[0].Library != discover.NGTCP2 {
		t.Fatalf("no ngtcp2 crypto library under %s: %v", root, libs)
	}
	events := startTracer(t, Options{Comm: "curl"}, targets)
	port := quinnServer(t, program)
	server := "127.0.0.1:" + port

	path := "/curl-h3"
	args := []string{"-sk", "--http3-only", "https://" + server + path}
	cmd := exec.Command("curl", args...)
	if root != "/" {
		cmd = exec.Command("chroot", append([]string{root, "curl"}, args...)...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("served "+path+" on "+port)) {
		t.Fatalf("curl --http3-only: %v: %s", err, out)
	}
	read := waitFor(t, events, "response", func(ev *Event) bool {
		return ev.Function == FuncNGTCP2Recv && contains("served "+path)(ev)
	})
	write := waitFor(t, events, "request", func(ev *Event) bool {
		return ev.Function == FuncNGTCP2Send && ev.PID == read.PID && len(ev.QUICHeader) > 0 &&
			ev.QUICHeader[0]&0x80 == 0 // after the handshake
	})
	// curl connects its socket, so the kernel knows the peer.
	checkConnection(t, read, server)
	checkConnection(t, write, server)
	if read.FD != write.FD {
		t.Errorf("response on fd %d, request on fd %d", read.FD, write.FD)
	}
}

// freeUDPPort returns a UDP port on 127.0.0.1 that was free a moment ago.
func freeUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, port, _ := net.SplitHostPort(c.LocalAddr().String())
	return port
}

func TestRustls(t *testing.T) {
	requireRoot(t)
	if os.Getenv("SNOOPY_TEST_RUSTLS") != "1" {
		t.Skip("set SNOOPY_TEST_RUSTLS=1 to build the rustls client with cargo and run this test")
	}
	cargo := requireTool(t, "cargo")
	build := exec.Command(cargo, "build", "--release", "--quiet", "--manifest-path", "testdata/rustlsclient/Cargo.toml")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build rustls client: %v: %s", err, out)
	}
	client, err := filepath.Abs("testdata/rustlsclient/target/release/rustlsclient")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := discover.Inspect(client)
	if err != nil {
		t.Fatal(err)
	}
	// The client uses ring, whose records TestRustlsAsync covers. Leaving
	// ring's functions out tests the Reader and Writer, which are what's
	// probed with other crypto providers.
	if len(targets) != 1 || targets[0].Rust == nil || !targets[0].Rust.AtRecords() {
		t.Fatalf("ring's AEAD functions not found: %+v", targets)
	}
	targets[0].Rust.RingSeals, targets[0].Rust.RingOpens = nil, nil
	events := startTracer(t, Options{Comm: "rustlsclient"}, targets)
	srv, port := newServer(t)
	if out, err := exec.Command(client, port, "/rustls").CombinedOutput(); err != nil {
		t.Fatalf("rustlsclient: %v: %s", err, out)
	}
	write := waitFor(t, events, "Writer::write", func(ev *Event) bool {
		return ev.Function == FuncRustlsWrite && contains("GET /rustls HTTP/1.0")(ev)
	})
	// The connection's first write is encrypted before its socket is known;
	// it is held back until the socket notice fills it in.
	checkConnection(t, write, srv.Listener.Addr().String())
	// The client reads into a growing buffer, so the response is spread
	// over several reads; one thread makes them, so they arrive in order.
	var reads []*Event
	var response []byte
	for deadline := time.Now().Add(20 * time.Second); !bytes.Contains(response, []byte("served /rustls ")); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			events.dump(t)
			t.Fatalf("response not captured; got %q", response)
		}
		reads, response = nil, nil
		events.mu.Lock()
		for _, ev := range events.events {
			if ev.Function == FuncRustlsRead {
				reads = append(reads, ev)
				response = append(response, ev.Data...)
			}
		}
		events.mu.Unlock()
	}
	// The socket of a read is the one the thread read from just before.
	for _, ev := range reads {
		checkConnection(t, ev, srv.Listener.Addr().String())
	}
}
