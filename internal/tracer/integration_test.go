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
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/tks98/snoopy/v2/internal/discover"
	"github.com/tks98/snoopy/v2/internal/javaagent"
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
// count returns how many of the events so far match.
func (l *eventLog) count(match func(*Event) bool) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, ev := range l.events {
		if match(ev) {
			n++
		}
	}
	return n
}

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
		if _, err := tr.Attach(target, 0); err != nil {
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
	stop, err := tr.WatchNewProcesses(discover.NewWatcher(nil, false), nil, nil, func(target discover.Target, funcs []string, err error) {
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

// The same, but answered at once: a short-lived program would be done
// before its private libssl is attached to, so it's held until then
// (WatchNewProcesses' hold), its libraries found from its LD_LIBRARY_PATH
// before it has loaded them.
func TestHoldNewProcess(t *testing.T) {
	requireRoot(t)
	curl := requireTool(t, "curl")
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
	hold := func(pid int) bool {
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		return err == nil && strings.TrimSpace(string(comm)) == "curl"
	}
	stop, err := tr.WatchNewProcesses(discover.NewWatcher(nil, false), nil, hold, func(discover.Target, []string, error) {})
	if err != nil {
		t.Fatal(err)
	}
	events := runTracer(t, tr)
	t.Cleanup(stop)

	srv, _ := newServer(t)
	// Under sh, so its parent isn't the tracer, as with snoopy: a parent
	// tracing its own child would see the hold's stop as the child's.
	cmd := exec.Command("sh", "-c", `"$0" -sk --http1.1 "$1"; :`, curl, srv.URL+"/held")
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+libDir)
	if out, err := cmd.CombinedOutput(); err != nil || !bytes.Contains(out, []byte("served /held")) {
		t.Fatalf("curl: %v: %s", err, out)
	}
	write := waitFor(t, events, "the request, through the private libssl", func(ev *Event) bool {
		return ev.Function == FuncSSLWrite && contains("GET /held")(ev)
	})
	checkConnection(t, write, srv.Listener.Addr().String())
}

// startPerProcess starts a tracer with probes per process, for those whose
// name starts with comm, attached to as they start, as snoopy --comm does.
func startPerProcess(t *testing.T, comm string) (*Tracer, *eventLog) {
	t.Helper()
	tr, err := New(Options{Comm: comm, PerProcess: true})
	if err != nil {
		t.Fatal(err)
	}
	if !tr.PerProcess() {
		tr.Close()
		t.Skip("no BTF, so probes are per file")
	}
	if err := tr.AttachSyscalls(); err != nil {
		t.Fatal(err)
	}
	named := func(pid int) bool {
		name, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		return err == nil && strings.HasPrefix(string(name), comm)
	}
	start := time.Now()
	stop, err := tr.WatchNewProcesses(discover.NewWatcher(nil, true), named, named, func(target discover.Target, funcs []string, err error) {
		if len(funcs) > 0 || err != nil {
			t.Logf("%v: attached %s: %v %v", time.Since(start), target.Path, funcs, err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	events := runTracer(t, tr)
	t.Cleanup(stop)
	return tr, events
}

// Per process, the probes are on the processes traced only: curl's calls
// are seen, and openssl's, through the same libssl, never reach the BPF
// program. Only this test's curl is traced: run counts are the whole
// machine's, and the calls of a curl something else runs meanwhile (another
// test suite, on a shared machine) would count too.
func TestPerProcess(t *testing.T) {
	requireRoot(t)
	curl := requireTool(t, "curl")
	openssl := requireTool(t, "openssl")
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Skipf("BPF statistics: %v", err)
	}
	defer stats.Close()
	tr, err := New(Options{Comm: "curl", PerProcess: true})
	if err != nil {
		t.Fatal(err)
	}
	if !tr.PerProcess() {
		tr.Close()
		t.Skip("no BTF, so probes are per file")
	}
	if err := tr.AttachSyscalls(); err != nil {
		t.Fatal(err)
	}
	ours := func(pid int) bool {
		return discover.NameMatches(pid, "curl") && discover.IsDescendant(pid, os.Getpid())
	}
	stop, err := tr.WatchNewProcesses(discover.NewWatcher(nil, true), ours, ours, func(discover.Target, []string, error) {})
	if err != nil {
		t.Fatal(err)
	}
	events := runTracer(t, tr)
	t.Cleanup(stop)

	srv, port := newServer(t)
	cmd := exec.Command("sh", "-c", `"$0" -sk --http1.1 "$1"; :`, curl, srv.URL+"/per-process")
	if out, err := cmd.CombinedOutput(); err != nil || !bytes.Contains(out, []byte("served /per-process")) {
		t.Fatalf("curl: %v: %s", err, out)
	}
	waitFor(t, events, "curl's request", func(ev *Event) bool {
		return ev.Function == FuncSSLWrite && contains("GET /per-process")(ev)
	})

	runs := func() uint64 {
		var n uint64
		for _, p := range []*ebpf.Program{tr.objs.SslReadEnter, tr.objs.SslReadExEnter, tr.objs.SslWriteEnter, tr.objs.SslWriteExEnter} {
			if s, err := p.Stats(); err == nil {
				n += s.RunCount
			}
		}
		return n
	}
	before := runs()
	cmd = exec.Command("sh", "-c", `printf 'GET /untraced HTTP/1.0\r\n\r\n' | "$0" s_client -quiet -connect "127.0.0.1:$1" 2>/dev/null; :`, openssl, port)
	if out, err := cmd.CombinedOutput(); err != nil || !bytes.Contains(out, []byte("served /untraced")) {
		t.Fatalf("openssl: %v: %s", err, out)
	}
	if after := runs(); after != before {
		t.Errorf("openssl's calls ran the BPF program %d times", after-before)
	}
}

// A process forked from a traced one, without executing a program, gets
// probes of its own: its parent's are only for its parent.
func TestPerProcessFork(t *testing.T) {
	requireRoot(t)
	python := requireTool(t, "python3")
	_, events := startPerProcess(t, "python3")

	srv, _ := newServer(t)
	const script = `
import os, ssl, sys, time, urllib.request
ctx = ssl._create_unverified_context()
urllib.request.urlopen(sys.argv[1] + "/parent", context=ctx).read()
pid = os.fork()
if pid == 0:
    time.sleep(0.5) # its probes are attached once it's found
    urllib.request.urlopen(sys.argv[1] + "/child", context=ctx).read()
    os._exit(0)
os.waitpid(pid, 0)
`
	cmd := exec.Command("sh", "-c", `"$0" -c "$1" "$2"; :`, python, script, srv.URL)
	if out, err := cmd.CombinedOutput(); err != nil || len(out) > 0 {
		t.Fatalf("python3: %v: %s", err, out)
	}
	parent := waitFor(t, events, "the parent's request", func(ev *Event) bool {
		return ev.Function.Direction() == Write && contains("GET /parent")(ev)
	})
	child := waitFor(t, events, "the forked child's request", func(ev *Event) bool {
		return ev.Function.Direction() == Write && contains("GET /child")(ev)
	})
	if child.PID == parent.PID {
		t.Errorf("the child's request came from its parent's PID %d", parent.PID)
	}
}

// javaLibs are the jars the Java tests use, from Maven Central: Netty with
// netty-tcnative's BoringSSL, and Conscrypt.
var javaLibs = []string{
	"io/netty/netty-common/4.1.139.Final/netty-common-4.1.139.Final.jar",
	"io/netty/netty-buffer/4.1.139.Final/netty-buffer-4.1.139.Final.jar",
	"io/netty/netty-transport/4.1.139.Final/netty-transport-4.1.139.Final.jar",
	"io/netty/netty-resolver/4.1.139.Final/netty-resolver-4.1.139.Final.jar",
	"io/netty/netty-codec/4.1.139.Final/netty-codec-4.1.139.Final.jar",
	"io/netty/netty-handler/4.1.139.Final/netty-handler-4.1.139.Final.jar",
	"io/netty/netty-transport-native-unix-common/4.1.139.Final/netty-transport-native-unix-common-4.1.139.Final.jar",
	"io/netty/netty-tcnative-classes/2.0.84.Final/netty-tcnative-classes-2.0.84.Final.jar",
	"io/netty/netty-tcnative-boringssl-static/2.0.84.Final/netty-tcnative-boringssl-static-2.0.84.Final-linux-{arch}.jar",
	"org/conscrypt/conscrypt-openjdk-uber/2.8.0/conscrypt-openjdk-uber-2.8.0.jar",
}

// javaClasspath downloads javaLibs into testdata/java/lib, once, checked
// against the SHA-1 sums Maven Central publishes, and returns their
// classpath.
func javaClasspath(t *testing.T) string {
	t.Helper()
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch_64"}[runtime.GOARCH]
	dir, err := filepath.Abs("testdata/java/lib")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	get := func(url string) []byte {
		resp, err := http.Get(url)
		if err != nil {
			t.Skipf("download %s: %v", url, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("download %s: %s", url, resp.Status)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var cp []string
	for _, lib := range javaLibs {
		lib = strings.ReplaceAll(lib, "{arch}", arch)
		path := filepath.Join(dir, filepath.Base(lib))
		cp = append(cp, path)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		url := "https://repo1.maven.org/maven2/" + lib
		jar, want := get(url), strings.Fields(string(get(url+".sha1")))
		if sum := sha1.Sum(jar); len(want) == 0 || hex.EncodeToString(sum[:]) != want[0] {
			t.Fatalf("%s: SHA-1 %x, Maven Central says %v", url, sum, want)
		}
		if err := os.WriteFile(path, jar, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return strings.Join(cp, ":")
}

// Java programs whose TLS is native, BoringSSL in a JNI library they extract
// to a temporary file, load and delete: Netty with netty-tcnative (gRPC-Java
// uses it too) and Conscrypt. Traced per process with --comm java, whether
// they load it at start or seconds later, when only the BPF program's notice
// of the library being mapped tells snoopy to look again.
func TestJavaNativeTLS(t *testing.T) {
	requireRoot(t)
	java := requireTool(t, "java")
	cp := javaClasspath(t)
	_, events := startPerProcess(t, "java")
	srv, _ := newServer(t)
	for _, c := range []struct {
		class, path string
		delay       time.Duration
	}{
		{"NettyClient", "/netty", 0},
		{"ConscryptClient", "/conscrypt", 0},
		{"NettyClient", "/netty-late", 5 * time.Second},
		{"ConscryptClient", "/conscrypt-late", 5 * time.Second},
	} {
		// Under sh, so its parent isn't the tracer (see TestHoldNewProcess).
		cmd := exec.Command("sh", "-c", `"$0" -cp "$1" "$2" "$3" "$4"; :`, java, cp,
			"testdata/java/"+c.class+".java", srv.URL+c.path, fmt.Sprint(c.delay.Milliseconds()))
		if out, err := cmd.CombinedOutput(); err != nil || !bytes.Contains(out, []byte("served "+c.path)) {
			t.Fatalf("%s %s: %v: %s", c.class, c.path, err, out)
		}
		waitFor(t, events, c.class+" "+c.path, func(ev *Event) bool {
			return ev.Function.Direction() == Write && contains("GET "+c.path+" ")(ev)
		})
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
		crate      string // in testdata
		features   []string
		send, recv Function
	}{
		{"aws-lc", "rustlsasync", nil, FuncRecordSend, FuncRecordRecv},
		{"ring", "rustlsasync", []string{"--no-default-features", "--features", "ring"}, FuncRingSend, FuncRingRecv},
		{"ring-0.16", "rustls020", nil, FuncRingSend, FuncRingRecv}, // with rustls 0.20
	}
	clients := map[string]string{}
	var targets []discover.Target
	for _, p := range providers {
		dir := "testdata/" + p.crate + "/target/" + p.name
		args := append([]string{"build", "--release", "--quiet", "--manifest-path", "testdata/" + p.crate + "/Cargo.toml",
			"--target-dir", dir}, p.features...)
		if out, err := exec.Command(cargo, args...).CombinedOutput(); err != nil {
			t.Fatalf("build rustls client with %s: %v: %s", p.name, err, out)
		}
		client, err := filepath.Abs(dir + "/release/" + p.crate)
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
	events := startTracer(t, Options{Comm: "rustls"}, targets) // rustlsasync and rustls020
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
				t.Fatalf("%s %s: %v: %s", p.crate, name, err, out)
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

// UDP traffic on port 443, HTTP/3's, is counted per process, for main to
// warn when none of a program's QUIC packets were captured.
func TestQUICTraffic(t *testing.T) {
	requireRoot(t)
	python := requireTool(t, "python3")
	tr, err := New(Options{Comm: "python3"})
	if err != nil {
		t.Fatal(err)
	}
	if !tr.ResolvesAddresses() {
		t.Skip("needs BTF")
	}
	if err := tr.AttachSyscalls(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	if err != nil {
		t.Skipf("listen on UDP port 443: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	script := `import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("127.0.0.1", 443))
for _ in range(40):
    s.send(b"\xc0 not really QUIC")
`
	cmd := exec.Command(python, "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("python: %v: %s", err, out)
	}
	traffic, err := tr.QUICTraffic()
	if err != nil {
		t.Fatal(err)
	}
	if got := traffic[uint32(cmd.Process.Pid)]; got.UDP443 < 32 || got.Untracked != 0 {
		t.Errorf("python's traffic: %+v", got)
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

// javaAgent builds snoopy's Java agent with java/build.sh, and returns the
// agent jar's path. With SNOOPY_TEST_JAVA=1 (CI), a missing or too old JDK
// fails the test rather than skipping it.
func javaAgent(t *testing.T) (java, agent string) {
	t.Helper()
	need := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("SNOOPY_TEST_JAVA") == "1" {
			t.Fatalf(format, args...)
		}
		t.Skipf(format, args...)
	}
	for _, tool := range []string{"java", "javac", "jar", "keytool"} {
		if _, err := exec.LookPath(tool); err != nil {
			need("%s not installed", tool)
		}
	}
	java, _ = exec.LookPath("java")
	if v := javaVersion(t, java); v < 17 {
		need("the Java agent needs JDK 17 or later; this is %d", v)
	}
	if out, err := exec.Command("sh", "../../java/build.sh").CombinedOutput(); err != nil {
		t.Fatalf("build the Java agent: %v: %s", err, out)
	}
	agent, err := filepath.Abs("../../java/out/snoopy-agent.jar")
	if err != nil {
		t.Fatal(err)
	}
	return java, agent
}

// javaVersion returns the feature version of the JDK java belongs to, from
// java -version's `version "21.0.13"` (or "1.8.0_402", which is 8).
func javaVersion(t *testing.T, java string) int {
	t.Helper()
	out, _ := exec.Command(java, "-version").CombinedOutput()
	_, v, ok := strings.Cut(string(out), `version "`)
	if !ok {
		t.Fatalf("java -version: %s", out)
	}
	v = strings.TrimPrefix(v, "1.")
	n, _ := strconv.Atoi(v[:strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })])
	return n
}

// A Java program under test, stopped until it's told to go twice: under
// sh, before it execs java, so a session can be registered for the PID
// first (-javaagent); then, once it prints "ready", before what's
// measured.
type javaProgram struct {
	jvm   uint32 // the JVM's PID, if not the command's
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *bufio.Scanner
	lines []string
}

func startJava(t *testing.T, java string, javaArgs []string, program string, args ...string) *javaProgram {
	t.Helper()
	return startJavaWith(t, []string{java}, javaArgs, "testdata/java/"+program, args...)
}

// startJavaWith starts a program with launcher, the command that runs java
// (under another user, in a container), and the program's path as java
// sees it.
func startJavaWith(t *testing.T, launcher, javaArgs []string, program string, args ...string) *javaProgram {
	t.Helper()
	all := append(append([]string{"-c", `read x; exec "$@"`, "sh"}, launcher...), javaArgs...)
	all = append(append(all, program), args...)
	cmd := exec.Command("sh", all...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return &javaProgram{cmd: cmd, stdin: stdin, out: bufio.NewScanner(stdout)}
}

func (p *javaProgram) pid() uint32 {
	if p.jvm != 0 {
		return p.jvm
	}
	return uint32(p.cmd.Process.Pid)
}

// findJVM sets the program's PID to that of the JVM whose command line has
// marker in it: in a container, it isn't the command's.
func (p *javaProgram) findJVM(t *testing.T, marker string) {
	t.Helper()
	dirs, _ := os.ReadDir("/proc")
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if ok, _ := javaagent.IsHotSpot(pid); ok && bytes.Contains(cmdline, []byte(marker)) {
			p.jvm = uint32(pid)
			return
		}
	}
	t.Fatalf("no JVM with %q in its command line", marker)
}

// exec lets sh exec java, and waits for the program to be ready.
func (p *javaProgram) exec(t *testing.T) {
	t.Helper()
	fmt.Fprintln(p.stdin)
	if !p.out.Scan() || p.out.Text() != "ready" {
		t.Fatalf("%v didn't get ready: %q %v", p.cmd.Args, p.out.Text(), p.out.Err())
	}
}

// run lets the program do what's measured, and waits for it to finish.
func (p *javaProgram) run(t *testing.T) {
	t.Helper()
	fmt.Fprintln(p.stdin)
	p.stdin.Close()
	for p.out.Scan() {
		p.lines = append(p.lines, p.out.Text())
	}
	if err := p.cmd.Wait(); err != nil {
		t.Fatalf("%v: %v; printed %q", p.cmd.Args, err, p.lines)
	}
}

func javaNonce(t *testing.T) uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return binary.LittleEndian.Uint64(b[:])
}

// newJSSEServer is an HTTPS server, HTTP/2 included, answering "served
// <path> with <n> body bytes", gRPC-framed with a grpc-status trailer for
// gRPC calls.
func newJSSEServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		msg := fmt.Sprintf("served %s with %d body bytes", r.URL.Path, n)
		if r.Header.Get("Content-Type") != "application/grpc" {
			fmt.Fprint(w, msg)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		frame := binary.BigEndian.AppendUint32([]byte{0}, uint32(len(msg)))
		w.Write(append(frame, msg...))
		w.Header().Set("Grpc-Status", "0")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// stream is what a connection's events of one function carried, in order.
func stream(events *eventLog, match func(*Event) bool) map[uint64][]byte {
	events.mu.Lock()
	var evs []*Event
	for _, ev := range events.events {
		if match(ev) {
			evs = append(evs, ev)
		}
	}
	events.mu.Unlock()
	slices.SortStableFunc(evs, func(a, b *Event) int { return a.Time.Compare(b.Time) })
	out := map[uint64][]byte{}
	for _, ev := range evs {
		out[ev.ConnID] = append(out[ev.ConnID], ev.Data...)
	}
	return out
}

// SunJSSE, through snoopy's Java agent: SSLSocket and SSLEngine
// (java.net.http.HttpClient, over HTTP/1.1, HTTP/2 and as gRPC) calls
// become events like a library's, with the socket's addresses for
// SSLSocket and none for SSLEngine; the agent is loaded into a JVM that has
// warmed up, or at its start.
func TestJSSE(t *testing.T) {
	requireRoot(t)
	java, agent := javaAgent(t)
	jdk := javaVersion(t, java)
	tr, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.AttachSyscalls(); err != nil {
		t.Fatal(err)
	}
	events := runTracer(t, tr)
	srv := newJSSEServer(t)
	server := netip.MustParseAddrPort(srv.Listener.Addr().String())
	options := func(nonce uint64) string { return fmt.Sprintf("nonce=%d,max=%d", nonce, MaxCaptureLimit) }
	// session registers a session for a program, with its own nonce or
	// with the one given, and returns it.
	session := func(t *testing.T, p *javaProgram, nonce ...uint64) uint64 {
		n := javaNonce(t)
		if len(nonce) > 0 {
			n = nonce[0]
		}
		if err := tr.RegisterJava(p.pid(), n); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { tr.UnregisterJava(p.pid()) })
		return n
	}
	load := func(t *testing.T, p *javaProgram, opts string) {
		t.Helper()
		if out, err := javaagent.Load(int(p.pid()), agent, opts, 10*time.Second); err != nil {
			t.Fatalf("load the agent with %s: %v: %s", opts, err, out)
		}
	}
	t.Logf("JDK %d", jdk)

	for _, c := range []struct {
		name, mode  string
		body        int
		startup     bool
		write, read Function
	}{
		{"socket", "socket", 100, false, FuncJSSESocketWrite, FuncJSSESocketRead},
		{"engine", "engine", 100, false, FuncJSSEEngineWrap, FuncJSSEEngineUnwrap},
		{"engine, HTTP/2", "h2", 100, false, FuncJSSEEngineWrap, FuncJSSEEngineUnwrap},
		{"engine, gRPC", "grpc", 100, false, FuncJSSEEngineWrap, FuncJSSEEngineUnwrap},
		{"socket, large", "socket", 40000, false, FuncJSSESocketWrite, FuncJSSESocketRead},
		{"engine, at startup", "engine", 100, true, FuncJSSEEngineWrap, FuncJSSEEngineUnwrap},
		{"engine, HTTP/2 at startup", "h2", 100, true, FuncJSSEEngineWrap, FuncJSSEEngineUnwrap},
	} {
		t.Run(c.name, func(t *testing.T) {
			nonce := javaNonce(t)
			var javaArgs []string
			if c.startup {
				javaArgs = []string{"-javaagent:" + agent + "=" + options(nonce)}
			}
			p := startJava(t, java, javaArgs, "JSSEClient.java", srv.URL, c.mode, fmt.Sprint(c.body), "200", "2")
			session(t, p, nonce)
			p.exec(t)
			if !c.startup {
				load(t, p, options(nonce))
			}
			p.run(t)

			pid := p.pid()
			for i := range 2 {
				path := fmt.Sprintf("/jsse/%s/%d", c.mode, i)
				w := waitFor(t, events, "the write of "+path, func(ev *Event) bool {
					return ev.PID == pid && ev.Function == c.write && bytes.Contains(ev.Data, []byte("jsse-body-"+path+"-"))
				})
				waitFor(t, events, "the read for "+path, func(ev *Event) bool {
					return ev.PID == pid && ev.Function == c.read && bytes.Contains(ev.Data, []byte("served "+path+" "))
				})
				if w.ConnID>>56 != 0x4a || w.FD != -1 || w.Latency <= 0 {
					t.Errorf("%s: conn %#x, fd %d, latency %v", c.write, w.ConnID, w.FD, w.Latency)
				}
				if c.mode == "socket" && (w.Remote != server || !w.Local.IsValid()) {
					t.Errorf("%s: addresses %s -> %s, want %s", c.write, w.Local, w.Remote, server)
				}
				if c.mode != "socket" && w.Remote.IsValid() {
					t.Errorf("%s: has addresses %s -> %s", c.write, w.Local, w.Remote)
				}
				if c.body > DefaultMaxCapture && (w.Size < uint32(c.body) || len(w.Data) != DefaultMaxCapture) {
					t.Errorf("%s: size %d, captured %d", c.write, w.Size, len(w.Data))
				}
			}
			// Loaded later, the agent finds HttpClient's HTTP/2 connection
			// from the warm-up already going.
			if c.mode == "h2" && c.startup {
				waitFor(t, events, "HTTP/2's preface", func(ev *Event) bool {
					return ev.PID == pid && ev.Function == c.write && bytes.HasPrefix(ev.Data, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
				})
			}
			warm := func(ev *Event) bool { return ev.PID == pid && bytes.Contains(ev.Data, []byte("/warm-")) }
			if n := events.count(warm); !c.startup && n != 0 {
				t.Errorf("%d events from before the agent was loaded", n)
			}
		})
	}

	// SSLEngine with each kind of buffer: what the client's wraps consumed
	// and the server's unwraps produced, byte for byte, with none for a wrap
	// that consumed nothing.
	t.Run("engine buffers", func(t *testing.T) {
		dir := t.TempDir()
		keystore := filepath.Join(dir, "server.p12")
		if out, err := exec.Command("keytool", "-genkeypair", "-alias", "server", "-keyalg", "EC", "-dname", "CN=localhost",
			"-validity", "2", "-storetype", "PKCS12", "-keystore", keystore, "-storepass", "testpass").CombinedOutput(); err != nil {
			t.Fatalf("keytool: %v: %s", err, out)
		}
		p := startJava(t, java, nil, "EngineBuffers.java", keystore, "testpass")
		nonce := session(t, p)
		p.exec(t)
		load(t, p, options(nonce))
		p.run(t)

		var want []byte
		kinds := []string{"heap", "direct", "sliced", "read-only", "gathered", "large"}
		dsts := []string{"heap", "direct", "offset", "scattered", "heap", "heap"}
		for i := range kinds {
			n := 20 * i
			if i == 5 {
				n = 30000
			}
			want = append(want, "engine-buffers-"+kinds[i]+"-into-"+dsts[i]+"-"+strings.Repeat("q", n)...)
		}
		pid := p.pid()
		waitFor(t, events, "the last unwrap", func(ev *Event) bool {
			return ev.PID == pid && ev.Function == FuncJSSEEngineUnwrap && bytes.HasSuffix(ev.Data, []byte("qqq"))
		})
		time.Sleep(500 * time.Millisecond)
		for _, fn := range []Function{FuncJSSEEngineWrap, FuncJSSEEngineUnwrap} {
			got := stream(events, func(ev *Event) bool { return ev.PID == pid && ev.Function == fn })
			if len(got) != 1 {
				t.Fatalf("%s: %d engines, want 1", fn, len(got))
			}
			for _, data := range got {
				if !bytes.Equal(data, want) {
					t.Errorf("%s: %d bytes, want %d; differ from %d", fn, len(data), len(want), mismatch(data, want))
				}
			}
		}
	})

	// Connections on virtual threads at once, each in several writes: each
	// connection's events are its own, in order.
	t.Run("virtual threads", func(t *testing.T) {
		if jdk < 21 {
			t.Skipf("virtual threads are JDK 21's; this is %d", jdk)
		}
		const n = 8
		p := startJava(t, java, nil, "VirtualClient.java", srv.URL, fmt.Sprint(n))
		nonce := session(t, p)
		p.exec(t)
		load(t, p, options(nonce))
		p.run(t)
		pid := p.pid()
		for i := range n {
			waitFor(t, events, fmt.Sprintf("connection %d's response", i), func(ev *Event) bool {
				return ev.PID == pid && ev.Function == FuncJSSESocketRead && bytes.Contains(ev.Data, []byte(fmt.Sprintf("served /jsse/virtual/%d ", i)))
			})
		}
		writes := stream(events, func(ev *Event) bool { return ev.PID == pid && ev.Function == FuncJSSESocketWrite })
		if len(writes) != n {
			t.Fatalf("writes on %d connections, want %d", len(writes), n)
		}
		for _, data := range writes {
			head, body, _ := bytes.Cut(data, []byte("\r\n\r\n"))
			var id int
			if _, err := fmt.Sscanf(string(head), "POST /jsse/virtual/%d ", &id); err != nil {
				t.Fatalf("a connection's writes start %q", data[:min(len(data), 40)])
			}
			if want := strings.Repeat(fmt.Sprintf("virtual-%d-", id), 50); string(body) != want {
				t.Errorf("connection %d's body is %d bytes, not its %d", id, len(body), len(want))
			}
		}
	})

	// JVMs of other users, as the kernel shows them in their own user
	// namespace too (as in rootless containers), and in containers: the
	// agent's jars are staged where each can read them, and the attach
	// socket is connected to as the JVM's user.
	t.Run("elsewhere", func(t *testing.T) {
		// Somewhere everyone can read the program from.
		dir, err := os.MkdirTemp("", "jsse")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		src, err := os.ReadFile("testdata/java/JSSEClient.java")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "JSSEClient.java"), src, 0o644); err != nil {
			t.Fatal(err)
		}
		for path, mode := range map[string]os.FileMode{dir: 0o755, filepath.Join(dir, "JSSEClient.java"): 0o644} {
			if err := os.Chmod(path, mode); err != nil { // not the umask's
				t.Fatal(err)
			}
		}
		docker, _ := exec.LookPath("docker")
		image := fmt.Sprintf("eclipse-temurin:%d-jdk", jdk)
		for _, c := range []struct {
			name     string
			launcher []string
			program  string
			docker   bool
		}{
			{"another user", []string{"setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", java}, dir, false},
			{"user namespace", []string{"unshare", "--user", "--map-users=0:65534:1", "--map-groups=0:65534:1",
				"--setuid=0", "--setgid=0", java}, dir, false},
			{"container", []string{docker, "run", "--rm", "-i", "--network", "host", "--user", "65534:65534",
				"-v", dir + ":/fx:ro", image, "java"}, "/fx", true},
		} {
			t.Run(c.name, func(t *testing.T) {
				if c.docker {
					if docker == "" {
						t.Skip("no docker")
					}
					if out, err := exec.Command(docker, "pull", "-q", image).CombinedOutput(); err != nil {
						if os.Getenv("SNOOPY_TEST_JAVA") == "1" {
							t.Fatalf("docker pull %s: %v: %s", image, err, out)
						}
						t.Skipf("docker pull %s: %v", image, err)
					}
				}
				if !c.docker {
					// The JDK has to be one other users can run (one under
					// /root isn't).
					probe := append(slices.Clone(c.launcher), "-version")
					if out, err := exec.Command(probe[0], probe[1:]...).CombinedOutput(); err != nil {
						t.Skipf("%s can't run this JDK as nobody: %v: %s", c.name, err, out)
					}
				}
				marker := fmt.Sprintf("jsse-%x", javaNonce(t))
				p := startJavaWith(t, c.launcher, nil, c.program+"/JSSEClient.java", srv.URL+"/"+marker, "socket", "100", "1", "2")
				p.exec(t)
				p.findJVM(t, marker)
				nonce := session(t, p)
				jar, err := javaagent.Stage(int(p.pid()), filepath.Dir(agent))
				if err != nil {
					t.Fatal(err)
				}
				if out, err := javaagent.Load(int(p.pid()), jar, options(nonce), 10*time.Second); err != nil {
					t.Fatalf("load the agent: %v: %s", err, out)
				}
				p.run(t)
				for i := range 2 {
					path := fmt.Sprintf("/jsse/socket/%d", i)
					waitFor(t, events, "the write of "+path, func(ev *Event) bool {
						return ev.PID == p.pid() && ev.Function == FuncJSSESocketWrite && bytes.Contains(ev.Data, []byte("jsse-body-"+path+"-"))
					})
				}
			})
		}
	})

	// Told to stop, the agent writes nothing more, while its session is
	// still there.
	t.Run("disabled", func(t *testing.T) {
		p := startJava(t, java, nil, "JSSEClient.java", srv.URL, "socket", "100", "1", "2")
		nonce := session(t, p)
		p.exec(t)
		load(t, p, options(nonce))
		load(t, p, "disable")
		p.run(t)
		time.Sleep(time.Second)
		if n := events.count(func(ev *Event) bool { return ev.PID == p.pid() }); n != 0 {
			t.Errorf("%d events after the agent was told to stop", n)
		}
	})

	// A JVM that can't be attached to is told apart without a signal (it
	// would answer with a thread dump), and one with fewer signal handlers
	// (-Xrs) can be attached to; both go on as before.
	for _, c := range []struct{ flag, want string }{
		{"-XX:+DisableAttachMechanism", "DisableAttachMechanism"},
		{"-Xrs", ""},
	} {
		t.Run(c.flag, func(t *testing.T) {
			p := startJava(t, java, []string{c.flag}, "JSSEClient.java", srv.URL, "socket", "100", "1", "1")
			p.exec(t)
			_, err := javaagent.Load(int(p.pid()), agent, options(1), 2*time.Second)
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Errorf("error %v, want %q", err, c.want)
			}
			p.run(t)
		})
	}

	// Frames without the session's nonce are written to /dev/null and that's
	// all.
	t.Run("other nonce", func(t *testing.T) {
		p := startJava(t, java, nil, "JSSEClient.java", srv.URL, "socket", "100", "1", "2")
		session(t, p)
		p.exec(t)
		load(t, p, options(javaNonce(t)))
		p.run(t)
		time.Sleep(time.Second)
		if n := events.count(func(ev *Event) bool { return ev.PID == p.pid() }); n != 0 {
			t.Errorf("%d events from frames with another nonce", n)
		}
	})
}

// mismatch returns where a and b first differ.
func mismatch(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}
