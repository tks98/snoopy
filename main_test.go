package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tks98/snoopy/v2/internal/discover"
	"github.com/tks98/snoopy/v2/internal/output"
	"github.com/tks98/snoopy/v2/internal/tracer"
)

func TestParseFlags(t *testing.T) {
	c, err := parseFlags([]string{"--json", "--pid", "1337", "--lib", "/a", "--lib", "/b", "-max-size=100"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !c.json || c.pid != 1337 || !reflect.DeepEqual([]string(c.libs), []string{"/a", "/b"}) || c.maxSize != 100 {
		t.Errorf("got %+v", c)
	}

	for _, args := range [][]string{{"--java", "--pid", "1"}, {"--java", "--container", "abc", "--java-agent", "/x"}} {
		if c, err := parseFlags(args, io.Discard); err != nil || !c.java {
			t.Errorf("%q: %+v, %v", args, c, err)
		}
	}

	for _, args := range [][]string{{"--count", "0"}, {"--quiet"}, {"--quiet", "--pcap", "x.pcap"}, {"--quiet", "--har", "-"}, {"--pcap", "-", "--har", "x.har"}} {
		if _, err := parseFlags(args, io.Discard); err != nil {
			t.Errorf("%q: %v", args, err)
		}
	}

	c, err = parseFlags(nil, io.Discard)
	if err != nil || c.maxSize != tracer.DefaultMaxCapture || c.pid != 0 || c.json {
		t.Errorf("defaults: %+v, %v", c, err)
	}

	if _, err := parseFlags([]string{"-h"}, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: %v", err)
	}
	c, err = parseFlags([]string{"--brief", "--host", "example.com", "--host", "10.0.0.0/8", "--port", "443", "--port", "8443", "--count", "5"}, io.Discard)
	if err != nil || !c.brief || len(c.hosts) != 2 || !reflect.DeepEqual([]uint16(c.ports), []uint16{443, 8443}) || c.count != 5 {
		t.Errorf("got %+v, %v", c, err)
	}

	for _, args := range [][]string{
		{"--pid", "-1"},
		{"--pid", "0"},
		{"--pcap", "-", "--har", "-"},
		{"--json", "--hex"},
		{"--brief", "--json"},
		{"--brief", "--hex"},
		{"--full", "--json"},
		{"--full", "--brief"},
		{"--full", "--hex"},
		{"--port", "0"},
		{"--port", "https"},
		{"--count", "-1"},
		{"--status", "6xx"},
		{"--path", "v1"},
		{"--redact", "--hex"},
		{"--redact", "--pcap", "out.pcap"},
		{"extra"},
		{"--nope"},
		{"--java"},
		{"--java", "--comm", "java"},
		{"--java", "--pid", "1", "--container", "abc"},
		{"--java-agent", "/x"},
	} {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("%q: no error", args)
		}
	}
}

// --container takes IDs and prefixes, named or not, repeated or
// comma-separated, and Kubernetes' runtime://ID form.
func TestContainers(t *testing.T) {
	c, err := parseFlags([]string{"--container", "containerd://3F2A=shop/checkout/app,9b1c", "--container", "77=db"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := containerList{{"3f2a", "shop/checkout/app"}, {"9b1c", ""}, {"77", "db"}}
	if !reflect.DeepEqual(c.containers, want) {
		t.Fatalf("got %+v, want %+v", c.containers, want)
	}
	for id, wantName := range map[string]string{"3f2a00": "shop/checkout/app", "9b1cff": "", "7788": "db"} {
		if name, ok := c.containers.match(id); !ok || name != wantName {
			t.Errorf("%s: %q, %v", id, name, ok)
		}
	}
	for _, id := range []string{"abcd", ""} {
		if _, ok := c.containers.match(id); ok {
			t.Errorf("%q matched", id)
		}
	}
	if _, ok := (containerList{}).match(""); !ok {
		t.Error("with no --container, a process outside containers didn't match")
	}
	if _, err := parseFlags([]string{"--container", "=name"}, io.Discard); err == nil {
		t.Error("an empty ID was accepted")
	}
}

// --method, --path and --status make one filter, with values repeated or
// comma-separated.
func TestHTTPFilterFlags(t *testing.T) {
	c, err := parseFlags([]string{"--method", "GET,post", "--path", "/v1/", "--status", "5xx", "--status", "404"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	f := c.filter
	if f == nil || len(f.Methods) != 2 || len(f.Paths) != 1 || len(f.Status) != 2 || f.Status[1] != (output.StatusRange{From: 404, To: 404}) {
		t.Errorf("filter %+v", f)
	}
	if c, _ := parseFlags(nil, io.Discard); c.filter != nil {
		t.Error("a filter without the flags")
	}
}

// Each flag is in the help text, which is written by hand.
func TestUsage(t *testing.T) {
	var help strings.Builder
	if _, err := parseFlags([]string{"--help"}, &help); !errors.Is(err, flag.ErrHelp) {
		t.Fatal(err)
	}
	if help.String() != usage {
		t.Error("--help doesn't print the help text")
	}
	n := 0
	flags(&config{}).VisitAll(func(f *flag.Flag) {
		n++
		if !strings.Contains(usage, "\n  --"+f.Name+" ") {
			t.Errorf("--%s isn't in the help text", f.Name)
		}
	})
	if m := strings.Count(usage, "\n  --"); m != n {
		t.Errorf("the help text has %d flags, not %d", m, n)
	}
}

func TestAttachSummary(t *testing.T) {
	target := func(lib discover.Library, path string) discover.Target {
		return discover.Target{Library: lib, Path: path}
	}
	for _, tc := range []struct {
		targets []discover.Target
		want    string
	}{
		{[]discover.Target{target(discover.OpenSSL, "/usr/lib/libssl.so.3")}, "the openssl library"},
		{[]discover.Target{
			target(discover.OpenSSL, "/usr/lib/libssl.so.3"),
			target(discover.OpenSSL, "/proc/7/root/usr/lib/libssl.so.1.1"),
			target(discover.NSS, "/usr/lib/libnspr4.so"),
			target(discover.OpenSSL, "/opt/google/chrome/chrome"),
		}, "the openssl and nss libraries, and to the program chrome"},
		{[]discover.Target{
			target(discover.GoTLS, "/a/one"), target(discover.GoTLS, "/a/two"), target(discover.GoTLS, "/a/three"),
			target(discover.GoTLS, "/a/four"), target(discover.GoTLS, "/a/five"), target(discover.GoTLS, "/a/six"),
		}, "the programs one, two, three, four and 2 more"},
	} {
		if got := attachSummary(tc.targets); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

func TestAddrFilter(t *testing.T) {
	ev := func(local, remote string) *tracer.Event {
		e := &tracer.Event{Function: tracer.FuncSSLWrite}
		if local != "" {
			e.Local = netip.MustParseAddrPort(local)
		}
		if remote != "" {
			e.Remote = netip.MustParseAddrPort(remote)
		}
		return e
	}
	f, err := newAddrFilter(config{hosts: stringList{"93.184.216.34", "10.1.0.0/16"}, ports: portList{443}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		local, remote string
		want          bool
	}{
		{"10.0.0.2:51234", "93.184.216.34:443", true},
		{"10.0.0.2:51234", "93.184.216.34:80", false},                  // wrong port
		{"10.0.0.2:51234", "192.0.2.1:443", false},                     // wrong host
		{"10.1.2.3:443", "192.0.2.1:51234", true},                      // a server in the network
		{"[::ffff:10.0.0.2]:5000", "[::ffff:93.184.216.34]:443", true}, // IPv4 in IPv6
		{"0.0.0.0:443", "0.0.0.0:0", false},                            // an unconnected UDP socket
		{"", "", false},                                                // addresses unknown
	} {
		if got := f.match(ev(tc.local, tc.remote)); got != tc.want {
			t.Errorf("%s > %s: %v", tc.local, tc.remote, got)
		}
	}
	if none, _ := newAddrFilter(config{}); !none.match(ev("", "")) {
		t.Error("no filter dropped an event")
	}
	if _, err := newAddrFilter(config{hosts: stringList{"no such host.invalid"}}); err == nil {
		t.Error("unresolvable host accepted")
	}
}

// A flag's error is said once, with flags named as --help names them, and
// without the help text.
func TestFlagErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--port", "70000"}, `invalid value "70000" for flag --port: ports are 1 to 65535`},
		{[]string{"--container", ""}, `invalid value "" for flag --container: empty container ID`},
		{[]string{"--nope"}, "flag provided but not defined: --nope"},
		{[]string{"--json=maybe"}, `invalid boolean value "maybe" for --json: parse error`},
		{[]string{"--pid"}, "flag needs an argument: --pid"},
	} {
		var stderr strings.Builder
		_, err := parseFlags(tc.args, &stderr)
		if err == nil || err.Error() != tc.want || stderr.Len() > 0 {
			t.Errorf("%q: %v, and wrote %q; want %s", tc.args, err, stderr.String(), tc.want)
		}
	}
}

// --host and --port apply once an event's peer is known: a QUIC packet on a
// socket that isn't connected (quinn's) gets its connection's, from where
// its packets were sent. Those whose peer stays unknown are counted.
func TestPipelineAddresses(t *testing.T) {
	var out strings.Builder
	f, err := newAddrFilter(config{hosts: stringList{"192.0.2.1"}})
	if err != nil {
		t.Fatal(err)
	}
	p := newPipeline(f, []output.Printer{output.NewBrief(&out, output.Options{Verbose: true})}, 0)
	server := netip.MustParseAddrPort("192.0.2.1:443")
	none := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	ev := func(fn tracer.Function, hdr []byte, remote netip.AddrPort, data []byte) *tracer.Event {
		return &tracer.Event{PID: 9, FD: 5, ConnID: 0xc0de, Function: fn, Size: uint32(len(data)), Data: data,
			QUICHeader: hdr, Local: netip.MustParseAddrPort("0.0.0.0:40000"), Remote: remote}
	}
	cid := func(b byte) []byte { return bytes.Repeat([]byte{b}, 8) }
	long := func(dcid, scid []byte) []byte {
		return append(append([]byte{0xc3, 0, 0, 0, 1, byte(len(dcid))}, dcid...), append([]byte{byte(len(scid))}, scid...)...)
	}
	short := func(dcid []byte) []byte { return append([]byte{0x41}, dcid...) }
	crypto := []byte{0x06, 0x00, 0x01, 0xff}
	// A STREAM frame on stream 0 with an HTTP/3 DATA frame.
	data := []byte{0x0f, 0x00, 0x00, 0x07, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}

	initial := long(cid(0xe), cid(0xc))
	for _, e := range []*tracer.Event{
		ev(tracer.FuncQUICSend, initial, none, crypto),
		ev(tracer.FuncQUICPacketSent, initial, server, nil),
		ev(tracer.FuncQUICRecv, long(cid(0xc), cid(0x5)), none, crypto),
	} {
		if _, err := p.handle(e); err != nil {
			t.Fatal(err)
		}
	}
	before, beforeNoAddr := p.calls, p.noAddr
	if _, err := p.handle(ev(tracer.FuncQUICRecv, short(cid(0xc)), none, data)); err != nil {
		t.Fatal(err)
	}
	if p.calls != before+1 {
		t.Errorf("the response on a connection to %s was left out:\n%s", server, out.String())
	}
	// A packet of a connection snoopy doesn't know, and an SSLEngine call.
	_, _ = p.handle(ev(tracer.FuncQUICRecv, short(cid(0x7)), none, data))
	_, _ = p.handle(&tracer.Event{Function: tracer.FuncJSSEEngineWrap, Data: []byte("GET / HTTP/1.1\r\n\r\n")})
	// And one that's known not to match.
	_, _ = p.handle(&tracer.Event{Function: tracer.FuncSSLWrite, Data: []byte("x"), Remote: netip.MustParseAddrPort("192.0.2.9:443")})
	if p.noAddr != beforeNoAddr+2 || p.calls != before+1 {
		t.Errorf("%d calls, %d without addresses", p.calls, p.noAddr)
	}
	if s := p.summary(nil); !strings.Contains(s, fmt.Sprintf("left out %d whose peer's address", p.noAddr)) {
		t.Errorf("summary %q", s)
	}
}

func TestSummary(t *testing.T) {
	for n, want := range map[int]string{0: "captured 0 calls", 1: "captured 1 call", 2: "captured 2 calls"} {
		if got := (&pipeline{calls: n}).summary(nil); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

// --count stops snoopy after that many calls shown.
func TestPipelineCount(t *testing.T) {
	p := newPipeline(addrFilter{}, []output.Printer{output.NewBrief(io.Discard, output.Options{})}, 2)
	for i, want := range []bool{false, true, true} {
		done, err := p.handle(&tracer.Event{Function: tracer.FuncSSLWrite, Data: []byte("GET / HTTP/1.1\r\n\r\n"), ConnID: uint64(i)})
		if err != nil || done != want {
			t.Errorf("call %d: done %v, %v", i, done, err)
		}
	}
	if p.calls != 2 {
		t.Errorf("%d calls", p.calls)
	}
}

// The verifier's log is left out, unless --verbose.
func TestLoadError(t *testing.T) {
	long := errors.New("the kernel's BPF verifier rejected snoopy's program: load program: permission denied:\n" + strings.Repeat("0: R1=ctx\n", 1000))
	if err := loadError(long, false); strings.Count(err.Error(), "\n") > 0 || !strings.Contains(err.Error(), "5.10 or later with BTF") {
		t.Errorf("got %q", err)
	}
	if err := loadError(long, true); err != long {
		t.Errorf("--verbose: got %q", err)
	}
	other := errors.New("load BPF program: operation not permitted (snoopy needs root)")
	if err := loadError(other, false); err != other {
		t.Errorf("got %q", err)
	}
}

// Once the --pid process, and those it started, have exited, snoopy is told.
func TestWatchExit(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 2 & sleep 1.2")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	exited := make(chan struct{})
	start := time.Now()
	go watchExit(t.Context(), cmd.Process.Pid, func() { close(exited) })
	go func() { _ = cmd.Wait() }()
	select {
	case <-exited:
		// Not before its child, the second sleep, is gone.
		if d := time.Since(start); d < 2*time.Second {
			t.Errorf("told after %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Error("not told")
	}
}

// --java --pid of a process that isn't a JVM says so, before looking for
// the agent's jars.
func TestJavaNotJVM(t *testing.T) {
	_, err := startJava(t.Context(), config{java: true, pid: os.Getpid(), javaAgent: "/nonexistent"}, nil)
	if err == nil || !strings.Contains(err.Error(), "isn't a HotSpot JVM") {
		t.Errorf("got %v", err)
	}
}

// What's kept of JVMs that exited goes.
func TestJavaForgetExited(t *testing.T) {
	self, ok := processKey(os.Getpid())
	if !ok {
		t.Skip("no /proc")
	}
	gone := procKey{pid: self.pid, start: self.start + "0"} // an earlier process with the PID
	l := &javaLoader{loaded: map[procKey]string{self: "a.jar", gone: "a.jar"},
		failing: map[procKey]time.Time{gone: time.Now()}, reported: map[procKey]bool{gone: true}}
	l.forgetExited()
	if len(l.loaded) != 1 || l.loaded[self] == "" || len(l.failing) != 0 || len(l.reported) != 0 {
		t.Errorf("loaded %v, failing %v, reported %v", l.loaded, l.failing, l.reported)
	}
}

// A process that exits before its probes are made isn't warned about.
func TestReportAttachGone(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = w
	target := discover.Target{Path: "/proc/1/root/usr/lib/libssl.so.3"}
	reportAttach(config{}, target, nil, fmt.Errorf("SSL_read: opening perf event: %w", syscall.ESRCH), false)
	reportAttach(config{}, target, nil, fmt.Errorf("open: %w", os.ErrNotExist), false)
	os.Stderr = stderr
	w.Close()
	if out, _ := io.ReadAll(r); len(out) != 0 {
		t.Errorf("warned: %s", out)
	}
}
