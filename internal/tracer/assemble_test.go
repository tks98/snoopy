package tracer

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The hand-written header must match the layout bpf2go derived from the C
// struct.
func TestHeaderMatchesBPFLayout(t *testing.T) {
	gen := reflect.TypeOf(snoopyEventHeader{})
	if headerSize != int(gen.Size()) {
		t.Fatalf("header is %d bytes, the C struct %d", headerSize, gen.Size())
	}

	hdr := reflect.TypeOf(rawHeader{})
	for i := 0; i < hdr.NumField(); i++ {
		f := hdr.Field(i)
		if f.Name == "_" {
			continue
		}
		name := strings.Replace(f.Name, "ConnID", "ConnId", 1)
		g, ok := gen.FieldByName(name)
		if !ok {
			t.Errorf("generated struct has no field %s", name)
			continue
		}
		if g.Offset != f.Offset || g.Type.Size() != f.Type.Size() {
			t.Errorf("%s: offset/size %d/%d, generated %d/%d", f.Name, f.Offset, f.Type.Size(), g.Offset, g.Type.Size())
		}
	}
}

// The Function constants must follow enum fn_id in bpf/snoopy.c.
func TestFunctionsMatchBPFEnum(t *testing.T) {
	src, err := os.ReadFile("../../bpf/snoopy.c")
	if err != nil {
		t.Fatal(err)
	}
	enum := regexp.MustCompile(`(?s)enum fn_id \{(.*?)\};`).FindSubmatch(src)
	if enum == nil {
		t.Fatal("enum fn_id not found")
	}
	names := regexp.MustCompile(`FN_[A-Z0-9_]+`).FindAllString(string(enum[1]), -1)

	want := map[string]Function{
		"FN_SSL_READ": FuncSSLRead, "FN_SSL_WRITE": FuncSSLWrite,
		"FN_SSL_READ_EX": FuncSSLReadEx, "FN_SSL_WRITE_EX": FuncSSLWriteEx,
		"FN_GNUTLS_RECORD_RECV": FuncGnuTLSRecv, "FN_GNUTLS_RECORD_SEND": FuncGnuTLSSend,
		"FN_PR_READ": FuncPRRead, "FN_PR_WRITE": FuncPRWrite,
		"FN_PR_RECV": FuncPRRecv, "FN_PR_SEND": FuncPRSend,
		"FN_GO_READ": FuncGoRead, "FN_GO_WRITE": FuncGoWrite,
		"FN_WOLFSSL_READ": FuncWolfSSLRead, "FN_WOLFSSL_WRITE": FuncWolfSSLWrite,
		"FN_MBEDTLS_SSL_READ": FuncMbedTLSRead, "FN_MBEDTLS_SSL_WRITE": FuncMbedTLSWrite,
		"FN_S2N_RECV": FuncS2NRecv, "FN_S2N_SEND": FuncS2NSend,
		"FN_RUSTLS_READ": FuncRustlsRead, "FN_RUSTLS_WRITE": FuncRustlsWrite,
		"FN_QUIC_SEND": FuncQUICSend, "FN_QUIC_RECV": FuncQUICRecv,
		"FN_NSS_QUIC_SEND": FuncNSSQUICSend, "FN_NSS_QUIC_RECV": FuncNSSQUICRecv,
		"FN_RECORD_SEND": FuncRecordSend, "FN_RECORD_RECV": FuncRecordRecv,
		"FN_RING_SEND": FuncRingSend, "FN_RING_RECV": FuncRingRecv,
		"FN_AWSLC_QUIC_SEND": FuncAwsLCQUICSend, "FN_AWSLC_QUIC_RECV": FuncAwsLCQUICRecv,
		"FN_RING_QUIC_SEND": FuncRingQUICSend, "FN_RING_QUIC_RECV": FuncRingQUICRecv,
	}
	if len(names) != len(want) {
		t.Fatalf("C enum has %d functions, Go has %d", len(names), len(want))
	}
	notice := regexp.MustCompile(`#define FN_SOCKET_NOTICE (0x[0-9a-f]+)`).FindSubmatch(src)
	if notice == nil || string(notice[1]) != fmt.Sprintf("%#x", fnSocketNotice) {
		t.Errorf("FN_SOCKET_NOTICE doesn't match fnSocketNotice (%#x)", fnSocketNotice)
	}
	sent := regexp.MustCompile(`#define FN_QUIC_PACKET_SENT (0x[0-9a-f]+)`).FindSubmatch(src)
	if sent == nil || string(sent[1]) != fmt.Sprintf("%#x", fnQUICPacketSent) {
		t.Errorf("FN_QUIC_PACKET_SENT doesn't match fnQUICPacketSent (%#x)", fnQUICPacketSent)
	}
	for i, name := range names {
		if fn, ok := want[name]; !ok || int(fn) != i+1 {
			t.Errorf("%s is %d in C but %d in Go", name, i+1, fn)
		}
	}
	for _, fn := range want {
		if fn.String() == "unknown" || fn.Library() == 0 {
			t.Errorf("function %d has no name or library", fn)
		}
	}
}

func TestFunctionDirection(t *testing.T) {
	for fn, want := range map[Function]Direction{
		FuncSSLRead: Read, FuncSSLWriteEx: Write, FuncGnuTLSRecv: Read,
		FuncPRSend: Write, FuncGoRead: Read, FuncGoWrite: Write,
		FuncWolfSSLRead: Read, FuncWolfSSLWrite: Write, FuncMbedTLSRead: Read,
		FuncMbedTLSWrite: Write, FuncS2NRecv: Read, FuncS2NSend: Write,
		FuncRustlsRead: Read, FuncRustlsWrite: Write, FuncQUICSend: Write, FuncQUICRecv: Read,
		FuncNSSQUICSend: Write, FuncNSSQUICRecv: Read, FuncRecordSend: Write, FuncRecordRecv: Read,
		FuncRingSend: Write, FuncRingRecv: Read,
		FuncAwsLCQUICSend: Write, FuncAwsLCQUICRecv: Read, FuncRingQUICSend: Write, FuncRingQUICRecv: Read,
	} {
		if got := fn.Direction(); got != want {
			t.Errorf("%s: direction %s, want %s", fn, got, want)
		}
	}
}

// record encodes a ring buffer record like the BPF program does.
func record(h rawHeader, data string) []byte {
	h.ChunkLen = uint32(len(data))
	buf := make([]byte, headerSize, headerSize+len(data))
	if _, err := binary.Encode(buf, binary.NativeEndian, h); err != nil {
		panic(err)
	}
	return append(buf, data...)
}

func mustParse(t *testing.T, rec []byte) chunk {
	t.Helper()
	c, err := parseChunk(rec)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testClock(ns uint64) time.Time { return time.Unix(0, int64(ns)) }

func TestParseChunk(t *testing.T) {
	h := rawHeader{TimestampNs: 42, Pid: 7, Tid: 8, Size: 5, Captured: 5, Fd: 3, Fn: uint8(FuncSSLWrite)}
	copy(h.Comm[:], "curl")
	c := mustParse(t, record(h, "hello"))
	if c.Pid != 7 || c.Tid != 8 || string(c.data) != "hello" {
		t.Fatalf("got %+v", c)
	}

	if _, err := parseChunk(record(h, "hello")[:headerSize-1]); err == nil {
		t.Error("short record accepted")
	}
	bad := record(h, "hello")
	if _, err := parseChunk(bad[:len(bad)-1]); err == nil {
		t.Error("record shorter than its chunk length accepted")
	}
}

func TestAddresses(t *testing.T) {
	h := rawHeader{Family: afInet, Lport: 51234, Rport: 443}
	copy(h.Laddr[:], []byte{10, 0, 0, 2})
	copy(h.Raddr[:], []byte{93, 184, 216, 34})
	l, r := h.addresses()
	if l != netip.MustParseAddrPort("10.0.0.2:51234") || r != netip.MustParseAddrPort("93.184.216.34:443") {
		t.Errorf("IPv4: got %s %s", l, r)
	}

	h = rawHeader{Family: afInet6, Lport: 40000, Rport: 443}
	h.Laddr = netip.MustParseAddr("2001:db8::1").As16()
	h.Raddr = netip.MustParseAddr("::ffff:192.0.2.7").As16()
	l, r = h.addresses()
	if l != netip.MustParseAddrPort("[2001:db8::1]:40000") || r != netip.MustParseAddrPort("192.0.2.7:443") {
		t.Errorf("IPv6: got %s %s", l, r)
	}

	if l, r := (&rawHeader{}).addresses(); l.IsValid() || r.IsValid() {
		t.Error("unknown family produced addresses")
	}
}

func TestAssembleSingleChunk(t *testing.T) {
	a := newAssembler(testClock)
	h := rawHeader{TimestampNs: 100, LatencyNs: 5000, ConnID: 0xabc, Pid: 1, Tid: 1, Size: 5, Captured: 5, Fd: 4, Fn: uint8(FuncSSLRead)}
	copy(h.Comm[:], "curl")

	evs := a.add(mustParse(t, record(h, "hello")), time.Now())
	if len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
	ev := evs[0]
	if string(ev.Data) != "hello" || ev.Comm != "curl" || ev.Function != FuncSSLRead || ev.FD != 4 ||
		ev.ConnID != 0xabc || ev.Latency != 5*time.Microsecond || !ev.Time.Equal(time.Unix(0, 100)) {
		t.Errorf("got %+v", ev)
	}
	if ev.Truncated() || ev.Incomplete || ev.ReadError {
		t.Errorf("unexpected flags: %+v", ev)
	}
}

func TestAssembleChunksAcrossThreads(t *testing.T) {
	a := newAssembler(testClock)
	now := time.Now()
	t1 := rawHeader{TimestampNs: 1, Tid: 1, Size: 10, Captured: 6}
	t2 := rawHeader{TimestampNs: 2, Tid: 2, Size: 4, Captured: 4}

	var got []*Event
	h := t1
	h.ChunkOffset = 0
	got = append(got, a.add(mustParse(t, record(h, "abc")), now)...)
	got = append(got, a.add(mustParse(t, record(t2, "wxyz")), now)...)
	h.ChunkOffset = 3
	got = append(got, a.add(mustParse(t, record(h, "def")), now)...)

	if len(got) != 2 || string(got[0].Data) != "wxyz" || string(got[1].Data) != "abcdef" {
		t.Fatalf("got %v", got)
	}
	if !got[1].Truncated() || got[1].Incomplete {
		t.Errorf("want truncated but complete capture: %+v", got[1])
	}
}

func TestAssembleLostTail(t *testing.T) {
	a := newAssembler(testClock)
	now := time.Now()
	first := rawHeader{TimestampNs: 1, Tid: 1, Size: 6, Captured: 6}
	if evs := a.add(mustParse(t, record(first, "abc")), now); len(evs) != 0 {
		t.Fatalf("incomplete call emitted early: %v", evs)
	}

	// The next call on the thread shows the rest of the first was dropped.
	second := rawHeader{TimestampNs: 2, Tid: 1, Size: 2, Captured: 2}
	evs := a.add(mustParse(t, record(second, "xy")), now)
	if len(evs) != 2 || !evs[0].Incomplete || string(evs[0].Data) != "abc" || string(evs[1].Data) != "xy" {
		t.Fatalf("got %+v", evs)
	}

	// Or the call times out.
	if evs := a.add(mustParse(t, record(first, "abc")), now); len(evs) != 0 {
		t.Fatal("emitted early")
	}
	if evs := a.expire(now.Add(time.Second/2), time.Second); len(evs) != 0 {
		t.Fatal("expired too early")
	}
	evs = a.expire(now.Add(2*time.Second), time.Second)
	if len(evs) != 1 || !evs[0].Incomplete {
		t.Fatalf("got %+v", evs)
	}
}

func TestAssembleLostHeadIsDropped(t *testing.T) {
	a := newAssembler(testClock)
	h := rawHeader{TimestampNs: 1, Tid: 1, Size: 6, Captured: 6, ChunkOffset: 3}
	if evs := a.add(mustParse(t, record(h, "def")), time.Now()); len(evs) != 0 {
		t.Fatalf("got %v", evs)
	}
}

func TestAssembleReadError(t *testing.T) {
	a := newAssembler(testClock)
	h := rawHeader{TimestampNs: 1, Tid: 1, Size: 6, Captured: 6, Flags: flagReadError}
	evs := a.add(mustParse(t, record(h, "")), time.Now())
	if len(evs) != 1 || !evs[0].ReadError {
		t.Fatalf("got %+v", evs)
	}
}
