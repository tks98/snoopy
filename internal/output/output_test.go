package output

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"

	"github.com/tks98/snoopy/internal/tracer"
)

func init() {
	color.NoColor = true
}

func event(fn tracer.Function, data string) *tracer.Event {
	return &tracer.Event{
		Time:     time.Date(2026, 1, 2, 3, 4, 5, 6000, time.UTC),
		Latency:  1500 * time.Microsecond,
		Function: fn,
		PID:      42,
		TID:      42,
		Comm:     "curl",
		ConnID:   0xbeef,
		FD:       5,
		Size:     uint32(len(data)),
		Data:     []byte(data),
		Local:    netip.MustParseAddrPort("10.0.0.2:51234"),
		Remote:   netip.MustParseAddrPort("93.184.216.34:443"),
	}
}

func TestIsText(t *testing.T) {
	for in, want := range map[string]bool{
		"":                         true,
		"hello\r\nworld\t!":        true,
		"héllo wörld":              true,
		"caf\xc3":                  true, // rune cut off at the end
		"\x00\x00\x12\x04\x00\x00": false,
		"\xff\xfe\xfd\xfc":         false,
	} {
		if got := isText([]byte(in)); got != want {
			t.Errorf("isText(%q) = %v", in, got)
		}
	}
}

func TestEscapeText(t *testing.T) {
	in := "a\r\nb\x1b[31mc\rd\tz\xff"
	want := "a\nb\\x1b[31mc\\x0dd\tz\\xff"
	if got := escapeText([]byte(in)); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseHTTP1(t *testing.T) {
	m, ok := parseHTTP1([]byte("GET /x HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\nbody"))
	if !ok || m.startLine != "GET /x HTTP/1.1" || len(m.headers) != 2 || m.headers[0] != [2]string{"Host", "example.com"} || string(m.body) != "body" || !m.complete {
		t.Errorf("request: %+v", m)
	}
	m, ok = parseHTTP1([]byte("HTTP/1.1 404 Not Found\r\nContent-Le"))
	if !ok || m.startLine != "HTTP/1.1 404 Not Found" || m.complete {
		t.Errorf("truncated response: %+v", m)
	}
	for _, in := range []string{"hello", "GET / HTTP/2.0\r\n", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} {
		if _, ok := parseHTTP1([]byte(in)); ok {
			t.Errorf("parsed %q as HTTP/1", in)
		}
	}
}

func TestSummarizeHTTP2(t *testing.T) {
	frames := http2Preface +
		"\x00\x00\x06\x04\x00\x00\x00\x00\x00" + "\x00\x03\x00\x00\x00\x64" + // SETTINGS
		"\x00\x00\x02\x01\x05\x00\x00\x00\x01" + "\x82\x84" // HEADERS, END_STREAM|END_HEADERS
	got := strings.Join(summarizeHTTP2([]byte(frames)), "; ")
	want := "connection preface; SETTINGS stream=0 length=6; HEADERS stream=1 length=2 [END_STREAM,END_HEADERS]"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}

	cut := summarizeHTTP2([]byte("\x00\x00\x10\x00\x01\x00\x00\x00\x03abc"))
	if len(cut) != 1 || !strings.HasSuffix(cut[0], "(cut off)") {
		t.Errorf("cut-off frame: %q", cut)
	}
	if got := summarizeHTTP2([]byte("\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6")); got != nil {
		t.Errorf("random bytes: %q", got)
	}
}

func TestTextHTTP(t *testing.T) {
	var buf bytes.Buffer
	ev := event(tracer.FuncSSLWrite, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err := NewText(&buf, false).Print(ev); err != nil {
		t.Fatal(err)
	}
	want := "03:04:05.000006 curl (pid 42) SSL_write → 93.184.216.34:443  37 bytes  1.5ms  fd 5, conn 0xbeef\n" +
		"GET / HTTP/1.1\nHost: example.com\n\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestTextBinaryAndNotes(t *testing.T) {
	var buf bytes.Buffer
	ev := event(tracer.FuncGoRead, "\x00\x01\x02\x03")
	ev.Size = 100
	ev.Remote = netip.AddrPort{}
	ev.FD = -1
	ev.ContainerID = "4b825dc642cb6eb9a060"
	ev.TID = 43
	if err := NewText(&buf, false).Print(ev); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"curl (pid 42, tid 43) crypto/tls.(*Conn).Read ← peer  100 bytes",
		"conn 0xbeef, container 4b825dc642cb",
		"00000000  00 01 02 03",
		"[truncated: captured 4 of 100 bytes; raise with --max-size]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "fd ") {
		t.Errorf("unknown fd printed:\n%s", out)
	}

	buf.Reset()
	NewText(&buf, true).Print(event(tracer.FuncSSLRead, "hi"))
	if !strings.Contains(buf.String(), "00000000  68 69") {
		t.Errorf("--hex didn't hex-dump text:\n%s", buf.String())
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	j := NewJSON(&buf)
	j.Print(event(tracer.FuncSSLWrite, "<html>"))
	bin := event(tracer.FuncGoRead, "\xff\x00")
	bin.FD = -1
	bin.Local, bin.Remote = netip.AddrPort{}, netip.AddrPort{}
	bin.Size = 10
	j.Print(bin)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %q", buf.String())
	}

	var text map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &text); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"function": "SSL_write", "library": "openssl", "direction": "write", "process_name": "curl",
		"pid": 42.0, "fd": 5.0, "conn_id": "0xbeef", "local_addr": "10.0.0.2:51234",
		"remote_addr": "93.184.216.34:443", "latency_ns": 1.5e6, "size": 6.0, "captured": 6.0,
		"data": "<html>", "time": "2026-01-02T03:04:05.000006Z",
	} {
		if text[k] != want {
			t.Errorf("%s = %v, want %v", k, text[k], want)
		}
	}
	if !strings.Contains(lines[0], `"data":"<html>"`) {
		t.Error("HTML was escaped")
	}

	var binary map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &binary); err != nil {
		t.Fatal(err)
	}
	if binary["data_base64"] != "/wA=" || binary["data"] != nil || binary["truncated"] != true {
		t.Errorf("binary event: %v", binary)
	}
	for _, k := range []string{"fd", "local_addr", "remote_addr", "container_id"} {
		if _, ok := binary[k]; ok {
			t.Errorf("%s present for unknown value", k)
		}
	}
}

type packet struct {
	src, dst netip.AddrPort
	seq, ack uint32
	flags    byte
	payload  []byte
}

// readPcap parses what Pcap wrote, checking every checksum.
func readPcap(t *testing.T, b []byte) []packet {
	t.Helper()
	if binary.LittleEndian.Uint32(b) != pcapMagicNanos || binary.LittleEndian.Uint32(b[20:]) != linktypeRaw {
		t.Fatal("bad pcap header")
	}
	var out []packet
	for b = b[24:]; len(b) > 0; {
		n := binary.LittleEndian.Uint32(b[8:])
		pkt := b[16 : 16+n]
		b = b[16+n:]

		var p packet
		var tcp []byte
		switch pkt[0] >> 4 {
		case 4:
			if checksum(pkt[:20], 0) != 0 {
				t.Error("bad IPv4 checksum")
			}
			src, dst := [4]byte(pkt[12:16]), [4]byte(pkt[16:20])
			tcp = pkt[20:]
			pseudo := append(append(append([]byte{}, src[:]...), dst[:]...), 0, 6, byte(len(tcp)>>8), byte(len(tcp)))
			if checksum(tcp, sum16(pseudo)) != 0 {
				t.Error("bad TCP checksum")
			}
			p.src = netip.AddrPortFrom(netip.AddrFrom4(src), binary.BigEndian.Uint16(tcp[0:]))
			p.dst = netip.AddrPortFrom(netip.AddrFrom4(dst), binary.BigEndian.Uint16(tcp[2:]))
		case 6:
			src, dst := [16]byte(pkt[8:24]), [16]byte(pkt[24:40])
			tcp = pkt[40:]
			pseudo := make([]byte, 40)
			copy(pseudo, src[:])
			copy(pseudo[16:], dst[:])
			binary.BigEndian.PutUint32(pseudo[32:], uint32(len(tcp)))
			pseudo[39] = 6
			if checksum(tcp, sum16(pseudo)) != 0 {
				t.Error("bad TCP checksum")
			}
			p.src = netip.AddrPortFrom(netip.AddrFrom16(src), binary.BigEndian.Uint16(tcp[0:]))
			p.dst = netip.AddrPortFrom(netip.AddrFrom16(dst), binary.BigEndian.Uint16(tcp[2:]))
		default:
			t.Fatalf("not an IP packet: %x", pkt[:1])
		}
		p.seq = binary.BigEndian.Uint32(tcp[4:])
		p.ack = binary.BigEndian.Uint32(tcp[8:])
		p.flags = tcp[13]
		p.payload = tcp[20:]
		out = append(out, p)
	}
	return out
}

func TestPcap(t *testing.T) {
	var buf bytes.Buffer
	p, err := NewPcap(&buf)
	if err != nil {
		t.Fatal(err)
	}

	req := event(tracer.FuncSSLWrite, "GET / HTTP/1.1\r\n\r\n")
	resp := event(tracer.FuncSSLRead, "HTTP/1.1 200 OK\r\n\r\n")
	resp.Size = 100 // only part of it was captured
	next := event(tracer.FuncSSLWrite, "GET /2 HTTP/1.1\r\n\r\n")
	// The server's view of the same connection, traced too: skipped.
	server := event(tracer.FuncSSLRead, "GET / HTTP/1.1\r\n\r\n")
	server.PID, server.ConnID = 7, 0x1234
	server.Local, server.Remote = req.Remote, req.Local
	// A connection without known addresses gets synthetic ones.
	anon := event(tracer.FuncGoWrite, "hello")
	anon.Local, anon.Remote = netip.AddrPort{}, netip.AddrPort{}

	for _, ev := range []*tracer.Event{req, server, resp, next, anon} {
		if err := p.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	pkts := readPcap(t, buf.Bytes())
	// 3 handshake + 3 data + FIN for the real connection, 3 + 1 + FIN for the anonymous one.
	if len(pkts) != 12 {
		t.Fatalf("got %d packets", len(pkts))
	}
	local, remote := req.Local, req.Remote
	syn, synack, ack := pkts[0], pkts[1], pkts[2]
	if syn.flags != tcpSYN || syn.src != local || synack.flags != tcpSYN|tcpACK || synack.src != remote || ack.ack != synack.seq+1 {
		t.Fatalf("bad handshake: %+v", pkts[:3])
	}

	get, ok, get2 := pkts[3], pkts[4], pkts[5]
	if get.src != local || get.dst != remote || string(get.payload) != string(req.Data) || get.seq != syn.seq+1 {
		t.Errorf("request packet: %+v", get)
	}
	if ok.src != remote || string(ok.payload) != string(resp.Data) || ok.seq != synack.seq+1 {
		t.Errorf("response packet: %+v", ok)
	}
	if get2.seq != get.seq+uint32(len(req.Data)) || get2.ack != ok.seq+100 {
		t.Errorf("sequence numbers don't account for uncaptured bytes: %+v", get2)
	}

	anonData := pkts[9]
	if anonData.src.Addr() != netip.MustParseAddr("127.0.0.1") || anonData.dst != netip.MustParseAddrPort("127.0.0.2:443") || string(anonData.payload) != "hello" {
		t.Errorf("anonymous connection: %+v", anonData)
	}
	fins := 0
	for _, pkt := range pkts {
		if pkt.flags&tcpFIN != 0 {
			fins++
		}
	}
	if fins != 2 {
		t.Errorf("%d FINs", fins)
	}
}

func TestPcapIPv6AndLargePayload(t *testing.T) {
	var buf bytes.Buffer
	p, _ := NewPcap(&buf)
	ev := event(tracer.FuncSSLRead, strings.Repeat("x", 3*maxSegment+10))
	ev.Local = netip.MustParseAddrPort("[2001:db8::2]:51234")
	ev.Remote = netip.MustParseAddrPort("[2001:db8::1]:443")
	p.Print(ev)
	p.Close()

	pkts := readPcap(t, buf.Bytes())
	var payload int
	for _, pkt := range pkts[3:] {
		if pkt.src != ev.Remote && len(pkt.payload) > 0 {
			t.Errorf("data from wrong side: %+v", pkt.src)
		}
		payload += len(pkt.payload)
	}
	if len(pkts) != 3+4+1 || payload != len(ev.Data) {
		t.Errorf("got %d packets with %d bytes", len(pkts), payload)
	}
}
