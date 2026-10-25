package output

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// Fuzz tests for the decoders, which take whatever the traced programs send.
// go test runs their seeds; go test -fuzz FuzzX runs one for longer. Each
// checks that nothing panics or hangs, and that the limits in limits_test.go
// hold.

// fzEvents splits fuzz input into events, each a control byte, a 2-byte
// little-endian length and that much data. The control byte's bit 0 makes
// it a write, bit 1 a call with bytes missing (Size larger than the data),
// bits 2-3 pick one of four connections, bit 4 makes it a TLS record
// function (whose connection is its socket) and, for QUIC, bit 5 takes a
// header from the start of the data.
func fzEvents(b []byte, quic bool) []*tracer.Event {
	var evs []*tracer.Event
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for len(b) >= 3 && len(evs) < 4096 {
		ctl := b[0]
		n := min(int(binary.LittleEndian.Uint16(b[1:3])), len(b)-3)
		data := b[3 : 3+n]
		b = b[3+n:]
		write := ctl&1 != 0
		var fn tracer.Function
		switch {
		case quic && write:
			fn = tracer.FuncQUICSend
		case quic:
			fn = tracer.FuncQUICRecv
		case ctl&0x10 != 0 && write:
			fn = tracer.FuncRecordSend
		case ctl&0x10 != 0:
			fn = tracer.FuncRecordRecv
		case write:
			fn = tracer.FuncSSLWrite
		default:
			fn = tracer.FuncSSLRead
		}
		ev := &tracer.Event{Time: t0.Add(time.Duration(len(evs)) * time.Millisecond), Function: fn, PID: 7, TID: 7,
			Comm: "x", ConnID: 0x100 + uint64(ctl>>2&3), FD: int32(5 + ctl>>2&3), Size: uint32(n), Data: data,
			Local: netip.MustParseAddrPort("10.0.0.2:5000"), Remote: netip.MustParseAddrPort("10.0.0.3:443")}
		if ctl&2 != 0 {
			ev.Size += 1000
		}
		if quic && ctl&0x20 != 0 && n > 0 {
			k := min(int(data[0])%48, n-1)
			ev.QUICHeader, ev.Data = data[1:1+k], data[1+k:]
			ev.Size = uint32(len(ev.Data))
		}
		evs = append(evs, ev)
	}
	return evs
}

// fzRec encodes one event for fzEvents.
func fzRec(ctl byte, data []byte) []byte {
	return append([]byte{ctl, byte(len(data)), byte(len(data) >> 8)}, data...)
}

// fzRun prints events with each printer, with the options that take
// different paths.
func fzRun(evs []*tracer.Event) {
	filter := &HTTPFilter{Methods: []string{"GET", "POST"}, Status: []StatusRange{{200, 599}}}
	har := NewHAR(io.Discard, "fuzz", Options{Redact: true})
	ps := []Printer{
		NewText(io.Discard, Options{Full: true, Verbose: true, Redact: true}),
		NewText(io.Discard, Options{Hex: true, Filter: filter, Warn: func(string) {}}),
		NewJSON(io.Discard, Options{Redact: true, Filter: filter}),
		NewBrief(io.Discard, Options{Verbose: true}),
		har,
	}
	for _, ev := range evs {
		for _, p := range ps {
			e := *ev
			e.Data = bytes.Clone(ev.Data)
			_ = p.Print(&e)
		}
	}
	_ = har.Close()
}

func fzGzip(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

func fzHPACK(fields ...string) []byte {
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	for i := 0; i+1 < len(fields); i += 2 {
		_ = enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
	}
	return b.Bytes()
}

// FuzzTLSStream decodes HTTP/1 and HTTP/2 in TLS plaintext.
func FuzzTLSStream(f *testing.F) {
	f.Add(cat(fzRec(1, []byte("GET /a?token=x HTTP/1.1\r\nHost: h\r\nCookie: a=b\r\n\r\n")),
		fzRec(0, cat([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 31\r\n\r\n"),
			fzGzip(`hello {"password":"x"}`)))))
	f.Add(cat(fzRec(1, []byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")),
		fzRec(0, []byte("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"+
			"Content-Encoding: br, gzip\r\n\r\n3\r\nabc\r\n0\r\n\r\n"))))
	// HTTP/2: a gRPC call, and a response with a padded, encoded body.
	c2s := cat([]byte(http2Preface), h2Frame(4, 0, 0, nil),
		h2Frame(1, 4, 1, fzHPACK(":method", "POST", ":path", "/svc/M", "content-type", "application/grpc", "grpc-encoding", "gzip")),
		h2Frame(0, 1, 1, []byte{0, 0, 0, 0, 5, 0x0a, 0x03, 'a', 'b', 'c'}))
	s2c := cat(h2Frame(4, 0, 0, nil),
		h2Frame(1, 0, 1, fzHPACK(":status", "200", "content-encoding", "gzip", "content-type", "text/plain")),
		h2Frame(9, 4, 1, nil),
		h2Frame(0, 9, 1, cat([]byte{2}, fzGzip("body"), []byte{0, 0})),
		h2Frame(1, 5, 3, fzHPACK("grpc-status", "0")))
	f.Add(cat(fzRec(1, c2s), fzRec(0, s2c)))
	f.Fuzz(func(t *testing.T, b []byte) {
		fzRun(fzEvents(b, false))
	})
}

// FuzzQUICStream decodes HTTP/3 in QUIC packets.
func FuzzQUICStream(f *testing.F) {
	// The client's control stream with SETTINGS, its encoder stream with an
	// insertion, and a request; the server's control stream and a response
	// with an encoded body, then NEW_CONNECTION_ID and CONNECTION_CLOSE.
	settings := cat(quicVar(0), h3Frame(4, cat(quicVar(1), quicVar(4096))))
	enc := []byte{2, 0x3f, 0xe1, 0x1f, 0x4a, 'x', '-', 't', 'o', 'k', 'e', 'n', 0x03, 'a', 'b', 'c'}
	request := cat([]byte{0x01, 0x02, 0x05, 0x00, 0x00, 0x00}, // PING, ACK
		streamFrameBytes(2, 0, settings, false),
		streamFrameBytes(6, 0, enc, false),
		streamFrameBytes(0, 0, h3Frame(1, []byte{0, 0, 0xd1, 0xd7, 0x51, 0x01, '/'}), true))
	response := cat(streamFrameBytes(3, 0, cat(quicVar(0), h3Frame(4, nil)), false),
		streamFrameBytes(0, 0, cat(h3Frame(1, []byte{0, 0, 0xd9, 0x5f, 0x1d, 0x04, 'g', 'z', 'i', 'p'}), h3Frame(0, fzGzip("hi"))), true),
		[]byte{0x18, 0x01, 0x00, 0x04, 1, 2, 3, 4}, make([]byte, 16),
		[]byte{0x1c, 0x00, 0x00, 0x02, 'o', 'k'})
	f.Add(cat(fzRec(1, request), fzRec(0, response)))
	f.Fuzz(func(t *testing.T, b []byte) {
		fzRun(fzEvents(b, true))
	})
}

// FuzzQPACK decodes an encoder stream and a field section.
func FuzzQPACK(f *testing.F) {
	f.Add([]byte{0x3f, 0xe1, 0x1f, 0x4a, 'x', '-', 't', 'o', 'k', 'e', 'n', 0x03, 'a', 'b', 'c', 0x00}, []byte{0x02, 0x00, 0x80, 0xd1, 0x10})
	f.Fuzz(func(t *testing.T, enc, section []byte) {
		var d qpackDecoder
		if len(enc) > 0 && enc[0]&1 != 0 { // the receiver's maximum is known
			d.maxEntries, d.maxCapacity, d.maxKnown = int(enc[0]), int64(enc[0])*32, true
		}
		for range 3 {
			_ = d.encoderStream(enc)
			fields, _ := d.fieldSection(section)
			size := 0
			for _, f := range fields {
				size += int(f.Size())
			}
			if size > maxHeaderList {
				t.Fatalf("fields of %d bytes", size)
			}
		}
		if d.capacity > maxQPACKCapacity || len(d.pending) > maxQPACKInstruction+3*len(enc) {
			t.Fatalf("capacity %d, %d bytes pending", d.capacity, len(d.pending))
		}
	})
}

// FuzzProtobuf decodes gRPC messages, compressed or not.
func FuzzProtobuf(f *testing.F) {
	f.Add([]byte{0x0a, 0x03, 'a', 'b', 'c', 0x10, 0x96, 0x01, 0x1a, 0x02, 0x08, 0x01}, byte(0))
	f.Add(cat([]byte{1, 0, 0, 0, 0}, fzGzip("\x08\x01")), byte(1))
	f.Fuzz(func(t *testing.T, b []byte, mode byte) {
		decodeProtobuf(b, 0)
		s := &grpcStream{encoding: []string{"", "gzip", "deflate", "zstd", "identity"}[int(mode)%5]}
		if len(b) >= 5 {
			binary.BigEndian.PutUint32(b[1:5], uint32(len(b)-5))
		}
		for i := 0; i < len(b); i += 7 {
			s.add(b[i:min(i+7, len(b))])
		}
	})
}

// FuzzBody undoes content codings on a body arriving in pieces.
func FuzzBody(f *testing.F) {
	f.Add("gzip", fzGzip("hello"), uint8(3))
	f.Add("br", []byte{0x0b, 0x02, 0x80, 'h', 'i', 0x03}, uint8(1))
	f.Add("zstd", []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x48, 0x11, 0x00, 0x00, 'h', 'i'}, uint8(2))
	f.Add("deflate", []byte{0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01}, uint8(5))
	f.Add("gzip, br, gzip, zstd, deflate", []byte("x"), uint8(1))
	f.Fuzz(func(t *testing.T, enc string, body []byte, step uint8) {
		pool := newBodyPool()
		dec := pool.start(enc)
		if dec == nil {
			return
		}
		if len(dec.stages) > maxContentCodings {
			t.Fatalf("%d stages", len(dec.stages))
		}
		st := int(step)%64 + 1
		total := 0
		for i := 0; i < len(body); i += st {
			total += len(dec.write(body[i:min(i+st, len(body))]))
		}
		total += len(dec.end())
		if total > maxDecodedBody || len(pool.live) != 0 {
			t.Fatalf("decoded %d bytes, %d bodies live", total, len(pool.live))
		}
	})
}
