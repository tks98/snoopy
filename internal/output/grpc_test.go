package output

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// protobuf builders: a field's key, then its value.
func protoVarint(field, v uint64) []byte {
	return binary.AppendUvarint(binary.AppendUvarint(nil, field<<3), v)
}

func protoBytes(field uint64, b []byte) []byte {
	out := binary.AppendUvarint(binary.AppendUvarint(nil, field<<3|2), uint64(len(b)))
	return append(out, b...)
}

func protoFixed32(field uint64, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(binary.AppendUvarint(nil, field<<3|5), v)
}

// grpcFrame frames a gRPC message.
func grpcFrame(compressed bool, msg []byte) []byte {
	out := []byte{0, 0, 0, 0, 0}
	if compressed {
		out[0] = 1
	}
	binary.BigEndian.PutUint32(out[1:], uint32(len(msg)))
	return append(out, msg...)
}

func TestDecodeProtobuf(t *testing.T) {
	msg := cat(protoVarint(1, 150), protoBytes(2, []byte("testing")),
		protoBytes(3, protoVarint(1, 1)),        // a nested message
		protoFixed32(4, 0x3fc00000),             // 1.5 as a float
		protoBytes(5, []byte{0x00, 0xff, 0x10})) // bytes
	got, ok := decodeProtobuf(msg, 0)
	want := []string{"1: 150", `2: "testing"`, "3 {", "  1: 1", "}", "4: 0x3fc00000 (1.5 as a float)", `5: "\x00\xff\x10"`}
	if !ok || !slices.Equal(got, want) {
		t.Errorf("got %q, %v", got, ok)
	}
	for _, b := range [][]byte{{0xff, 0xff}, {0x0a, 0x05, 'a'}, {0x00, 0x01}, {0x0b}} { // bad varint, short, field 0, group
		if _, ok := decodeProtobuf(b, 0); ok {
			t.Errorf("% x taken for protobuf", b)
		}
	}
}

func TestGRPCStream(t *testing.T) {
	s := &grpcStream{encoding: "gzip"}
	one := grpcFrame(false, protoBytes(1, []byte("world")))
	// A message across three pieces, the prefix itself split.
	if got := s.add(one[:3]); len(got) != 0 {
		t.Fatalf("early: %+v", got)
	}
	if got := s.add(one[3:8]); len(got) != 0 {
		t.Fatalf("early: %+v", got)
	}
	got := s.add(one[8:])
	if len(got) != 1 || !slices.Equal(got[0].Fields, []string{`1: "world"`}) {
		t.Fatalf("got %+v", got)
	}

	// Two at once, the second compressed.
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write(protoVarint(2, 7))
	zw.Close()
	got = s.add(cat(grpcFrame(false, nil), grpcFrame(true, z.Bytes())))
	if len(got) != 2 || len(got[0].Fields) != 0 || got[0].Err != "" || !got[1].Compressed || !slices.Equal(got[1].Fields, []string{"2: 7"}) {
		t.Fatalf("got %+v", got)
	}

	// One too large to decode is skipped, and the next one still found.
	big := make([]byte, 5)
	binary.BigEndian.PutUint32(big[1:], maxGRPCMessage+1)
	got = s.add(big)
	if len(got) != 1 || !strings.Contains(got[0].Err, "not decoded") {
		t.Fatalf("got %+v", got)
	}
	s.add(make([]byte, maxGRPCMessage+1))
	if got = s.add(one); len(got) != 1 || len(got[0].Fields) != 1 {
		t.Errorf("after skipping: %+v", got)
	}
}

// A unary call, its request split across DATA frames and events, as the
// text, brief and JSON output show it.
func TestGRPCCall(t *testing.T) {
	client := newHTTP2Writer(true)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: client.block(
		":method", "POST", ":path", "/helloworld.Greeter/SayHello", ":authority", "localhost", "content-type", "application/grpc")})
	request := grpcFrame(false, protoBytes(1, []byte("world")))
	client.fr.WriteData(1, false, request[:4])
	client.fr.WriteData(1, true, request[4:])
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: server.block(
		":status", "200", "content-type", "application/grpc")})
	server.fr.WriteData(1, false, grpcFrame(false, cat(protoBytes(1, []byte("Hello world")), protoVarint(2, 3))))
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: true, BlockFragment: server.block(
		"grpc-status", "0")})
	calls := append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 60, 20), events(tracer.FuncSSLRead, server.buf.Bytes(), 1<<20)...)

	var text, brief, js bytes.Buffer
	for _, p := range []Printer{NewText(&text, Options{}), NewBrief(&brief, Options{}), NewJSON(&js, Options{})} {
		for _, ev := range calls {
			if err := p.Print(ev); err != nil {
				t.Fatal(err)
			}
		}
	}
	for out, wants := range map[*bytes.Buffer][]string{
		&text:  {"gRPC message, 7 bytes", `1: "world"`, `1: "Hello world"`, "2: 3", "grpc-status: 0 (OK)"},
		&brief: {"POST localhost/helloworld.Greeter/SayHello", "DATA s1 gRPC 1 message", "grpc-status 0 OK"},
		&js:    {`"grpc_messages":[{"bytes":7,"protobuf":["1: \"world\""]}]`},
	} {
		for _, want := range wants {
			if !strings.Contains(out.String(), want) {
				t.Errorf("no %q in:\n%s", want, out.String())
			}
		}
	}
}
