package output

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2"

	"os"
	"path/filepath"

	"github.com/tks98/snoopy/v2/internal/tracer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
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
		&text: {"gRPC request /helloworld.Greeter/SayHello, 7 bytes", `1: "world"`,
			"gRPC response /helloworld.Greeter/SayHello, 15 bytes", `1: "Hello world"`, "2: 3", "grpc-status: 0 (OK)"},
		&brief: {"POST localhost/helloworld.Greeter/SayHello", "DATA s1 gRPC request /helloworld.Greeter/SayHello",
			"DATA s1 gRPC response /helloworld.Greeter/SayHello", "grpc-status 0 OK"},
		&js: {`"grpc_messages":[{"method":"/helloworld.Greeter/SayHello","request":true,"bytes":7,"protobuf":["1: \"world\""]}]`},
	} {
		for _, want := range wants {
			if !strings.Contains(out.String(), want) {
				t.Errorf("no %q in:\n%s", want, out.String())
			}
		}
	}
}

// helloworldSchema writes a descriptor set for helloworld.Greeter, as
// protoc --descriptor_set_out would, and returns its path.
func helloworldSchema(t *testing.T) string {
	t.Helper()
	str, i32 := descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_TYPE_INT32
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	field := func(name string, n int32, typ descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(n), Type: typ.Enum(), Label: opt.Enum(),
			JsonName: proto.String(name)}
	}
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name: proto.String("helloworld.proto"), Package: proto.String("helloworld"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("HelloRequest"), Field: []*descriptorpb.FieldDescriptorProto{field("name", 1, str)}},
			{Name: proto.String("HelloReply"), Field: []*descriptorpb.FieldDescriptorProto{field("message", 1, str), field("count", 2, i32)}},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Greeter"), Method: []*descriptorpb.MethodDescriptorProto{{
			Name: proto.String("SayHello"), InputType: proto.String(".helloworld.HelloRequest"), OutputType: proto.String(".helloworld.HelloReply"),
		}}}},
	}}}
	data, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "helloworld.binpb")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// With --proto, messages are shown with their fields' names, and their
// types; methods the schemas don't have, as without.
func TestGRPCWithSchema(t *testing.T) {
	schemas, err := LoadProtoSchemas([]string{helloworldSchema(t)})
	if err != nil {
		t.Fatal(err)
	}
	if schemas.Methods() != 1 {
		t.Errorf("%d methods", schemas.Methods())
	}
	call := func(path string) []*tracer.Event {
		client := newHTTP2Writer(true)
		client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: client.block(
			":method", "POST", ":path", path, ":authority", "localhost", "content-type", "application/grpc")})
		client.fr.WriteData(1, true, grpcFrame(false, protoBytes(1, []byte("world"))))
		server := newHTTP2Writer(false)
		server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: server.block(
			":status", "200", "content-type", "application/grpc")})
		server.fr.WriteData(1, false, grpcFrame(false, cat(protoBytes(1, []byte("Hello world")), protoVarint(2, 3))))
		return append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, server.buf.Bytes(), 1<<20)...)
	}
	for path, wants := range map[string][]string{
		"/helloworld.Greeter/SayHello": {
			"gRPC request /helloworld.Greeter/SayHello (helloworld.HelloRequest), 7 bytes", `name: "world"`,
			"gRPC response /helloworld.Greeter/SayHello (helloworld.HelloReply), 15 bytes", `message: "Hello world"`, "count: 3"},
		"/helloworld.Greeter/Unknown": {"gRPC request /helloworld.Greeter/Unknown, 7 bytes", `1: "world"`},
	} {
		var text bytes.Buffer
		p := NewText(&text, Options{Proto: schemas})
		for _, ev := range call(path) {
			if err := p.Print(ev); err != nil {
				t.Fatal(err)
			}
		}
		for _, want := range wants {
			if !strings.Contains(text.String(), want) {
				t.Errorf("%s: no %q in:\n%s", path, want, text.String())
			}
		}
	}

	// What isn't a descriptor set says what to make one with.
	junk := filepath.Join(t.TempDir(), "x.proto")
	os.WriteFile(junk, []byte("syntax = \"proto3\";"), 0o644)
	if _, err := LoadProtoSchemas([]string{junk}); err == nil || !strings.Contains(err.Error(), "descriptor_set_out") {
		t.Errorf("got %v", err)
	}
}
