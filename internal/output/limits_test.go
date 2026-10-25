package output

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// Tests that what peers send can't make the decoders hold or produce
// without bound: each sends what real traffic never does, and checks that
// the limit holds and the output says what was left out.

// allocated returns the bytes f allocates.
func allocated(f func()) uint64 {
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	f()
	runtime.ReadMemStats(&m1)
	return m1.TotalAlloc - m0.TotalAlloc
}

func TestManyContentCodings(t *testing.T) {
	g0 := runtime.NumGoroutine()
	pool := newBodyPool()
	dec := pool.start(strings.Repeat("br,", 20000))
	if len(dec.stages) != 0 || runtime.NumGoroutine() > g0+1 {
		t.Fatalf("%d stages, %d goroutines started", len(dec.stages), runtime.NumGoroutine()-g0)
	}
	if err := dec.failed(); err == nil || !strings.Contains(err.Error(), "20000 content codings") {
		t.Errorf("error %v", err)
	}
	if len(pool.live) != 0 {
		t.Errorf("%d bodies live", len(pool.live))
	}
	// As many as are undone still are.
	codings := strings.TrimSuffix(strings.Repeat("gzip,", maxContentCodings), ",")
	body := encode(t, []byte("hello"), codings)
	dec = pool.start(codings)
	out := append(dec.write(body), dec.end()...)
	if string(out) != "hello" || dec.failed() != nil {
		t.Errorf("%d codings: %q, %v", maxContentCodings, out, dec.failed())
	}
}

// http2Bomb returns two header blocks, the first adding an entry of about
// size bytes to the dynamic table, the second referring to it n times.
func http2Bomb(table uint32, size, n int) (first, second []byte) {
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	enc.SetMaxDynamicTableSizeLimit(table)
	enc.SetMaxDynamicTableSize(table)
	f := hpack.HeaderField{Name: "x", Value: strings.Repeat("v", size)}
	_ = enc.WriteField(f)
	first = bytes.Clone(b.Bytes())
	b.Reset()
	for range n {
		_ = enc.WriteField(f)
	}
	return first, b.Bytes()
}

func TestHTTP2HeaderListLimit(t *testing.T) {
	first, second := http2Bomb(maxHPACKTable, maxHPACKTable-100, 300)
	if len(second) != 300 {
		t.Fatalf("second block of %d bytes", len(second))
	}
	c := newHTTP2Conns(newBodyPool())
	var data []byte
	data = append(data, http2.ClientPreface...)
	data = append(data, h2Frame(1, 5, 1, first)...)
	if _, ok, note := c.process(h2Event(data)); !ok || note != "" {
		t.Fatalf("first block: %v %q", ok, note)
	}
	var frames []http2Frame
	var note string
	n := allocated(func() { frames, _, note = c.process(h2Event(h2Frame(1, 5, 3, second))) })
	size := 0
	for _, f := range frames {
		for _, h := range f.Headers {
			size += int(h.Size())
		}
	}
	if size == 0 || size > maxHeaderList {
		t.Errorf("headers of %d bytes", size)
	}
	if !strings.Contains(note, "the rest of its fields aren't shown") {
		t.Errorf("note %q", note)
	}
	if n > 16<<20 {
		t.Errorf("allocated %d MiB", n>>20)
	}
	// The connection goes on.
	frames, ok, note := c.process(h2Event(h2Frame(1, 5, 5, first)))
	if !ok || note != "" || len(frames) != 1 || len(frames[0].Headers) != 1 {
		t.Errorf("after: %v %q %+v", ok, note, frames)
	}

	// A table larger than browsers allow isn't followed.
	first, _ = http2Bomb(1<<20, 1<<19, 0)
	c = newHTTP2Conns(newBodyPool())
	data = append([]byte(http2.ClientPreface), h2Frame(1, 5, 1, first)...)
	if _, _, note := c.process(h2Event(data)); !strings.Contains(note, "HTTP/2 decoding stopped") {
		t.Errorf("1 MiB table: note %q", note)
	}
}

func h2Frame(typ, flags byte, stream uint32, payload []byte) []byte {
	h := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags,
		byte(stream >> 24), byte(stream >> 16), byte(stream >> 8), byte(stream)}
	return append(h, payload...)
}

func h2Event(data []byte) *tracer.Event {
	return &tracer.Event{PID: 7, ConnID: 1, Function: tracer.FuncSSLWrite, Size: uint32(len(data)), Data: data}
}

func TestHTTP2ContinuationLimit(t *testing.T) {
	c := newHTTP2Conns(newBodyPool())
	c.process(h2Event(append([]byte(http2.ClientPreface), h2Frame(1, 0, 1, []byte{0x82})...)))
	var many []byte
	for range 16 {
		many = append(many, h2Frame(9, 0, 1, make([]byte, 16000))...)
	}
	var note string
	for i := 0; i < 8 && note == ""; i++ {
		_, _, note = c.process(h2Event(many))
	}
	if !strings.Contains(note, "header block of more than") {
		t.Errorf("note %q", note)
	}
	if d := &c.conns[http2Key{7, 1}].dirs[tracer.Write]; len(d.block) > maxHTTP2Pending {
		t.Errorf("block of %d bytes", len(d.block))
	}
}

func TestHTTP2BodiesBounded(t *testing.T) {
	w := newHTTP2Writer(true)
	for i := range 3000 {
		w.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: uint32(2*i + 1), EndHeaders: true,
			BlockFragment: w.block(":method", "POST", ":path", "/", "content-encoding", "gzip")})
	}
	c := newHTTP2Conns(newBodyPool())
	if _, ok, note := c.process(h2Event(w.buf.Bytes())); !ok || note != "" {
		t.Fatalf("%v %q", ok, note)
	}
	if d := &c.conns[http2Key{7, 1}].dirs[tracer.Write]; len(d.bodies) > maxBodyInfos {
		t.Errorf("%d bodies kept", len(d.bodies))
	}
}

func TestGRPCZstdLimits(t *testing.T) {
	// A frame whose header asks for a 4 GiB window.
	hostile := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xb0, 0x29, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o'}
	var err error
	if n := allocated(func() { _, err = decompressGRPC("zstd", hostile) }); err == nil || n > 16<<20 {
		t.Errorf("4 GiB window: %v, allocated %d MiB", err, n>>20)
	}
	enc, _ := zstd.NewWriter(nil)
	out, err := decompressGRPC("zstd", enc.EncodeAll([]byte("hello"), nil))
	if string(out) != "hello" || err != nil {
		t.Errorf("%q, %v", out, err)
	}
	_, err = decompressGRPC("zstd", enc.EncodeAll(make([]byte, maxGRPCMessage+1), nil))
	if err == nil || !strings.Contains(err.Error(), "bytes decompressed, not decoded") {
		t.Errorf("too large: %v", err)
	}
}
