package output

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
	"time"

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

// qpackInsert returns an encoder instruction inserting a literal name and
// value.
func qpackInsert(name, value string) []byte {
	b := qpackPrefixInt(0x40, 5, uint64(len(name)))
	b = append(b, name...)
	b = append(b, qpackPrefixInt(0, 7, uint64(len(value)))...)
	return append(b, value...)
}

// qpackPrefixInt encodes v as a prefixed integer, first holding the bits
// above the prefix.
func qpackPrefixInt(first byte, bits uint, v uint64) []byte {
	limit := uint64(1)<<bits - 1
	if v < limit {
		return []byte{first | byte(v)}
	}
	b := []byte{first | byte(limit)}
	for v -= limit; v >= 128; v >>= 7 {
		b = append(b, byte(v)|0x80)
	}
	return append(b, byte(v))
}

func TestQPACKLimits(t *testing.T) {
	setCapacity := func(c uint64) []byte { return qpackPrefixInt(0x20, 5, c) }
	d := qpackDecoder{maxCapacity: 4096, maxKnown: true}
	if err := d.encoderStream(setCapacity(8192)); err == nil {
		t.Error("capacity above the advertised maximum accepted")
	}
	d = qpackDecoder{}
	if err := d.encoderStream(setCapacity(1 << 32)); err == nil {
		t.Error("4 GiB capacity accepted")
	}
	// Duplicates fill the table but no more.
	d = qpackDecoder{}
	if err := d.encoderStream(append(setCapacity(maxQPACKCapacity), qpackInsert("x-token", "v")...)); err != nil {
		t.Fatal(err)
	}
	if err := d.encoderStream(make([]byte, 1<<20)); err != nil { // Duplicate the newest entry
		t.Fatal(err)
	}
	if len(d.entries) > maxQPACKCapacity/32 {
		t.Errorf("%d entries", len(d.entries))
	}
	// An instruction that never ends.
	d = qpackDecoder{}
	d.encoderStream(setCapacity(maxQPACKCapacity))
	var err error
	for i := 0; i < 64 && err == nil; i++ {
		err = d.encoderStream(append(qpackPrefixInt(0x40, 5, 1<<35), make([]byte, 64<<10)...))
	}
	if err == nil || len(d.pending) > maxQPACKInstruction+64<<10 {
		t.Errorf("%v, %d bytes pending", err, len(d.pending))
	}
}

func TestQPACKHeaderListLimit(t *testing.T) {
	d := newQUICDir(newBodyPool())
	enc := append([]byte{0x02}, qpackPrefixInt(0x20, 5, maxQPACKCapacity)...) // encoder stream
	enc = append(enc, qpackInsert("x", strings.Repeat("v", maxQPACKCapacity-100))...)
	d.streamData(streamFrame{id: 2, data: enc})
	section := append([]byte{0x02, 0x00}, bytes.Repeat([]byte{0x80}, 300)...) // the entry, 300 times
	items := d.streamData(streamFrame{id: 0, data: h3Frame(1, section), fin: true})
	size, cut := 0, false
	for _, it := range items {
		for _, h := range it.Headers {
			size += int(h.Size())
		}
		cut = cut || strings.Contains(it.Err, "the rest of its fields aren't shown")
	}
	if size == 0 || size > maxHeaderList || !cut {
		t.Errorf("headers of %d bytes, cut %v: %+v", size, cut, items)
	}
}

func TestQUICReassembly(t *testing.T) {
	// A DATA frame of n bytes, its first byte last and the others in
	// reverse order: each piece is out of order until the first comes.
	const n = 15000
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i)
	}
	frame := h3Frame(0, payload)
	head := len(frame) - n
	d := newQUICDir(newBodyPool())
	for i := len(frame) - 1; i >= head; i-- {
		if items := d.streamData(streamFrame{id: 0, offset: uint64(i), data: frame[i : i+1]}); items != nil {
			t.Fatalf("at %d: %+v", i, items)
		}
	}
	start := time.Now()
	items := d.streamData(streamFrame{id: 0, data: frame[:head], fin: true})
	if took := time.Since(start); took > time.Second {
		t.Errorf("reassembly took %v", took)
	}
	var got []byte
	for _, it := range items {
		got = append(got, it.Data...)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("reassembled %d bytes, not the %d sent", len(got), n)
	}

	// Empty frames ahead are kept as nothing.
	d = newQUICDir(newBodyPool())
	for i := range 100000 {
		d.streamData(streamFrame{id: 4, offset: uint64(10 + i)})
	}
	if s := d.streams[4]; len(s.early) != 0 || s.pending != 0 {
		t.Errorf("%d empty pieces kept", len(s.early))
	}
}

func TestQUICStreamsBounded(t *testing.T) {
	// Finished streams are forgotten, and their retransmissions ignored.
	d := newQUICDir(newBodyPool())
	for i := range 100000 {
		d.streamData(streamFrame{id: uint64(4 * i), data: h3Frame(7, nil), fin: true})
	}
	if len(d.streams) != 0 || len(d.done.ids) > maxQUICDone {
		t.Errorf("%d streams, %d done kept", len(d.streams), len(d.done.ids))
	}
	if items := d.streamData(streamFrame{id: 0, data: h3Frame(7, nil), fin: true}); items != nil {
		t.Errorf("retransmission: %+v", items)
	}
	// Streams left open are given up on, oldest first, but not the
	// control and QPACK streams.
	d = newQUICDir(newBodyPool())
	d.streamData(streamFrame{id: 2, data: []byte{0x00}})
	var given int
	for i := range 1000 {
		for _, it := range d.streamData(streamFrame{id: uint64(4 * i), data: h3Frame(1, nil)[:1]}) {
			if it.HTTP3 == "(stream given up)" {
				given++
			}
		}
	}
	if len(d.streams) > maxQUICStreams || given == 0 || d.streams[2] == nil || d.streams[4*999] == nil {
		t.Errorf("%d streams, %d given up", len(d.streams), given)
	}
	// Out-of-order data is bounded per direction, not just per stream.
	d = newQUICDir(newBodyPool())
	chunk := make([]byte, 1200)
	given = 0
	h0 := heapInUse()
	for s := range 300 {
		for off := 0; off < maxQUICStreamEarly*7/8; off += len(chunk) {
			if d.streamData(streamFrame{id: uint64(4 * s), offset: uint64(1 + off), data: chunk}) != nil {
				given++
			}
		}
	}
	if h := heapInUse(); d.held > maxQUICDirHeld || h > h0+3*maxQUICDirHeld || given != 300-4 {
		t.Errorf("%d bytes held, heap grew %d MiB, %d streams given up", d.held, (h-h0)>>20, given)
	}
	runtime.KeepAlive(d)
}

func heapInUse() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

func TestQUICBlockedBounded(t *testing.T) {
	d := newQUICDir(newBodyPool())
	d.startSeen = true
	section := append([]byte{0x05, 0x00}, make([]byte, 100<<10)...) // needs entries never inserted
	for i := range 64 {
		d.streamData(streamFrame{id: uint64(4 * i), data: h3Frame(1, section)})
	}
	if d.blockedBytes > maxBlockedBytes || len(d.blocked) == 0 {
		t.Errorf("%d blocked sections of %d bytes", len(d.blocked), d.blockedBytes)
	}
}
