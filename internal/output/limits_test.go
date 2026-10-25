package output

import (
	"runtime"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
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
