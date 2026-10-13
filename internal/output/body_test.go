package output

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"math/rand"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// encode applies the codings of a Content-Encoding value, in order.
func encode(t *testing.T, data []byte, contentEncoding string) []byte {
	t.Helper()
	for _, c := range strings.Split(contentEncoding, ",") {
		var buf bytes.Buffer
		var w io.WriteCloser
		switch strings.TrimSpace(c) {
		case "gzip":
			w = gzip.NewWriter(&buf)
		case "deflate":
			w = zlib.NewWriter(&buf)
		case "raw-deflate":
			w, _ = flate.NewWriter(&buf, flate.DefaultCompression)
		case "br":
			w = brotli.NewWriter(&buf)
		case "zstd":
			w, _ = zstd.NewWriter(&buf)
		default:
			t.Fatalf("no encoder for %q", c)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		data = buf.Bytes()
	}
	return data
}

// testBody is varied text that compresses, but not to nothing.
func testBody(n int) []byte {
	r := rand.New(rand.NewSource(1))
	words := strings.Fields("the quick brown fox jumps over a lazy dog while snoopy watches TLS and QUIC go by")
	var b bytes.Buffer
	for b.Len() < n {
		b.WriteString(words[r.Intn(len(words))])
		b.WriteByte(" \n"[r.Intn(2)])
	}
	return b.Bytes()[:n]
}

// decodeInPieces feeds encoded to a decoder in random pieces and returns
// what it decoded, and whether any of it came out before the end.
func decodeInPieces(t *testing.T, d *bodyDecoder, encoded []byte, finish bool) (out []byte, early bool) {
	t.Helper()
	r := rand.New(rand.NewSource(2))
	for len(encoded) > 0 {
		n := min(1+r.Intn(3000), len(encoded))
		got := d.write(encoded[:n])
		out = append(out, got...)
		early = early || len(got) > 0
		encoded = encoded[n:]
	}
	if finish {
		out = append(out, d.end()...)
	}
	return out, early
}

func TestBodyDecoder(t *testing.T) {
	body := testBody(200 << 10)
	for _, enc := range []string{"gzip", "x-gzip", "deflate", "br", "zstd", "gzip, br", "identity, zstd"} {
		t.Run(enc, func(t *testing.T) {
			pool := newBodyPool()
			d := pool.start(enc)
			encoded := encode(t, body, strings.ReplaceAll(strings.ReplaceAll(enc, "x-gzip", "gzip"), "identity, ", ""))
			got, early := decodeInPieces(t, d, encoded, true)
			if !bytes.Equal(got, body) {
				t.Fatalf("decoded %d bytes, want %d", len(got), len(body))
			}
			if !early {
				t.Error("nothing was decoded before the end of the body")
			}
			if err := d.failed(); err != nil {
				t.Errorf("failed: %v", err)
			}
			if len(pool.live) != 0 {
				t.Errorf("%d decoders still live", len(pool.live))
			}
		})
	}
}

// All of a complete stream comes out when its last byte goes in, without
// waiting for the end of the body.
func TestBodyDecoderNoDelay(t *testing.T) {
	body := testBody(1000)
	for _, enc := range []string{"gzip", "deflate", "br", "zstd"} {
		d := newBodyPool().start(enc)
		if got := d.write(encode(t, body, enc)); !bytes.Equal(got, body) {
			t.Errorf("%s: %d of %d bytes before the end", enc, len(got), len(body))
		}
		d.end()
	}
}

func TestBodyDecoderRawDeflate(t *testing.T) {
	body := testBody(10 << 10)
	d := newBodyPool().start("deflate")
	got, _ := decodeInPieces(t, d, encode(t, body, "raw-deflate"), true)
	if !bytes.Equal(got, body) || d.failed() != nil {
		t.Fatalf("decoded %d bytes, %v", len(got), d.failed())
	}
}

func TestBodyDecoderErrors(t *testing.T) {
	body := testBody(400 << 10) // zstd decodes whole blocks, of up to 128 KiB
	pool := newBodyPool()

	if d := pool.start("identity"); d != nil {
		t.Error("identity got a decoder")
	}
	if d := pool.start("dcb"); d == nil || d.failed() == nil || d.write([]byte("x")) != nil {
		t.Error("a shared-dictionary body wasn't refused")
	}

	// Cut short: what arrived is decoded, and the end says it's missing.
	for _, enc := range []string{"gzip", "br", "zstd"} {
		encoded := encode(t, body, enc)
		d := pool.start(enc)
		got, _ := decodeInPieces(t, d, encoded[:len(encoded)*3/4], true)
		if len(got) == 0 || !bytes.HasPrefix(body, got) {
			t.Errorf("%s: decoded %d bytes of a prefix", enc, len(got))
		}
		if err := d.failed(); err == nil || !strings.Contains(err.Error(), "ended before") {
			t.Errorf("%s: cut short: %v", enc, err)
		}
	}

	// Corrupt.
	encoded := encode(t, body, "gzip")
	encoded[len(encoded)/2] ^= 0xff
	d := pool.start("gzip")
	decodeInPieces(t, d, encoded, true)
	if d.failed() == nil {
		t.Error("corrupt gzip decoded")
	}
	if len(pool.live) != 0 {
		t.Errorf("%d decoders still live", len(pool.live))
	}
}

func TestBodyDecoderLimits(t *testing.T) {
	pool := newBodyPool()
	d := pool.start("gzip")
	out, _ := decodeInPieces(t, d, encode(t, make([]byte, maxDecodedBody+(1<<20)), "gzip"), true)
	if len(out) != maxDecodedBody || !errors.Is(d.failed(), errBodyTooLarge) {
		t.Errorf("decoded %d bytes, %v", len(out), d.failed())
	}

	before := runtime.NumGoroutine()
	var first *bodyDecoder
	for i := range maxLiveBodies + 1 {
		d := pool.start("br")
		if i == 0 {
			first = d
		}
	}
	if len(pool.live) != maxLiveBodies || first.failed() == nil {
		t.Errorf("%d live, the oldest: %v", len(pool.live), first.failed())
	}
	for d := range pool.live {
		d.end()
	}
	// The decompressors' goroutines are gone.
	for deadline := time.Now().Add(5 * time.Second); runtime.NumGoroutine() > before; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines, %d before", runtime.NumGoroutine(), before)
		}
	}
}
