package main

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
	n  int // writes
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n++
	return l.b.Write(p)
}

func (l *lockedBuffer) get() (string, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String(), l.n
}

// Output is written out in one go shortly after, and all of it on Close.
func TestFlushWriter(t *testing.T) {
	var out lockedBuffer
	f := newFlushWriter(&out)
	start := time.Now()
	for range 100 {
		f.Write([]byte("call\n"))
	}
	// The flush is due flushDelay after the first write. A loaded machine
	// can stall the loop for longer than that, and then some of it has gone
	// out already, which is fine; only output sooner than flushDelay isn't.
	s, _ := out.get()
	if s != "" && time.Since(start) < flushDelay {
		t.Fatalf("written at once: %q", s)
	}
	batched := s == ""
	deadline := time.Now().Add(5 * time.Second)
	for s, _ = out.get(); len(s) < 500 && time.Now().Before(deadline); s, _ = out.get() {
		time.Sleep(10 * time.Millisecond)
	}
	// All buffered before the flush, the 100 calls go out in one write.
	if s, n := out.get(); len(s) != 500 || n > 100 || batched && n != 1 {
		t.Errorf("after the delay: %d bytes in %d writes", len(s), n)
	}
	f.Write([]byte("last\n"))
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if s, _ := out.get(); len(s) != 505 {
		t.Errorf("after Close: %d bytes", len(s))
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A failed flush is reported by the next Write, so printing stops.
func TestFlushWriterError(t *testing.T) {
	f := newFlushWriter(failingWriter{})
	f.Write([]byte("x"))
	// Writes before the flush is done just buffer, so keep writing until one
	// is refused, rather than assuming the flush has run by some time.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := f.Write([]byte("y")); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no error after a failed flush")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
