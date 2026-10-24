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
	for range 100 {
		f.Write([]byte("call\n"))
	}
	if s, _ := out.get(); s != "" {
		t.Fatalf("written at once: %q", s)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s, _ := out.get(); s == "" && time.Now().Before(deadline); s, _ = out.get() {
		time.Sleep(10 * time.Millisecond)
	}
	if s, n := out.get(); len(s) != 500 || n != 1 {
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
	time.Sleep(2 * flushDelay)
	if _, err := f.Write([]byte("y")); err == nil {
		t.Error("no error after a failed flush")
	}
}
