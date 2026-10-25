package main

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuffer is a bytes.Buffer safe to write to and read at once.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// A text event whose body has a blank line in it isn't split there: the
// other pod's event comes after it, not in it.
func TestMergeTextBlankLineInBody(t *testing.T) {
	var out lockedBuffer
	m := newMerger(&out, true)
	m.idle = time.Hour // only whole events, for now
	a, b := m.stream(), m.stream()
	eventA := "12:00:00.000001 curl (pid 1) SSL_write 10.0.0.1:1 > 10.0.0.2:443  9 bytes  1µs  conn 0x1\n" +
		"POST / HTTP/1.1\n\nfirst part\n\nsecond part\n\n"
	eventB := "12:00:00.000002 curl (pid 2) SSL_write 10.0.0.3:1 > 10.0.0.2:443  9 bytes  1µs  conn 0x2\nGET / HTTP/1.1\n\n"
	next := "12:00:00.000003 curl (pid 1) SSL_read"
	// a's event arrives up to its body's first blank line, then b's whole
	// event (and the start of its next), then the rest of a's.
	cut := strings.Index(eventA, "first")
	_, _ = a.Write([]byte(eventA[:cut]))
	_, _ = b.Write([]byte(eventB + next))
	_, _ = a.Write([]byte(eventA[cut:] + next))
	if got, want := out.String(), eventB+eventA; got != want {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
	_ = a.Flush()
	_ = b.Flush()
	if got, want := out.String(), eventB+eventA+next+next; got != want {
		t.Errorf("flushed: %q", got)
	}
}

// The last event goes out once the stream is quiet, without waiting for
// the next.
func TestMergeTextQuiet(t *testing.T) {
	var out lockedBuffer
	m := newMerger(&out, true)
	m.idle = 10 * time.Millisecond
	s := m.stream()
	event := "12:00:00.000001 curl (pid 1) SSL_write 10.0.0.1:1 > 10.0.0.2:443  9 bytes  1µs  conn 0x1\nhello\n\n"
	_, _ = s.Write([]byte(event))
	for deadline := time.Now().Add(5 * time.Second); out.String() != event; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("got %q", out.String())
		}
	}
	_ = s.Flush()
}

func TestMergeLines(t *testing.T) {
	var out lockedBuffer
	m := newMerger(&out, false)
	a, b := m.stream(), m.stream()
	_, _ = a.Write([]byte(`{"a":1}` + "\n" + `{"a":`))
	_, _ = b.Write([]byte(`{"b":1}` + "\n"))
	_, _ = a.Write([]byte("2}\n"))
	if got, want := out.String(), `{"a":1}`+"\n"+`{"b":1}`+"\n"+`{"a":2}`+"\n"; got != want {
		t.Errorf("got %q", got)
	}
}

// client-go's stream can return while its copy is still writing, so Flush
// and Write may run at once: with -race, this fails if they aren't safe.
func TestMergeFlushWhileWriting(t *testing.T) {
	var out lockedBuffer
	m := newMerger(&out, true)
	s := m.stream()
	p := &prefixWriter{m: newMerger(&out, false), prefix: []byte("[n] ")}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 200 {
			_, _ = s.Write([]byte("12:00:00.000001 x\nbody\n\n"))
			_, _ = p.Write([]byte("message\npart"))
		}
	})
	for range 50 {
		_ = s.Flush()
		_ = p.Flush()
	}
	wg.Wait()
}
