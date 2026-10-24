package main

import (
	"bufio"
	"io"
	"sync"
	"time"
)

// flushDelay is how long output may wait in flushWriter's buffer.
const flushDelay = 50 * time.Millisecond

// flushWriter buffers what's written to w and writes it out at most
// flushDelay later. Under load, many calls' output goes out in one write
// rather than each in its own, which snoopy couldn't keep up with at tens of
// thousands of calls a second; at a terminal it still shows at once, to the
// eye.
type flushWriter struct {
	mu    sync.Mutex
	buf   *bufio.Writer
	timer *time.Timer // set while a flush is due
	err   error       // from a flush, returned by the next Write
}

func newFlushWriter(w io.Writer) *flushWriter {
	return &flushWriter{buf: bufio.NewWriterSize(w, 64<<10)}
}

func (f *flushWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	n, err := f.buf.Write(p)
	if f.timer == nil {
		f.timer = time.AfterFunc(flushDelay, f.flushLater)
	}
	return n, err
}

func (f *flushWriter) flushLater() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.timer = nil
	if err := f.buf.Flush(); err != nil && f.err == nil {
		f.err = err
	}
}

// Close writes out what's buffered.
func (f *flushWriter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.timer != nil {
		f.timer.Stop()
		f.timer = nil
	}
	if err := f.buf.Flush(); err != nil {
		return err
	}
	return f.err
}
