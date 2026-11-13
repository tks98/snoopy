package main

import (
	"bytes"
	"io"
	"regexp"
	"sync"
	"time"
)

// merger writes several snoopy pods' output to one writer, whole events at
// a time, so that one's don't land in the middle of another's: a line each
// with --brief and --json, and in text, a block (see textEvent).
type merger struct {
	mu     sync.Mutex
	w      io.Writer
	blocks bool
	idle   time.Duration // how long a text block waits for the next one
}

func newMerger(w io.Writer, blocks bool) *merger {
	return &merger{w: w, blocks: blocks, idle: 200 * time.Millisecond}
}

// stream returns a writer for one pod's output. Flush writes what's left
// of it when the stream ends.
func (m *merger) stream() *mergeStream {
	return &mergeStream{m: m}
}

// A text event starts with a header line, its time first (15:04:05.000000,
// colored or not), and ends with a blank line. A body can hold blank lines
// too, so a blank line alone doesn't end an event: one followed by a
// header does.
var textEvent = regexp.MustCompile(`\n\n(?:\x1b\[[0-9;]*m)*\d\d:\d\d:\d\d\.\d{6} `)

// mergeStream is one pod's output. Write and Flush may be called at the
// same time: client-go's stream can still be writing when it returns.
type mergeStream struct {
	m       *merger
	mu      sync.Mutex
	buf     []byte
	flushed bool
	timer   *time.Timer
}

func (s *mergeStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flushed {
		return len(p), s.m.write(p)
	}
	s.buf = append(s.buf, p...)
	if n := s.whole(); n > 0 {
		if err := s.m.write(s.buf[:n]); err != nil {
			return 0, err
		}
		s.buf = append(s.buf[:0], s.buf[n:]...)
	}
	if s.m.blocks && len(s.buf) > 0 {
		// The last event is only known to have ended when the next one
		// starts, or when the stream goes quiet after a blank line: snoopy
		// writes an event out in one go, so it doesn't pause in the middle
		// of one for long.
		if s.timer == nil {
			s.timer = time.AfterFunc(s.m.idle, s.quiet)
		} else {
			s.timer.Reset(s.m.idle)
		}
	}
	return len(p), nil
}

// whole returns how much of the buffer is whole events.
func (s *mergeStream) whole() int {
	if !s.m.blocks {
		return bytes.LastIndexByte(s.buf, '\n') + 1
	}
	all := textEvent.FindAllIndex(s.buf, -1)
	if len(all) == 0 {
		return 0
	}
	return all[len(all)-1][0] + 2
}

func (s *mergeStream) quiet() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flushed || !bytes.HasSuffix(s.buf, []byte("\n\n")) {
		return
	}
	if s.m.write(s.buf) == nil {
		s.buf = s.buf[:0]
	}
}

func (s *mergeStream) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	if len(s.buf) == 0 {
		return nil
	}
	err := s.m.write(s.buf)
	s.buf = nil
	return err
}

func (m *merger) write(b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.w.Write(b)
	return err
}

// prefixWriter writes lines with a prefix, for one of several snoopy pods'
// messages, a line at a time, through a merger. Like mergeStream's, its
// Write and Flush may be called at the same time.
type prefixWriter struct {
	m      *merger
	prefix []byte
	mu     sync.Mutex
	buf    []byte
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.write(b)
}

func (p *prefixWriter) write(b []byte) (int, error) {
	p.buf = append(p.buf, b...)
	for {
		i := bytes.IndexByte(p.buf, '\n')
		if i < 0 {
			return len(b), nil
		}
		line := append(append([]byte{}, p.prefix...), p.buf[:i+1]...)
		if err := p.m.write(line); err != nil {
			return 0, err
		}
		p.buf = append(p.buf[:0], p.buf[i+1:]...)
	}
}

func (p *prefixWriter) Flush() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.buf) == 0 {
		return nil
	}
	_, err := p.write([]byte("\n"))
	return err
}
