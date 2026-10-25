package main

import (
	"bytes"
	"io"
	"sync"
)

// merger writes several snoopy pods' output to one writer, whole events at
// a time, so that one's don't land in the middle of another's: a line each
// with --brief and --json, and in text, a block that ends with a blank
// line.
type merger struct {
	mu  sync.Mutex
	w   io.Writer
	sep []byte
}

func newMerger(w io.Writer, blocks bool) *merger {
	sep := []byte("\n")
	if blocks {
		sep = []byte("\n\n")
	}
	return &merger{w: w, sep: sep}
}

// stream returns a writer for one pod's output. Flush writes what's left
// of it when the stream ends.
func (m *merger) stream() *mergeStream {
	return &mergeStream{m: m}
}

type mergeStream struct {
	m   *merger
	buf []byte
}

func (s *mergeStream) Write(p []byte) (int, error) {
	s.buf = append(s.buf, p...)
	i := bytes.LastIndex(s.buf, s.m.sep)
	if i < 0 {
		return len(p), nil
	}
	n := i + len(s.m.sep)
	if err := s.m.write(s.buf[:n]); err != nil {
		return 0, err
	}
	s.buf = append(s.buf[:0], s.buf[n:]...)
	return len(p), nil
}

func (s *mergeStream) Flush() error {
	if len(s.buf) == 0 {
		return nil
	}
	err := s.m.write(s.buf)
	s.buf = s.buf[:0]
	return err
}

func (m *merger) write(b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.w.Write(b)
	return err
}

// prefixWriter writes lines with a prefix, for one of several snoopy pods'
// messages, a line at a time, through a merger.
type prefixWriter struct {
	m      *merger
	prefix []byte
	buf    []byte
}

func (p *prefixWriter) Write(b []byte) (int, error) {
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
	if len(p.buf) == 0 {
		return nil
	}
	_, err := p.Write([]byte("\n"))
	return err
}
