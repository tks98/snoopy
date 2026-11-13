package output

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Limits on decoding message bodies. Bodies can be large and compression
// ratios high, and each body being decoded holds a decompressor.
const (
	maxDecodedBody = 16 << 20 // decoded bytes per body
	maxLiveBodies  = 256      // bodies being decoded at once, over all connections
	zstdMaxWindow  = 8 << 20  // what HTTP allows (RFC 9659)
	// Codings undone per body. Each takes a goroutine and a decompressor;
	// real bodies have one, rarely two.
	maxContentCodings = 4
)

var errBodyTooLarge = fmt.Errorf("decoded body exceeds %d MiB", maxDecodedBody>>20)

// bodyDecoder undoes a message body's Content-Encoding as the body arrives,
// in pieces spread over many events.
type bodyDecoder struct {
	encoding string     // as the header gave it, e.g. "br" or "gzip, br"
	stages   []*inflate // in the order they're undone
	err      error      // why decoding stopped
	written  int        // encoded bytes so far
	decoded  int
	reported bool // err was shown
	pool     *bodyPool
	lastUsed uint64
}

// bodyPool tracks the bodies being decoded, so the least recently used ones
// can be given up on when there are too many: a body whose end goes
// unnoticed would otherwise hold its decompressor forever.
type bodyPool struct {
	live  map[*bodyDecoder]struct{}
	clock uint64
}

func newBodyPool() *bodyPool {
	return &bodyPool{live: map[*bodyDecoder]struct{}{}}
}

// contentCodings returns the codings of a Content-Encoding value, leaving out
// identity, or false if they can't all be undone.
func contentCodings(value string) ([]string, bool) {
	var codings []string
	for _, c := range strings.Split(value, ",") {
		c = strings.ToLower(strings.TrimSpace(c))
		switch c {
		case "", "identity":
		case "gzip", "x-gzip", "deflate", "br", "zstd":
			codings = append(codings, c)
		default: // e.g. compress, or a shared dictionary (dcb, dcz)
			return nil, false
		}
	}
	return codings, true
}

// start returns a decoder for a body with the given Content-Encoding, or
// nil if the body isn't encoded. A body in an encoding that can't be undone
// gets a decoder that only reports that.
func (p *bodyPool) start(contentEncoding string) *bodyDecoder {
	codings, ok := contentCodings(contentEncoding)
	if ok && len(codings) == 0 {
		return nil
	}
	b := &bodyDecoder{encoding: contentEncoding, pool: p}
	if !ok {
		b.err = fmt.Errorf("can't decode content encoding %q", contentEncoding)
		return b
	}
	if len(codings) > maxContentCodings {
		b.err = fmt.Errorf("%d content codings, more than snoopy undoes (%d)", len(codings), maxContentCodings)
		return b
	}
	if len(p.live) >= maxLiveBodies {
		var oldest *bodyDecoder
		for d := range p.live {
			if oldest == nil || d.lastUsed < oldest.lastUsed {
				oldest = d
			}
		}
		oldest.stop(errors.New("given up: too many bodies being decoded at once"))
	}
	for i := len(codings) - 1; i >= 0; i-- { // codings are listed in the order applied
		b.stages = append(b.stages, newInflate(codings[i]))
	}
	p.live[b] = struct{}{}
	p.clock++
	b.lastUsed = p.clock
	return b
}

// write decodes the next bytes of the body and returns what they decode to.
func (b *bodyDecoder) write(p []byte) []byte {
	if b.err != nil || len(p) == 0 {
		return nil
	}
	b.pool.clock++
	b.lastUsed = b.pool.clock
	b.written += len(p)
	out := p
	for _, s := range b.stages {
		out = s.push(out)
		if err := s.failed(); err != nil {
			b.stop(err)
			break
		}
	}
	return b.limit(out)
}

// end finishes the body, returning any last decoded bytes. err is set if the
// body was cut short or didn't decode.
func (b *bodyDecoder) end() []byte {
	if b.err != nil {
		return nil
	}
	if b.written == 0 { // no body after all, e.g. a response to HEAD
		b.stop(io.EOF)
		return nil
	}
	var out []byte
	for i, s := range b.stages {
		if i > 0 && len(out) > 0 {
			out = s.push(out)
		}
		out = append(out, s.close()...)
		if err := s.failed(); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = errors.New("the body ended before its encoding did")
			}
			b.stop(err)
			return b.limit(out)
		}
	}
	b.stop(io.EOF)
	return b.limit(out)
}

// fail stops decoding, e.g. because bytes of the body weren't captured.
func (b *bodyDecoder) fail(err error) {
	if b.err == nil {
		b.stop(err)
	}
}

// failed returns why decoding stopped early, or nil.
func (b *bodyDecoder) failed() error {
	if b.err == io.EOF {
		return nil
	}
	return b.err
}

func (b *bodyDecoder) stop(err error) {
	b.err = err
	for _, s := range b.stages {
		s.close()
	}
	delete(b.pool.live, b)
}

func (b *bodyDecoder) limit(out []byte) []byte {
	if b.decoded+len(out) > maxDecodedBody {
		out = out[:maxDecodedBody-b.decoded]
		b.fail(errBodyTooLarge)
	}
	b.decoded += len(out)
	return out
}

// inflate undoes one content coding on bytes pushed to it. The
// decompressors read from an io.Reader, so each runs in a goroutine that
// pulls the pushed bytes; push hands over a piece and returns once the
// decompressor has used it all and asks for more, by which time it has
// produced everything that piece allows.
type inflate struct {
	in    chan []byte   // pieces; closed at the end of the body
	ready chan struct{} // the decompressor wants input; closed when it's done
	cur   []byte        // the piece being read (decompressor's side)
	eof   bool          // in was closed (decompressor's side)
	out   []byte        // decoded bytes not yet returned
	err   error         // why the decompressor stopped, once ready is closed
	done  bool          // ready was closed (caller's side)
}

func newInflate(coding string) *inflate {
	z := &inflate{in: make(chan []byte), ready: make(chan struct{})}
	go z.run(coding)
	z.wait()
	return z
}

// Read is the decompressor's source.
func (z *inflate) Read(p []byte) (int, error) {
	for len(z.cur) == 0 {
		if z.eof {
			return 0, io.EOF
		}
		z.ready <- struct{}{}
		b, ok := <-z.in
		if !ok {
			z.eof = true
			return 0, io.EOF
		}
		z.cur = b
	}
	n := copy(p, z.cur)
	z.cur = z.cur[n:]
	return n, nil
}

func (z *inflate) run(coding string) {
	var r io.Reader
	var err error
	switch coding {
	case "gzip", "x-gzip":
		var g *gzip.Reader
		if g, err = gzip.NewReader(z); err == nil {
			// One member, as HTTP bodies are: otherwise it reads on for
			// another before returning the last bytes of the first.
			g.Multistream(false)
			r = g
		}
	case "deflate":
		r, err = newDeflateReader(z)
	case "br":
		r = brotli.NewReader(z)
	case "zstd":
		var d *zstd.Decoder
		d, err = zstd.NewReader(z, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(zstdMaxWindow))
		if err == nil {
			defer d.Close()
			r = d
		}
	default:
		err = fmt.Errorf("unknown coding %q", coding)
	}
	buf := make([]byte, 32<<10)
	for err == nil {
		var n int
		n, err = r.Read(buf)
		z.out = append(z.out, buf[:n]...)
		if len(z.out) > maxDecodedBody {
			err = errBodyTooLarge
		}
	}
	z.err = err
	close(z.ready)
}

// newDeflateReader reads "deflate", which is meant to be zlib (RFC 1950)
// but which some servers send without the zlib wrapper.
func newDeflateReader(src io.Reader) (io.Reader, error) {
	br := bufio.NewReader(src)
	header, err := br.Peek(2)
	if err != nil {
		return nil, err
	}
	if (uint16(header[0])<<8|uint16(header[1]))%31 == 0 && header[0]&0x0f == 8 {
		return zlib.NewReader(br)
	}
	return flate.NewReader(br), nil
}

// failed returns why the decompressor stopped, other than reaching the end
// of its stream, once it has.
func (z *inflate) failed() error {
	if !z.done || z.err == io.EOF {
		return nil
	}
	return z.err
}

func (z *inflate) wait() {
	if _, ok := <-z.ready; !ok {
		z.done = true
	}
}

// push hands the decompressor more input and returns what it decoded.
func (z *inflate) push(p []byte) []byte {
	if !z.done && len(p) > 0 {
		z.in <- p
		z.wait()
	}
	out := z.out
	z.out = nil
	return out
}

// close ends the input and returns the last decoded bytes.
func (z *inflate) close() []byte {
	if !z.done {
		close(z.in)
		for !z.done {
			z.wait()
		}
	}
	out := z.out
	z.out = nil
	return out
}
