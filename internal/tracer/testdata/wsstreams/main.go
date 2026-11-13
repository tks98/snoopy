// wsstreams is a WebSocket client and server for TestWebSocketStreams,
// over one stream of an HTTP/2 connection (RFC 8441) or of an HTTP/3 one
// (RFC 9220):
//
//	wsstreams h2
//	wsstreams h3
//
// serves on 127.0.0.1 with a self-signed certificate, connects to itself
// with an extended CONNECT for WebSocket, negotiating permessage-deflate
// with context takeover, sends the messages the test looks for, reads them
// echoed, closes, and prints "ok". The HTTP/2 server and client are
// net/http's, which want GODEBUG=http2xconnect=1 for extended CONNECT; the
// HTTP/3 ones quic-go's. (The HTTP/2 client is x/net/http2's: net/http's
// Transport refuses the :protocol pseudo-header before HTTP/2 sees it.)
//
// No WebSocket library speaks RFC 8441 or RFC 9220 that snoopy's tests
// would want to depend on, so the framing is written here: the client
// masks its frames, and the server echoes each frame unmasked, compressed
// payloads as they are (which, with context takeover in both directions,
// is the same compressed stream). It has its own module, so quic-go isn't
// a dependency of snoopy's.
package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// The test's expectations, which it repeats.
var (
	short = strings.Repeat("snoopy decodes WebSocket over HTTP/2 and HTTP/3. ", 8)
	long  = strings.Repeat("a long message that compresses well, ", 2000)
)

func main() {
	var err error
	switch {
	case len(os.Args) == 2 && os.Args[1] == "h2":
		err = runH2()
	case len(os.Args) == 2 && os.Args[1] == "h3":
		err = runH3()
	default:
		err = errors.New("usage: wsstreams h2 | wsstreams h3")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("ok")
}

const extensions = "permessage-deflate"

func runH2() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cert, err := selfSigned()
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get(":protocol") != "websocket" {
			http.Error(w, "not a WebSocket", http.StatusBadRequest)
			return
		}
		w.Header().Set("Sec-WebSocket-Extensions", extensions)
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		if err := rc.Flush(); err != nil {
			return
		}
		echo(r.Body, flushWriter{w, rc})
	})}
	go srv.Serve(ln)
	defer srv.Close()

	tr := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.CloseIdleConnections()
	body, send := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+ln.Addr().String()+"/echo", body)
	if err != nil {
		return err
	}
	req.Header.Set(":protocol", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Extensions", extensions)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		return fmt.Errorf("handshake: %s %s", resp.Proto, resp.Status)
	}
	return talk(send, resp.Body)
}

func runH3() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cert, err := selfSigned()
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	srv := &http3.Server{TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect || r.Proto != "websocket" {
				http.Error(w, "not a WebSocket", http.StatusBadRequest)
				return
			}
			w.Header().Set("Sec-WebSocket-Extensions", extensions)
			w.WriteHeader(http.StatusOK)
			str, err := w.(http3.HTTPStreamer).HTTPStream()
			if err != nil {
				return
			}
			defer str.Close()
			echo(str, str)
		})}
	go srv.Serve(udp)
	defer srv.Close()

	// A Transport of its own gives the client connection IDs (4 bytes), as
	// http3.Transport's default does; quic.DialAddr's zero-length ones are
	// TestQuicGoDialAddr's.
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	qt := &quic.Transport{Conn: clientUDP}
	defer qt.Close()
	conn, err := qt.Dial(ctx, udp.LocalAddr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}, nil)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	cc := (&http3.Transport{}).NewClientConn(conn)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		return ctx.Err()
	}
	if !cc.Settings().EnableExtendedConnect {
		return errors.New("the server doesn't allow extended CONNECT")
	}
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+udp.LocalAddr().String()+"/echo", nil)
	if err != nil {
		return err
	}
	req.Proto = "websocket"
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Extensions", extensions)
	if err := str.SendRequestHeader(req); err != nil {
		return err
	}
	resp, err := str.ReadResponse()
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("handshake: %s", resp.Status)
	}
	return talk(str, str)
}

// talk sends the messages, compressed, reads each echoed, and closes.
func talk(w io.WriteCloser, r io.Reader) error {
	var buf bytes.Buffer
	z, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return err
	}
	compress := func(s string) []byte {
		buf.Reset()
		z.Write([]byte(s))
		z.Flush()
		return bytes.Clone(bytes.TrimSuffix(buf.Bytes(), []byte{0, 0, 0xff, 0xff}))
	}
	type frame struct {
		op            byte
		fin, compress bool
		payload       []byte
	}
	// The second short message refers back to the first; the fragmented
	// one is compressed as one and sent as two frames.
	fragmented := compress("fragment one, fragment two")
	messages := [][]frame{
		{{0x1, true, true, compress(short)}},
		{{0x1, true, true, compress(short)}},
		{{0x1, true, true, compress(long)}},
		{{0x1, false, true, fragmented[:len(fragmented)/2]}, {0x0, true, false, fragmented[len(fragmented)/2:]}},
		{{0x2, true, true, compress("\x00\x01\x02 binary")}},
		{{0x8, true, false, append([]byte{0x03, 0xe8}, "done"...)}},
	}
	for _, m := range messages {
		var sent []byte
		for _, f := range m {
			if _, err := w.Write(frameBytes(f.op, f.fin, f.compress, true, f.payload)); err != nil {
				return err
			}
			sent = append(sent, f.payload...)
		}
		var echoed []byte
		for range m {
			_, _, _, payload, err := readFrame(r)
			if err != nil {
				return fmt.Errorf("reading the echo: %w", err)
			}
			echoed = append(echoed, payload...)
		}
		if !bytes.Equal(echoed, sent) {
			return fmt.Errorf("echoed %q, sent %q", echoed, sent)
		}
	}
	return w.Close()
}

// echo sends back each frame read from r, unmasked, until a close frame.
func echo(r io.Reader, w io.Writer) {
	for {
		op, fin, rsv1, payload, err := readFrame(r)
		if err != nil {
			return
		}
		if _, err := w.Write(frameBytes(op, fin, rsv1, false, payload)); err != nil || op == 0x8 {
			return
		}
	}
}

type flushWriter struct {
	w  io.Writer
	rc *http.ResponseController
}

func (f flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if err == nil {
		err = f.rc.Flush()
	}
	return n, err
}

// frameBytes builds a frame (RFC 6455, section 5.2), masked if mask is set.
func frameBytes(op byte, fin, rsv1, mask bool, payload []byte) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	if rsv1 {
		b0 |= 0x40
	}
	out := []byte{b0}
	var m byte
	if mask {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		out = append(out, m|byte(n))
	case n < 1<<16:
		out = binary.BigEndian.AppendUint16(append(out, m|126), uint16(n))
	default:
		out = binary.BigEndian.AppendUint64(append(out, m|127), uint64(n))
	}
	if !mask {
		return append(out, payload...)
	}
	key := make([]byte, 4)
	rand.Read(key)
	out = append(out, key...)
	for i, c := range payload {
		out = append(out, c^key[i%4])
	}
	return out
}

// readFrame reads a frame and returns its payload unmasked.
func readFrame(r io.Reader) (op byte, fin, rsv1 bool, payload []byte, err error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return 0, false, false, nil, err
	}
	op, fin, rsv1 = h[0]&0x0f, h[0]&0x80 != 0, h[0]&0x40 != 0
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		b := make([]byte, 2)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, false, false, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b))
	case 127:
		b := make([]byte, 8)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, false, false, nil, err
		}
		n = binary.BigEndian.Uint64(b)
	}
	if n > 1<<20 {
		return 0, false, false, nil, fmt.Errorf("frame of %d bytes", n)
	}
	var key []byte
	if h[1]&0x80 != 0 {
		key = make([]byte, 4)
		if _, err := io.ReadFull(r, key); err != nil {
			return 0, false, false, nil, err
		}
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, false, false, nil, err
	}
	if key != nil {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return op, fin, rsv1, payload, nil
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
