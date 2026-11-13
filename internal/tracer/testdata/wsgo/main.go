// wsgo is a WebSocket client and server for TestWebSocket: it serves
// WebSocket over TLS (HTTP/1.1) on 127.0.0.1, echoing what it's sent,
// connects to itself with permessage-deflate and context takeover, sends
// the messages the test looks for, and prints "ok". It's a module of its
// own, so that snoopy's doesn't depend on a WebSocket library.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// The test's expectations, which it repeats.
var (
	short = strings.Repeat("snoopy decodes WebSocket messages. ", 8)
	long  = strings.Repeat("a long message that compresses well, ", 2000)
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("ok")
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cert, err := selfSigned()
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: http.HandlerFunc(echo)}
	go srv.Serve(ln)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}}}
	c, _, err := websocket.Dial(ctx, "wss://"+ln.Addr().String()+"/echo", &websocket.DialOptions{
		HTTPClient: client, CompressionMode: websocket.CompressionContextTakeover, CompressionThreshold: 1})
	if err != nil {
		return err
	}
	c.SetReadLimit(1 << 20)
	send := func(typ websocket.MessageType, parts ...string) error {
		w, err := c.Writer(ctx, typ)
		if err != nil {
			return err
		}
		for _, p := range parts { // a frame each, as written
			if _, err := w.Write([]byte(p)); err != nil {
				return err
			}
		}
		if err := w.Close(); err != nil {
			return err
		}
		_, echoed, err := c.Read(ctx)
		if err != nil {
			return err
		}
		if string(echoed) != strings.Join(parts, "") {
			return fmt.Errorf("echoed %q", echoed)
		}
		return nil
	}
	// The second time, the message refers back to the first.
	for _, m := range [][]string{{short}, {short}, {long}, {"fragment one, ", "fragment two"}} {
		if err := send(websocket.MessageText, m...); err != nil {
			return err
		}
	}
	if err := send(websocket.MessageBinary, "\x00\x01\x02 binary"); err != nil {
		return err
	}
	return c.Close(websocket.StatusNormalClosure, "done")
}

func echo(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover, CompressionThreshold: 1})
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(1 << 20)
	for {
		typ, msg, err := c.Read(r.Context())
		if err != nil {
			return
		}
		if err := c.Write(r.Context(), typ, msg); err != nil {
			return
		}
	}
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
