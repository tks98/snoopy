// HTTP/3 server and client over quic-go for the integration tests, like
// testdata/quinnh3:
//
//	quicgo server <port>
//
// serves "served <path> on <port>" for any request on 127.0.0.1:<port>, with
// a self-signed certificate, and prints "listening" once it is ready;
//
//	quicgo client <port>[,<port>...] <path>
//
// sends a GET for <path> to each, at once over one socket, accepting any
// certificate, and prints each response's status and body.
//
// It has its own module, so quic-go isn't a dependency of snoopy's.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	switch {
	case len(os.Args) == 3 && os.Args[1] == "server":
		serve(os.Args[2])
	case len(os.Args) == 4 && os.Args[1] == "client":
		get(strings.Split(os.Args[2], ","), os.Args[3])
	default:
		fmt.Fprintln(os.Stderr, "usage: quicgo server <port> | quicgo client <port>[,<port>...] <path>")
		os.Exit(2)
	}
}

func serve(port string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	srv := &http3.Server{
		Addr:      "127.0.0.1:" + port,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			fmt.Fprintf(w, "served %s on %s", r.URL.Path, port)
		}),
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: atoi(port)})
	if err != nil {
		panic(err)
	}
	fmt.Println("listening")
	panic(srv.Serve(conn))
}

func get(ports []string, path string) {
	// One socket for every connection, as quic-go's Transport does.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		panic(err)
	}
	tr := &quic.Transport{Conn: conn}
	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			udp, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return tr.DialEarly(ctx, udp, tlsConf, conf)
		},
	}
	defer rt.Close()
	client := &http.Client{Transport: rt}
	out := make([]string, len(ports))
	var wg sync.WaitGroup
	for i, port := range ports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get("https://127.0.0.1:" + port + path)
			if err != nil {
				out[i] = err.Error()
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			out[i] = fmt.Sprintf("%s %s", resp.Status, body)
		}()
	}
	wg.Wait()
	for _, line := range out {
		fmt.Println(line)
	}
}

func atoi(s string) int {
	var n int
	fmt.Sscan(s, &n)
	return n
}
