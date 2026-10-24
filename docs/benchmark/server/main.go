// Command server is the Go HTTPS server docs/benchmark/run.sh measures:
//
//	server -addr 127.0.0.1:8443 -size 1024
//
// answers every request with -size bytes, over TLS with a self-signed
// certificate it makes at startup.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "address to listen on")
	size := flag.Int("size", 1024, "bytes in each response")
	flag.Parse()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	body := make([]byte, *size)
	for i := range body {
		body[i] = 'a' + byte(i%26)
	}
	srv := &http.Server{
		Addr:      *addr,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body) // a client that went away is no concern here
		}),
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
