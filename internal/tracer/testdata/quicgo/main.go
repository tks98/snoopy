// HTTP/3 server and client over quic-go for the integration tests, like
// testdata/quinnh3:
//
//	quicgo server <port>
//
// serves "served <path> on <port>" for any request on 127.0.0.1:<port>, with
// a self-signed certificate, and prints "listening" once it is ready. Paths
// under /events are server-sent events instead (see events), and /page an
// HTML page that reads them with EventSource, for a browser. With
// QUICGO_SPKI_FILE set, it first writes the certificate's public key's
// SHA-256 there, in base64, for Chrome's --ignore-certificate-errors-spki-list;
//
//	quicgo client <port>[,<port>...] <path>
//
// sends a GET for <path> to each, at once over one socket, accepting any
// certificate, and prints each response's status and body. For one port and
// a path under /events, it prints the body's pieces as they arrive instead,
// each on a line of its own after the time since the response's headers.
// With QUICGO_DIAL=addr, each connection is dialed with quic.DialAddrEarly
// instead, which gives it a socket of its own and a zero-length connection
// ID, so the server's short headers are only 2 to 5 bytes; with
// QUICGO_DIAL=default, http3.Transport dials as it does by default.
//
// It has its own module, so quic-go isn't a dependency of snoopy's.
package main

import (
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
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
	if file := os.Getenv("QUICGO_SPKI_FILE"); file != "" {
		spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(spki)
		if err := os.WriteFile(file, []byte(base64.StdEncoding.EncodeToString(sum[:])), 0o644); err != nil {
			panic(err)
		}
	}
	srv := &http3.Server{
		Addr:      "127.0.0.1:" + port,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			switch {
			case strings.HasPrefix(r.URL.Path, "/events"):
				events(w, r)
			case r.URL.Path == "/page":
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, page)
			default:
				fmt.Fprintf(w, "served %s on %s", r.URL.Path, port)
			}
		}),
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: atoi(port)})
	if err != nil {
		panic(err)
	}
	fmt.Println("listening")
	panic(srv.Serve(conn))
}

// events streams server-sent events: n of them (the n parameter, 5 by
// default), gap apart (the gap parameter, 300ms by default), each flushed on
// its own, shaped like an LLM API's answer, with a comment between them as a
// keep-alive. The big parameter adds an event of that many bytes of data,
// which takes several QUIC packets, and gzip=1 compresses the stream, as a
// server does for a client that asks.
func events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n, gap := 5, 300*time.Millisecond
	if v, err := strconv.Atoi(q.Get("n")); err == nil {
		n = v
	}
	if v, err := time.ParseDuration(q.Get("gap")); err == nil {
		gap = v
	}
	big, _ := strconv.Atoi(q.Get("big"))
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	out, flush := io.Writer(w), w.(http.Flusher).Flush
	if q.Get("gzip") == "1" {
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		defer zw.Close()
		out, flush = zw, func() { _ = zw.Flush(); w.(http.Flusher).Flush() }
	}
	fmt.Fprint(out, "event: message_start\ndata: {\"type\": \"message_start\"}\n\n")
	flush()
	for i := range n {
		time.Sleep(gap)
		fmt.Fprintf(out, "id: %d\nevent: delta\ndata: {\"index\": %d, \"text\": \"word%d\"}\n\n", i, i, i)
		if i == n/2 {
			fmt.Fprint(out, ": ping\n\n")
			if big > 0 {
				fmt.Fprintf(out, "event: big\ndata: %s\n\n", strings.Repeat("x", big))
			}
		}
		flush()
	}
	fmt.Fprint(out, "event: done\ndata: [DONE]\n\n")
}

// page reads /events with EventSource and shows each event's data, closing
// it at the "done" event, which EventSource would otherwise reconnect after.
const page = `<!doctype html><title>events</title><pre id=out></pre><script>
const es = new EventSource("/events" + location.search), out = document.getElementById("out");
const show = e => { out.textContent += e.type + " " + e.data + "\n"; };
for (const t of ["message_start", "delta", "big"]) es.addEventListener(t, show);
es.addEventListener("done", e => { show(e); es.close(); out.textContent += "closed\n"; });
</script>`

func get(ports []string, path string) {
	rt := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	switch os.Getenv("QUICGO_DIAL") {
	case "addr":
		rt.Dial = quic.DialAddrEarly
	case "default":
	default:
		// One socket for every connection, as quic-go's Transport does.
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			panic(err)
		}
		tr := &quic.Transport{Conn: conn}
		rt.Dial = func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			udp, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return tr.DialEarly(ctx, udp, tlsConf, conf)
		}
	}
	defer rt.Close()
	client := &http.Client{Transport: rt}
	if len(ports) == 1 && strings.HasPrefix(path, "/events") {
		stream(client, "https://127.0.0.1:"+ports[0]+path)
		return
	}
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

// stream prints a response's status, then its body's pieces as they
// arrive, each after the time since the headers.
func stream(client *http.Client, url string) {
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status, resp.Header.Get("Content-Type"))
	start := time.Now()
	buf := make([]byte, 64<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			fmt.Printf("%dms %q\n", time.Since(start).Milliseconds(), buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func atoi(s string) int {
	var n int
	fmt.Sscan(s, &n)
	return n
}
