// A Go program that uses crypto/tls, built by the tests.
package main

import (
	"crypto/tls"
	"os"
)

func main() {
	conn, err := tls.Dial("tcp", os.Args[1], &tls.Config{})
	if err != nil {
		os.Exit(1)
	}
	conn.Write([]byte("hello"))
	buf := make([]byte, 10)
	conn.Read(buf)
	conn.Close()
}
