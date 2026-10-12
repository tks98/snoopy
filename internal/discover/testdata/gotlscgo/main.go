// A cgo program that uses crypto/tls, built with external linking by the
// tests: the C runtime's code then comes before Go's in .text.
package main

// #include <stdlib.h>
import "C"

import (
	"crypto/tls"
	"os"
)

func main() {
	C.free(C.malloc(1))
	conn, err := tls.Dial("tcp", os.Args[1], &tls.Config{})
	if err != nil {
		os.Exit(1)
	}
	conn.Write([]byte("hello"))
	buf := make([]byte, 10)
	conn.Read(buf)
	conn.Close()
}
