//go:build !linux

// Command snoopy traces the plaintext of TLS connections using eBPF, so it
// runs only on Linux. On other systems it builds to this stub, so that
// `go build` and `go install` there give one clear message instead of
// compile errors from the Linux-only packages.
package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(os.Stderr, `snoopy runs only on Linux: it traces TLS with eBPF, and this build is for %s.
On macOS or Windows, use mitmproxy, or Wireshark with a key log, or run snoopy
in a Linux VM. See https://github.com/tks98/snoopy/blob/main/docs/comparison.md
`, runtime.GOOS)
	os.Exit(1)
}
