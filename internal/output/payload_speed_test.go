package output

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// The rune-at-a-time versions isText and escapeText replaced, which they
// have to agree with.
func isTextSlow(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	bad := 0
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			if !utf8.FullRune(b[i:]) {
				i = len(b)
				continue
			}
			bad++
		case unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' && r != '\f' && r != '\v':
			bad++
		}
		i += size
	}
	return bad*20 <= len(b)
}

func escapeTextSlow(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r == '\r' && i+1 < len(b) && b[i+1] == '\n':
		case r == '\n' || r == '\t':
			sb.WriteRune(r)
		case r == utf8.RuneError && size <= 1, unicode.IsControl(r):
			for _, c := range b[i : i+size] {
				fmt.Fprintf(&sb, `\x%02x`, c)
			}
		default:
			sb.Write(b[i : i+size])
		}
		i += size
	}
	return sb.String()
}

func TestTextFastPaths(t *testing.T) {
	cases := [][]byte{nil, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), []byte("tab\tand\nnewline"), []byte("lone\rcr"),
		[]byte("\x00\x01\x7f\x80\xff"), []byte("héllo wörld ✓"), []byte("\xc2\x85 C1 control"), []byte("cut \xe2\x9c"),
		[]byte("\xed\xa0\x80 surrogate")}
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("aZ \r\n\t\x00\x1b\x7f\x80\xc3\xa9\xe2\x9c\x93\xff")
	for range 20000 {
		b := make([]byte, rng.Intn(24))
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		cases = append(cases, b)
	}
	for _, b := range cases {
		if got, want := isText(b), isTextSlow(b); got != want {
			t.Errorf("isText(%q) = %v, want %v", b, got, want)
		}
		if got, want := escapeText(b), escapeTextSlow(b); got != want {
			t.Errorf("escapeText(%q) = %q, want %q", b, got, want)
		}
	}
}
