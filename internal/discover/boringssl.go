package discover

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/tks98/snoopy/v2/internal/funcfind"
)

// BoringSSL reason codes (include/openssl/err.h and ssl.h). They are part of
// BoringSSL's API and keep their values across releases.
const (
	errShouldNotHaveBeenCalled = 0x42 // ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED
	errBadLength               = 0x6f // SSL_R_BAD_LENGTH
	errUninitialized           = 0xd7 // SSL_R_UNINITIALIZED
	errProtocolIsShutdown      = 0xe2 // SSL_R_PROTOCOL_IS_SHUTDOWN
)

// Reason codes (CIPHER_R_*) that crypto/fipsmodule/cipher/aead.cc.inc
// reports; like all of BoringSSL's, they keep their values.
const (
	aeadReasonBadDecrypt = 0x65 // open: input shorter than the tag
	aeadReasonTooSmall   = 0x67 // seal and open: output buffer too small
	aeadReasonGather     = 0x73 // open_gather (which open calls, or has inlined)
)

var errNotBoringSSL = errors.New("no statically linked BoringSSL")

// Progress, if set, is told about slow work as it starts, such as analyzing
// a large program for BoringSSL the first time it's seen.
var Progress func(msg string)

// boringSSLCacheVersion is part of cached results' names: bump it when
// findBoringSSL would answer differently, so that older answers aren't used.
const boringSSLCacheVersion = 6

// cachedFindBoringSSL is findBoringSSL with its results kept by build ID in
// the user's cache directory, so a large program (Chrome is 300 MB) is
// analyzed once. Later runs attach to it right away, which matters for
// programs found as they start.
//
// A build ID is only a claim, which a program in a container can copy from
// another (a host's Chrome, say) to leave wrong offsets for it. So each
// entry keeps the first bytes of every function it found, and is used only
// for a file that has the same bytes at the same offsets.
func cachedFindBoringSSL(path string, f *elf.File) (map[string]uint64, error) {
	var file string
	if id := funcfind.BuildID(f); id != nil {
		if dir, err := os.UserCacheDir(); err == nil {
			file = filepath.Join(dir, "snoopy", "boringssl", fmt.Sprintf("%x-v%d.json", id, boringSSLCacheVersion))
		}
	}
	if file != "" {
		var cached boringSSLCache
		if data, err := os.ReadFile(file); err == nil && json.Unmarshal(data, &cached) == nil &&
			cached.Offsets["SSL_read"] != 0 && cached.Offsets["SSL_write"] != 0 && cached.matches(f) {
			return cached.Offsets, nil
		}
	}
	offsets, err := findBoringSSL(f, func() {
		if Progress != nil {
			Progress(fmt.Sprintf("analyzing %s to find BoringSSL's functions; the first time takes a few seconds", path))
		}
	})
	if err == nil && file != "" {
		cached := boringSSLCache{Offsets: offsets, Starts: map[string][]byte{}}
		for name, off := range offsets {
			if b, ok := bytesAt(f, off, cacheCheckLen); ok {
				cached.Starts[name] = b
			}
		}
		if data, err := json.Marshal(cached); err == nil && os.MkdirAll(filepath.Dir(file), 0o755) == nil {
			_ = os.WriteFile(file, data, 0o644) // a cache: failing only costs time
		}
	}
	return offsets, err
}

// cacheCheckLen is how many of a function's first bytes a cache entry
// keeps, to tell its file from another with the same build ID.
const cacheCheckLen = 32

type boringSSLCache struct {
	Offsets map[string]uint64
	Starts  map[string][]byte // each function's first cacheCheckLen bytes
}

// matches reports whether f has each function's first bytes where the
// entry says.
func (c boringSSLCache) matches(f *elf.File) bool {
	if len(c.Starts) != len(c.Offsets) {
		return false
	}
	for name, off := range c.Offsets {
		b, ok := bytesAt(f, off, cacheCheckLen)
		if !ok || !bytes.Equal(b, c.Starts[name]) {
			return false
		}
	}
	return true
}

// bytesAt reads n bytes at file offset off, from the loadable segment that
// has them.
func bytesAt(f *elf.File, off uint64, n int) ([]byte, bool) {
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || off < p.Off || off+uint64(n) > p.Off+p.Filesz {
			continue
		}
		b := make([]byte, n)
		if _, err := p.ReadAt(b, int64(off-p.Off)); err != nil {
			return nil, false
		}
		return b, true
	}
	return nil, false
}

// findBoringSSL locates SSL_read and SSL_write in a program that links
// BoringSSL statically and is stripped, like Chrome, other Chromium-based
// browsers and Electron apps. It returns their file offsets.
//
// BoringSSL's OPENSSL_PUT_ERROR passes the source file's name and a reason
// code to ERR_put_error, so the functions of ssl/ssl_lib.cc load that name's
// address, each with its own reason codes. What the compiler inlines varies
// between builds (Chrome 156 stopped inlining ssl_read_impl into SSL_read),
// so a function's codes include those of the ssl_lib.cc functions it calls:
//
//   - SSL_write is the one that reports SSL_R_BAD_LENGTH, besides
//     SSL_R_UNINITIALIZED and SSL_R_PROTOCOL_IS_SHUTDOWN.
//   - SSL_read reports SSL_R_UNINITIALIZED, SSL_R_PROTOCOL_IS_SHUTDOWN and
//     ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, and so does SSL_peek, which SSL_read
//     is built on: SSL_read either calls SSL_peek or, with SSL_peek inlined,
//     is the larger of the two.
//   - Both take (ssl, buf, num), which rules out the callers that BoringSSL
//     code was inlined into.
//
// Anything less than one clear answer for each is an error: probing the
// wrong function would capture the wrong data.
//
// onBoringSSL, if not nil, is called once the program turns out to contain
// BoringSSL, before the slow part.
func findBoringSSL(f *elf.File, onBoringSSL func()) (map[string]uint64, error) {
	b, err := funcfind.Open(f)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNotBoringSSL, err)
	}
	file, ok := b.FindString("/ssl/ssl_lib.cc")
	if !ok {
		return nil, errNotBoringSSL
	}
	if onBoringSSL != nil {
		onBoringSSL()
	}

	// The functions referencing the file name, and the reason codes each
	// passes: ERR_put_error(library, unused, reason, file, line).
	var fns []*funcfind.Func
	own := map[uint64][]int64{}
	for _, ref := range b.Refs(file) {
		fn, ok := b.FuncAt(ref)
		if !ok || own[fn.Start] != nil {
			continue
		}
		reasons, err := b.ConstArgsNear(fn, file, 2)
		if err != nil {
			return nil, err
		}
		fns = append(fns, fn)
		own[fn.Start] = append(reasons, -1) // never empty, to mark it seen
	}

	var writes, reads []*funcfind.Func
	for _, fn := range fns {
		reasons := own[fn.Start]
		for _, callee := range b.Calls(fn) {
			reasons = append(reasons, own[callee]...)
		}
		has := func(want ...int64) bool {
			for _, r := range want {
				if !slices.Contains(reasons, r) {
					return false
				}
			}
			return true
		}
		// Callers that BoringSSL code was inlined into (Chrome's
		// SSLClientSocketImpl::DoPeek) report the same errors, but don't
		// take SSL_read's and SSL_write's (ssl, buf, num) arguments.
		if !b.ReadsArgs(fn, 3) {
			continue
		}
		switch {
		case has(errUninitialized, errProtocolIsShutdown, errBadLength):
			writes = append(writes, fn)
		case has(errUninitialized, errProtocolIsShutdown, errShouldNotHaveBeenCalled):
			reads = append(reads, fn)
		}
	}
	if len(writes) != 1 {
		return nil, fmt.Errorf("BoringSSL: %d candidates for SSL_write", len(writes))
	}
	read, err := pickSSLRead(b, reads)
	if err != nil {
		return nil, err
	}

	found := map[string]*funcfind.Func{"SSL_read": read, "SSL_write": writes[0]}
	if seal, open, err := findAEAD(b); err == nil {
		found["EVP_AEAD_CTX_seal"], found["EVP_AEAD_CTX_open"] = seal, open
	}
	out := map[string]uint64{}
	for name, fn := range found {
		off, err := b.FileOffset(fn.Start)
		if err != nil {
			return nil, err
		}
		out[name] = off
	}
	return out, nil
}

// pickSSLRead tells SSL_read from SSL_peek, which report the same errors.
func pickSSLRead(b *funcfind.Binary, reads []*funcfind.Func) (*funcfind.Func, error) {
	switch len(reads) {
	case 1: // SSL_peek inlined everywhere, or not linked in
		return reads[0], nil
	case 2:
		x, y := reads[0], reads[1]
		xCallsY, yCallsX := slices.Contains(b.Calls(x), y.Start), slices.Contains(b.Calls(y), x.Start)
		switch {
		case xCallsY && !yCallsX:
			return x, nil
		case yCallsX && !xCallsY:
			return y, nil
		case !xCallsY && !yCallsX && x.Size() > y.Size():
			return x, nil
		case !xCallsY && !yCallsX && y.Size() > x.Size():
			return y, nil
		}
	}
	return nil, fmt.Errorf("BoringSSL: can't tell SSL_read among %d candidates", len(reads))
}

// findAEAD locates EVP_AEAD_CTX_seal and EVP_AEAD_CTX_open, which QUIC's
// packet protection uses: Chrome encrypts and decrypts HTTP/3 packets with
// them, while its TLS records go through EVP_AEAD_CTX_seal_scatter and, for
// reading, also EVP_AEAD_CTX_open. Both take ten arguments (seal_scatter
// takes thirteen), and so does EVP_AEAD_CTX_open_gather, which open calls.
// By their own reason codes: open is the one that reports a bad decrypt;
// seal reports a buffer too small, but not open_gather's codes.
func findAEAD(b *funcfind.Binary) (seal, open *funcfind.Func, err error) {
	file, ok := b.FindString("/cipher/aead.cc.inc")
	if !ok {
		return nil, nil, errors.New("BoringSSL: no aead.cc.inc")
	}
	own := map[uint64][]int64{}
	var fns []*funcfind.Func
	for _, ref := range b.Refs(file) {
		fn, ok := b.FuncAt(ref)
		if !ok || own[fn.Start] != nil {
			continue
		}
		reasons, err := b.ConstArgsNear(fn, file, 2)
		if err != nil {
			return nil, nil, err
		}
		fns = append(fns, fn)
		own[fn.Start] = append(reasons, -1)
	}
	var seals, opens []*funcfind.Func
	for _, fn := range fns {
		if b.StackArgs(fn) != 10 {
			continue
		}
		// Their own codes, without their callees': seal calls a helper that
		// reports open_gather's codes too.
		reasons := own[fn.Start]
		switch {
		case slices.Contains(reasons, aeadReasonBadDecrypt):
			opens = append(opens, fn)
		case slices.Contains(reasons, aeadReasonTooSmall) && !slices.Contains(reasons, aeadReasonGather):
			seals = append(seals, fn)
		}
	}
	if len(seals) != 1 || len(opens) != 1 {
		return nil, nil, fmt.Errorf("BoringSSL: %d candidates for EVP_AEAD_CTX_seal, %d for open", len(seals), len(opens))
	}
	return seals[0], opens[0], nil
}
