package discover

import (
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/tks98/snoopy/internal/funcfind"
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
// reports from EVP_AEAD_CTX_seal and EVP_AEAD_CTX_open; like all of
// BoringSSL's, they keep their values.
const (
	aeadReasonSealOpen = 0x67 // reported by both
	aeadReasonOpen     = 0x73 // reported by open only
)

var errNotBoringSSL = errors.New("no statically linked BoringSSL")

// cachedFindBoringSSL is findBoringSSL with its results kept by build ID in
// the user's cache directory, so a large program (Chrome is 300 MB) is
// analyzed once. Later runs attach to it right away, which matters for
// programs found as they start.
func cachedFindBoringSSL(f *elf.File) (map[string]uint64, error) {
	var file string
	if id := funcfind.BuildID(f); id != nil {
		if dir, err := os.UserCacheDir(); err == nil {
			file = filepath.Join(dir, "snoopy", "boringssl", hex.EncodeToString(id)+"-v2.json")
		}
	}
	if file != "" {
		var offsets map[string]uint64
		if data, err := os.ReadFile(file); err == nil && json.Unmarshal(data, &offsets) == nil &&
			offsets["SSL_read"] != 0 && offsets["SSL_write"] != 0 {
			return offsets, nil
		}
	}
	offsets, err := findBoringSSL(f)
	if err == nil && file != "" {
		if data, err := json.Marshal(offsets); err == nil && os.MkdirAll(filepath.Dir(file), 0o755) == nil {
			os.WriteFile(file, data, 0o644)
		}
	}
	return offsets, err
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
func findBoringSSL(f *elf.File) (map[string]uint64, error) {
	b, err := funcfind.Open(f)
	if err != nil {
		return nil, err
	}
	file, ok := b.FindString("/ssl/ssl_lib.cc")
	if !ok {
		return nil, errNotBoringSSL
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
// takes thirteen); open is the one that reports aeadReasonOpen.
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
		// reports aeadReasonOpen too.
		reasons := own[fn.Start]
		switch {
		case slices.Contains(reasons, aeadReasonOpen):
			opens = append(opens, fn)
		case slices.Contains(reasons, aeadReasonSealOpen):
			seals = append(seals, fn)
		}
	}
	if len(seals) != 1 || len(opens) != 1 {
		return nil, nil, fmt.Errorf("BoringSSL: %d candidates for EVP_AEAD_CTX_seal, %d for open", len(seals), len(opens))
	}
	return seals[0], opens[0], nil
}
