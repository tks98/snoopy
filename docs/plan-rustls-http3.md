# Plan: rustls under tokio, and HTTP/3 outside browsers

Two gaps, one idea. snoopy already captures HTTP/3 by probing the functions
that encrypt and decrypt each QUIC packet (`EVP_AEAD_CTX_seal` and `open` in
Chrome, freebl's `AES_AEAD` in Firefox), because the socket I/O and the
plaintext are far apart there. The same move covers both gaps:

- **rustls under tokio** (reqwest, hyper, axum, tonic, Deno): rustls hands
  plaintext to the application through functions that tokio-rustls inlines
  away, so the current `Reader::read` probe never fires. But every record
  still goes through the crypto provider's AEAD, which is a function with a
  C ABI in the common case.
- **HTTP/3 in curl and Go programs**: curl's QUIC stack (ngtcp2) encrypts
  packets through an exported function, and Go's does it through standard
  library functions that keep their names even in stripped binaries.

The plan: generalize the AEAD capture path once, then attach it to four
places.

**Status:** Part 0, Part 1a, Part 1b, Part 2a and Part 2b are done, and HTTP/3 over
quinn, which wasn't planned: its packets go through the same functions. For
2a, the tag's size is read from `ngtcp2_crypto_aead` rather than assumed,
and the test runs in the weekly canary (`canary.yml`). For 2b, Go's AEADs
are probed only in programs with quic-go, and their sockets and peers come
from the machinery built for quinn rather than from `recv_bufs` alone.
Connections sharing quinn's one socket are told apart by their connection
IDs (see docs/how-it-works.md, "HTTP/3"). For 1b, ring's
`aes_gcm_seal`/`_open` and `chacha20_poly1305_seal`/`_open` (the first
option below) see every record; their arguments were checked with bpftrace
on x86-64 and arm64. For 1a: Two things differ from the plan
below: instead of a per-process switch, Rust programs' aws-lc functions get
their own BPF programs (`aead_seal_enter`, `aead_seal_scatter_enter`,
`aead_open_enter`) that keep TLS records, while Chromium's keep only QUIC
packets; and aws-lc-rs seals TLS 1.2 records with `EVP_AEAD_CTX_seal_scatter`,
which is probed too. Testing found one more thing to fix: encryption
contexts' memory is reused by later connections, so a context's socket is
now only trusted while its fd still refers to the same socket. Everything below marked *verified* was checked on real binaries
while writing this; the rest is to confirm in the first step of each part.

## What was verified

- A tokio-rustls program built with rustls 0.23.46's default provider,
  aws-lc-rs, keeps `aws_lc_0_46_0_EVP_AEAD_CTX_open` and `_seal` as symbols
  in a release build, plus `aead_aes_gcm_open_gather` and the
  `MessageDecrypter`/`MessageEncrypter` trait implementations. `Reader::read`
  is gone (inlined), as HANDOFF.md says; `Writer::write` is still there.
- The same program built with ring 0.17.14 keeps
  `ring_core_0_17_14__chacha20_poly1305_open`/`_seal` (C ABI, BoringSSL's
  assembly) and the Rust functions `ring::aead::algorithm::aes_gcm_open`,
  `aes_gcm_seal`, `chacha20_poly1305_open` and `chacha20_poly1305_seal`.
- reqwest 0.12 picks ring (`rustls-tls` enables `__rustls-ring`); reqwest's
  main branch picks aws-lc-rs. So both providers matter for years.
- Fedora's curl 8.18 does HTTP/3 through ngtcp2 with
  `libngtcp2_crypto_ossl.so.0`, which exports `ngtcp2_crypto_decrypt`,
  `ngtcp2_crypto_encrypt` and `ngtcp2_crypto_hp_mask`. Debian trixie's and
  Ubuntu 26.04's curl have no HTTP/3 at all.
- A Go 1.25 binary using crypto/tls has
  `crypto/internal/fips140/aes/gcm.(*GCM).Open`/`Seal` and
  `vendor/golang.org/x/crypto/chacha20poly1305.(*chacha20poly1305).Open`/`Seal`.
  quic-go 0.64 decrypts 1-RTT packets in `(*updatableAEAD).Open(dst, src,
  rcvTime, pn, kp, ad)` and seals in `(*updatableAEAD).Seal(dst, src, pn,
  ad)`, with `longHeaderOpener`/`longHeaderSealer` for the handshake. It
  reads packets on one goroutine and decrypts them on another, and needs Go
  1.26.
- In `bpf/snoopy.c`, `recv_bufs` is keyed by (tgid, buffer address), not by
  thread, and `is_quic_aad` already recognizes TLS record headers (5 bytes,
  type 0x14 to 0x18, version 0x03xx) and TLS 1.2 associated data (13 bytes)
  in order to reject them.

## Part 0: one AEAD capture path

Today the AEAD probes keep QUIC packets and drop TLS records, because
`SSL_read`/`SSL_write` already cover Chrome's TLS. The foundation for
everything else is letting them keep TLS records too, for programs that have
no other plaintext boundary.

1. **Classify the associated data** instead of a yes/no: `AAD_QUIC`,
   `AAD_TLS13` (5-byte record header), `AAD_TLS12` (13 bytes: sequence,
   type, version, length), `AAD_OTHER`. Reuse the checks in `is_quic_aad`.
2. **Per-process switch.** A BPF map `aead_tls_tgids` (like `traced_tgids`)
   marks processes whose TLS is captured at the AEAD. User space sets it
   when it attaches an AEAD-only target (a rustls binary, a Go binary for
   QUIC only, see Part 2b) to the processes mapping that file. For other
   processes TLS records are dropped as now.
3. **TLS record plaintext.** For `AAD_TLS13` the decrypted record is
   `content || type || zero padding`: strip the padding, read the type, and
   keep only application data (0x17). Handshake (0x16, post-handshake
   tickets and key updates) and alerts (0x15) are dropped. For `AAD_TLS12`
   the type is byte 8 of the AAD and the plaintext is the content. Seal sees
   the plaintext at entry, open on return (`RET_BOOL_EX`, as now).
4. **Two new function ids**, `FN_AEAD_TLS_READ` and `FN_AEAD_TLS_WRITE`,
   emitted with the AEAD context as the connection handle and the fd from
   the existing heuristics: `recv_bufs` for decrypts, the thread's next send
   (`io_threads` and the socket notice) for encrypts. Records are at most
   16 KiB plus overhead, so they fit `CHUNK_SIZE`.
5. **User space:** the new ids are TLS reads and writes to the output
   package, which already decodes byte streams per (pid, connection). The
   context changes at a key update, so key the HTTP/2 decoder by fd when it
   is known, falling back to the context (the QUIC decoder does this today).
6. **Tests:** unit tests for the TLS 1.3 inner-plaintext parsing and the
   classifier; the integration tests of Parts 1 and 2 cover the rest.

About three to four days. Nothing user-visible changes until a later part
attaches to it, so it can merge on its own.

## Part 1: rustls

### 1a. aws-lc-rs (rustls 0.23's default provider)

aws-lc is a BoringSSL fork, and aws-lc-sys prefixes every C symbol with
`aws_lc_<version>_`. The functions have BoringSSL's signatures, so the
existing `EVP_AEAD_CTX_open`/`seal` BPF programs attach unchanged.

1. In `internal/discover`, when a binary has rustls symbols (what
   `inspectRustls` looks for today), also look for symbols ending in
   `_EVP_AEAD_CTX_open` and `_EVP_AEAD_CTX_seal`. They are local symbols, so
   read `.symtab`, not `.dynsym`. Found: a target with those offsets, flagged
   AEAD-only; not found: fall back to the `Reader::read`/`Writer::write`
   probes as today (sync programs built with ring still work that way).
2. Attach the AEAD programs at those offsets and add the process to
   `aead_tls_tgids`. Don't also attach `Writer::write` in that case, or every
   write would show twice.
3. The socket: tokio-rustls decrypts on the thread that just read the socket
   and encrypts on the thread about to write it, so the heuristics from
   Part 0 should give the fd. Verify with a multi-threaded tokio runtime,
   where a task can move between threads between the read and the decrypt.
4. Tests: a tokio-rustls client and a reqwest client in
   `internal/tracer/testdata`, built with cargo under `SNOOPY_TEST_RUSTLS=1`
   like `rustlsclient` is now, one with aws-lc-rs and one with ring; plus an
   `axum` server, since servers are the common deployment.

Two to three days. This is the part with the most users behind it.

### 1b. ring

ring's AEAD is reached through Rust functions whose ABI isn't stable, which
is the same footing as the current `Reader::read` probe (snoopy already
reads a Rust `io::Result<usize>` from two registers). Two candidates, to
settle with a day's spike using tracefs uprobes as in docs/maintenance.md:

- `ring::aead::algorithm::aes_gcm_open`/`seal` and
  `chacha20_poly1305_open`/`seal`: four functions, present in release builds,
  arguments are references and slices (pointer and length pairs). Likely
  stable across ring 0.17.x, and the names say which cipher.
- The assembly entry points `ring_core_<v>__chacha20_poly1305_open`/`seal`:
  C ABI with `(out, in, in_len, ad, ad_len, data)`, so trivially probeable,
  but AES-GCM has no equivalent single entry point (ring splits it into CTR
  and GHASH calls without the AAD), and AES-GCM is what most connections
  negotiate. So this only helps for ChaCha20.

Whichever wins, the symbol names carry ring's version, so discovery matches
by suffix, and docs/release-risks.md gets an entry: a ring release can move
the plaintext to other functions, which shows as rustls programs going
silent. Two to three days after the spike.

### 1c. Stripped Rust binaries

Cargo keeps symbols in release builds by default, so 1a and 1b cover most
programs. Binaries built with `strip = true` need the signature finding that
Chrome gets. aws-lc keeps BoringSSL's error strings and source file names,
so `findBoringSSL`'s approach should carry over with different anchors
(there is no `ssl/ssl_lib.cc` to key on). Not in this plan; note it as a
follow-up once 1a shows demand.

## Part 2: HTTP/3 outside browsers

### 2a. ngtcp2: curl on Fedora and RHEL, and anything else on ngtcp2

`ngtcp2_crypto_decrypt(dest, aead, aead_ctx, ciphertext, ciphertextlen,
nonce, noncelen, aad, aadlen)` and `ngtcp2_crypto_encrypt(dest, aead,
aead_ctx, plaintext, plaintextlen, nonce, noncelen, aad, aadlen)` are public
API, exported from `libngtcp2_crypto_ossl.so`, `_quictls`, `_gnutls`,
`_boringssl` and `_wolfssl` alike, and the AAD is the packet header.

1. Add `libngtcp2_crypto_*.so*` to `libPatterns`, and the two symbols to the
   NSS-style exported-symbol targets, so a curl that links them dynamically
   is attached to at startup and a static build is found through its symbol
   table.
2. Two BPF programs: encrypt captures `plaintext` at entry, decrypt captures
   `dest` on return with length `ciphertextlen - 16` (every QUIC AEAD has a
   16-byte tag) when the return value is 0. Nine arguments: on x86-64 the
   last three are on the stack, which `func_arg` already handles for the
   ten-argument BoringSSL functions. Both go through `is_quic_aad` and the
   existing QUIC send and receive paths, so the socket comes from the
   thread's last `recvmsg` or next `sendmsg`; curl is single-threaded, which
   is the easy case.
3. Tests: CI's Ubuntu runners have no HTTP/3 curl, so the integration test
   skips unless `curl --version` lists ngtcp2, and a scheduled job runs it in
   a Fedora container (privileged Docker on the runner works; the README's
   Docker example was tested that way). The test server can be quic-go's
   example server once 2b lands, or a public HTTP/3 site until then.

Two days.

### 2b. Go: quic-go, Caddy and friends

Go binaries keep function names in `.gopclntab`, which snoopy already reads
for stripped programs, and Go's QUIC libraries all encrypt through the
standard library's AEADs.

1. Probe the standard library, not quic-go: `(*GCM).Open`/`Seal` in
   `crypto/internal/fips140/aes/gcm` (Go 1.24 and later; `crypto/aes.(*gcmAsm)`
   and `crypto/cipher.(*gcm)` before) and `(*chacha20poly1305).Open`/`Seal`
   in the vendored `golang.org/x/crypto`. A table of names per Go version,
   resolved the way `tls.Conn` methods are now. This covers quic-go and any
   future Go QUIC library, and needs no quic-go version tracking.
2. Arguments: receiver plus four slices is thirteen words, more than the nine
   integer registers of Go's amd64 ABI, so the tail spills to the stack in
   ABIInternal's order; arm64 has sixteen and fits. Extend the Go argument
   reading (`GO_ARG1`, `GO_ARG2` today) with the spill rules; the Go ABI
   document specifies them and they are stable since Go 1.17. `Open` returns
   the plaintext slice in registers, read at the `RET` probes snoopy already
   places.
3. Classify the AAD as in Part 0: QUIC packets are events, TLS records are
   dropped, because `(*tls.Conn).Read` and `Write` already cover them.
4. The socket: quic-go decrypts on the connection's goroutine, not the one
   that called `recvmsg`, but it decrypts in place in the pooled receive
   buffer, and `recv_bufs` is keyed by process and buffer address, so the
   lookup should still match. Sends go through a separate send-queue
   goroutine, so there is no fd for them; the QUIC decoder already falls
   back to keying by AEAD context. Remote addresses can come later from
   `receivedPacket.remoteAddr` if the fd route doesn't pan out.
5. Tests: a quic-go client and server in `testdata`, like the Go TLS test.
   quic-go needs Go 1.26, so this part comes after the Go bump that
   Dependabot's #19 is waiting on.

Four to five days, the stack-spill handling being the uncertain piece.

### 2c. quiche (curl's other backend, Envoy)

quiche bundles BoringSSL, so the existing signature finder may locate its
AEAD functions as is; a day to try against a quiche-built curl. Not
scheduled.

### Not planned

msquic, picoquic and quicly (few Linux users), Node (no HTTP/3 in core),
Firefox's ChaCha20 (separate, small: freebl table entries 214 and 215).

## Order

1. Go 1.26 and the golangci-lint bump, merging #19 (prerequisite for 2b).
2. Part 0, as its own PR.
3. Part 1a. First user-visible win: reqwest on the main branch, hyper, axum,
   tonic with aws-lc-rs.
4. Part 2a. curl on Fedora.
5. Part 1b spike, then ring. Covers reqwest 0.12 and Deno.
6. Part 2b.
7. Docs: `docs/how-it-works.md` (supported libraries and the AEAD design),
   `docs/release-risks.md` (aws-lc's symbol prefix, ring's Rust ABI, Go's
   function names per release; ngtcp2 is stable API), `docs/maintenance.md`
   (how each was found, the tracefs recipes used).

About three weeks of the kind of work HTTP/3 took, with Part 0 plus 1a the
first thing worth shipping.

## Open questions for the spikes

- Does a multi-threaded tokio runtime ever decrypt on a different thread
  than the one that read the socket? (If so, `recv_bufs` still matches by
  buffer address; only the thread-based fallback would be wrong.)
- Which of ring's functions see every record without being inlined, across
  ring 0.17.8 to current.
- Whether rustls's own `MessageDecrypter::decrypt` implementations, present
  in both builds, are a better single probe point than the providers'
  functions: one set of names for both providers, at the cost of Rust ABI
  structs by pointer.
- Go: whether `recv_bufs` matches quic-go's pooled buffers in practice, and
  how often the GC moves them.
