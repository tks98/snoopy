# Release risks

What in snoopy breaks when the things it traces ship new releases, how each
failure shows up, and what guards against it. [maintenance.md](maintenance.md)
has how each piece was found and how to fix it when it breaks.

Most of snoopy rests on stable ground: exported library APIs, kernel types
relocated through BTF, and protocol standards. The brittle parts are the ones
that reach browsers and Rust by inference: functions recognized from their
code, sockets worked out from how threads behave, and internal struct layouts.
For each of those, what matters most is how it fails:

- **Loud:** snoopy doesn't attach, or a CI check goes red. Someone notices.
- **Quiet:** data goes missing or lands in the wrong place, with no error.
  Nobody may notice.
- **Partial:** something visible changes, like hex dumps where HTTP/3 should
  be, but nothing says why.

## At a glance

Roughly from most to least likely to break soon. The cadence is how often the
thing it depends on ships.

| Piece | Changed by | Cadence | Failure |
| --- | --- | --- | --- |
| [Chrome and Electron found by signature](#chrome-and-electron-found-by-signature) | Chromium releases, distro builds | every 4 weeks | Loud |
| [Which socket a QUIC packet belongs to](#which-socket-a-quic-packet-belongs-to) | Browser networking internals | unpredictable | Quiet |
| [QUIC frame parser](#quic-frame-parser) | New QUIC extensions | occasional | Partial |
| [Firefox HTTP/3 through freebl](#firefox-http3-through-freebl) | neqo's choice of crypto | rare | Quiet |
| [rustls](#rustls) | rustls internals, rustc | 6 weeks (Rust) | Loud, or quiet |
| [Go crypto/tls](#go-cryptotls) | Go's internal structs, pclntab | 6 months | Mostly loud |
| [Java's JSSE (`--java`)](#javas-jsse---java) | OpenJDK's `sun.security.ssl` internals, class file versions | 6 months | Quiet |
| [arm64 analysis in funcfind](#arm64-analysis-in-funcfind) | `golang.org/x/arch` updates | per bump | Partial |
| [Committed BPF objects](#committed-bpf-objects) | clang version | on regenerate | Loud |

## The fragile pieces

### Chrome and Electron found by signature

- **Depends on:** BoringSSL's source file names (`ssl/ssl_lib.cc`,
  `cipher/aead.cc.inc`), its reason codes, what the compiler inlines into
  what, frame pointer prologues on x86-64, argument counts (ten for the AEAD
  functions), and branch-protection markers on arm64.
- **Breaks when:** a Chromium release or a different builder inlines
  differently, BoringSSL renames a file (it went from `.c` to `.cc` once), or
  a build drops frame pointers.
- **How it shows:** the finder needs exactly one candidate for each function,
  so a change usually leaves none, and snoopy warns that the build can't be
  traced and why. A build whose HTTP/3 functions weren't found is attached
  to with a warning saying so. A wrong but unique answer would put probes on the
  wrong function, and answers are cached by build ID until
  `boringSSLCacheVersion` is bumped.
- **Already seen:** Chrome 156 stopped inlining `ssl_read_impl` into
  `SSL_read`. Ubuntu's Chromium snap keeps `EVP_AEAD_CTX_open_gather`
  separate, where Google's and Electron's builds inline it, so the rule
  telling seal from open had to change.
- **Guarded by:** `TestBoringSSLBinaries` against published symbols, run by
  hand.

### Which socket a QUIC packet belongs to

- **Depends on:** browsers decrypting a packet from the buffer it was
  received into, and sending a packet right after encrypting it, on the same
  thread. The crypto functions never touch the socket themselves.
- **Breaks when:** a browser moves packet I/O to another thread, batches
  sends across connections, or copies packets somewhere else before
  decrypting them.
- **How it shows:** packets are filed under the wrong connection or under
  none. You see header blocks waiting for QPACK encoder stream data and gaps
  in bodies, not an error.
- **Already seen:** Chrome reads packets in batches and yields between them,
  and holds back packets that arrive before their keys, so the thread's last
  receive was sometimes another connection's. Chrome's Mojo IPC sockets and
  event-loop wakeups also polluted the guess, until only network sockets
  counted.
- **Guarded by:** nothing automatic. The browser runs are done by hand.

### QUIC frame parser

- **Depends on:** knowing every frame type, because QUIC frames carry no
  general length field, so an unknown frame can't be skipped.
- **Breaks when:** a browser or server starts sending an extension frame
  snoopy doesn't know.
- **How it shows:** the frames before the unknown one are kept, and the
  packet's frame line ends with `(unknown frame type 0x...; the rest of the
  packet isn't shown)`. Stream data after it is lost, so HTTP/3 decoding
  can get gaps. A packet that starts with an unknown frame is rejected as
  not QUIC and shown as a hex dump.
- **Already seen:** not yet. `ACK_FREQUENCY`, `IMMEDIATE_ACK` and `DATAGRAM`
  are handled.
- **Guarded by:** unit tests, for the frames snoopy knows.

### Firefox HTTP/3 through freebl

- **Depends on:** neqo, through the `nss_rs` crate, calling freebl's
  `AES_CreateContext` and `AES_AEAD` through function pointers. The table
  snoopy reads them from is NSS ABI and safe; the risk is Firefox's choice of
  crypto.
- **Breaks when:** Mozilla moves neqo to another crypto backend, or a
  connection negotiates ChaCha20-Poly1305, which snoopy doesn't probe.
- **How it shows:** Firefox's HTTP/3 stops appearing. Nothing says so;
  the warning about connections opened before snoopy only covers those.
- **Already seen:** on arm64, `AES_AEAD`'s 32-bit length came with garbage in
  the upper half of its stack slot, which dropped most packets until it was
  truncated. Ubuntu's x86-64 freebl starts `FREEBL_GetVector` with `endbr64`,
  which the decoder didn't know. `libfreebl3.so` turned out to be a loader
  stub, which broke CI.
- **Guarded by:** `TestFreeblBinaries`, run by hand.

### rustls

- **Depends on:** with rustls's default provider, aws-lc-rs: aws-lc-sys
  naming its C functions `aws_lc_<version>_EVP_AEAD_CTX_seal` and so on, and
  aws-lc-rs calling `seal` for TLS 1.3, `seal_scatter` for TLS 1.2 and
  `open` for both, without one of them calling another's exported symbol.
  With ring: the mangled names of `ring::aead::algorithm::aes_gcm_seal` and
  the like (ring 0.17; `ring::aead::aes_gcm::aes_gcm_seal` and the like in
  0.16, whose open takes its arguments in another order), ring calling them through function pointers (so they aren't
  inlined), and their arguments' places, which depend on Rust returning
  their `Result<Tag, Unspecified>` through a hidden pointer. With other
  providers: the mangled names of `Reader::read` and `Writer::write`, and
  Rust returning `io::Result<usize>` in two registers.
- **Breaks when:** aws-lc-sys changes its prefix, or aws-lc-rs moves to other
  AEAD functions; ring renames or reorganizes `aead::algorithm` (ring 0.18,
  or changing those functions' arguments); rustls moves `Reader` and `Writer`, or rustc changes how it
  returns that `Result`. Rust's ABI is explicitly unstable.
- **How it shows:** renamed symbols mean nothing attaches, which is loud,
  except that a program with rustls but neither provider's functions found
  falls back to the reader and writer, so under tokio only its writes show.
  Moved arguments in ring's functions mean garbage or nothing, quietly. Another
  AEAD function for one TLS version loses that direction's data quietly, as
  TLS 1.2's requests were before `seal_scatter` was probed. A changed return
  layout means wrong lengths or no data, which is quiet.
- **Already seen:** under tokio, `Reader::read` is inlined and writes are
  vectored, so async programs weren't covered until records were read at
  aws-lc. aws-lc-rs seals TLS 1.2 records with `seal_scatter`, not `seal`.

- **Guarded by:** `TestRustls` and `TestRustlsAsync` (TLS 1.3 and 1.2), only
  with `SNOOPY_TEST_RUSTLS=1`, and `TestRustlsSymbols` and
  `TestAwsLCSymbols`.

### HTTP/3 over quinn

- **Depends on:** what rustls's records depend on (above), and quinn
  encrypting each packet in the buffer it's then sent from, starting with
  its header, with `sendmsg` or `sendto` to an address; packets' connection
  IDs not being zero-length.
- **Breaks when:** quinn copies packets into another buffer before sending
  them, or connects its socket (which would be fine: the kernel would know
  the peer).
- **How it shows:** responses show "peer" for the remote address, and
  connections sharing a socket may be decoded mixed together, quietly.
- **Guarded by:** `TestQuinnHTTP3` (`SNOOPY_TEST_RUSTLS=1`), two
  connections over one socket with each provider.

### HTTP/3 over ngtcp2 (curl)

- **Depends on:** ngtcp2's crypto library exporting `ngtcp2_crypto_encrypt`
  and `ngtcp2_crypto_decrypt` with their current arguments, which is public
  API; `ngtcp2_crypto_aead` starting with the cipher and then its tag size;
  and ngtcp2 encrypting packets through them rather than through the TLS
  library directly.
- **Breaks when:** ngtcp2 changes that API (a major version), or curl moves
  to another QUIC stack (it also builds with quiche and OpenSSL's own QUIC,
  which would need their own probes).
- **How it shows:** renamed functions mean nothing attaches, which is loud;
  a changed `ngtcp2_crypto_aead` means wrong lengths, quietly.
- **Guarded by:** `TestCurlHTTP3`, only with `SNOOPY_TEST_CURL_HTTP3` set to
  the root of a system with an HTTP/3 curl (Fedora's).

### HTTP/3 over quic-go

- **Depends on:** Go's AES-GCM being `crypto/internal/fips140/aes/gcm.(*GCM)`
  (since Go 1.24) and ChaCha20-Poly1305 being x/crypto's, with `Seal` and
  `Open` taking the receiver and four slices in Go's register ABI; quic-go
  calling them for every packet, and having
  `internal/handshake.(*updatableAEAD).Open`, which marks a program as
  using it; and, as with quinn, packets encrypted in the buffer they're sent
  from.
- **Breaks when:** Go moves or renames the AEAD types (it did in 1.24), or
  changes how many arguments go in registers; quic-go renames that function
  or stops using the standard library's AEADs.
- **How it shows:** renamed functions mean the program is attached to only
  for its TLS connections, and its HTTP/3 doesn't show, quietly. Moved
  arguments mean nothing or garbage.
- **Guarded by:** `TestQuicGoHTTP3`, in CI, which builds the quic-go program
  in `internal/tracer/testdata/quicgo` with the latest quic-go it was
  updated to.

### Go crypto/tls

- **Depends on:** offsets from `tls.Conn` down to the socket fd (8, 0, 16,
  with family and socket type at 56 and 64), Go's stack-check prologue, and
  the `.gopclntab` format for stripped binaries.
- **Breaks when:** a Go release reshuffles `internal/poll`, changes the
  prologue, or adds a pclntab version. There have been four formats so far.
- **How it shows:** the fd sanity check falls back to "no socket". An unknown
  prologue or pclntab format refuses to attach.
- **Already seen:** `runtime.morestack` restarting a function made one call
  look like two, until the entry probe moved past the stack check.
- **Guarded by:** integration tests in CI, for the Go version CI builds with.

### arm64 analysis in funcfind

- **Depends on:** parsing the printed form of `golang.org/x/arch`'s arm64
  instructions in a few places: stack offsets and immediates in
  `internal/funcfind/arm64.go` and `internal/discover/freebl.go`.
- **Breaks when:** an `x/arch` update changes that formatting.
- **How it shows:** stack arguments aren't counted, so `EVP_AEAD_CTX_seal`
  and `open` aren't found and arm64 Chromium loses HTTP/3 while TLS keeps
  working. On arm64 freebl, the function table isn't found.
- **Guarded by:** `TestArm64`, which runs in CI on hand-assembled code and
  would catch a change in what it covers. The freebl parsing is only checked
  by hand.

### Java's JSSE (`--java`)

- **Depends on:** SunJSSE's internal classes keeping their shape:
  `sun.security.ssl.SSLSocketImpl$AppInputStream.read(byte[], int, int)`
  and `$AppOutputStream.write(byte[], int, int)` with the `this$0` field
  for their socket, and `SSLEngineImpl`'s six-argument `wrap` and `unwrap`,
  which the shorter ones call. Also ASM knowing the JDK's class file
  version, and HotSpot's attach protocol.
- **Breaks when:** a JDK renames or restructures those methods, has the
  shorter `wrap`/`unwrap` stop going through the six-argument ones, or
  ships a class file version the agent's ASM doesn't read.
- **How it shows:** a missing method is quiet in the agent, which only
  instruments what matches, so `--java` loads and then captures nothing
  for that path; a class file version ASM doesn't know makes the agent
  print "not instrumenting" on the JVM's stderr. A changed delegation could
  capture an engine call twice or not at all.
- **Already seen:** nothing yet; the shapes are the same in 17, 21 and 25.
- **Guarded by:** `TestJSSE`, in CI for JDK 17, 21 and 25 on x86-64 and
  arm64, which checks bytes captured exactly once; and the kind e2e's Java
  pod. A new JDK release needs adding there.

### Committed BPF objects

- **Depends on:** clang 18 producing byte-identical objects from
  `bpf/snoopy.c`.
- **Breaks when:** someone regenerates with another clang version.
- **How it shows:** CI's "BPF objects are up to date" check goes red.

## Low risk

- **TLS libraries with exported functions.** OpenSSL, GnuTLS, NSS, wolfSSL,
  Mbed TLS and s2n-tls are probed at public API functions.
- **The kernel side.** Socket and process details, and a process's parents
  for `--pid`, are read through BTF relocations, and syscall numbers are
  fixed per architecture. Linux 5.10,
  5.15, 6.1, 6.6 and 6.12 pass with the current program, and newer verifiers
  have only grown more lenient.
- **Protocols and compression.** HTTP/2 with HPACK, QPACK, and gzip, deflate,
  Brotli and zstd follow published standards. A new `Content-Encoding` shows
  a "can't decode" note.
- **freebl's function table.** Positions in it are NSS ABI and are only ever
  appended to.


## What to do about it

In order of how much each removes.

1. **Done: a scheduled canary job.** Every Monday, `.github/workflows/canary.yml`
   downloads the latest Chrome stable and beta with Google's debug symbols,
   the latest Electron (x86-64 and arm64) with its Breakpad symbols, Bun and
   Envoy (checked for one clear answer, having no matching symbols), and
   Firefox (x86-64 and arm64) with Mozilla's, and runs `TestBoringSSLBinaries`
   and `TestFreeblBinaries` on them; and it runs `TestCurlHTTP3` against
   Fedora's latest curl on both architectures. A release that breaks one of
   them shows as a failed run within a week. When a release's symbols
   aren't out yet, the job only checks that one answer is found, and warns.
2. **Check `golang.org/x/arch` bumps before merging them.** Run those
   signature tests against real arm64 binaries, or switch `arm64.go` and
   `freebl.go` to reading decoded fields instead of printed text.
3. **Done: the QUIC parser keeps what it parsed** before an unknown frame,
   instead of dropping the whole packet.
4. **Done: warnings for the quiet failures.** snoopy warns about Firefox's
   QUIC connections from before it started; about a program whose UDP
   traffic on port 443 had none of its QUIC packets captured, which is how a
   browser's or library's changed QUIC path would show; about a tokio
   program whose rustls provider isn't aws-lc-rs or ring, and a quic-go
   program whose AEADs weren't found, when attaching; and about headers that
   can't be decoded because their connection started before snoopy. The
   maintenance guide's "Which part broke?" table lists them.
