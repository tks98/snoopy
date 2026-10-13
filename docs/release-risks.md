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
  to with a note saying so. A wrong but unique answer would put probes on the
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
- **How it shows:** the whole packet is rejected as not QUIC and shown as a
  hex dump. Its stream data is lost, so HTTP/3 decoding gets gaps.
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
- **How it shows:** Firefox's HTTP/3 stops appearing. Nothing says so.
- **Already seen:** on arm64, `AES_AEAD`'s 32-bit length came with garbage in
  the upper half of its stack slot, which dropped most packets until it was
  truncated. Ubuntu's x86-64 freebl starts `FREEBL_GetVector` with `endbr64`,
  which the decoder didn't know. `libfreebl3.so` turned out to be a loader
  stub, which broke CI.
- **Guarded by:** `TestFreeblBinaries`, run by hand.

### rustls

- **Depends on:** the mangled names of `Reader::read` and `Writer::write`,
  and Rust returning `io::Result<usize>` in two registers.
- **Breaks when:** rustls moves those types to other modules, or rustc
  changes how it returns that `Result`. Rust's ABI is explicitly unstable.
- **How it shows:** renamed symbols mean nothing attaches, which is loud. A
  changed return layout means wrong lengths or no data, which is quiet.
- **Already seen:** under tokio, `Reader::read` is inlined and writes are
  vectored, so async programs were never covered.
- **Guarded by:** `TestRustls`, only with `SNOOPY_TEST_RUSTLS=1`, and
  `TestRustlsSymbols`.

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

### Committed BPF objects

- **Depends on:** clang 18 producing byte-identical objects from
  `bpf/snoopy.c`.
- **Breaks when:** someone regenerates with another clang version.
- **How it shows:** CI's "BPF objects are up to date" check goes red.

## Low risk

- **TLS libraries with exported functions.** OpenSSL, GnuTLS, NSS, wolfSSL,
  Mbed TLS and s2n-tls are probed at public API functions.
- **The kernel side.** Socket and process details are read through BTF
  relocations, and syscall numbers are fixed per architecture. Linux 5.10,
  5.15, 6.1, 6.6 and 6.12 pass with the current program, and newer verifiers
  have only grown more lenient.
- **Protocols and compression.** HTTP/2 with HPACK, QPACK, and gzip, deflate,
  Brotli and zstd follow published standards. A new `Content-Encoding` shows
  a "can't decode" note.
- **freebl's function table.** Positions in it are NSS ABI and are only ever
  appended to.

A gap rather than a release risk: curl's own HTTP/3, through ngtcp2, isn't
captured at all.

## What to do about it

In order of how much each removes.

1. **Add a scheduled canary job.** Weekly in CI, download the latest Chrome
   stable and beta with Google's debug symbols, the latest Electron arm64
   with its Breakpad symbols, and Firefox, then run `TestBoringSSLBinaries`
   and `TestFreeblBinaries`. That turns the most likely breakage into a red
   check within a week of a release. Everything it needs exists except the
   workflow; [maintenance.md](maintenance.md#getting-browsers-and-their-symbols)
   has the download URLs.
2. **Check `golang.org/x/arch` bumps before merging them.** Run those
   signature tests against real arm64 binaries, or switch `arm64.go` and
   `freebl.go` to reading decoded fields instead of printed text.
3. **Make the QUIC parser keep what it parsed** before an unknown frame,
   instead of dropping the whole packet.
4. **Warn about the quiet failures.** For example, say so when snoopy is
   attached to a browser's QUIC functions but its connections keep showing
   stuck header blocks, or when it attached to Firefox's freebl but captured
   nothing while Firefox used UDP port 443.
