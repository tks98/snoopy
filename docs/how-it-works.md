# How snoopy works

What snoopy can trace, and how it does it.

## Supported libraries


| Library | Functions probed | Notes |
| --- | --- | --- |
| OpenSSL, BoringSSL, LibreSSL | `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex` | Also copies linked into a program that exports them, like Node.js. |
| BoringSSL in Chrome, Brave, Edge, Electron apps, Bun and Envoy | `SSL_read`, `SSL_write`, found by signature | No symbols, so the functions are recognized by what they do. Bun does its own socket I/O, so its events have no addresses; Envoy's HTTP/3 isn't traced. |
| HTTP/3 in Chrome, Brave, Edge and Electron apps | BoringSSL's `EVP_AEAD_CTX_seal`, `EVP_AEAD_CTX_open`, found by signature | Each QUIC packet, decrypted. |
| HTTP/3 in Firefox | freebl's `AES_CreateContext`, `AES_AEAD` | AES-GCM connections opened while snoopy runs. |
| HTTP/3 over quinn (Rust) | the same functions as for rustls's records, below | With rustls's aws-lc-rs and ring providers. |
| HTTP/3 over ngtcp2 (curl) | `ngtcp2_crypto_encrypt`, `ngtcp2_crypto_decrypt` | In each of ngtcp2's crypto libraries (OpenSSL, GnuTLS, wolfSSL, BoringSSL, quictls). |
| HTTP/3 over quic-go (Go) | Go's AES-GCM and ChaCha20-Poly1305 `Seal` and `Open` | Only in programs that use quic-go; stripped ones too. |
| GnuTLS | `gnutls_record_recv`, `gnutls_record_send` | |
| NSS (Firefox, Thunderbird) | `PR_Read`, `PR_Write`, `PR_Recv`, `PR_Send` | Also the copy bundled with Firefox. |
| wolfSSL | `wolfSSL_read`, `wolfSSL_write` | |
| Mbed TLS | `mbedtls_ssl_read`, `mbedtls_ssl_write` | 2.x and 3.x. |
| s2n-tls | `s2n_recv`, `s2n_send` | Not `s2n_sendv`. |
| rustls | aws-lc's `EVP_AEAD_CTX_seal` and `EVP_AEAD_CTX_open`, ring's `aes_gcm_seal`, `aes_gcm_open` and ChaCha20-Poly1305's, or `Reader::read` and `Writer::write` | Async (tokio) too, with the aws-lc-rs and ring providers; needs the program's symbols. |
| Go `crypto/tls` | `(*tls.Conn).Read`, `(*tls.Conn).Write` | Go 1.17+ on amd64, 1.18+ on arm64, stripped binaries too. |

All of them on x86_64 and arm64. Some details:

- **Chromium-based browsers and Electron apps** link BoringSSL without
  symbols, so snoopy recognizes its functions by the error codes they report
  (see [below](#chrome-and-other-stripped-boringssl-builds)). It attaches only if that gives one
  clear answer, and otherwise warns that the build can't be traced. This was
  checked against published debug symbols on Chrome 155 and 156 (x86_64) and
  Electron 42 and 44 (arm64), and on Brave 1.97, Edge 155 and Ubuntu's
  Chromium 155 snap (arm64). Browsers in their usual install locations are
  analyzed at startup, which takes a few seconds the first time, so they are
  traced from the moment they start; results are cached by build ID.
- **HTTP/3** is captured where each QUIC packet is encrypted and decrypted;
  the plaintext is the packet's frames, which snoopy reassembles into HTTP/3
  with QPACK-decoded headers. Firefox's QUIC stack (neqo) calls freebl's
  AES-GCM directly, through its exported function table. A Firefox connection
  that negotiates ChaCha20-Poly1305 isn't captured, and neither are those set
  up before snoopy started, since a context's direction is learned when it's
  created. Rust programs using quinn (reqwest's `http3`, h3) are captured
  where rustls's crypto provider encrypts and decrypts their packets, and
  curl's HTTP/3 (Fedora's curl has it; Ubuntu's doesn't) where ngtcp2's
  crypto library does. Go programs using quic-go (Caddy, Traefik, Go's
  `http3` clients) are captured where Go's AEADs encrypt and decrypt their
  packets.
- **NSS** functions are used for all kinds of files, so only layered
  descriptors (the SSL layer) are captured.
- **rustls** is seen where its crypto provider encrypts and decrypts each
  record, with its default provider, aws-lc-rs, and with ring (0.16 and
  0.17, so rustls 0.20 on), so
  async programs on tokio-rustls (`hyper`, `reqwest`, `axum`, `tonic`,
  Deno) are covered as well as synchronous ones. With any other provider,
  snoopy falls back to rustls's reader and writer, which works for programs
  that use them directly, such as `ureq` or `rustls::Stream`, but not under
  tokio, where the read path is inlined. All of them are found by their
  symbols, which Cargo keeps by default.

Programs that do their own socket I/O around the TLS library, such as .NET's
`SslStream` over OpenSSL, are captured without a file descriptor or addresses.

### Languages and runtimes

What common runtimes use for TLS, and whether snoopy sees it, as tested on
Ubuntu 26.04 (arm64) in October 2026, with each one fetching a page over
HTTPS:

| Runtime | TLS | Traced |
| --- | --- | --- |
| curl | the system's OpenSSL | yes |
| Python, Ruby, PHP | the system's OpenSSL | yes |
| Node.js, distribution packages | the system's OpenSSL | yes |
| Node.js, official builds and `node` images | OpenSSL built into the `node` binary | yes; `--comm node` matches it by its file name, since it calls itself `MainThread` |
| .NET | the system's OpenSSL, around its own socket I/O | yes, without socket addresses |
| Go | `crypto/tls` | yes, stripped binaries too |
| Rust | rustls, or OpenSSL through the `openssl` crate | yes (see above for rustls) |
| Bun | BoringSSL, built in | yes |
| Chrome, Firefox, Electron apps | BoringSSL, NSS | yes, HTTP/3 too |
| Deno | rustls, in a stripped binary | no: rustls is found by its symbols |
| Java with Netty's netty-tcnative (gRPC-Java and Netty, when it's there) | BoringSSL in a JNI library, extracted to a temporary file | yes, found when the JVM loads it, however late |
| Java with Conscrypt | BoringSSL in a JNI library, stripped | yes, found by signature |
| Java (OpenJDK), otherwise | JSSE, written in Java | with `--java`, through snoopy's agent ([below](#java-and-jsse)) |
| Erlang, Elixir | OTP's `ssl`, written in Erlang | no |

A TLS library a process loads after it started, such as the ones a JVM
extracts and loads the first time it needs TLS, is found when it's mapped:
the BPF program tells user space when a process it traces maps a file whose
name is a TLS library's, and with `--comm`, `--pid` or `--container` the
thread that loaded it is held until snoopy has attached to it, so its first
connection isn't missed.

Not supported: rustls under tokio with providers other than aws-lc-rs and
ring, Erlang's `ssl`, stripped TLS
libraries other than
BoringSSL, QUIC/HTTP/3 outside Chromium, Firefox, quinn, ngtcp2 and quic-go (quiche, for
example), programs that use OpenSSL only through its BIO layer (e.g.
`openssl s_server -www`), and bodies compressed with a shared dictionary
(Chrome's `dcb` and `dcz`), which are shown as sent.


## Tracing calls

1. snoopy finds the files to probe: shared libraries in the usual system
   directories, the libraries and executables mapped by running processes
   (reached through `/proc/<pid>/root`, which also covers containers), and any
   `--lib` paths. While it runs, a `sched_process_exec` tracepoint reports
   new programs, whose files are inspected the same way.
2. A uprobe on each read/write function records the buffer pointer and the
   connection handle. A return probe copies the bytes actually transferred
   into a ring buffer, in chunks of up to 16 KiB. Go programs can't use return
   probes, because Go moves goroutine stacks, so snoopy disassembles the
   function and puts a probe on each `RET` instruction instead.
3. A `sys_enter` tracepoint records which socket each TLS call uses. Socket
   addresses are read from the kernel's `struct sock`, located with CO-RE
   (BTF-based relocation) so one compiled program works on every kernel
   version.
4. User space reassembles the chunks and adds the container ID.

## Chrome and other stripped BoringSSL builds

Stripped programs that link BoringSSL statically, like Chrome, have no
`SSL_read` or `SSL_write` symbols, so snoopy recognizes the functions by what
they do (`internal/funcfind`). BoringSSL reports errors with the source file's
name and a reason code, and those codes are fixed constants. Among the
functions that load the address of `ssl/ssl_lib.cc`, `SSL_write` is the one
that reports "bad length" besides "uninitialized" and "protocol is shutdown",
and `SSL_read` reports "uninitialized", "protocol is shutdown" and "should not
have been called", counting the BoringSSL functions they call (the compiler
inlines differently from build to build). Both must take three arguments,
which rules out callers that BoringSSL code was inlined into. Function starts
are direct call targets (with a frame pointer prologue, on x86_64). If any of
this doesn't give exactly one answer for each function, snoopy doesn't
attach.

## HTTP/3

QUIC (HTTP/3) encrypts each packet separately, with the packet's header as
associated data, so snoopy captures packets where they're encrypted and
decrypted: BoringSSL's `EVP_AEAD_CTX_seal` and `EVP_AEAD_CTX_open` in Chrome,
freebl's `AES_AEAD` in Firefox. The same functions protect TLS records, whose
associated data looks different. None of them touch the socket. A received
packet is usually decrypted from the buffer it was received into, so for
threads that decrypt packets the BPF program remembers which socket each
receive buffer was last filled from, and otherwise uses the thread's last
receive. A packet is sent just after it's encrypted, so the thread's next
send tells its connection's socket; when the BPF program learns a socket that
way, it sends user space a notice, and packets that went out before it are
held back until then (rustls's writes work the same way). User space
reassembles each direction's streams per socket, across the encryption keys a
connection goes through and the sockets it migrates to, and decodes the
HTTP/3 frames and QPACK headers.

quinn runs all of a program's connections over one UDP socket that isn't
connected, so neither the socket nor the thread tells a packet's connection
or peer. Its packets' connection IDs do: each event carries its packet's
header, and user space learns each connection's IDs from its handshake
packets (whose long headers have both sides' IDs) and the NEW_CONNECTION_ID
frames it sends and receives, then matches each packet by the ID in its
header. quinn encrypts a packet where it's then sent from, so a send whose
buffer starts at a packet the BPF program saw encrypted gives the packet's
socket, and its destination is sent to user space with the packet's header,
which tells whose peer it is. Connections whose handshake wasn't seen, or
that use zero-length IDs, are followed by their socket as before.

## TLS records

Where a program's plaintext has no read or write function to probe, snoopy
reads it where each TLS record is encrypted and decrypted, as it does for
QUIC packets. For rustls on aws-lc-rs, that's aws-lc's `EVP_AEAD_CTX_seal`
(TLS 1.3), `EVP_AEAD_CTX_seal_scatter` (TLS 1.2) and `EVP_AEAD_CTX_open`.
For rustls on ring, it's ring's `aes_gcm_seal` and `aes_gcm_open` and their
ChaCha20-Poly1305 counterparts, Rust functions that ring calls through
function pointers, so they aren't inlined. They encrypt and decrypt in
place, and ring's `open` leaves checking the tag to its caller, so a forged
record would show as whatever it decrypts to.
The associated data tells a record from a QUIC packet: a TLS 1.3 record's
is its 5-byte header, a TLS 1.2 record's is 13 bytes with the content type
in it. A TLS 1.3 record's real type is the last non-zero byte of its
plaintext, after the content and before any padding; only application data
is shown, so handshake messages and alerts are left out. The socket comes
from the same per-thread bookkeeping as for QUIC, and both directions of a
connection, which have separate encryption contexts, are tied together by
their socket. An encryption context's memory is often reused for the next
connection, so what's known about a context's socket is only trusted while
its fd still refers to the same socket.

## Java and JSSE

Java's own TLS, SunJSSE, is Java code that the JIT compiles: there's no
library to put uprobes on, and its functions move as the JIT pleases. So
with `--java`, snoopy has the JVM tell it instead, through a small
`java.lang.instrument` agent (`java/agent`):

1. snoopy checks the process maps `libjvm.so`, copies the agent's two jars
   into its `/tmp` (so a JVM in a container can read them), and registers a
   session for it with the BPF program: its PID and a random nonce.
2. It loads the agent with HotSpot's attach mechanism, in Go
   (`internal/javaagent`), with no JDK needed where snoopy runs: an attach
   file, a SIGQUIT, and a request over the JVM's attach socket. For a JVM
   that isn't root's, the socket is connected to as the JVM's user, on a
   thread of its own, since the JVM checks who connects, and in a user
   namespace root is no one.
3. The agent instruments, with ASM, the methods where application data
   goes in and out of SunJSSE: `SSLSocketImpl`'s `AppInputStream.read` and
   `AppOutputStream.write`, and `SSLEngineImpl`'s `wrap` and `unwrap` (the
   six-argument ones, which the others call). On each call's return, the
   added code copies what was read or written (for the engine, what `wrap`
   consumed from its sources and `unwrap` produced into its destinations,
   from their positions at entry, without moving them) into a frame, a
   header and the bytes, and writes it to `/dev/null`.
4. The BPF program's `sys_enter` sees each write of a registered process:
   one that starts with the frame's magic and the session's nonce, and with
   BTF, is to the null device, is turned into events like a library call's,
   and kept out of the socket tracking. User space doesn't tell them apart
   from any other library's from there.

`SSLSocket` events carry the socket's addresses, from the agent. `SSLEngine`
isn't tied to a socket (it's what `java.net.http.HttpClient`, Netty without
tcnative and most servers use), so its events have none.

When snoopy stops, it tells the agent to stop capturing. The agent can't be
unloaded: its hooks stay in the JVM, checking a flag and doing nothing else,
until it exits, and a later snoopy turns them on again with a new nonce.

## The code

The eBPF program is `bpf/snoopy.c`. It is compiled with `bpf2go` into the
`internal/tracer/snoopy_*_bpfel.{o,go}` files, which are committed so that a
plain `go build` works. The Java agent is in `java/`, built into two jars by
`java/build.sh` (releases and the image ship them), and `internal/javaagent`
loads it.

Some of this depends on other programs' internals, which their new releases
can change. [release-risks.md](release-risks.md) lists what's likely
to break and how it would show, and [maintenance.md](maintenance.md)
explains how each of those parts was found and how to fix it when it breaks.

## References


- https://www.airplane.dev/blog/decrypting-ssl-at-scale-with-ebpf
- https://medium.com/@yunwei356/ebpf-practical-tutorial-capturing-ssl-tls-plain-text-using-uprobe-fccb010cfd64
- https://github.com/eunomia-bpf/bpf-developer-tutorial
- https://www.datadoghq.com/blog/ebpf-guide/
- https://blog.px.dev/ebpf-openssl-tracing/
- https://github.com/cilium/ebpf
