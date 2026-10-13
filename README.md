# snoopy

snoopy shows the plaintext of TLS connections on a Linux machine, without
certificates, proxies or changes to the applications. It uses eBPF uprobes on
the functions applications call to send and receive data through their TLS
library, so it sees the data before it is encrypted and after it is decrypted.

```console
$ sudo snoopy
snoopy: attached to openssl /usr/lib/x86_64-linux-gnu/libssl.so.3
snoopy: attached to gnutls  /usr/lib/x86_64-linux-gnu/libgnutls.so.30.37.1
snoopy: attached to nss     /usr/lib/x86_64-linux-gnu/libnspr4.so
snoopy: attached to go      /proc/5078/root/usr/local/bin/api-server (go1.24.7)
snoopy: tracing; press Ctrl-C to stop
00:27:03.731924 curl (pid 5565) SSL_write → 127.0.0.1:8444  84 bytes  134µs  fd 5, conn 0x55afcecfdf80
GET /curl-h1 HTTP/1.1
Host: 127.0.0.1:8444
User-Agent: curl/8.5.0
Accept: */*

00:27:03.776086 curl (pid 5565) SSL_read ← 127.0.0.1:8444  145 bytes  103µs  fd 5, conn 0x55afcecfdf80
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.13.16
Content-Type: application/json
Content-Length: 35

16:21:30.061843 curl (pid 754998) SSL_read ← 104.20.23.154:443  171 bytes  127µs  fd 5, conn 0xbe9168ce6300
HTTP/2 HEADERS stream=1 length=162 [END_HEADERS]
:status: 200
content-type: text/html; charset=utf-8
server: cloudflare
...

20:38:45.316878 chrome (pid 14779, tid 14792) EVP_AEAD_CTX_open ← 172.66.147.243:443  553 bytes  53µs  fd 30, conn 0x1f5400297058
QUIC: STREAM id=0 off=0 len=548 FIN
HTTP/3 HEADERS stream=0
:status: 200
content-type: text/html; charset=utf-8
content-encoding: br
...
HTTP/3 DATA stream=0 (334 bytes)
[br: 334 bytes decoded to 577]
<!doctype html><html lang=en><head><meta charset=utf-8>...<title>Example Domain</title>...
```

## Features

- **Libraries:** OpenSSL (also BoringSSL and LibreSSL), GnuTLS, NSS, wolfSSL,
  Mbed TLS, s2n-tls, rustls (synchronous use) and Go's `crypto/tls`,
  including stripped Go binaries, and the stripped BoringSSL inside Chrome,
  other Chromium-based browsers and Electron apps, on x86_64 and arm64.
- **HTTP/3:** the QUIC traffic of Chrome, other Chromium-based programs and
  Firefox, captured where each packet is encrypted and decrypted.
- **Finds what to trace:** system libraries, libraries loaded by running
  processes (including inside containers, and copies that an upgrade has
  since replaced), Go programs, and anything you point it at with `--lib`.
  Programs and containers started while snoopy runs are picked up as they
  start.
- **Tunnels:** traffic sent through an HTTPS proxy shows up as plaintext,
  not as the TLS records sent to the proxy.
- **Connection details:** process, thread, socket and local and remote
  address for every call, plus the container ID when the process runs in one.
- **Readable output:** HTTP/1.x is pretty-printed, HTTP/2 and HTTP/3 are
  shown frame by frame with their headers decoded (HPACK, QPACK), bodies
  compressed with gzip, deflate, Brotli or zstd are shown decompressed as
  they arrive, and binary data is hex-dumped. With
  `--json` you get one JSON object per line instead.
- **Wireshark:** `--pcap` writes the plaintext as TCP streams so Wireshark
  can dissect the application protocol.
- **Single static binary:** the eBPF program is compiled ahead of time and
  embedded. The target machine needs no compiler, kernel headers or BCC.

## Requirements

- Linux 5.10 or later on x86_64 or arm64. CI tests the current kernels of
  GitHub's x86_64 and arm64 runners; 5.10, 5.15, 6.1, 6.6 and 6.12 have been
  tested in VMs (see [Development](#development)), and 5.8 and 5.9 should
  work but aren't tested.
- Root. The minimal set of capabilities is `CAP_BPF`, `CAP_PERFMON`,
  `CAP_SYS_RESOURCE` and `CAP_SYS_PTRACE` (to inspect other processes), plus
  `CAP_SYS_ADMIN` to trace libraries that were replaced while in use.
- Kernel BTF (`/sys/kernel/btf/vmlinux`), which most distributions have
  shipped since around 2020. Without it snoopy still works, but it looks
  socket addresses and process names up in `/proc`, which misses connections
  and processes that end quickly.

## Install

Download a binary from the [releases page](https://github.com/tks98/snoopy/releases),
or build from source with Go 1.25+:

```bash
go install github.com/tks98/snoopy@latest
# or
git clone https://github.com/tks98/snoopy && cd snoopy && make build
```

## Usage

```bash
sudo snoopy                         # everything, as text
sudo snoopy --pid 1234              # one process
sudo snoopy --comm curl             # processes named curl
sudo snoopy --container 4b825dc642  # one container (ID prefix)
sudo snoopy --json | jq 'select(.direction == "write") | .data'
sudo snoopy --max-size 1048576      # capture up to 1 MiB per call (default 16 KiB)
sudo snoopy --lib /usr/bin/node     # also attach to a binary with OpenSSL linked in
```

| Flag | Description |
| --- | --- |
| `--pid N` | Trace only this process. |
| `--comm NAME` | Trace only processes with exactly this name, as in `/proc/<pid>/comm` (at most 15 characters). |
| `--container ID` | Trace only processes in this container, given as an ID or ID prefix. |
| `--lib PATH` | Also attach to this library or executable. Can be repeated. |
| `--no-scan` | Don't scan running or newly started processes; attach only to system libraries and `--lib`. |
| `--json` | Print one JSON object per line. |
| `--hex` | Always hex-dump payloads as captured, without decoding HTTP. |
| `--max-size N` | Maximum bytes captured per call, up to 1 MiB. Defaults to 16384. |
| `--pcap FILE` | Also write the plaintext to a pcap file; `-` writes it to stdout. |
| `--quiet` | Don't print events. Useful with `--pcap`. |
| `--no-color` | Disable colors. Colors are also off automatically when stdout isn't a terminal. |
| `--verbose` | List the functions attached in each file. |
| `--version` | Print the version. |

snoopy also watches for programs that start while it runs and attaches to
the TLS libraries and Go programs they use. It looks at a new process right
after its `exec` and again after 50 ms, 500 ms and 3 s, since shared libraries
are loaded after the `exec`. TLS calls a new program makes before then are
missed, unless it uses a library snoopy was already attached to, such as the
system `libssl`. With `--pid`, only that process is traced and nothing new is
picked up.

### Wireshark

`--pcap` turns each TLS connection into a synthetic TCP stream that carries the
plaintext, using the real addresses where they are known. Wireshark expects
TLS on port 443, so tell it the stream holds the application protocol:

```bash
sudo snoopy --quiet --pcap capture.pcap
wireshark -d tcp.port==443,http capture.pcap      # or http2

# or watch live
sudo snoopy --pcap - | wireshark -k -i - -d tcp.port==443,http
```

### JSON output

Each line is one call to a TLS read or write function:

```json
{"time":"2026-10-12T00:27:49.234626041Z","function":"SSL_write","library":"openssl","direction":"write","process_name":"curl","pid":5919,"tid":5919,"conn_id":"0x55e3c74a8f80","fd":5,"local_addr":"127.0.0.1:46780","remote_addr":"127.0.0.1:8444","latency_ns":83685,"size":84,"captured":84,"data":"GET /curl-h1 HTTP/1.1\r\nHost: 127.0.0.1:8444\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"}
```

| Field | Description |
| --- | --- |
| `time` | When the call returned. |
| `function`, `library` | The traced function, e.g. `SSL_read`, `EVP_AEAD_CTX_open` or `AES_AEAD (decrypt)` (QUIC packets), and its library: `openssl`, `gnutls`, `nss`, `wolfssl`, `mbedtls`, `s2n`, `rustls` or `go`. |
| `direction` | `read` (received from the peer) or `write` (sent to it). |
| `process_name`, `pid`, `tid` | The calling process and thread. |
| `container_id` | The container the process runs in, if any. |
| `conn_id` | The library's handle for the connection (`SSL*`, `gnutls_session_t`, `PRFileDesc*`, `WOLFSSL*`, `mbedtls_ssl_context*`, `struct s2n_connection*` or `*tls.Conn`). Stays the same for the lifetime of a connection; a library may reuse it for a later connection. For QUIC packets it is the encryption context, of which a connection uses several. |
| `fd`, `local_addr`, `remote_addr` | The socket, if known. |
| `latency_ns` | Time spent inside the call. |
| `size` | Bytes the call transferred. |
| `captured` | Bytes captured; less than `size` when `truncated` is set (see `--max-size`). |
| `incomplete` | Set when part of the payload was dropped because the ring buffer was full. |
| `read_error` | Set when the payload couldn't be read from the process's memory. |
| `data` / `data_base64` | The captured bytes: as a string if they are valid UTF-8, otherwise base64. |
| `http2` | The HTTP/2 frames in the data: `type`, `stream`, `length`, `flags`, `data_bytes`, `continued` (more of a DATA frame from an earlier call), decoded `headers` (`name`, `value`) and `body` (see below). Only for connections whose start snoopy saw: HPACK compresses headers against a table built up over the connection. |
| `http2_error` | Why HTTP/2 decoding stopped for this direction of the connection, e.g. because bytes weren't captured. Later events of it have no `http2`. |
| `quic_frames`, `http3` | For a QUIC packet (`EVP_AEAD_CTX_seal`, `EVP_AEAD_CTX_open` and `AES_AEAD` events, whose data is the packet's decrypted frames): a summary of each frame, and the HTTP/3 frames its stream data completed: `type`, `stream`, `data_bytes`, decoded `headers`, an `error` if they couldn't be decoded, and `body` (see below). |
| `body` | For the bytes of a body with a `Content-Encoding` (gzip, deflate, br, zstd, or several): `content_encoding`, what they decompressed to as `decoded` (UTF-8) or `decoded_base64`, and an `error` once decompressing stops, e.g. because bytes weren't captured. On HTTP/2 and HTTP/3 frames, and on the event for HTTP/1.x, whose bodies snoopy follows from their headers through `Content-Length` or chunked framing. Bodies are decompressed up to 16 MiB each. |

Fields that don't apply are left out.

### Containers and Kubernetes

Run snoopy on the host, or in a privileged container that shares the host's
PID namespace, so it can see other containers' processes and their files
through `/proc`:

```bash
docker run --rm -it --privileged --pid=host -v "$PWD/snoopy:/snoopy" ubuntu /snoopy
```

## Supported libraries

| Library | Functions | Notes |
| --- | --- | --- |
| OpenSSL, BoringSSL, LibreSSL | `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex` | Any copy whose symbols are visible, including ones statically linked into an executable that exports them (e.g. Node.js). |
| BoringSSL without symbols (Chrome, Brave, Edge, Electron apps) | `SSL_read`, `SSL_write`, found by signature | x86_64 and arm64. The functions are recognized by the error codes they report (see [How it works](#how-it-works)); snoopy attaches only if that gives one clear answer. Checked against published debug symbols on Chrome 155 and 156 (x86_64) and Electron 42 and 44 (arm64), and on Brave 1.97, Edge 155 and Ubuntu's Chromium 155 snap (arm64). Browsers in their usual install locations are analyzed at startup, so they are traced from the moment they start; results are cached by build ID. Chrome's HTTP/3 traffic is captured too, see below. |
| QUIC (HTTP/3) in Chrome, Brave, Edge, Electron apps | BoringSSL's `EVP_AEAD_CTX_seal`, `EVP_AEAD_CTX_open`, found by signature | x86_64 and arm64. QUIC encrypts each packet with these, and the plaintext is the packet's frames, which snoopy reassembles into HTTP/3 with QPACK-decoded headers. Packets are told apart from TLS records and other callers by their header. |
| QUIC (HTTP/3) in Firefox | NSS's `AES_CreateContext` and `AES_AEAD` in freebl, found through its exported function table | x86_64 and arm64. Firefox's QUIC stack (neqo) calls freebl's AES-GCM directly, so packets are captured there, as for Chrome. AES-GCM only: a connection that negotiates ChaCha20-Poly1305 isn't captured. Neither are connections set up before snoopy started, since a context's direction is learned when it's created. |
| GnuTLS | `gnutls_record_recv`, `gnutls_record_send` | |
| NSS (Firefox, Thunderbird, ...) | `PR_Read`, `PR_Write`, `PR_Recv`, `PR_Send` in NSPR | Only layered descriptors (the SSL layer) are captured, not plain files or sockets. Includes the copy bundled with Firefox, also when Firefox starts after snoopy. |
| wolfSSL | `wolfSSL_read`, `wolfSSL_write` | Also covers `wolfSSL_recv` and `wolfSSL_send`, which call them. |
| Mbed TLS | `mbedtls_ssl_read`, `mbedtls_ssl_write` | 2.x and 3.x. |
| s2n-tls | `s2n_recv`, `s2n_send` | Data sent with `s2n_sendv` isn't captured. |
| rustls | `Reader::read`, `Writer::write`, found by their mangled names | Programs that use rustls's reader and writer directly, such as `ureq` or `rustls::Stream`. Needs the program's symbol table, which Cargo keeps by default. Not async stacks built on tokio-rustls (`hyper`, `reqwest`, `axum`): there the read path is inlined and writes are vectored. |
| Go `crypto/tls` | `(*tls.Conn).Read`, `(*tls.Conn).Write` | Go 1.17+ on amd64, 1.18+ on arm64. Works on stripped binaries. |

Programs that do their own socket I/O around the TLS library, such as .NET's
`SslStream` over OpenSSL, are captured without a file descriptor or addresses.

Not supported: rustls under tokio (see above), Java, stripped TLS libraries
other than BoringSSL, QUIC/HTTP/3 outside Chromium and Firefox, programs that
use OpenSSL only through its BIO layer (e.g. `openssl s_server -www`), and
bodies compressed with a shared dictionary (Chrome's `dcb` and `dcz`), which
are shown as sent.

## How it works

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

The eBPF program is `bpf/snoopy.c`. It is compiled with `bpf2go` into the
`internal/tracer/snoopy_*_bpfel.{o,go}` files, which are committed so that a
plain `go build` works.

Some of this depends on other programs' internals, which their new releases
can change. [docs/release-risks.md](docs/release-risks.md) lists what's likely
to break and how it would show, and [docs/maintenance.md](docs/maintenance.md)
explains how each of those parts was found and how to fix it when it breaks.

## Development

```bash
make build        # build ./snoopy
make test         # unit tests
make integration  # load the eBPF program and trace real clients (uses sudo)
make lint         # golangci-lint
make generate     # recompile bpf/snoopy.c after changing it (needs clang 18 and llvm-strip)
```

The integration tests use whichever of `curl`, `python3`, `gnutls-cli` and the
NSS, wolfSSL, Mbed TLS and s2n-tls development files (`libnss3-dev`,
`libwolfssl-dev`, `libmbedtls-dev`; s2n-tls has to be built from source) are
installed, and skip the rest. The rustls test builds a client with `cargo`,
which takes a while, so it only runs with `SNOOPY_TEST_RUSTLS=1`. CI runs
them on x86_64 and arm64. To run them on an older kernel in a VM, use
[vimto](https://github.com/lmb/vimto): `make integration-vm KERNEL=5.10`.
Install vimto with `CGO_ENABLED=0 go install lmb.io/vimto@v0.4.0`; a build
with cgo refuses to run.

Two tests check the signature-based finding against real programs, and only
run when pointed at them. `SNOOPY_BORINGSSL_TEST` takes a comma-separated list
of Chromium-based executables, each optionally followed by `=` and a file
with its symbols to compare with: an ELF debug file (Google publishes them for
Chrome) or a Breakpad `.sym` file (Electron publishes them with each release).
`SNOOPY_FREEBL_TEST` does the same for freebl libraries:

```bash
SNOOPY_BORINGSSL_TEST=/opt/google/chrome/chrome=chrome.debug go test ./internal/discover -run TestBoringSSLBinaries -v
```

To release, push a tag like `v2.0.0`. GoReleaser builds and publishes the
binaries.

## Security

snoopy's output contains whatever the traced programs send: passwords, API
tokens, cookies and personal data. Only use it on systems you are authorized
to inspect, and treat its output and pcap files as sensitive.

## Upgrading from 1.x

Version 2 replaces the BCC-based implementation, which needed BCC and kernel
headers at runtime and no longer builds against current BCC releases.

- `--json` now prints one compact object per line. Fields were renamed:
  `elapsed_time` → `latency_ns`, `message_size` → `size`,
  `tls_content` → `data` or `data_base64`. `result` was removed.
- `--pid` now restricts tracing to that process. In 1.x it printed every process's events.
- The binary no longer needs to run from the repository directory.

## License

MIT. The eBPF program (`bpf/snoopy.c`) is dual-licensed MIT/GPL-2.0, as the
kernel requires a GPL-compatible license for the helpers it uses. The vendored
libbpf headers in `bpf/headers` are LGPL-2.1 OR BSD-2-Clause.

## References

- https://www.airplane.dev/blog/decrypting-ssl-at-scale-with-ebpf
- https://medium.com/@yunwei356/ebpf-practical-tutorial-capturing-ssl-tls-plain-text-using-uprobe-fccb010cfd64
- https://github.com/eunomia-bpf/bpf-developer-tutorial
- https://www.datadoghq.com/blog/ebpf-guide/
- https://blog.px.dev/ebpf-openssl-tracing/
- https://github.com/cilium/ebpf
