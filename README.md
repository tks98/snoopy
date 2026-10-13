# snoopy

snoopy shows the plaintext of TLS connections on a Linux machine, without
certificates, proxies or changes to the applications. It uses eBPF uprobes on
the functions applications call to send and receive data through their TLS
library, so it sees the data before it is encrypted and after it is decrypted.

![snoopy in one terminal and Chromium, opened from another, loading pages while their requests and responses scroll by](docs/demo.gif)

Chromium loading example.com and Cloudflare's test page over HTTP/3, and
Wikipedia over HTTP/2, recorded with
[docs/demo/record.sh](docs/demo/record.sh).

```console
$ sudo snoopy
snoopy: attached to the openssl and gnutls libraries, and to the program chrome (--verbose lists every file)
snoopy: tracing; press Ctrl-C to stop
06:42:46.026011 curl (pid 32570) SSL_write 192.168.5.15:58278 > 172.66.147.243:443  116 bytes  2.15ms  fd 5, conn 0x5f49f76814f0
GET / HTTP/1.1
Host: example.com
User-Agent: curl/8.5.0
Accept: */*
Accept-Encoding: deflate, gzip, br, zstd

06:42:46.073841 curl (pid 32570) SSL_read 172.66.147.243:443 > 192.168.5.15:58278  689 bytes  1.58ms  fd 5, conn 0x5f49f76814f0
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Server: cloudflare
Content-Encoding: br
...

[br: 341 bytes decoded to 577]
<!doctype html><html lang=en><head><meta charset=utf-8>...<title>Example Domain</title>...
```

Or one line per call, like tcpdump, here with curl over HTTP/1.1 and HTTP/2
and Chrome over HTTP/3:

```console
$ sudo snoopy --brief
06:42:53.389996 curl[32719] 192.168.5.15:33736 > 172.66.147.243:443 TLS 116: GET / HTTP/1.1, host example.com
06:42:53.430619 curl[32719] 172.66.147.243:443 > 192.168.5.15:33736 TLS 689: HTTP/1.1 200 OK, text/html; charset=utf-8, br; body 341 bytes (br, 577 decoded)
06:42:54.835128 curl[32722] 192.168.5.15:33748 > 172.66.147.243:443 TLS 57: HTTP/2 HEADERS s1 GET example.com/ [END_STREAM]
06:42:54.874490 curl[32722] 172.66.147.243:443 > 192.168.5.15:33748 TLS 170: HTTP/2 HEADERS s1 200, text/html; charset=utf-8, br
06:42:54.877224 curl[32722] 172.66.147.243:443 > 192.168.5.15:33748 TLS 343: HTTP/2 DATA s1 334 bytes (br, 577 decoded)
06:43:04.105915 chrome[32786] 192.168.5.15:54267 > 172.66.147.243:443 QUIC 457: HTTP/3 HEADERS s0 GET example.com/
06:43:04.149725 chrome[32786] 172.66.147.243:443 > 192.168.5.15:54267 QUIC 551: HTTP/3 HEADERS s0 200, text/html; charset=utf-8, br; DATA s0 334 bytes (br, 577 decoded)
```

## Quick start

On Linux 5.10 or later, x86_64 or arm64, with Go 1.25 or later:

```bash
go install github.com/tks98/snoopy/v2@latest
sudo "$(go env GOPATH)/bin/snoopy" --brief
```

Then run `curl https://example.com` in another terminal. snoopy needs root,
and `sudo` doesn't search your Go bin directory, hence the full path. To
trace one program, name it: `--comm curl`, `--comm firefox`, `--comm chrome`.
Binaries are on the [releases page](https://github.com/tks98/snoopy/releases)
once a version is tagged.

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
  shown frame by frame with their headers decoded (HPACK, QPACK), and bodies
  compressed with gzip, deflate, Brotli or zstd are shown decompressed as
  they arrive. A body's first 2 KiB are shown and binary bodies are described
  in a line, and calls that only keep connections going are left out; `--full`
  and `--verbose` show everything. With `--json` you get one JSON object per
  line instead.
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

With Go 1.25 or later:

```bash
go install github.com/tks98/snoopy/v2@latest
```

This builds the committed eBPF objects into the binary, so it needs no
compiler or kernel headers. `sudo snoopy` won't find it, since `sudo` uses its
own `PATH`; run `sudo "$(go env GOPATH)/bin/snoopy"`, or copy the binary
somewhere like `/usr/local/bin`. Or clone the repository and run
`make build`. Tagged versions also come as binaries on the
[releases page](https://github.com/tks98/snoopy/releases).

## Usage

```bash
sudo snoopy                                 # everything, decoded
sudo snoopy --brief                         # one line per call, like tcpdump
sudo snoopy --comm curl                     # processes whose name starts with curl
sudo snoopy --pid 1234                      # one process and those it starts
sudo snoopy --container 4b825dc642          # one container (ID prefix)
sudo snoopy --host example.com --port 443   # connections to example.com on port 443
sudo snoopy --count 20                      # stop after 20 calls
sudo snoopy --full                          # whole bodies, and binary data as hex dumps
sudo snoopy --json | jq 'select(.direction == "write") | .data'
sudo snoopy --lib /usr/bin/node             # also attach to a binary with OpenSSL linked in
```

`snoopy --help` lists every flag:

```text
Which processes:
  --pid PID          only this process and those it starts
  --comm NAME        only processes whose name starts with NAME, as in
                     /proc/<pid>/comm (curl, firefox, chrome)
  --container ID     only processes in the container with this ID, or ID prefix

Which connections (repeatable):
  --host HOST        only connections with this IP address, network (CIDR)
                     or host name at either end
  --port PORT        only connections with this port at either end

Output:
  --brief            one line per call, like tcpdump
  --json             one JSON object per call
  --full             whole bodies, and binary data as hex dumps (by default,
                     a body's first 2 KiB, and binary data described)
  --hex              payloads as hex dumps
  --verbose          also calls that only keep connections going (HTTP/2
                     settings and flow control, QUIC acknowledgments), and
                     every file attached to
  --count N          stop after N calls
  --pcap FILE        also write the plaintext as TCP streams to a pcap file
                     ("-" for stdout, to pipe to wireshark -k -i - or tcpdump -r -)
  --quiet            don't print calls (with --pcap)
  --no-color         no colors

Capture:
  --max-size BYTES   bytes to capture per call (default 16384, at most 1048576)
  --lib PATH         also attach to this library or program, e.g. one with
                     OpenSSL linked in statically (repeatable)
  --no-scan          only attach to system libraries and --lib, not to what
                     running and new processes use

  --version          print the version and exit
```

### What you see

Each call shows where its data went, as tcpdump writes it: from the sender's
address to the receiver's, so a read shows the server first. An end that
isn't known shows as `local` or `peer`.

A body is shown up to its first 2 KiB, over however many calls it takes, and
the calls after that say how many more bytes of it arrived. Binary bodies,
like images, get a line saying their size and content type. Data that isn't
HTTP is shown as text, or hex-dumped up to 256 bytes. `--full` shows all of
it, binary data as hex dumps.

Calls that carry nothing of the requests and responses, only what keeps the
connection going (HTTP/2 `SETTINGS`, `WINDOW_UPDATE` and `PING`, QUIC
packets with only acknowledgments and the like), are left out, and so are
those frames within other calls. When snoopy stops, it says how many calls it
left out; `--verbose` shows them. `--count` counts the calls shown.

Connections that were already open when snoopy started are shown as well as
they can be. HTTP/2 compresses headers against a table built up over the
connection, so for those connections the frames are listed but their headers
can't be decoded, and the same goes for HTTP/3 header blocks that refer to
earlier ones. Firefox's HTTP/3 connections from before snoopy can't be
traced at all, and snoopy warns when it sees them.

`--host` and `--port` need a connection's addresses. Connections whose
addresses aren't known don't match: on kernels without BTF, those of
processes that ended before snoopy looked them up, and Firefox's HTTP/3,
whose UDP socket isn't connected to one server.

snoopy also watches for programs that start while it runs and attaches to
the TLS libraries and Go programs they use. It looks at a new process right
after its `exec` and again after 50 ms, 500 ms and 3 s, since shared libraries
are loaded after the `exec`. TLS calls a new program makes before then are
missed, unless it uses a library snoopy was already attached to, such as the
system `libssl`.

`--pid` follows the processes the given one starts, which matters for
browsers: Chrome does its networking in a separate process, so `--pid` of
its main process captures that one. Without kernel BTF, a child that doesn't
execute a new program (a fork) is only found by a scan of `/proc` every
second.

### Wireshark and tcpdump

`--pcap` turns each TLS connection into a synthetic TCP stream that carries the
plaintext, using the real addresses where they are known. Wireshark expects
TLS on port 443, so tell it the stream holds the application protocol:

```bash
sudo snoopy --quiet --pcap capture.pcap
wireshark -d tcp.port==443,http capture.pcap      # or http2

# or watch live
sudo snoopy --pcap - | wireshark -k -i - -d tcp.port==443,http
```

tcpdump reads the same stream, for its exact output format and its filters:

```bash
sudo snoopy --quiet --pcap - | tcpdump -r - -nn -A 'port 443'
```

QUIC (HTTP/3) packets aren't written to the pcap.

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
| `http2` | The HTTP/2 frames in the data: `type`, `stream`, `length`, `flags`, `data_bytes`, `continued` (more of a DATA frame from an earlier call), decoded `headers` (`name`, `value`) and `body` (see below). HPACK compresses headers against a table built up over the connection, so on a connection that started before snoopy, frames are followed from the first call that starts with one, and a header block has `headers_not_decoded` instead of `headers`. |
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

On Kubernetes, that's a pod with `hostPID: true` and a privileged container,
on the node to trace.

## Supported libraries

| Library | Functions probed | Notes |
| --- | --- | --- |
| OpenSSL, BoringSSL, LibreSSL | `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex` | Also copies linked into a program that exports them, like Node.js. |
| BoringSSL in Chrome, Brave, Edge and Electron apps | `SSL_read`, `SSL_write`, found by signature | No symbols, so the functions are recognized by what they do. |
| HTTP/3 in Chrome, Brave, Edge and Electron apps | BoringSSL's `EVP_AEAD_CTX_seal`, `EVP_AEAD_CTX_open`, found by signature | Each QUIC packet, decrypted. |
| HTTP/3 in Firefox | freebl's `AES_CreateContext`, `AES_AEAD` | AES-GCM connections opened while snoopy runs. |
| GnuTLS | `gnutls_record_recv`, `gnutls_record_send` | |
| NSS (Firefox, Thunderbird) | `PR_Read`, `PR_Write`, `PR_Recv`, `PR_Send` | Also the copy bundled with Firefox. |
| wolfSSL | `wolfSSL_read`, `wolfSSL_write` | |
| Mbed TLS | `mbedtls_ssl_read`, `mbedtls_ssl_write` | 2.x and 3.x. |
| s2n-tls | `s2n_recv`, `s2n_send` | Not `s2n_sendv`. |
| rustls | `Reader::read`, `Writer::write` | Synchronous use only; needs the program's symbols. |
| Go `crypto/tls` | `(*tls.Conn).Read`, `(*tls.Conn).Write` | Go 1.17+ on amd64, 1.18+ on arm64, stripped binaries too. |

All of them on x86_64 and arm64. Some details:

- **Chromium-based browsers and Electron apps** link BoringSSL without
  symbols, so snoopy recognizes its functions by the error codes they report
  (see [How it works](#how-it-works)). It attaches only if that gives one
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
  created.
- **NSS** functions are used for all kinds of files, so only layered
  descriptors (the SSL layer) are captured.
- **rustls** is found by its mangled names, in programs that use its reader
  and writer directly, such as `ureq` or `rustls::Stream`; Cargo keeps the
  symbols by default. Not async stacks built on tokio-rustls (`hyper`,
  `reqwest`, `axum`): there the read path is inlined and writes are vectored.

Programs that do their own socket I/O around the TLS library, such as .NET's
`SslStream` over OpenSSL, are captured without a file descriptor or addresses.

Not supported: rustls under tokio, Java, stripped TLS libraries other than
BoringSSL, QUIC/HTTP/3 outside Chromium and Firefox (curl's own HTTP/3, for
example), programs that use OpenSSL only through its BIO layer (e.g.
`openssl s_server -www`), and bodies compressed with a shared dictionary
(Chrome's `dcb` and `dcz`), which are shown as sent.

## Troubleshooting

**`sudo: snoopy: command not found`** after `go install`: `sudo` doesn't
search your Go bin directory. Run `sudo "$(go env GOPATH)/bin/snoopy"`.

**Nothing from a browser, or HTTP/2 frames without headers.** Browsers keep
connections open for minutes, and snoopy can't decode the headers of a
connection that started before it did, nor see Firefox's HTTP/3 from before
then. Restart the browser, or open a site it hasn't connected to yet. Also
check the startup lines: a browser outside the usual install locations is
only attached to once it's running, and a warning says if a build can't be
traced.

**`--pid` shows nothing.** The process may not be the one doing the TLS:
browsers and many servers hand it to another process. snoopy follows the
processes the given one starts, so use the parent's PID, or `--comm`.

**Too much output.** Use `--brief`, narrow it down with `--comm`, `--host`
and `--port`, or stop after a number of calls with `--count`.

**Hex dumps instead of HTTP.** The data isn't HTTP that snoopy can follow: a
different protocol, or a connection it joined partway through.

**The first start takes a few seconds.** snoopy analyzes Chromium-based
browsers it finds to locate their TLS functions, and says so while it does.
The result is cached by build ID, in `/root/.cache/snoopy` when run with
`sudo`.

**`snoopy needs root`.** It loads an eBPF program. The minimal capabilities
are listed under [Requirements](#requirements).

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
- `--pid` now restricts tracing to that process and the processes it starts.
  In 1.x it printed every process's events.
- `--comm` matches the processes whose name starts with the given name.
- The Go module path is `github.com/tks98/snoopy/v2`.
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
