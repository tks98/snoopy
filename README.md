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
```

## Features

- **Libraries:** OpenSSL (also BoringSSL and LibreSSL), GnuTLS, NSS, wolfSSL,
  Mbed TLS, s2n-tls and Go's `crypto/tls`, including stripped Go binaries.
- **Finds what to trace:** system libraries, libraries loaded by running
  processes (including inside containers, and copies that an upgrade has
  since replaced), Go programs, and anything you point it at with `--lib`.
  Programs and containers started while snoopy runs are picked up as they
  start.
- **Tunnels:** traffic sent through an HTTPS proxy shows up as plaintext,
  not as the TLS records sent to the proxy.
- **Connection details:** process, thread, socket and local and remote
  address for every call, plus the container ID when the process runs in one.
- **Readable output:** HTTP/1.x is pretty-printed, HTTP/2 is shown frame by
  frame with its headers decoded (HPACK), and binary data is hex-dumped. With
  `--json` you get one JSON object per line instead.
- **Wireshark:** `--pcap` writes the plaintext as TCP streams so Wireshark
  can dissect the application protocol.
- **Single static binary:** the eBPF program is compiled ahead of time and
  embedded. The target machine needs no compiler, kernel headers or BCC.

## Requirements

- Linux 5.10 or later on x86_64 or arm64. CI tests 5.10, 5.15, 6.1, 6.6 and
  current kernels; 5.8 and 5.9 should work but aren't tested.
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
| `--hex` | Always hex-dump payloads. |
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
| `function`, `library` | The traced function, e.g. `SSL_read`, and its library: `openssl`, `gnutls`, `nss`, `wolfssl`, `mbedtls`, `s2n` or `go`. |
| `direction` | `read` (received from the peer) or `write` (sent to it). |
| `process_name`, `pid`, `tid` | The calling process and thread. |
| `container_id` | The container the process runs in, if any. |
| `conn_id` | The library's handle for the connection (`SSL*`, `gnutls_session_t`, `PRFileDesc*`, `WOLFSSL*`, `mbedtls_ssl_context*`, `struct s2n_connection*` or `*tls.Conn`). Stays the same for the lifetime of a connection; a library may reuse it for a later connection. |
| `fd`, `local_addr`, `remote_addr` | The socket, if known. |
| `latency_ns` | Time spent inside the call. |
| `size` | Bytes the call transferred. |
| `captured` | Bytes captured; less than `size` when `truncated` is set (see `--max-size`). |
| `incomplete` | Set when part of the payload was dropped because the ring buffer was full. |
| `read_error` | Set when the payload couldn't be read from the process's memory. |
| `data` / `data_base64` | The captured bytes: as a string if they are valid UTF-8, otherwise base64. |
| `http2` | The HTTP/2 frames in the data: `type`, `stream`, `length`, `flags`, `data_bytes`, `continued` (more of a DATA frame from an earlier call) and decoded `headers` (`name`, `value`). Only for connections whose start snoopy saw: HPACK compresses headers against a table built up over the connection. |
| `http2_error` | Why HTTP/2 decoding stopped for this direction of the connection, e.g. because bytes weren't captured. Later events of it have no `http2`. |

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
| GnuTLS | `gnutls_record_recv`, `gnutls_record_send` | |
| NSS (Firefox, Thunderbird, ...) | `PR_Read`, `PR_Write`, `PR_Recv`, `PR_Send` in NSPR | Only layered descriptors (the SSL layer) are captured, not plain files or sockets. Includes the copy bundled with Firefox, also when Firefox starts after snoopy. |
| wolfSSL | `wolfSSL_read`, `wolfSSL_write` | Also covers `wolfSSL_recv` and `wolfSSL_send`, which call them. |
| Mbed TLS | `mbedtls_ssl_read`, `mbedtls_ssl_write` | 2.x and 3.x. |
| s2n-tls | `s2n_recv`, `s2n_send` | Data sent with `s2n_sendv` isn't captured. |
| Go `crypto/tls` | `(*tls.Conn).Read`, `(*tls.Conn).Write` | Go 1.17+ on amd64, 1.18+ on arm64. Works on stripped binaries. |

Programs that do their own socket I/O around the TLS library, such as .NET's
`SslStream` over OpenSSL, are captured without a file descriptor or addresses.

Not supported: rustls, Java, TLS libraries with stripped symbols (such as the
BoringSSL inside Chrome), QUIC/HTTP/3, and programs that use OpenSSL only
through its BIO layer (e.g. `openssl s_server -www`).

Browsers use HTTP/3 (QUIC) with many sites, and that traffic doesn't pass
through the TLS library's read and write functions, so snoopy doesn't see it.
To see it in Firefox, set `network.http.http3.enable` to `false` in
`about:config`; Firefox then uses HTTP/2 or HTTP/1.1 over TLS.

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

The eBPF program is `bpf/snoopy.c`. It is compiled with `bpf2go` into the
`internal/tracer/snoopy_*_bpfel.{o,go}` files, which are committed so that a
plain `go build` works.

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
installed, and skip the rest. CI runs
them on x86_64 and arm64. To run them on an older kernel in a VM, use
[vimto](https://github.com/lmb/vimto): `make integration-vm KERNEL=5.10`.
Install vimto with `CGO_ENABLED=0 go install lmb.io/vimto@v0.4.0`; a build
with cgo refuses to run.

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
