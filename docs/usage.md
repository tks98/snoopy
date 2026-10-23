# Using snoopy

The flags, what the output shows and leaves out, JSON and pcap output,
containers, and what to do when something doesn't show up. The
[README](../README.md) has the quick start.


## Examples

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

## Flags

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

## What you see

The default output shows each call with its decoded HTTP, here curl over
HTTP/1.1:

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

Each call shows where its data went, as tcpdump writes it: from the sender's
address to the receiver's, so a read shows the server first. An end that
isn't known shows as `local` or `peer`. Calls also show their process and
thread, socket and connection, and container when there is one. Traffic sent
through an HTTPS proxy shows up as the plaintext inside the tunnel, not as
the TLS records sent to the proxy.

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

## Wireshark and tcpdump

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

## JSON output

Each line is one call to a TLS read or write function:

```json
{"time":"2026-10-12T00:27:49.234626041Z","function":"SSL_write","library":"openssl","direction":"write","process_name":"curl","pid":5919,"tid":5919,"conn_id":"0x55e3c74a8f80","fd":5,"local_addr":"127.0.0.1:46780","remote_addr":"127.0.0.1:8444","latency_ns":83685,"size":84,"captured":84,"data":"GET /curl-h1 HTTP/1.1\r\nHost: 127.0.0.1:8444\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"}
```

| Field | Description |
| --- | --- |
| `time` | When the call returned. |
| `function`, `library` | The traced function, e.g. `SSL_read`, `EVP_AEAD_CTX_open` or `AES_AEAD (decrypt)` (QUIC packets), or `EVP_AEAD_CTX_open (TLS)` (TLS records, for rustls), and its library: `openssl`, `gnutls`, `nss`, `wolfssl`, `mbedtls`, `s2n`, `rustls` or `go`. |
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

## Containers and Kubernetes

Run snoopy on the host, or in a privileged container that shares the host's
PID namespace, so it can see other containers' processes and their files
through `/proc`:

```bash
docker run --rm -it --privileged --pid=host -v "$PWD/snoopy:/snoopy" ubuntu /snoopy
```

On Kubernetes, that's a pod with `hostPID: true` and a privileged container,
on the node to trace.

## Troubleshooting


**`sudo snoopy` says command not found** after `go install`: `sudo` doesn't
search Go's bin directory. Copy the binary to one it does search, once:
`sudo install "$(go env GOPATH)/bin/snoopy" /usr/local/bin/`.

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
are listed under [Requirements](../README.md#requirements).

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
