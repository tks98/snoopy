# snoopy

Debug HTTPS without a proxy. snoopy shows what any Linux program sends and
receives over TLS, browsers included, without certificates or changes to the
program. It uses eBPF to read the data where the program hands it to its TLS
library, before it's encrypted and after it's decrypted.

![snoopy in one terminal and Chromium, opened from another, loading pages while their requests and responses scroll by](docs/demo.gif)

Chromium loading example.com and Cloudflare's test page over HTTP/3, and
Wikipedia over HTTP/2, recorded with
[docs/demo/record.sh](docs/demo/record.sh).

## Quick start

Download a binary for `linux_amd64` or `linux_arm64` from the
[releases page](https://github.com/tks98/snoopy/releases), or build one with
Go 1.26 or later, and copy it to where `sudo` finds it:

```bash
# a release binary
tar xzf snoopy_*_linux_amd64.tar.gz snoopy
sudo install snoopy /usr/local/bin/

# or with Go; sudo doesn't search Go's bin directory, hence the copy
go install github.com/tks98/snoopy/v2@latest
sudo install "$(go env GOPATH)/bin/snoopy" /usr/local/bin/
```

Then run `sudo snoopy --brief` and make some requests from another terminal,
here with curl over HTTP/1.1 and HTTP/2, and Chrome over HTTP/3:

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

## Usage

```bash
sudo snoopy                                 # everything, decoded
sudo snoopy --brief                         # one line per call, like tcpdump
sudo snoopy --comm firefox                  # processes whose name starts with firefox
sudo snoopy --pid 1234                      # one process and those it starts
sudo snoopy --host example.com --port 443   # connections to example.com on port 443
sudo snoopy --json | jq 'select(.direction == "write") | .data'
sudo snoopy --quiet --pcap - | tcpdump -r - -nn -A
```

A body is shown up to its first 2 KiB, binary bodies are described in a line,
and calls that only keep connections going (HTTP/2 flow control, QUIC
acknowledgments) are left out; `--full` and `--verbose` show everything.
`snoopy --help` lists every flag, and [docs/usage.md](docs/usage.md) covers
the output, JSON and pcap, containers, and troubleshooting.

## What it traces

- **TLS libraries:** OpenSSL, BoringSSL, LibreSSL, GnuTLS, NSS, wolfSSL,
  Mbed TLS, s2n-tls, rustls (async too, and HTTP/3 over quinn), ngtcp2 (curl's HTTP/3)
  and Go's `crypto/tls` (and HTTP/3 over quic-go), stripped Go
  programs included.
- **Browsers:** Chrome, Brave, Edge and Electron apps, whose BoringSSL has no
  symbols and is found by signature, and Firefox. Their HTTP/3 too.
- **Protocols:** HTTP/1.1, HTTP/2 and HTTP/3 with their headers decoded, and
  bodies compressed with gzip, deflate, Brotli or zstd decompressed.
- **Where:** running processes, those started while snoopy runs, and
  processes in containers.

[docs/how-it-works.md](docs/how-it-works.md) has the details, and what isn't
supported.

## Requirements

- Linux 5.10 or later, on x86_64 or arm64 (tested on 5.10, 5.15, 6.1, 6.6,
  6.12 and current kernels).
- Root, or `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` and `CAP_SYS_PTRACE`
  (and `CAP_SYS_ADMIN` for libraries replaced while in use).
- Kernel BTF (`/sys/kernel/btf/vmlinux`), which most distributions ship.
  Without it, snoopy looks socket addresses and process names up in `/proc`,
  and can miss them for short-lived connections and processes.

That's all: snoopy is one static binary with its eBPF program built in, so it
needs no compiler, kernel headers or BCC.

## Documentation

- [Using snoopy](docs/usage.md): flags, output, JSON, pcap and Wireshark,
  containers, troubleshooting, and upgrading from 1.x.
- [How snoopy works](docs/how-it-works.md): supported libraries, and how the
  tracing works.
- [Contributing](CONTRIBUTING.md): building, testing and releasing.
- [Release risks](docs/release-risks.md) and
  [maintenance](docs/maintenance.md): what breaks when browsers and libraries
  change, and how to fix it.

## Security

snoopy's output contains whatever the traced programs send: passwords, API
tokens, cookies and personal data. Only use it on systems you are authorized
to inspect, and treat its output and pcap files as sensitive.

## License

MIT. The eBPF program (`bpf/snoopy.c`) is dual-licensed MIT/GPL-2.0, as the
kernel requires a GPL-compatible license for the helpers it uses. The vendored
libbpf headers in `bpf/headers` are LGPL-2.1 OR BSD-2-Clause.
