# snoopy and similar tools

There are several ways to see what a program sends over TLS, and which one
fits depends on what you can change: the client's trust store, its
environment, the cluster, or nothing at all. This page is what each is good
at, as far as their own documentation says (checked October 2026), and where
snoopy is or isn't the better choice. Corrections are welcome.

## In short

| | snoopy | mitmproxy | Wireshark + key log | eCapture | BCC `sslsniff` | Pixie, Kubeshark |
| --- | --- | --- | --- | --- | --- | --- |
| How | eBPF uprobes on TLS libraries | proxy with its own CA | the client writes its TLS keys | eBPF uprobes | eBPF uprobes | eBPF, cluster-wide |
| Changes to the program | none | trust the CA, use the proxy | `SSLKEYLOGFILE`, if it supports it | none | none | none, but an install in the cluster |
| Certificate pinning | not affected | breaks it | not affected | not affected | not affected | not affected |
| Servers as well as clients | yes | clients only, unless it's a reverse proxy | rarely: few servers write key logs | yes | yes | yes |
| Libraries | OpenSSL, BoringSSL (also stripped, in Chrome), LibreSSL, GnuTLS, NSS, wolfSSL, Mbed TLS, s2n-tls, rustls, ngtcp2, Go | any (it's the network) | whatever honors the key log | OpenSSL, LibreSSL, BoringSSL, GnuTLS, NSS, Go | OpenSSL, GnuTLS, NSS | OpenSSL, Go, and BoringSSL for Kubeshark |
| HTTP/2 decoded | yes | yes | yes | yes | no, raw data | yes |
| HTTP/3 decoded | yes, browsers included | yes | yes, with the keys | captured to pcap, not decoded as text | no | no, as far as I can tell |
| gRPC | messages decoded without the schema | decoded, also without the schema | with the schema, or raw | as HTTP/2 | no | yes |
| Modify or replay traffic | no | yes | no | no | no | no |
| Platforms | Linux 5.10+, x86-64 and arm64 | any | any | Linux 4.18+ (x86-64), 5.5+ (arm64), Android | Linux, with BCC | Kubernetes |
| Install | one static binary, or a container image | Python package or binary | Wireshark | one binary | BCC and Python | a cluster deployment |

## When to use something else

- **To change requests or responses**, or to replay them, use mitmproxy.
  snoopy only watches.
- **On macOS or Windows**, use mitmproxy, or Wireshark with a key log. snoopy
  is Linux only, since it's built on eBPF.
- **For a program that writes a key log anyway** (Firefox, Chrome and curl do
  with `SSLKEYLOGFILE`), Wireshark gives you every packet and its timing as
  well, which snoopy doesn't show below the TLS layer. snoopy's `--pcap`
  writes the plaintext as a pcap, without the encrypted packets.
- **On Android**, or to capture database queries and shell commands too, use
  eCapture, which has modules for MySQL, PostgreSQL and bash.
- **For a cluster-wide view with a UI**, metrics, and history, use Pixie or
  Kubeshark. snoopy is a command line tool for looking at one machine at a
  time.
- **Java** isn't covered by snoopy, nor by the other eBPF tools here: its
  TLS is written in Java and JIT-compiled, not a native library. Use
  mitmproxy, or a Java agent.

## Where snoopy is different

- **Nothing to set up in the program.** No proxy, no CA to trust, no
  environment variable, so it works on programs you can't restart or
  reconfigure, on servers, and on programs that pin certificates.
- **Browsers, HTTP/3 included.** Chrome, Brave, Edge and Electron apps link a
  stripped BoringSSL, which snoopy finds by signature, and their HTTP/3 is
  decoded from the QUIC packets they encrypt.
- **More libraries:** rustls (and HTTP/3 over quinn), wolfSSL, Mbed TLS,
  s2n-tls, ngtcp2 and quic-go, besides the common ones.
- **Decoded, not dumped.** HTTP/1.1, HTTP/2 and HTTP/3 headers and bodies,
  decompressed (gzip, deflate, Brotli, zstd), and gRPC messages shown as
  protobuf fields without the schema, or one line per call with `--brief`,
  JSON with `--json`, or a pcap with `--pcap`.
- **Cheap enough to leave running**, with `--comm`, `--pid` or `--container` especially,
  where only the processes asked for pay for its probes;
  [performance.md](performance.md) has the numbers.
