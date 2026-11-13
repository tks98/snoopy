# snoopy: development notes

Notes for picking up work on snoopy, for people and Claude Code sessions:
where things stand, how the pieces work and why, and what's left. The
README covers what snoopy does; this covers what to keep in mind when
changing it. Two more documents cover the parts that depend on other
programs' internals: [docs/release-risks.md](docs/release-risks.md), what new
releases are likely to break, and [docs/maintenance.md](docs/maintenance.md),
how those parts were found and how to fix them, with the tools and commands
used. [AGENTS.md](AGENTS.md) is the short list for coding agents.

## Status

Released: v2.11.3, the latest of the v2 releases (the first was v2.0.0). A
`v*` tag runs `release.yml`: GoReleaser publishes the snoopy archives
(linux amd64 and arm64, with the Java agent's jars), .deb, .rpm and .apk
packages, kubectl-snoopy's for Linux, macOS and Windows, an SBOM for each
archive, the jars, the krew manifest,
`checksums.txt` and the image `ghcr.io/tks98/snoopy`, and the workflow
attests the build provenance of `checksums.txt`'s files and of the image
(since v2.10.0). `go install
github.com/tks98/snoopy/v2@latest` installs it too.

What CI checks, and when:

| Check | When |
| --- | --- |
| gofmt, vet, golangci-lint, unit and race tests, amd64 and arm64 builds, BPF objects and the embedded Java agent's jars up to date (`ci.yml`) | Each pull request |
| Known vulnerabilities, none allowed, reachable or not: govulncheck on both modules and their release-built binaries, OSV-Scanner on every lockfile (test programs' too), and the Java agent's ASM against OSV (`vulnscan.yml`) | Each pull request, and daily |
| CodeQL on the Go code and the workflows (`codeql.yml`) | Each pull request, and weekly |
| Integration tests on the runners' kernels, x86_64 and arm64, every C client including s2n-tls (built from source), and Erlang's `ssl`, with `SNOOPY_TEST_STRICT=1` so a missing client fails, run twice: attaching through uprobe_multi links, and a link per probe as older kernels do (`ci.yml`) | Each pull request |
| `TestJSSE` on JDK 17, 21 and 25, x86_64 and arm64 (`ci.yml`) | Each pull request |
| The kubectl plugin, and a kind cluster end to end (`kubectl-snoopy.yml`) | Each pull request |
| Every BPF program loads under 5.10, 5.15, 6.1, 6.6 and 6.12, in QEMU, x86_64 and arm64 (`loadcheck.yml`) | Changes to the BPF code or how it's loaded |
| A snapshot release: GoReleaser's config, the image, krew installing the plugin, the packages installing on Ubuntu, Fedora and Alpine, reproducible jars and archives (`release-check.yml`) | Changes to the release's configuration |
| `TestRustls`, `TestRustlsAsync`, `TestQuinnHTTP3`, x86_64 and arm64 (`rust.yml`) | Weekly, and changes to those clients |
| Latest Chrome, Electron, Bun, Envoy and Firefox found by signature, Chrome stable and beta capturing HTTP/3 end to end (`TestChromeHTTP3`), Fedora's curl over HTTP/3 (`TestCurlHTTP3`), and Debian's through OpenSSL's QUIC (`TestOpenSSLQUIC`) (`canary.yml`) | Weekly, and changes to the canary |
| Overhead (`benchmark.yml`, `docs/benchmark/`) | By hand; results in [docs/performance.md](docs/performance.md) |

Not in CI: the integration tests on 5.10 to 6.12, which took too long
there (#8); run them with vimto after changing `bpf/snoopy.c` (AGENTS.md,
[docs/maintenance.md](docs/maintenance.md#older-kernels)). Browsers beyond
the canary's signature checks are tested by hand (docs/maintenance.md has
the recipes).

### To do

1. **Guard against browser releases.** The rest of the list in
   [docs/release-risks.md](docs/release-risks.md#what-to-do-about-it); the
   weekly canary covers finding them by signature, and capturing for
   Chrome's HTTP/3 (`TestChromeHTTP3`), not yet for Electron or Firefox.

## Working on it from a Mac

eBPF only runs on Linux, and the generated `internal/tracer/snoopy_*_bpfel.go`
files have `linux` build tags. So `internal/tracer` and `main` don't even
compile for darwin, and `go test ./...` fails on macOS. Work inside a Linux VM:

- **OrbStack** or **Lima** (`brew install lima && limactl start
  template://ubuntu-24.04`) give you an Ubuntu 24.04 arm64 VM on Apple Silicon.
  That also tests the arm64 code natively. Ubuntu 24.04 matches CI.
- In the VM, install Go 1.26+ and run:

  ```bash
  sudo apt-get install -y clang-18 llvm-18 curl python3 gnutls-bin libnss3-dev pkg-config qemu-system-x86 iproute2 erlang-base erlang-ssl erlang-inets
  ```

- Editing on the Mac and building, testing and running in the VM against the
  same checkout works fine. Lima mounts your home directory.
- From macOS you can still cross-check that things build:
  `GOOS=linux go build ./... && GOOS=linux go vet ./...`.

CI's jobs run locally too, with `tools/act.sh` and act (`brew install act`,
0.2.89 or later for node24 actions), in Docker Desktop on the Mac, whose
Linux kernel has the BTF the BPF tests need: `tools/act.sh -W
.github/workflows/ci.yml -j integration` ran the integration tests on it,
as root, in about two minutes. Only arm64, the Mac's architecture; jobs
with x86-64 in their matrix run there only. The script's comments have more.

Running other kernels (vimto) needs QEMU. Without KVM it is slow but works:
`VIMTO_DISABLE_KVM=true make integration-vm KERNEL=5.10` took about a minute
per kernel here. Nested virtualization in a Mac VM needs an M3 or newer and
macOS 15; otherwise use `VIMTO_DISABLE_KVM=true` or let CI do it. The
`ci-kernels` images come for x86_64 and arm64; `tools/loadcheck` uses
both.

## Commands

```bash
make build                 # static ./snoopy
make test                  # unit tests (no root needed)
make integration           # loads the BPF program, traces real clients (sudo)
make integration-vm KERNEL=5.10   # same, in a VM with another kernel (vimto + QEMU)
make lint                  # golangci-lint (v2 config in .golangci.yml)
make generate              # recompile bpf/snoopy.c; use clang 18 or CI's diff check fails
make jars                  # rebuild the embedded Java agent; use Temurin 21.0.13+9 or CI's diff check fails
sudo ./snoopy --verbose    # try it
```

The integration tests skip clients that aren't installed: curl, python3,
gnutls-cli, erl (erlang-base, erlang-ssl, erlang-inets), and cc with libnss3-dev for the NSS client in
`internal/tracer/testdata`, or with `SNOOPY_TEST_STRICT=1` (CI) fail
instead. `SNOOPY_TEST_RUSTLS=1` builds and runs the rustls
and quinn clients with cargo, and `SNOOPY_TEST_CURL_HTTP3` runs curl's HTTP/3
from a system that has it (see AGENTS.md). `SNOOPY_TEST_LEGACY_UPROBES=1`
attaches a perf-based link per probe, as kernels before 6.6 do, whatever
the kernel (see "Attaching" below). `SNOOPY_BORINGSSL_TEST` and `SNOOPY_FREEBL_TEST` check the
signature finding against real binaries (see
[CONTRIBUTING.md](CONTRIBUTING.md)).

## Repository map

| Path | What |
| --- | --- |
| `bpf/snoopy.c` | The eBPF program: uprobes on TLS read/write, return probes, `sys_enter` raw tracepoint, ring buffer output |
| `bpf/headers/vmlinux.h` | Hand-written minimal kernel types (`preserve_access_index` ones are relocated via CO-RE) |
| `bpf/headers/bpf_*.h` | Vendored libbpf 1.3.0 headers |
| `internal/tracer/gen.go` | `go:generate` → bpf2go (`go tool bpf2go`, declared as a tool in go.mod) |
| `internal/tracer/snoopy_{x86,arm64}_bpfel.{go,o}` | Generated and committed |
| `internal/tracer/tracer.go` | Load (BTF detection and fallback), attach, ring buffer loop, lost-event counter |
| `internal/tracer/uprobes.go` | Making the links: uprobe_multi detection, grouping probes into links, C symbols' file offsets |
| `internal/tracer/assemble.go` | Decodes records and reassembles chunks into events |
| `internal/tracer/sockets.go` | Holds writes back until the socket notice for their connection arrives |
| `internal/tracer/event.go` | `Event`, `Function` (must match `enum fn_id` in C; a test checks) |
| `internal/discover/` | Finds targets: system libs, `/proc/*/maps`, deleted files, Go binaries, RET offsets, prologue check, rustls by mangled name, stripped BoringSSL (`boringssl.go`), freebl's function table (`freebl.go`) |
| `internal/funcfind/` | Locates functions in stripped x86-64 and arm64 binaries by the strings and constants they use (`x86.go`, `arm64.go`) |
| `internal/procinfo/` | Container ID from cgroups; `/proc` socket lookup (fallback when there's no BTF) |
| `internal/output/` | Text, NDJSON and pcap writers; HTTP/1 message framing (`http1.go`), HTTP/2 with HPACK (`http2.go`), gRPC messages and schema-less protobuf (`grpc.go`), with `--proto`'s schemas (`protoschema.go`), QUIC and HTTP/3 with QPACK (`quic.go`, `qpack.go`), body decompression (`body.go`); `--requests` (`requests.go`, on HAR's pairing), `--brief`'s folding of bodies (`fold.go`) |
| `internal/javaagent/` | `--java`: staging the agent's jars in a JVM's `/tmp`, and HotSpot's attach protocol, in Go; the jars themselves, embedded (`jars/`, built by `make jars`) |
| `java/` | The Java agent (`agent/src`: the ASM transformer and `Hooks`, which writes frames to `/dev/null`), `build.sh`, and the spike's tools |
| `main.go` | CLI flags and wiring |
| `lost.go` | `--buffer-size`, and saying while snoopy runs that calls were lost to a full ring buffer |
| `java.go` | `--java`: which JVMs, loading the agent into them, stopping it |
| `.github/workflows/ci.yml` | Lint, unit tests, build, generate check, integration tests (x86_64, arm64), the Java agent per JDK |
| `.github/workflows/rust.yml`, `canary.yml`, `loadcheck.yml`, `release-check.yml`, `kubectl-snoopy.yml`, `benchmark.yml`, `vulnscan.yml`, `codeql.yml` | The other checks in the Status table |
| `java/vulncheck.sh` | Checks the ASM release `java/build.sh` bundles against OSV, which no scanner sees |
| `SECURITY.md`, `**/osv-scanner.toml` | How to report a vulnerability; the scan's exceptions, each with its reason |
| `.github/workflows/release.yml`, `.goreleaser.yaml`, `Dockerfile` | Releases on `v*` tags, and their attestations |
| `tools/loadcheck/` | Loads every BPF program under older kernels in QEMU (`fetch.sh`, `run.sh`) |
| `tools/act.sh` | Runs the workflows' jobs locally with act |
| `.vimto.toml` | VM settings for kernel-matrix tests (root, 2 GB, loopback up) |

## How it works, and what to keep in mind when changing it

### BPF program (`bpf/snoopy.c`)

- **Entry and return pairing.** Calls in flight live in `active_calls`, keyed
  by (thread, goroutine, depth); `call_depth` tracks the nesting depth.
  Nesting happens with TLS over TLS, e.g. through an HTTPS proxy.
  - **C libraries:** a uretprobe finds its call by stack pointer
    (`RETURN_TO_ENTRY_SP`: entry SP is the return SP minus 8 on x86, the same
    on arm64). This self-heals if a return is ever missed.
  - **Go:** the stack pointer can't be used because goroutine stacks move, so
    Go matches by depth. Go uses uprobes on every `RET` instruction (found by
    disassembly in `internal/discover/inspect.go`), never uretprobes, which
    corrupt Go stacks.
  - **Go entry probes go after the stack check**, not on the first
    instruction (`GoFunc.Body`). When the stack has to grow,
    `runtime.morestack` restarts the function from the top, so a probe on
    the first instruction saw one call twice. Depth matching then paired an
    outer Read's arguments with the inner Read's result in TLS over TLS
    (flaky `TestNestedGo`; `TestGoStackGrowth` reproduces it every time).
- **Verifier constraints, all learned the hard way:**
  - **Zero every struct passed to a helper** (`__builtin_memset`). Kernels
    without a backport of 6.3's relaxed checks (e.g. 5.10.100) reject
    uninitialized padding. Current point releases accept it, so the CI kernel
    matrix won't catch a regression here. Keep the habit.
  - **Keep the chunk loop shape.** Only the last chunk picks a record size
    (`output_last_chunk`); full chunks use a fixed 16 KiB record. Letting
    every iteration branch three ways blew past the 1M-instruction verifier
    limit with `--max-size 1048576`. Today the largest program needs about
    17k instructions.
  - **Records:** each chunk gets its own ring buffer record (`bpf_ringbuf_reserve`,
    sizes 256 B, 2 KB and 16 KB). Don't go back to per-CPU scratch: preemptible
    kernels can interleave programs on one CPU.
- **CO-RE is optional.** Socket addresses (`resolve_socket`) and process names
  (`get_process_name`: the group leader's comm) read kernel structs. Without
  kernel BTF, `tracer.New` passes an empty BTF spec, so those relocations are
  "poisoned", and `have_btf=false` lets the verifier drop that code. User space
  then fills in process names, the `--comm` filter and addresses from `/proc`.
  `TestWithoutKernelBTF` covers this.
- **fd tracking** uses the `raw_tracepoint/sys_enter` raw tracepoint, which
  doesn't need tracefs (not mounted in some containers), filtered to the
  read/write/send/recv family. Syscall numbers are per-arch.
- **Go fd** is read via `tls.Conn → net.Conn → *netFD → poll.FD.Sysfd`
  (offsets 8, 0, 16), and only accepted if `netFD.family`/`sotype` (at 56/64)
  look like TCP. These offsets have been stable since Go 1.12; re-check them
  when a new Go release changes `internal/poll`.
- **Closed sockets:** `track_conn` keeps known-good addresses when a socket is
  later seen with port 0, because the kernel releases the port on reset.
- **NSS:** only *layered* `PRFileDesc`s (`file_type == PR_DESC_LAYERED`) are
  traced. Otherwise plain file and socket I/O through NSPR would show up.
  `PR_Recv` with `PR_MSG_PEEK` is skipped: Firefox peeks at a byte of idle
  connections, which is read again later.
- **`--pid`** sets `filter_tgids`, and `should_trace` looks the process up in
  `traced_tgids`. With BTF, `is_traced_tgid` also walks up to 8 parents
  (`real_parent`, CO-RE) and adds a process that descends from a traced one,
  so a fork that never executes a program (Chrome's network service) is
  traced from its first call. Uprobes aren't attached per process for the
  same reason. Without BTF, `main.go` adds new children from a `/proc` scan
  every second, and the exec watcher adds those that execute a program.
- **Counters** (`counters`, per CPU): records the ring buffer had no room
  for (`count_lost`: once per call, at the chunk that didn't fit, which
  ends it, and for a socket or packet-sent notice), and Firefox QUIC
  packets of contexts created before snoopy, which `main.go` warns about
  once. `lostReporter` (`lost.go`) reads the first every second and says
  when it goes up: at once with what to try, then at most every 5 s, and
  the total at exit, which `docs/benchmark/*.sh` read. A call lost whole
  never reaches the decoders, so they're given `Tracer.LostEvents`
  (`Options.Lost`) and, when one stops (HTTP/2's `http2Stopped`, QPACK and
  QUIC stream errors, `quicItem.mayBeLoss`), add that lost calls may be
  why; a call lost in part is `Incomplete`, and the decoders put its
  missing bytes down to the ring buffer rather than `--max-size`
  (`missingWhy`). Nothing tells an HTTP/2 decoder that a call with whole
  frames went missing, so its HPACK table can go out of step silently.

### Go side

- **Attaching:** each attach function builds a list of probes for the
  file (`uprobe`), and `Tracer.link` makes the links. Where the kernel has
  uprobe_multi links with their PID filtering fixed (`HaveUprobeMulti`:
  6.6 and later, the fix included in 6.6.y), the probes running the same
  program the same way are one link (`groupUprobes`), so a file takes a
  few links rather than one per probe, return probes' first. The
  programs are the same, loaded with `AttachTraceUprobeMulti`, which the
  kernel then requires (they can't be attached the other way), so the
  choice is made once, in `New`; should the kernel's verifier refuse them
  so, they're loaded as before, which `tools/loadcheck` reports as a
  failure. Otherwise each probe is a perf-based link, as before 2.11. C
  functions are found by their symbols' file offsets (`symbolOffsets`,
  as cilium/ebpf finds them, which `TestSymbolOffsets` checks), since a
  uprobe_multi link takes a list of offsets and fails as a whole on a
  missing symbol. Why: the kernel detaches a perf-based uprobe in tens of
  ms, mostly waiting for RCU grace periods, one at a time; with `--comm`
  and twenty Go programs, snoopy took 90 s to exit, 0.3 s now (see
  [docs/performance.md](docs/performance.md#attaching-and-exiting)).
  Kernels without the PID fix filtered per-process links by thread, so a
  per-process probe only saw the main thread's calls; libbpf turns
  uprobe_multi off for them too.
- **Header layout:** `rawHeader` (Go) must match `struct event_header` (C,
  112 bytes with explicit padding); `TestHeaderMatchesBPFLayout` checks it
  against the bpf2go type.
- **Stripped Go binaries** are located via `.gopclntab`, using `runtime.text`
  from the pclntab header. With cgo/external linking it isn't the start of
  `.text`. `goBodyOffset` (`internal/discover/inspect.go`) refuses to attach
  unless the function starts with Go's stack check, so a mistake can't plant
  breakpoints mid-instruction, and attaches after it, where a call that
  grows the stack doesn't fire the probe twice.
- **Deleted or replaced files** in use by a process are attached through
  `/proc/<pid>/map_files/<range>` or `/proc/<pid>/exe`. This needs
  CAP_SYS_ADMIN.
- **pcap:** streams are keyed by 4-tuple. If both ends are traced, only the
  first endpoint seen is written. Synthetic ports are handed out sequentially,
  and the least recently used of 16384 streams is evicted.
- **HTTP/2** (`internal/output/http2.go`) is decoded per (pid, connection,
  direction) from the connection preface on, as a byte stream: frames can
  span calls. HPACK's table is built up over the connection, so a connection
  that started before snoopy is followed without headers (`HeadersLost`)
  from the first call that starts with a frame (`http2Aligned`, which also
  takes a lone 9-byte frame header, as Firefox reads them), and found again
  if the framing is lost. Missing bytes (truncated captures) are tolerated
  inside DATA payloads; anywhere else, decoding stops for that direction
  with a note. A connection snoopy hasn't seen whose first frame is a
  SETTINGS that isn't an ACK is a server's start, not a late connection
  (`http2ServerPreface`): servers send it before reading the client's
  preface. gRPC streams (`application/grpc` content types) are reassembled
  into messages per direction (`grpcStream`) and decoded as schema-less
  protobuf (`decodeProtobuf`), each length-delimited field shown as a
  string if it's printable, else as a nested message if it parses as one,
  else as bytes.
- **rustls with aws-lc-rs** (its default provider) is read at aws-lc's
  `EVP_AEAD_CTX_seal`, `seal_scatter` (TLS 1.2) and `open`, found by
  symbol (`awsLCAEAD`) and probed with `aead_*_enter`, which unlike
  Chromium's `quic_*_enter` keep TLS records as well as QUIC packets
  (`classify_aad`). A TLS 1.3 record's type is its plaintext's last non-zero
  byte (`tls13_content_len`); only application data is emitted, as
  `FN_RECORD_SEND`/`FN_RECORD_RECV`. Each direction has its own AEAD
  context, so `output.connOf` ties a connection's directions together by
  socket. Contexts' memory gets reused by later connections, so
  `conn_infos` keeps the socket's struct file and `emit` only trusts it
  while the fd still refers to that socket (`conn_info_live`).
- **rustls with ring** (0.17, and 0.16 for rustls 0.20 and early 0.21) is
  read the same way at ring's
  `ring::aead::algorithm::aes_gcm_seal`/`_open` and
  `chacha20_poly1305_seal`/`_open` (`ringAEAD`; `ring_*_enter`, emitting
  `FN_RING_SEND`/`FN_RING_RECV`). They're Rust functions: their result is
  returned through a hidden pointer, which x86-64 passes as the first
  argument (`RING_ARG`), and `open`'s plaintext length is known at entry
  (`RET_KNOWN_LEN`). ring 0.16's are in `aead::aes_gcm` and
  `aead::chacha20_poly1305` (`ring016AEAD`); their seal takes the same
  arguments, and their open takes the ciphertext's start before `in_out`
  (`ring016_open_enter`).
- **QUIC in Rust programs (quinn)** is captured at the same functions as
  rustls's records, as `FN_AWSLC_QUIC_*` and `FN_RING_QUIC_*`. quinn uses
  one unconnected UDP socket for all its connections and spreads the work
  over tokio's threads, so the per-thread bookkeeping doesn't hold. Instead:
  QUIC events carry the packet's header (`quic_header`, up to 47 bytes);
  `sealed_packets` remembers where each packet was encrypted, and a send
  whose buffer starts there (`note_packet_send`) gives its connection's
  socket and, with `FN_QUIC_PACKET_SENT`, its destination and header as
  sent; `quic_procs` keeps such processes' last receive socket, for
  packets decrypted on a thread that didn't receive them. In user space,
  `output/quic_cid.go` follows connections by their connection IDs (long
  headers, NEW_CONNECTION_ID frames) and gives their packets the peer from
  the notices. Encryption contexts' memory is reused between connections
  sharing the socket, so nothing per context is trusted for the peer.
- **rustls's Reader and Writer**, when neither provider's functions are
  found, are found by mangled symbol names (v0 and legacy;
  `inspectRustls`). They do no socket I/O, so
  `io_threads` remembers, per thread that called them, the last receive's
  socket (a read's socket is the one just read from) and which Writer is
  waiting for the next send (which teaches `conn_infos` its socket). With
  BTF, only AF_INET/AF_INET6 sockets count, not pipes, eventfds or Unix
  sockets (an event loop's wakeups, Chrome's Mojo IPC). A
  connection's first write is emitted before that, so when `note_thread_fd`
  learns a new socket for a connection it emits a header-only record
  (`FN_SOCKET_NOTICE`, 0xff), and `tracer/sockets.go` holds such writes
  (rustls, QUIC sends) until it arrives, or 300 ms. Returns are
  `io::Result<usize>` in two registers (`RET_RUST_RESULT`).
- **OpenSSL over memory BIOs** (Node.js; `memory_bio_return`): an
  `SSL_read` or `SSL_write` that returns without a socket syscall during it,
  on a connection whose socket isn't known, makes its thread an `io_threads`
  one. A write sets `want_conn` with the length of its first record's
  plaintext (`want_len`), and the thread's next send, within `WANT_MAX_NS`
  (10 ms), teaches its socket only if one of its first records
  (`has_app_record`) is an application data record of that length plus an
  AEAD's overhead (16 or 8 bytes of tag, plus 1 for TLS 1.3's content type
  or 8 for TLS 1.2's explicit nonce). A read takes the thread's last receive
  (`last_buf`, `last_len`, `last_file`) the same way. The record check is
  what keeps another connection's I/O on the thread, a deferred write
  (Node's `EncOut` waits while a write is in progress), or a send on another
  thread from being taken for the call's: a wrong address is worse than
  none. The write's event carries `EVENT_FLAG_SOCKET_LATER`, so
  `sockets.go` holds it for the notice like rustls's (`Event.socketLater`).
  Only with BTF, which tells sockets from files. Measured in November 2026
  with bpftrace: Node 18 (Ubuntu's) and 22 (official) call `SSL_read`,
  `SSL_write` and do their `read`/`write` on the socket all on the main
  thread, the write right after `SSL_write` returns (sometimes with the
  `SSL_write` nested in an `SSL_read`, from the handshake's callback); Dart
  3.14 calls them on a `DartWorker` thread and reads and writes the socket on
  another, so it isn't paired.
- **Stripped BoringSSL** (Chrome, Brave, Edge, Electron) is found by
  signature: `internal/discover/boringssl.go` on top of
  `internal/funcfind`, a small library for locating functions in stripped
  x86-64 and arm64 binaries (strings, the instructions that load them,
  function starts at direct call targets, constant call arguments, which
  arguments a function reads, how many stack arguments it reads).
  [docs/how-it-works.md](docs/how-it-works.md) has the rules. Results are cached by build ID in
  the user's cache dir, under a version (`boringSSLCacheVersion`) to bump
  whenever the answers could change. Check new browser releases with
  `SNOOPY_BORINGSSL_TEST` (see `TestBoringSSLBinaries`), which takes an ELF
  debug file or a Breakpad .sym file to compare with: Google publishes debug
  symbols for official Chrome builds at
  `https://edgedl.me.gvt1.com/chrome/linux/symbols/google-chrome-debug-info-linux64-<version>.zip`
  (stable, beta, dev), and Electron publishes Breakpad symbols with each
  release (`electron-v<version>-linux-arm64-symbols.zip`, the only arm64
  Chromium with symbols that's easy to get), so the answers can be checked
  exactly. Chrome 156 changed what was inlined, which is why reason codes
  count callees and candidates must read three arguments.
- **funcfind on arm64** (`funcfind/arm64.go`): references are adrp+add
  pairs and calls are bl, both matched as raw bits over the whole text;
  per-function analysis decodes with arm64asm. Functions are 4-byte aligned
  and start at bl targets; one also ends where a function that's only called
  indirectly starts, recognized by paciasp or bti after an unconditional
  branch or return (Chromium builds with branch protection). Stack
  arguments are at the entry sp, found by following the prologue's sub sp,
  pre-indexed stp and add x29.
- **QUIC (HTTP/3)** in Chromium is captured at BoringSSL's
  `EVP_AEAD_CTX_seal`/`open` (found by signature next to SSL_read: both take
  10 arguments, which `funcfind.StackArgs` checks, but so does
  `EVP_AEAD_CTX_open_gather`, which Chrome's and Electron's builds inline into
  open and Ubuntu's Chromium snap doesn't. So by their own reason codes: open
  reports bad decrypt (0x65); seal reports buffer too small (0x67) but not
  open_gather's 0x73). The associated data is the packet header. `is_quic_aad` leaves out
  TLS records, which also use these functions, by the shape of theirs (a
  5-byte record header, or TLS 1.2's 13 bytes); QUIC's fixed bit can't be
  used, since peers may grease it (RFC 9287). Seal encrypts in place, so it
  captures at entry. A send's socket comes from `io_threads` (as for
  rustls). A received packet's comes from `recv_bufs`: `sys_enter` records,
  for these threads, which socket each receive buffer was filled from (and
  the socket's `struct file`, since a buffer can be freed with its socket and
  reused), and `packet_fd` looks up the packet's start: `in - ad_len`, since
  Chrome copies the header to remove header protection but decrypts the
  rest in place. Later packets of a coalesced datagram are inside the same
  buffer (`dgram_start`/`dgram_end`). Only then does it fall back to the
  thread's last receive, which goes wrong when a program reads a packet and
  decrypts it later (Chrome yields between batches, and buffers packets that
  arrive before their keys).
- **QUIC in curl (ngtcp2):** at `ngtcp2_crypto_encrypt` and
  `ngtcp2_crypto_decrypt`, public API exported by each of ngtcp2's crypto
  libraries (`libngtcp2_crypto_ossl`, `_gnutls`, ...), found like the C TLS
  libraries (`readSymbols`, `libPatterns`), as `FN_NGTCP2_SEND`/`_RECV`.
  Encrypt is in place, so it emits at entry; decrypt writes elsewhere and
  emits on returning 0, with the ciphertext's length less the cipher's tag
  size, read from `ngtcp2_crypto_aead` (`RET_ZERO_KNOWN_LEN`). curl connects
  its socket and does its I/O on one thread, so the usual QUIC bookkeeping
  gives the socket. A chrooted process's `/proc/<pid>/maps` names files by
  their host path, which `processFiles` strips its root from.
- **QUIC in Go (quic-go):** at Go's AEADs, `(*GCM).Seal`/`Open` and
  ChaCha20-Poly1305's (`goAEADs` in `discover/inspect.go`), found like
  `tls.Conn`'s methods, stripped binaries included, but only in programs
  with quic-go (`quicGoFunc`): every Go TLS record goes through them, and
  other code uses AES-GCM too. `go_quic_header` also wants a plausible QUIC
  header. Their thirteen argument words spill to the stack on amd64
  (`go_aead_args`). `Seal` emits at entry and notes the packet for
  `sealed_packets`; `Open` is pushed for every call, so `(*tls.Conn).Read`'s
  depth matching holds, and emits at its RETs. quic-go uses one
  unconnected socket and separate goroutines like quinn, so the same
  `quic_procs`, packet-sent notices and connection IDs give sockets and
  peers.
- **Warnings for quiet failures:** `quic_traffic` counts, per traced
  process, datagrams on UDP sockets connected to port 443 (`note_udp443`,
  only the datagram syscalls, up to 64) and untraceable Firefox packets;
  `watchCounters` in `main.go` warns about a process with enough of the
  first and no QUIC events for a whole tick. `RustInfo.describe` and
  `GoInfo.QUICMissing` give attach-time warnings (`Target.Limits`, or a
  `Problem` when nothing can be attached), and `Options.Warn` is told when
  headers can't be decoded because the connection started before snoopy.
- **QUIC in Firefox:** neqo (via the `nss_rs` crate) calls freebl's
  `AES_CreateContext` and `AES_AEAD` directly, through function pointers, not
  through PK11 or any exported function. `FREEBL_GetVector` is exported and
  returns freebl's function table, whose layout is NSS ABI
  (`discover/freebl.go` reads entries 31 and 238 through RELA or RELR
  relocations). The direction is only known at creation (`encrypt` flag,
  mode 4 = GCM), so contexts created before snoopy started are skipped. QUIC
  runs on the parent process's "Socket Thread", not the socket process.
  `AES_AEAD` takes `unsigned int` lengths: on arm64 the upper half of a
  32-bit stack argument's slot is garbage, which made `is_quic_aad` drop
  most packets until the length was truncated. To test, start Firefox with
  a `user.js` setting `network.http.http3.enable`,
  `network.http.http3.alt-svc-mapping-for-testing` to `"example.com;h3=:443"`
  and `network.http.http3.force-use-alt-svc-mapping-for-testing`.
- **HTTP/3 decoding** (`output/quic.go`, `qpack.go`) parses frames,
  reassembles streams per connection known by its connection IDs (see
  above), otherwise per (pid, socket fd, direction), falling back to the
  AEAD context when the fd is unknown: a direction goes through several
  contexts (Initial, Handshake, 1-RTT, key updates). A new local address on
  the same fd means a new connection. A new socket whose first packet uses
  a context an open connection used in the last 10 s is that connection
  migrating (Chrome does when a path seems to degrade, often under QEMU);
  a connection that sent or received CONNECTION_CLOSE is left out, since
  freed contexts' memory is reused. Within a packet, unidirectional
  streams go first, so a header block can use encoder instructions sent
  after it in the same packet. QPACK's Required Insert Count is decoded as
  in RFC 9204 4.5.1.1, with the table size from the other direction's
  SETTINGS; without them it assumes no wrap. A blocked header block on a
  direction whose start wasn't seen (no stream 0 and no unidirectional
  stream type: `startSeen`) is reported as probably from before snoopy, and
  at most 64 blocked blocks are kept. `qpack_static.go` is generated
  from RFC 9204's text, and `TestQPACKExamples` runs its Appendix B
  examples.
- **Output and filters:** the text printer writes each call's ends as
  `source > destination`, in the direction the data went (`endpoints` in
  `output/text.go`). Text, `--brief` (`output/brief.go`) and JSON run the
  same decoders (`output/decode.go`). Text and brief leave out calls that
  only carry connection housekeeping (`decoded.housekeeping`: HTTP/2
  SETTINGS, WINDOW_UPDATE, PING, PRIORITY, partial header blocks; QUIC
  packets without HTTP/3, HTTP/3 SETTINGS and stream types) unless
  `--verbose`, and count them (`Hider`). Text shows a body up to 2 KiB into
  it (`bodyInfo` tracks each body's content type and offset per stream) and
  describes binary bodies, unless `--full`. `--host`, `--port` and `--count`
  are applied in `main.go`, so the first two also limit `--pcap`; `--count`
  counts the calls shown. A stripped BoringSSL whose functions can't be told
  apart becomes a `Target` with a `Problem`, which is reported as a warning
  instead of attached to; one whose HTTP/3 functions weren't found gets
  `Limits`, also a warning.
- **Startup:** `main.go` loads the BPF program before discovery, so the
  error without root comes first, then prints one line summarizing what it
  attached to (each file with `--verbose`). The help text is written by
  hand in `usage`; `TestUsage` checks that it lists every flag. With
  `--comm`, discovery skips other processes and the known programs whose
  names don't match.
- **Compressed bodies** (`output/body.go`): a body with a Content-Encoding
  is decompressed as its pieces arrive. Go's decompressors pull from an
  io.Reader, so each runs in a goroutine fed through channels: `push`
  returns once the decompressor asks for more input, by which time it has
  produced all it can (gzip's multistream mode is off, since it would hold
  the last bytes back while looking for another member; zstd decodes whole
  blocks of up to 128 KiB). `bodyPool` caps live decompressors at 256
  (least recently used ones are given up on) and each body at 16 MiB.
  HTTP/2 and HTTP/3 find the encoding in a stream's HEADERS and end the body
  at END_STREAM or FIN; HTTP/1 (`output/http1.go`) follows messages per
  connection: Content-Length, chunked framing, until close, no body for HEAD
  responses, 1xx, 204 and 304, and it stops at 101 and CONNECT. Bytes that
  weren't captured stop a body's decoding, said once.
- **`--requests`** (`output/requests.go`) is the HAR writer's pairing with
  no entries kept (`maxKept` 0, so bodies are only counted) and a `done`
  hook, called once per exchange when its response ends: an HTTP/2 or
  HTTP/3 stream's END_STREAM or reset (`streamEnds`), or the HTTP/1
  segment marked `ends` (the body's last byte by Content-Length or
  chunked framing, or the headers of a message without a body). A body
  that ends at the connection's close never ends there, so its exchange
  isn't shown. `--count` counts its lines, and the pipeline asks it how
  many (`Shown`). HTTP/1 segments carry the body's own bytes
  (`payload`, chunked framing left out), which HAR keeps; before, it kept
  a chunked body's framing.
- **`--brief`'s folding** (`output/fold.go`): once a body's first call is
  shown, calls carrying only more of it (`bodyRefs`) are counted, not
  shown, and the call that ends it says how many. Folded calls aren't
  shown calls for the pipeline or `--count` (`Folded`).
- **gRPC methods and `--proto`:** the HTTP/2 decoder keeps each stream's
  request `:path` on the connection (`http2Conn.paths`), since a
  response's messages come in the other direction, and each `grpcStream`
  knows its method, whether it carries requests, and, with `--proto`, its
  messages' type. `decodeTyped` formats a message itself: prototext varies
  its spacing from run to run on purpose, which tests and docs can't
  have. Descriptor sets only; parsing `.proto` files would mean resolving
  their imports as protoc does.
- **`--grep`** matches after decoding and redaction (`decoded.matches`),
  and marks what it doesn't match `filteredOut`, as the HTTP filters do.
- **HAR files** are written as they go: `WriteFile` writes a temporary
  file renamed over the old one, every `harInterval` while the log
  changes, less often if writing takes long. HAR's printer has a mutex for
  that, since its writer runs in its own goroutine.
- **The Java agent is embedded** (`internal/javaagent/jars`), for `go
  install`: committed, built by `make jars` with the release's JDK, and
  checked by CI as the BPF objects are. `build.sh` dates the jars'
  entries 2000-01-01, not by a commit, which committed jars couldn't
  match. Jars next to snoopy, or `--java-agent`'s, come first.
- **Startup's Ctrl-C:** `exitOnSignalUntil` asks for SIGINT and SIGTERM at
  the start of `run` and exits at once on them until tracing starts. A
  program started with SIGINT ignored, as a script's background job is,
  keeps ignoring it until it asks, and snoopy used to ask only once
  tracing started.
- **x86 testing on an Apple Silicon Mac:** `limactl start --arch=x86_64
  --vm-type=qemu template://ubuntu-24.04` gives an emulated x86 VM where
  uprobes work (Docker's amd64 emulation is user-space only). Slow, but fine
  for running Chrome headless.

## Review findings (all addressed in commit `a35431f`)

| # | Finding | Fix | Verified |
| --- | --- | --- | --- |
| 1 | Uninitialized struct padding rejected on older kernels | memset everything | Confirmed in disassembly; 5.10.100 source lacks the relaxation |
| 2 | Stripped cgo Go binaries: probes off by 0x100 | textStart from pclntab and prologue check | Reproduced and fixed; `TestPclntabMatchesSymtab`; live capture |
| 3 | TLS-over-TLS lost plaintext | Depth-keyed calls and SP matching | `TestNestedGo`, `TestNestedOpenSSL` |
| 4 | `--comm` matched thread names | Group leader's comm (CO-RE), /proc fallback | `TestThreadName` |
| 5 | Per-CPU scratch overwritten under preemption | Reserve per chunk | Not directly testable |
| 6 | Deleted or upgraded libraries not traced | map_files and exe | Live test with a deleted libssl and Go binary |
| 7 | pcap port collisions, unbounded stream map | Sequential ports, LRU eviction | Unit test |
| 8 | README capabilities incomplete | Docs and a permission warning | n/a |

## Known limitations and ideas for next steps

- **New programs after startup** are found through a `sched_process_exec`
  raw tracepoint (`WatchNewProcesses`) and inspected at 0, 50 ms, 500 ms and
  3 s after the exec. With `--comm` or `--pid` (`holdProcess` in `main.go`),
  a selected process whose executable, root or library path is new is held
  first: seized and interrupted with ptrace from a goroutine locked to its
  thread (`seize`, `release`), so its parent doesn't see a stop, while
  `Watcher.Root` (TLS libraries in its root's library directories) and
  `Watcher.Needed` (its DT_NEEDED tree, resolved as ld.so would) are
  attached to, for at most `maxHold`. A process snoopy is the parent of
  can have the stop's notification taken by its own wait, so `seize` polls
  and checks `/proc/<pid>/stat` too. Without those options, TLS calls made
  before a new library is attached are missed, and so are those of
  libraries a long-running process `dlopen`s more than 3 s after its exec.
- **Not supported:** rustls under tokio with providers other than aws-lc-rs
  and ring (`Reader::read` is inlined into tokio-rustls), QUIC/HTTP/3
  outside Chromium, Firefox, quinn, ngtcp2, quic-go and OpenSSL's own QUIC,
  OpenSSL's QUIC in processes not selected with `--comm`, `--pid` or
  `--container` (libcrypto's cipher functions carry all of a program's
  symmetric encryption, so they're probed only there, and only in those
  that import OpenSSL's QUIC methods; one `dlopen`ed late is missed, see
  docs/maintenance.md), Firefox's QUIC with
  ChaCha20-Poly1305 (which, a spike showed, reaches freebl's HACL* Poly1305
  without going through its exported `ChaCha20Poly1305_Seal`/`Open`/
  `Encrypt`/`Decrypt`, so where to probe is still to be found; Firefox only
  uses it with servers that pick ChaCha20), apps using OpenSSL only via its BIO layer (`openssl s_server
  -www`), and bodies with shared-dictionary encodings (Chrome's `dcb`, `dcz`).
- **HTTP/3 and bodies need the connection's start:** QPACK and HPACK tables
  are built up over a connection, Firefox's packet keys get their direction
  when created, and a body's decompressor needs its first bytes. Connections
  that started before snoopy show frames without headers, and encoded
  bodies as binary data.
- **HTTP/1 pipelining:** a response is matched to the last request sent, so
  with pipelined requests a response to HEAD can be taken to have a body.
- **No socket details** (fd or addresses) for apps that do their own socket
  I/O around OpenSSL with memory BIOs on another thread than the one calling
  `SSL_read` and `SSL_write`, e.g. Dart (whose `SecureSocket` encrypts on a
  worker thread), nor, as last checked, .NET; nor for Java's `SSLEngine`;
  nor, over memory BIOs, for CBC cipher suites or without BTF. Node.js,
  which does its I/O on the thread that calls them, gets them (see "OpenSSL
  over memory BIOs"). (Before 2.10, Node's calls could get the address of a
  file OpenSSL read, or of a later socket with that fd.)
- **Detaching is slow before Linux 6.6:** there, and on kernels without
  uprobe_multi's PID fix, each probe is a perf-based link, which the kernel
  takes tens of ms to detach, so a snoopy with thousands of links takes
  seconds to exit, or more than a minute per-process with many processes.
  6.6 and later attach through uprobe_multi links (see "Attaching").
- **A lower-layer file deleted through an overlay keeps its probes** until
  snoopy exits: the overlay only hides it, its link count stays 1, so
  `DetachUnused` doesn't take it for deleted. That's the safe way to be
  wrong (it can still be opened from the lower directory); it costs the
  links. Files on a container's root (`/proc/<pid>/root/...`) are let go
  of with the root instead.
- **Probably duplicate events across containers of one image:** uprobes go
  on the real (lower layer) inode, but snoopy tells files apart by the
  overlay's device and inode, so two running containers from one image may
  get two sets of probes on the same file. Not checked yet.
- **kubectl snoopy's text merge** of several nodes' output splits events at
  a blank line followed by a header-shaped line, a heuristic: a body with
  such a line in it can be split. --json is exact. An event delimiter in
  snoopy's text output would make it exact.
- **--redact is slow:** about 10 ms per 15 KB body, mostly regexps; a cheap
  pre-check before them would help.
- **Java's JSSE needs `--java`,** which loads snoopy's agent into the JVM
  (docs/how-it-works.md, "Java and JSSE"). It can't be unloaded, only told
  to stop. Not covered: writes that throw part way, kernels without BTF
  (untested), and the agent's own lost frames, which aren't reported.
- **Untested:**
  - IPv6 end to end: the dev container had IPv6 disabled. Unit tests cover the
    decoding.
  - Kernels 5.8 and 5.9.
- **Go versions:** Go < 1.17 (amd64) and < 1.18 (arm64) are refused, since
  they predate the register ABI.
- **Ideas:**
  - rustls under tokio with ring, and HTTP/3 in curl and Go:
    docs/plan-rustls-http3.md.
  - An `--sslkeylog` mode.

## Things learned about the environment

- vimto refuses to run unless it was itself built without cgo: install it
  with `CGO_ENABLED=0 go install lmb.io/vimto@v0.4.0`. The test binary is
  also built with `CGO_ENABLED=0` in CI and the Makefile.
- vimto picks the QEMU binary and kernel image from its own GOARCH. To run
  CI's x86_64 kernels on Apple Silicon, run it in an amd64 container
  (`docker run --platform linux/amd64 ubuntu:24.04`, then
  `VIMTO_DISABLE_KVM=true`); about 1.5 to 2.5 minutes per kernel.
- curl 8.18 writes the request headers and the start of the body in one
  `SSL_write`; `TestOpenSSLLargePayload` used to assume separate writes.
- The ring buffer doesn't guarantee events from different CPUs arrive in
  call order. Integration tests use `eventLog`, so waits are order-independent.
  An earlier version flaked on 6.12.
- `no_proxy` in the environment makes curl ignore an explicit `--proxy`.
  The proxy test passes `--noproxy ''`.
- The GitHub API rate-limits unauthenticated polling at 60 requests per hour.
