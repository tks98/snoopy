# snoopy: development notes

Notes for picking up work on snoopy, for people and Claude Code sessions:
where things stand, how the pieces work and why, and what's left. The
README covers what snoopy does; this covers what to keep in mind when
changing it. Two more documents cover the parts that depend on other
programs' internals: [docs/release-risks.md](docs/release-risks.md), what new
releases are likely to break, and [docs/maintenance.md](docs/maintenance.md),
how those parts were found and how to fix them, with the tools and commands
used.

## Status

On main: version 2, the rewrite on cilium/ebpf with a CO-RE eBPF program
(#4); exec watching with wolfSSL, Mbed TLS and s2n-tls (#9); and HPACK,
rustls, Chrome by signature (x86_64 and arm64), HTTP/3 for Chromium and
Firefox, and compressed bodies (#10).

| Check | Status |
| --- | --- |
| Lint, unit and race tests, amd64 and arm64 builds, BPF objects up to date | Green in CI |
| Integration tests on the runners' kernels (x86_64 and arm64) | Green in CI |
| Integration tests on Linux 5.10, 5.15, 6.1, 6.6, 6.12 (vimto VMs) | No longer in CI, which took too long (#8). All pass with #10 (23 tests each; the clients for s2n, wolfSSL, Mbed TLS and rustls aren't in the VM image), run by hand as described in [docs/maintenance.md](docs/maintenance.md#older-kernels). |
| Integration tests on Linux 7.0 arm64 (Ubuntu 26.04 in Parallels) | 27 pass, rustls included (`SNOOPY_TEST_RUSTLS=1`) |
| Browsers, by hand | Chrome 155 (x86_64, in Lima), Firefox 153 snap (arm64) and 157 (x86_64), Electron 44 and Chromium 155 snap (arm64): HTTP/2 and HTTP/3 captured with headers and bodies decoded |

### To do

1. **Delete the logs of CI run 38189398199**, if that hasn't happened
   (https://github.com/tks98/snoopy/actions/runs/38189398199, then ⋯, then
   "Delete all logs"). Its smoke test printed the runner's own TLS traffic,
   including short-lived Azure SAS signatures and the job's `GITHUB_TOKEN`
   basic-auth header. Both expire quickly, but they shouldn't stay public. The
   smoke test now runs with `--quiet`.
2. Tag the first release (`git tag v2.0.0 && git push --tags`). GoReleaser
   publishes linux amd64 and arm64 binaries. No release has been made yet.
3. Dependabot's #5, #6 and #7 are open. #6 bumps `golang.org/x/arch`, so check
   it as [docs/maintenance.md](docs/maintenance.md#funcfind-and-golangorgxarch)
   describes before merging it; it may also need a rebase, since #10 changed
   go.mod.

## Working on it from a Mac

eBPF only runs on Linux, and the generated `internal/tracer/snoopy_*_bpfel.go`
files have `linux` build tags. So `internal/tracer` and `main` don't even
compile for darwin, and `go test ./...` fails on macOS. Work inside a Linux VM:

- **OrbStack** or **Lima** (`brew install lima && limactl start
  template://ubuntu-24.04`) give you an Ubuntu 24.04 arm64 VM on Apple Silicon.
  That also tests the arm64 code natively. Ubuntu 24.04 matches CI.
- In the VM, install Go 1.25+ and run:

  ```bash
  sudo apt-get install -y clang-18 llvm-18 curl python3 gnutls-bin libnss3-dev pkg-config qemu-system-x86 iproute2
  ```

- Editing on the Mac and building, testing and running in the VM against the
  same checkout works fine. Lima mounts your home directory.
- From macOS you can still cross-check that things build:
  `GOOS=linux go build ./... && GOOS=linux go vet ./...`.

Running other kernels (vimto) needs QEMU. Without KVM it is slow but works:
`VIMTO_DISABLE_KVM=true make integration-vm KERNEL=5.10` took about a minute
per kernel here. Nested virtualization in a Mac VM needs an M3 or newer and
macOS 15; otherwise use `VIMTO_DISABLE_KVM=true` or let CI do it. The
`ci-kernels` images used so far were x86_64. If arm64 images aren't
available, run that matrix only in CI.

## Commands

```bash
make build                 # static ./snoopy
make test                  # unit tests (no root needed)
make integration           # loads the BPF program, traces real clients (sudo)
make integration-vm KERNEL=5.10   # same, in a VM with another kernel (vimto + QEMU)
make lint                  # golangci-lint (v2 config in .golangci.yml)
make generate              # recompile bpf/snoopy.c; use clang 18 or CI's diff check fails
sudo ./snoopy --verbose    # try it
```

The integration tests skip clients that aren't installed: curl, python3,
gnutls-cli, and cc with libnss3-dev for the NSS client in
`internal/tracer/testdata`. `SNOOPY_TEST_RUSTLS=1` builds and runs the rustls
client with cargo. `SNOOPY_BORINGSSL_TEST` and `SNOOPY_FREEBL_TEST` check the
signature finding against real binaries (see the README's Development
section).

## Repository map

| Path | What |
| --- | --- |
| `bpf/snoopy.c` | The eBPF program: uprobes on TLS read/write, return probes, `sys_enter` raw tracepoint, ring buffer output |
| `bpf/headers/vmlinux.h` | Hand-written minimal kernel types (`preserve_access_index` ones are relocated via CO-RE) |
| `bpf/headers/bpf_*.h` | Vendored libbpf 1.3.0 headers |
| `internal/tracer/gen.go` | `go:generate` → bpf2go (`go tool bpf2go`, declared as a tool in go.mod) |
| `internal/tracer/snoopy_{x86,arm64}_bpfel.{go,o}` | Generated and committed |
| `internal/tracer/tracer.go` | Load (BTF detection and fallback), attach, ring buffer loop, lost-event counter |
| `internal/tracer/assemble.go` | Decodes records and reassembles chunks into events |
| `internal/tracer/sockets.go` | Holds writes back until the socket notice for their connection arrives |
| `internal/tracer/event.go` | `Event`, `Function` (must match `enum fn_id` in C; a test checks) |
| `internal/discover/` | Finds targets: system libs, `/proc/*/maps`, deleted files, Go binaries, RET offsets, prologue check, rustls by mangled name, stripped BoringSSL (`boringssl.go`), freebl's function table (`freebl.go`) |
| `internal/funcfind/` | Locates functions in stripped x86-64 and arm64 binaries by the strings and constants they use (`x86.go`, `arm64.go`) |
| `internal/procinfo/` | Container ID from cgroups; `/proc` socket lookup (fallback when there's no BTF) |
| `internal/output/` | Text, NDJSON and pcap writers; HTTP/1 message framing (`http1.go`), HTTP/2 with HPACK (`http2.go`), QUIC and HTTP/3 with QPACK (`quic.go`, `qpack.go`), body decompression (`body.go`) |
| `main.go` | CLI flags and wiring |
| `.github/workflows/ci.yml` | Lint, unit tests, build, generate check, integration tests (x86_64, arm64) |
| `.github/workflows/release.yml`, `.goreleaser.yaml` | Releases on `v*` tags |
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

### Go side

- **Header layout:** `rawHeader` (Go) must match `struct event_header` (C,
  112 bytes with explicit padding); `TestHeaderMatchesBPFLayout` checks it
  against the bpf2go type.
- **Stripped Go binaries** are located via `.gopclntab`, using `runtime.text`
  from the pclntab header. With cgo/external linking it isn't the start of
  `.text`. `checkGoPrologue` refuses to attach unless the function starts with
  Go's stack check, so a mistake can't plant breakpoints mid-instruction.
- **Deleted or replaced files** in use by a process are attached through
  `/proc/<pid>/map_files/<range>` or `/proc/<pid>/exe`. This needs
  CAP_SYS_ADMIN.
- **pcap:** streams are keyed by 4-tuple. If both ends are traced, only the
  first endpoint seen is written. Synthetic ports are handed out sequentially,
  and the least recently used of 16384 streams is evicted.
- **HTTP/2** (`internal/output/http2.go`) is decoded per (pid, connection,
  direction) from the connection preface on, as a byte stream: frames can
  span calls. HPACK's table is built up over the connection, so connections
  that started before snoopy only get the old per-call frame summary.
  Missing bytes (truncated captures) are tolerated inside DATA payloads;
  anywhere else, decoding stops for that direction with a note.
- **rustls** is found by mangled symbol names (v0 and legacy;
  `inspectRustls`). Its Reader and Writer do no socket I/O, so
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
- **Stripped BoringSSL** (Chrome, Brave, Edge, Electron) is found by
  signature: `internal/discover/boringssl.go` on top of
  `internal/funcfind`, a small library for locating functions in stripped
  x86-64 and arm64 binaries (strings, the instructions that load them,
  function starts at direct call targets, constant call arguments, which
  arguments a function reads, how many stack arguments it reads). The
  README's "How it works" has the rules. Results are cached by build ID in
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
  reassembles streams per (pid, socket fd, direction), falling back to the
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
  SETTINGS; without them it assumes no wrap. `qpack_static.go` is generated
  from RFC 9204's text, and `TestQPACKExamples` runs its Appendix B
  examples.
- **Output and filters:** the text printer writes each call's ends as
  `source > destination`, in the direction the data went (`endpoints` in
  `output/text.go`). `--brief` (`output/brief.go`) prints one line per call
  from the same decoders, with a summary per protocol. `--host`, `--port` and
  `--count` are applied in `main.go` before any printer, so they also limit
  `--pcap`. A stripped BoringSSL whose functions can't be told apart becomes
  a `Target` with a `Problem`, which is reported as a warning instead of
  attached to.
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
  3 s after the exec. TLS calls made before a new library is attached are
  missed, and libraries a long-running process `dlopen`s more than 3 s after
  its exec aren't picked up.
- **Not supported:** rustls under tokio (hyper, reqwest: `Reader::read` is
  inlined into tokio-rustls, writes use `write_vectored`), Java, QUIC/HTTP/3
  outside Chromium and Firefox, Firefox's QUIC with ChaCha20-Poly1305
  (freebl's `ChaCha20Poly1305_Seal`/`Open`, table entries 214/215, would be
  the place), apps using OpenSSL only via its BIO layer (`openssl s_server
  -www`), and bodies with shared-dictionary encodings (Chrome's `dcb`, `dcz`).
- **HTTP/3 and bodies need the connection's start:** QPACK and HPACK tables
  are built up over a connection, Firefox's packet keys get their direction
  when created, and a body's decompressor needs its first bytes. Connections
  that started before snoopy show less.
- **HTTP/1 pipelining:** a response is matched to the last request sent, so
  with pipelined requests a response to HEAD can be taken to have a body.
- **No socket details** (fd or addresses) for apps that do their own socket
  I/O around OpenSSL with memory BIOs, e.g. .NET.
- **Untested:**
  - IPv6 end to end: the dev container had IPv6 disabled. Unit tests cover the
    decoding.
  - Kernels 5.8 and 5.9.
  - The `docker run` example in the README.
- **Go versions:** Go < 1.17 (amd64) and < 1.18 (arm64) are refused, since
  they predate the register ABI.
- **Ideas:**
  - rustls under tokio, the biggest gap that looks reachable.
  - Java's TLS (JSSE), a big gap but hard: the code is JIT-compiled.
  - Publish a container image (the static binary makes it trivial).
  - An `--sslkeylog` mode.
  - A flag for the ring buffer size (`tracer.Options.RingBufferSize` exists,
    but there's no CLI flag).
- **Possible cleanup:** `internal/discover`'s cgo-fixture test tries to build
  for linux with `cc` when one exists, so it fails if ever run on macOS.
  Skip it unless `runtime.GOOS == "linux"`.

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
