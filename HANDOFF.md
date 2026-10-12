# snoopy rewrite: handoff notes

The work is on branch `claude/snoopy-project-review-f9wf21`. These notes let you
(or a new Claude Code session) pick it up. Delete this file before merging.

## Status

The branch replaces the BCC/gobpf implementation with a CO-RE eBPF program
loaded by cilium/ebpf, fixes the old bugs, adds features, tests, CI and release
automation, and fixes 8 issues found in an independent review.

| Check | Status |
| --- | --- |
| Unit tests, lint, amd64 and arm64 builds | Green in CI |
| Committed BPF objects match `bpf/snoopy.c` | Green in CI |
| Integration tests on the runners' kernels (x86_64 and arm64) | Green in CI (run #3) |
| Integration tests on Linux 5.10, 5.15, 6.1, 6.6, 6.12 (vimto VMs) | All five pass locally (QEMU without KVM), after fixing a test race that showed on 6.12. Red in CI run #3 only because vimto needs a static test binary, fixed in `9015ae7` (`CGO_ENABLED=0`). **Check that the CI run for the latest commit is green.** |

### To do first

1. Check that the latest CI run on the branch is green, especially the
   "Integration tests (Linux x.y)" jobs:
   https://github.com/tks98/snoopy/actions
2. **Delete the logs of CI run 38189398199**
   (https://github.com/tks98/snoopy/actions/runs/38189398199, then ⋯, then
   "Delete all logs"). Its smoke test printed the runner's own TLS traffic,
   including short-lived Azure SAS signatures and the job's `GITHUB_TOKEN`
   basic-auth header. Both expire quickly, but they shouldn't stay public. The
   smoke test now runs with `--quiet`.
3. Close PR #2 ("add actions workflow", from the `build` branch). This work
   supersedes it.
4. Open a PR from this branch, merge, then tag a release (`git tag v2.0.0 && git
   push --tags`). GoReleaser publishes linux amd64 and arm64 binaries.

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
`internal/tracer/testdata`.

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
| `internal/tracer/event.go` | `Event`, `Function` (must match `enum fn_id` in C; a test checks) |
| `internal/discover/` | Finds targets: system libs, `/proc/*/maps`, deleted files, Go binaries, RET offsets, prologue check |
| `internal/procinfo/` | Container ID from cgroups; `/proc` socket lookup (fallback when there's no BTF) |
| `internal/output/` | Text (HTTP/1 pretty-print, HTTP/2 frame summary, hexdump), NDJSON, pcap writer |
| `main.go` | CLI flags and wiring |
| `.github/workflows/ci.yml` | Lint, unit tests, build, generate check, integration tests (x86, arm64, 5 kernels) |
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

- **New programs after startup:** processes started later are traced only if
  they use an already-attached file (e.g. system libssl). New Go binaries or
  container images need a restart. Idea: rescan `/proc` periodically, or
  watch exec events, and attach incrementally.
- **Not supported:** rustls, Java, stripped BoringSSL (Chrome), QUIC/HTTP/3,
  apps using OpenSSL only via its BIO layer (`openssl s_server -www`).
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
  - Publish a container image (the static binary makes it trivial).
  - An `--sslkeylog` mode.
  - A flag for the ring buffer size (`tracer.Options.RingBufferSize` exists,
    but there's no CLI flag).
  - HPACK decoding for HTTP/2 headers.
- **Possible cleanup:** `internal/discover`'s cgo-fixture test tries to build
  for linux with `cc` when one exists, so it fails if ever run on macOS.
  Skip it unless `runtime.GOOS == "linux"`.

## Things learned about the environment

- `go test -c` with cgo enabled gives a dynamically linked binary;
  vimto's `exec` needs a static one, hence `CGO_ENABLED=0` in CI and the
  Makefile.
- The ring buffer doesn't guarantee events from different CPUs arrive in
  call order. Integration tests use `eventLog`, so waits are order-independent.
  An earlier version flaked on 6.12.
- `no_proxy` in the environment makes curl ignore an explicit `--proxy`.
  The proxy test passes `--noproxy ''`.
- The GitHub API rate-limits unauthenticated polling at 60 requests per hour.
