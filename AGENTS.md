# Working on snoopy

snoopy traces TLS plaintext with eBPF uprobes: a C program in `bpf/snoopy.c`,
loaded and read by Go (cilium/ebpf). This file is the short list of what to
know before changing it. [HANDOFF.md](HANDOFF.md) has the design notes and a
map of the code, [docs/maintenance.md](docs/maintenance.md) how the fragile
parts were found and how to fix them, and
[docs/release-risks.md](docs/release-risks.md) what new releases of other
programs are likely to break.

## Never publish captured output

snoopy prints whatever the traced programs send: tokens, cookies, passwords.
Don't put real output in CI logs, PRs, issues or commits. It has happened:
a CI smoke test once printed the runner's own `GITHUB_TOKEN`. Use `--quiet`
in CI, and test servers and clients you control.

## Building and testing

eBPF only runs on Linux, and the generated `internal/tracer/snoopy_*_bpfel.go`
files have `linux` build tags, so `internal/tracer` and most other packages
don't compile on macOS. The root package's files have `linux` tags too, and on
other systems it builds `main_other.go`, a stub that says snoopy is Linux only.
On a Mac, `GOOS=linux go vet ./...` checks the build; run tests in a Linux VM
or container (see HANDOFF.md, "Working on it from a Mac").

```bash
make build         # ./snoopy, a static binary
make test          # unit tests
make lint          # golangci-lint, also with -tags integration
make integration   # loads the eBPF program and traces real clients; needs root
make integration-vm KERNEL=5.10   # the same on another kernel, with vimto
```

- Integration tests skip the clients that aren't installed (`curl`,
  `python3` and its `websockets`, `gnutls-cli`, the NSS, wolfSSL, Mbed TLS
  and s2n-tls dev files). With `SNOOPY_TEST_STRICT=1`, as in CI, a missing
  tool, library or download fails a test instead of skipping it. `SNOOPY_TEST_RUSTLS=1` adds
  the rustls and quinn tests (CI runs them weekly, rust.yml), which
  build with cargo. `SNOOPY_TEST_CURL_HTTP3` (with cargo too) adds curl's
  HTTP/3, given the root of a system whose curl has it: `/` on Fedora, or a
  Fedora root filesystem to chroot into, since Ubuntu's curl doesn't.
  `SNOOPY_TEST_LEGACY_UPROBES=1` attaches a link per probe, as kernels
  before 6.6 do, on a kernel that has uprobe_multi links; CI runs the
  tests both ways.
  `TestQuicGoHTTP3`, `TestQuicGoDialAddr` and `TestSSEHTTP3` download
  quic-go with the Go toolchain, for the test program in
  `internal/tracer/testdata/quicgo`, which is its own module, and
  `TestWebSocket` coder/websocket, for `testdata/wsgo`.
- `SNOOPY_BORINGSSL_TEST` and `SNOOPY_FREEBL_TEST` check the signature-based
  finding against real browser binaries; see
  [CONTRIBUTING.md](CONTRIBUTING.md).
- Browsers are tested by hand; docs/maintenance.md has the recipes.

## Changing the eBPF program

- The compiled objects are committed and must be what clang 18 produces:
  run `make generate` with clang 18 (CI fails otherwise) and commit the
  `.o` and `.go` files with the change.
- The 5.10 verifier is the strictest one supported. After changing
  `bpf/snoopy.c`, run the integration tests on 5.10, 5.15, 6.1, 6.6 and 6.12
  (`make integration-vm`). From 6.6 the uprobe programs are loaded for
  uprobe_multi links, which the verifier checks again. The Load check workflow loads every program
  under 5.10 to 6.12 for such changes (`tools/loadcheck`, also runnable by
  hand); CI's other jobs only run their runners' kernels.
- Rules learned the hard way: zero every struct passed to a helper
  (`__builtin_memset`), keep the chunk loop's shape, and truncate 32-bit
  arguments (`(__u32)func_arg(ctx, n)`), whose upper halves are garbage.
- Kernel structs come from the hand-written `bpf/headers/vmlinux.h`, with
  only the fields snoopy reads. Add fields there as needed; CO-RE relocates
  them.
- `enum fn_id` and `struct event_header` are mirrored in
  `internal/tracer/event.go`; tests check they match.

## Changing the Java agent

- snoopy embeds the agent's jars (`internal/javaagent/jars`), for `go
  install`. After changing `java/agent` or `java/build.sh`, run `make jars`
  with Temurin 21.0.13+9, the release's JDK (CI fails otherwise: another
  JDK builds other bytes), and commit the jars with the change.

## Keeping things in sync

- **Output:** the examples in README.md and docs/usage.md come from real
  runs. Update them when the text, `--brief` or JSON output changes, and
  docs/usage.md's JSON field table too.
- **Demo GIF:** `docs/demo.gif` is recorded with `docs/demo/record.sh`.
  Record it again when the output changes, and read the capture it saves
  before committing the new one.
- **Flags:** `--help` is written by hand (`usage` in `main.go`).
  `TestUsage` fails if a flag is missing from it; docs/usage.md repeats it.
- **Messages:** docs/maintenance.md's "Which part broke?" table quotes
  warnings word for word.
- **Behavior:** update HANDOFF.md's notes for the part you changed, and
  docs/release-risks.md if it changes how something fails.
- **Signature-based finding:** bump `boringSSLCacheVersion` whenever its
  answers could change, or users keep stale cached results.
- **Vulnerabilities:** `vulnscan.yml` fails on any known vulnerability in a
  dependency, reachable or not, daily too. Fix it by updating the
  dependency (both modules for one they share). An exception goes in an
  `osv-scanner.toml` next to the lockfile, with its reason, and only for a
  test program that has to stay on an old version; nothing shipped gets
  one. ASM is pinned in `java/build.sh`, which `java/vulncheck.sh` checks.

## Conventions

- The module path is `github.com/tks98/snoopy/v2`.
- Comments say why, in full sentences. Tests sit next to the code, and unit
  tests build their input (HTTP/2 frames, QUIC packets, machine code) where
  they can, rather than load captures.
- Errors and warnings name the file or function involved and say what to do
  when there's something to do.
