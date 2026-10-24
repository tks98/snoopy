# Contributing

How to build and test snoopy. [AGENTS.md](AGENTS.md) is the short list of
what to know before changing it, [HANDOFF.md](HANDOFF.md) has the design
notes, and [docs/maintenance.md](docs/maintenance.md) covers the parts that
depend on other programs' internals.


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
installed, and skip the rest. The rustls tests build two clients with
`cargo`, which takes a while, so they only run with `SNOOPY_TEST_RUSTLS=1`.
`TestCurlHTTP3` needs a curl with HTTP/3, which Ubuntu's isn't: set
`SNOOPY_TEST_CURL_HTTP3` to `/` on Fedora, or to a Fedora root filesystem
(curl is run chrooted in it). CI runs
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
