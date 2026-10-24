# Maintaining the fragile parts

How the parts of snoopy that depend on other projects' internals were
found, how they work, how to tell when one has broken, and how to fix it.
[release-risks.md](release-risks.md) lists what's likely to break and why;
[HANDOFF.md](../HANDOFF.md) has design notes for the rest of the code.

Everything here was worked out by running the real programs and comparing
what snoopy saw with ground truth: published debug symbols, uprobes set by
hand, and syscall traces. The [toolbox](#toolbox) has the recipes; the
sections after it use them.

- [Which part broke?](#which-part-broke)
- [Toolbox](#toolbox)
- [Chrome, Electron and other Chromium builds](#chrome-electron-and-other-chromium-builds)
- [HTTP/3 in Chromium](#http3-in-chromium)
- [HTTP/3 in Firefox](#http3-in-firefox)
- [rustls](#rustls)
- [Go crypto/tls](#go-cryptotls)
- [funcfind and golang.org/x/arch](#funcfind-and-golangorgxarch)
- [The BPF program](#the-bpf-program)
- [HTTP decoding and compressed bodies](#http-decoding-and-compressed-bodies)

## Which part broke?

Run snoopy with `--verbose`, which lists the functions it attached to in each
file, then match what you see:

| What you see | Likely cause | Go to |
| --- | --- | --- |
| `warning: ...: BoringSSL is linked in, but its functions couldn't be told apart` | Signature finding failed | [Chrome, Electron and other Chromium builds](#chrome-electron-and-other-chromium-builds) |
| `warning: ...: BoringSSL's QUIC packet encryption wasn't found in this build, so its HTTP/3 isn't traced` | The AEAD functions weren't found | [Chrome, Electron and other Chromium builds](#chrome-electron-and-other-chromium-builds) |
| QUIC events appear, but HTTP/3 shows `waiting for QPACK encoder stream data` that never resolves, gaps in bodies, or one connection's packets on several fds | Packets matched to the wrong socket | [HTTP/3 in Chromium](#http3-in-chromium) |
| QUIC events are hex dumps instead of `QUIC: ...` lines | A frame type snoopy doesn't know | [HTTP/3 in Chromium](#http3-in-chromium) |
| Firefox uses HTTP/3 (UDP port 443 in `tcpdump`) but there are no `AES_AEAD` events, and no warning about connections from before snoopy | Firefox's QUIC path changed, or freebl's table wasn't found | [HTTP/3 in Firefox](#http3-in-firefox) |
| A Rust program shows nothing, or wrong sizes | rustls symbol names or Rust's return layout | [rustls](#rustls) |
| A Go program shows events without fd or addresses, or isn't attached | Go's struct offsets, prologue or pclntab | [Go crypto/tls](#go-cryptotls) |
| arm64 Chromium has TLS but no HTTP/3, after a dependency update | `golang.org/x/arch` output changed | [funcfind and golang.org/x/arch](#funcfind-and-golangorgxarch) |
| CI's "BPF objects are up to date" is red, or loading fails on an old kernel | Generated objects or the verifier | [The BPF program](#the-bpf-program) |
| `[br body not decoded: ...]` | Usually bytes that weren't captured | [HTTP decoding and compressed bodies](#http-decoding-and-compressed-bodies) |

## Toolbox

### Machines

- **arm64:** an Ubuntu VM on Apple Silicon (Lima or Parallels). Ubuntu's
  Chromium and Firefox are snaps there, and Electron publishes arm64 builds.
- **x86-64 on Apple Silicon:** uprobes need a real kernel, and Docker's amd64
  emulation is user space only, so use an emulated VM:

  ```bash
  limactl start --name=snoopy-x86 --arch=x86_64 --vm-type=qemu template://ubuntu-24.04
  ```

  It's slow, but Chrome and Firefox run headless in it.
- **Building in a container:** the BPF objects must come from clang 18, which
  Ubuntu 24.04 has:

  ```bash
  docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 bash -c '
    apt-get update -qq && apt-get install -y -qq curl ca-certificates clang-18 llvm-18 libbpf-dev >/dev/null &&
    ln -s /usr/bin/clang-18 /usr/local/bin/clang && ln -s /usr/bin/llvm-strip-18 /usr/local/bin/llvm-strip &&
    curl -fsSL https://go.dev/dl/go1.26.9.linux-$(dpkg --print-architecture).tar.gz | tar -C /usr/local -xz &&
    export PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local && go generate ./... && go test ./...'
  ```

### The canary

`.github/workflows/canary.yml` runs weekly (and from the Actions tab, and on
PRs that change it) against the latest browsers and Fedora's curl; its
download script, `.github/canary/fetch.sh`, does what this section describes.
When it fails, the job's name says which program, and the sections below say
how to fix each. The script runs locally too, e.g.
`spec=$(.github/canary/fetch.sh chrome beta /tmp/chrome)` and then
`SNOOPY_BORINGSSL_TEST=$spec go test ./internal/discover -run TestBoringSSLBinaries -v`.

### Getting browsers and their symbols

Symbols are what make a fix checkable: with them, a test compares snoopy's
answer with the real address instead of with a guess.

| Program | Binary | Symbols |
| --- | --- | --- |
| Chrome (x86-64) | `https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_<version>-1_amd64.deb` (`-beta` for beta) | `https://edgedl.me.gvt1.com/chrome/linux/symbols/google-chrome-debug-info-linux64-<version>.zip`, an ELF `debug-info/chrome.debug` |
| Current Chrome versions | `https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/stable/versions` (or `beta`) | |
| Electron (x86-64, arm64) | `electron-v<version>-linux-<arch>.zip` on [Electron's releases](https://github.com/electron/electron/releases) | `electron-v<version>-linux-<arch>-symbols.zip` from the same release, a Breakpad `electron.sym` |
| Firefox (x86-64) | `https://download.mozilla.org/?product=firefox-latest-ssl&os=linux64&lang=en-US` | Mozilla's symbol server (below), Breakpad |
| Firefox, Chromium (arm64) | `snap install firefox`, `snap install chromium` | Firefox's from Mozilla's symbol server; none for Chromium |
| Brave, Edge | Brave's GitHub releases, `packages.microsoft.com/repos/edge` | none |

The symbol files are large (Electron's `.sym` alone is 700 MB unpacked), so
keep only the lines you need:

```bash
unzip -p electron-v44.7.0-linux-arm64-symbols.zip 'breakpad_symbols/electron/*/electron.sym' |
  grep -E '^(MODULE|FUNC (m )?[0-9a-f]+ [0-9a-f]+ [0-9a-f]+ (SSL_read|SSL_write|EVP_AEAD_CTX_seal|EVP_AEAD_CTX_open)$)' > electron-ssl.sym
```

Mozilla's symbol server finds a library's symbols by its Breakpad ID: the
first 16 bytes of the GNU build ID as a GUID (the first three fields
byte-swapped), in upper case, followed by `0`:

```bash
id=$(readelf -n libfreeblpriv3.so | awk '/Build ID/ {print $3}')
bid=$(python3 -c 'import sys; b=bytes.fromhex(sys.argv[1])[:16]; print((b[3::-1]+b[5:3:-1]+b[7:5:-1]+b[8:]).hex().upper()+"0")' $id)
curl -fsSL -o freebl.sym "https://symbols.mozilla.org/libfreeblpriv3.so/$bid/libfreeblpriv3.so.sym"
file freebl.sym   # it may come gzipped
```

Breakpad addresses (`FUNC <address> ...`) are relative to the module's load
address. snoopy attaches by file offset: subtract the executable `PT_LOAD`'s
virtual address and add its file offset. Both signature tests accept an ELF
debug file or a Breakpad file and do this for you:

```bash
SNOOPY_BORINGSSL_TEST=/opt/google/chrome/chrome=chrome.debug,electron=electron-ssl.sym \
  go test ./internal/discover -run TestBoringSSLBinaries -v
SNOOPY_FREEBL_TEST=/opt/firefox/libfreeblpriv3.so=freebl.sym \
  go test ./internal/discover -run TestFreeblBinaries -v
```

Without `=symbols`, a test only reports what was found, which still tells you
whether the finder gave one clear answer.

### Running browsers for a capture

Start snoopy first and wait for `tracing`, so connections are seen from their
start; HTTP/2 and HTTP/3 headers can't be decoded otherwise.

```bash
# Chrome, forcing HTTP/3 for one origin
google-chrome --headless=new --no-sandbox --no-first-run --user-data-dir=$(mktemp -d) \
  --origin-to-force-quic-on=example.com:443 --dump-dom https://example.com

# Ubuntu's Chromium snap, as a desktop user
sudo -u <user> -H env XDG_RUNTIME_DIR=/run/user/<uid> /snap/bin/chromium --headless=new --no-sandbox \
  --origin-to-force-quic-on=example.com:443 --dump-dom https://example.com

# Electron's default app loads a URL; it needs a display (and an unpacked
# directory other users can read, chmod -R a+rX)
xvfb-run -a ./electron --no-sandbox --origin-to-force-quic-on=example.com:443 https://example.com
```

Firefox needs preferences to use HTTP/3 right away, in a `user.js` in a fresh
profile directory:

```js
user_pref("network.http.http3.enable", true);
user_pref("network.http.http3.alt-svc-mapping-for-testing", "example.com;h3=:443");
user_pref("network.http.http3.force-use-alt-svc-mapping-for-testing", true);
```

```bash
firefox --headless --profile <dir> https://example.com
```

Firefox's QUIC runs on the parent process's "Socket Thread", not in its
socket process.

### Reading machine code

```bash
objdump -d --no-show-raw-insn --start-address=0x70a02c0 --stop-address=0x70a0408 electron
```

(`llvm-objdump` on macOS reads both architectures.) To see what funcfind
makes of a binary, a throwaway test in `internal/discover` that prints every
candidate is quicker than reading code. This one debugged the AEAD finding on
Ubuntu's Chromium:

```go
func TestZZDebugAEAD(t *testing.T) {
	f, err := elf.Open(os.Getenv("ZZ_BIN"))
	if err != nil {
		t.Skip(err)
	}
	b, _ := funcfind.Open(f)
	file, _ := b.FindString("/cipher/aead.cc.inc")
	for _, ref := range b.Refs(file) {
		fn, ok := b.FuncAt(ref)
		if !ok {
			t.Logf("ref %#x: no function", ref)
			continue
		}
		reasons, _ := b.ConstArgsNear(fn, file, 2)
		t.Logf("ref %#x: fn %#x-%#x callers %d reasons %#x stack args %d reads 3 args %v",
			ref, fn.Start, fn.End, fn.Callers, reasons, b.StackArgs(fn), b.ReadsArgs(fn, 3))
	}
}
```

### Watching a function without snoopy

bpftrace can't attach to raw addresses in a stripped binary, but tracefs
uprobes can, by file offset, and they can fetch arguments. This is how
Firefox's QUIC path was found and how the arm64 length bug was confirmed:

```bash
T=/sys/kernel/tracing
F=/snap/firefox/current/usr/lib/firefox/libfreeblpriv3.so
echo > $T/uprobe_events
echo "p:aead $F:0x55a0c cx=%x0 inlen=%x5:u32 aadlen=+8(%sp):u32 b0=+0(+0(%sp)):u8" >> $T/uprobe_events
echo "r:aeadr $F:0x55a0c rc=%x0:s32" >> $T/uprobe_events
echo 1 > $T/events/uprobes/enable
# ... run the program ...
cat $T/trace            # one line per call, with the task name and thread ID
cat $T/uprobe_profile   # hits per probe
echo 0 > $T/events/uprobes/enable; echo > $T/uprobe_events
```

Arguments at a function's entry:

| | Registers | On the stack |
| --- | --- | --- |
| x86-64 | `%di %si %dx %cx %r8 %r9` | `+8(%sp)`, `+16(%sp)`, ... (the return address is at `+0`) |
| arm64 | `%x0` to `%x7` | `+0(%sp)`, `+8(%sp)`, ... |

### Is the BPF program even running?

When snoopy misses calls that a tracefs probe sees, check whether its program
runs and filters them out, or doesn't run at all:

```bash
sudo sysctl -w kernel.bpf_stats_enabled=1
sudo bpftool prog show name aes_aead_enter   # run_cnt
cat /sys/kernel/tracing/uprobe_profile        # compare with the tracefs probe's hits
sudo sysctl -w kernel.bpf_stats_enabled=0
```

Equal counts with fewer events means the program drops them. That's how the
arm64 bug showed up: `AES_AEAD`'s 32-bit length had garbage in the upper half
of its stack slot, so the length check rejected most packets.

### Which syscalls a program uses

```bash
strace -f --seccomp-bpf -qq -e trace=recvmsg,recvfrom,recvmmsg -o recv.txt google-chrome --no-sandbox ...
```

This showed that Chrome receives each QUIC datagram with `recvmsg` into a
single buffer, which is what snoopy's receive-buffer tracking relies on.

### Older kernels

CI no longer runs other kernels, which took too long. `make integration-vm
KERNEL=5.10` runs the integration tests on one in a VM, with
[vimto](https://github.com/lmb/vimto) and QEMU; vimto must be built without
cgo (`CGO_ENABLED=0 go install lmb.io/vimto@v0.4.0`) or it refuses to run.
On Apple Silicon, run it in an amd64 container, where it takes about two
minutes per kernel:

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/src" -w /src ubuntu:24.04 bash -c '
  apt-get update -qq && apt-get install -y -qq qemu-system-x86 gnutls-bin libnss3-dev pkg-config curl python3 git gcc ca-certificates iproute2 >/dev/null &&
  curl -fsSL https://go.dev/dl/go1.26.9.linux-amd64.tar.gz | tar -C /usr/local -xz &&
  export PATH=/usr/local/go/bin:/root/go/bin:$PATH GOTOOLCHAIN=local VIMTO_DISABLE_KVM=true &&
  CGO_ENABLED=0 go install lmb.io/vimto@v0.4.0 &&
  for k in 5.10 5.15 6.1 6.6 6.12; do make integration-vm KERNEL=$k || echo "Linux $k failed"; done'
```

vimto needs the checkout to be a git repository; a git worktree's `.git` file
points outside the mount, so copy the tree and `git init` it first.

## Chrome, Electron and other Chromium builds

### How it was found

Chrome links BoringSSL statically and is stripped, so `SSL_read` and
`SSL_write` have no symbols. Google publishes debug symbols for every Chrome
build, which gave the right answers to work toward.

BoringSSL reports errors with `OPENSSL_PUT_ERROR(library, reason)`, which
expands to `ERR_put_error(library, 0, reason, __FILE__, __LINE__)`. So every
function that can fail loads the address of its source file's name and passes
constant reason codes in the third argument register. Those codes are public
constants (`SSL_R_*` in `ssl.h`, `CIPHER_R_*` in `cipher.h`) that never
change value. That's the signature:

1. Find the string ending in `/ssl/ssl_lib.cc`.
2. Find the instructions that load its address: `lea reg, [rip+disp]` on
   x86-64, an `adrp` and `add` pair on arm64.
3. Find the function around each. A function starts at an address something
   calls directly (`call rel32`, `bl`), with a frame pointer prologue on
   x86-64. It ends where the next one starts, or on arm64 where a `paciasp` or
   `bti` follows a return or branch.
4. Collect the constants loaded into the reason register next to each
   reference.
5. Classify: `SSL_write` reports bad length (`0x6f`) besides uninitialized
   (`0xd7`) and protocol is shutdown (`0xe2`); `SSL_read` reports those two and
   should not have been called (`0x42`).

Inlining is what makes it hard, and each problem added a rule:

- Chrome's own `SSLClientSocketImpl::DoPeek` has BoringSSL code inlined into
  it and reports the same codes. It doesn't take `(ssl, buf, num)`, so
  candidates must read their first three argument registers before
  overwriting them (`ReadsArgs`), following both sides of early error checks.
- Chrome 156 stopped inlining `ssl_read_impl` into `SSL_read`, so a function's
  codes include those of the `ssl_lib.cc` functions it calls.
- `SSL_peek` reports the same codes as `SSL_read`, which calls it or has it
  inlined; `pickSSLRead` takes the caller, or the larger.

For HTTP/3, `EVP_AEAD_CTX_seal` and `EVP_AEAD_CTX_open` are found the same way
from `cipher/aead.cc.inc`. Both take ten arguments, which `StackArgs` checks
by the stack arguments a function reads. `EVP_AEAD_CTX_open_gather` takes ten
too, and Ubuntu's Chromium keeps it separate where Google's and Electron's
builds inline it into `open`, so they're told apart by their own codes: open
reports bad decrypt (`0x65`); seal reports buffer too small (`0x67`) but not
open_gather's `0x73`.

### Where it lives

- `internal/funcfind`: the generic search, in `funcfind.go`, `x86.go` and
  `arm64.go`.
- `internal/discover/boringssl.go`: the rules, and the cache of answers by
  build ID in the user's cache directory, named with `boringSSLCacheVersion`.
- `knownPrograms` in `internal/discover/discover.go`: where browsers are
  installed, so they're analyzed at startup instead of when they start.

### How to tell it broke

snoopy warns that BoringSSL is linked in but its functions couldn't be told
apart, with the reason (e.g. `BoringSSL: 2 candidates for SSL_write`), or
attaches with a warning that HTTP/3 won't be captured. The test gives the same
reason, and with symbols, which function it got wrong:

```bash
SNOOPY_BORINGSSL_TEST=/opt/google/chrome/chrome go test ./internal/discover -run TestBoringSSLBinaries -v
```

### How to fix it

1. Get the build that fails and, if there are any, its symbols (Chrome,
   Electron). Run the test with the symbols to see which function is missing
   or wrong.
2. Print every candidate with a throwaway test like `TestZZDebugAEAD` above:
   reference, function bounds, callers, reason codes, stack arguments.
3. Disassemble the right function (its address from the symbols) and the
   candidates that got in the way, and compare what they report, what they
   call and what they read. Usually one build inlines differently.
4. Change the rule in `boringssl.go` so that every build in the list in
   [how-it-works.md](how-it-works.md#supported-libraries)
   still gives the same answers. Keep the requirement of exactly one answer:
   attaching to the wrong function captures the wrong data.
5. If the instructions themselves changed (a new prologue, a new way of
   loading addresses, like `endbr64` before the prologue), fix funcfind and
   add a hand-assembled case to `funcfind_test.go` or `arm64_test.go`.
6. Bump `boringSSLCacheVersion`, or machines keep their cached answers.
7. Run the test on all the builds again, add the new one to that list, and
   do a live capture.

## HTTP/3 in Chromium

### How it was found

QUIC traffic never reaches `SSL_read`: TLS only does the handshake. Chrome's
QUIC stack (quiche) encrypts each packet with an AEAD whose associated data is
the packet's header, using BoringSSL's `EVP_AEAD_CTX_seal` and `open`. Probing
those showed QUIC-shaped associated data (a first byte, a connection ID, a
packet number) next to TLS records, whose associated data is a 5-byte record
header (or 13 bytes for TLS 1.2).

### How it works

- **BPF** (`bpf/snoopy.c`): `quic_seal_enter` copies the plaintext at entry,
  since seal encrypts in place; `quic_open_enter` and its return probe copy it
  after decrypting. `is_quic_aad` leaves out TLS records by the shape of their
  associated data. QUIC's fixed bit can't be used, since peers may grease it
  (RFC 9287).
- **Sockets:** the AEAD functions never touch the socket. A packet is sent
  right after it's encrypted, so `io_threads` remembers which connection
  waits for the thread's next send, and when that teaches it a new socket,
  emits a notice that `internal/tracer/sockets.go` waits for before releasing
  the connection's first packets. A received packet is decrypted from the
  buffer it was received into, so `sys_enter` records which socket filled each
  receive buffer (`recv_bufs`), and `packet_fd` looks up the packet's start:
  `in - ad_len`, since Chrome copies the header to remove header protection
  but decrypts the rest where it is. Later packets of a coalesced datagram
  are inside the same buffer. Only then does it fall back to the thread's last
  receive. With BTF, only AF_INET and AF_INET6 sockets count.
- **User space** (`internal/output/quic.go`, `qpack.go`): streams are
  reassembled per process, socket and direction, across the encryption
  contexts a connection goes through, and across a move to a new socket
  (connection migration); HTTP/3 frames and QPACK headers are decoded.

### How to tell it broke, and how to fix it

- **No `EVP_AEAD_CTX_*` events:** the AEAD functions weren't found, see
  [above](#chrome-electron-and-other-chromium-builds); or Chrome no longer
  uses them for QUIC. To check the second, put tracefs probes on them and look
  for QUIC-shaped associated data (argument 8, with its length in argument 9).
- **Stuck header blocks or gaps:** packets are probably filed under the wrong
  socket. This counts, per encryption context, how often its fd changes and
  then changes back, which a real move to a new socket doesn't do:

  ```python
  import re, sys, collections
  seq = collections.defaultdict(list)
  for line in open(sys.argv[1]):   # snoopy's text output
      m = re.search(r'(EVP_AEAD_CTX_open|AES_AEAD \(decrypt\)) .*?fd (\d+), conn (0x[0-9a-f]+)', line)
      if m:
          s = seq[m.group(3)]
          if not s or s[-1] != m.group(2):
              s.append(m.group(2))
  print(sum(1 for s in seq.values() for i in range(len(s) - 2) if s[i] == s[i + 2]))
  ```

  A context address can also be freed and reused by a later connection, so
  look at the flips before trusting the count. Then check how the browser
  receives now (`strace`, above) and where it decrypts from (a tracefs probe
  on `open` printing argument 6, `in`, next to the `recvmsg` buffers), and
  adapt `note_recv_buf` and `packet_fd` in `bpf/snoopy.c`.
- **Hex dumps instead of `QUIC: ...`:** a frame type `parseQUICFrames` doesn't
  know made it reject the packet. Find the type in the dump (it follows the
  frames that did parse), look up its layout in its RFC or draft, and add it
  to `parseQUICFrames` with a test. Frames can't be skipped without knowing
  their layout.

## HTTP/3 in Firefox

### How it was found

Firefox's HTTP/3 never reaches NSPR's `PR_Read` and `PR_Write`. With
addresses from Mozilla's symbol server, tracefs probes on freebl's AEAD
functions showed `AES_AEAD` being called with QUIC-shaped associated data on
the parent process's "Socket Thread", from libxul (neqo's `nss_rs` crate),
and `AES_CreateContext` creating its contexts with mode 4 (GCM) and an
encrypt flag. Both are called through function pointers, not exported.

freebl does export `FREEBL_GetVector`, which returns its function table,
`struct FREEBLVectorStr` in NSS's `lib/freebl/loader.h`. The table is NSS's
ABI, so entries keep their positions: `AES_CreateContext` is entry 31 and
`AES_AEAD` entry 238 (since `FREEBL_VERSION` 0x0322).
`internal/discover/freebl.go` decodes the start of `FREEBL_GetVector` for the
address it returns, checks the table's header (its length, and version 3.x),
and reads the two pointers, through their `R_*_RELATIVE` relocations or, with
packed (RELR) relocations, from the file. The BPF program learns each GCM
context's direction when it's created, so contexts created before snoopy
started are skipped; it counts their packets, and snoopy warns once it sees
any.

Three things went wrong along the way:

- On arm64, `AES_AEAD`'s `unsigned int` length comes with garbage in the upper
  half of its 8-byte stack slot, which made most packets fail the length
  check. Truncate 32-bit arguments (`(__u32)func_arg(ctx, 9)`).
- Ubuntu's x86-64 freebl is built with CET, so `FREEBL_GetVector` starts with
  `endbr64`, which `x86asm` doesn't decode.
- Ubuntu's `libfreebl3.so` is only a loader for `libfreeblpriv3.so` and has
  no table, which broke CI when it was among the libraries snoopy inspects.

### How to tell it broke

Firefox uses HTTP/3 (UDP port 443 in `tcpdump`), but there are no `AES_AEAD`
events. Restart Firefox first: snoopy warns about HTTP/3 connections that
were open before it started, which it can't trace, but only while their
packets go by. `--verbose` shows `(freebl, for QUIC)` when the table was
found; `TestFreeblBinaries` shows what was found and checks it against
symbols.

### How to fix it

- **The table isn't found:** disassemble `FREEBL_GetVector` (its address is in
  the dynamic symbol table) and see how it computes the address it returns;
  extend `loadedAddresses`.
- **Firefox stopped using freebl's AES-GCM for QUIC:** find what it uses now.
  Probe candidate AEAD functions with tracefs (freebl's
  `ChaCha20Poly1305_Seal` and `Open`, table entries 214 and 215, if it's
  ChaCha20; NSS's `PK11_` functions; or what neqo's crypto code calls in the
  version Firefox ships) and look for QUIC-shaped associated data on the
  Socket Thread. Then probe that, as `aes_aead_enter` does.
- Test with the preferences under [Running browsers for a
  capture](#running-browsers-for-a-capture), on x86-64 and arm64.

## rustls

### How it was found

With aws-lc-rs, rustls's default crypto provider, the plaintext is read where
aws-lc encrypts and decrypts each record. A bpftrace session on a
tokio-rustls client showed which of aws-lc's AEAD functions are called, with
which associated data, and on which threads relative to the socket syscalls:

```bash
B=<program>; P=aws_lc_0_46_0_EVP_AEAD_CTX
bpftrace -e "uprobe:$B:${P}_open { printf(\"%d open in_len=%d ad_len=%d\n\", tid, arg7, *(uint64*)(reg(\"sp\")+8)); }
  uprobe:$B:${P}_seal { printf(\"%d seal in_len=%d\n\", tid, arg7); }
  tracepoint:syscalls:sys_enter_recvfrom /comm == \"<name>\"/ { printf(\"%d recvfrom fd=%d\n\", tid, args.fd); }"
```

(On arm64 the ninth and tenth arguments are on the stack; on x86-64 from the
seventh.) `open` decrypts every record (calling `open_gather` itself, so that
one isn't probed); `seal` encrypts TLS 1.3 records and `seal_scatter` TLS
1.2's. The associated data is the record header (5 bytes, TLS 1.3) or 13
bytes (TLS 1.2). Each decrypt follows a receive on the same thread and each
encrypt precedes a send, as with QUIC packets. Under load, a new
connection's encryption context was often allocated where a closed
connection's had been, which is why `conn_infos` keeps the socket's struct
file and checks it.

With ring, rustls's other provider (reqwest 0.12 picks it), ring's AEAD
code is Rust, and the functions that see every record are the ones ring
calls through `ring::aead::Algorithm`'s function pointers:
`ring::aead::algorithm::aes_gcm_seal`, `aes_gcm_open` and the
`chacha20_poly1305_` pair. Their argument places were found with bpftrace,
printing each argument and reading the buffers before and after `open`:

```bash
B=<program>; F=$(nm $B | grep -oE '_R\S*4ring4aead9algorithm12aes_gcm_open$')
# arm64; on x86-64 use arg3, arg4 and arg5, and the stack for the rest
bpftrace -e "uprobe:$B:$F { printf(\"ad=%r ad_len=%d len=%d src=%d\n\", buf(arg2, 5), arg3, arg5, arg6); }"
```

`aad` is a slice (pointer and length), as is `in_out`, and `open`'s `src`
is where the ciphertext starts in `in_out` (8 for TLS 1.2's explicit nonce).
The `Result<Tag, Unspecified>` they return is too big for registers: arm64
returns it through `x8`, x86-64 through a hidden first argument, which moves
the others along by one (`RING_ARG` in `bpf/snoopy.c`). Both encrypt and
decrypt in place; after `open`, the plaintext is at the start of `in_out`.

Without aws-lc or ring, rustls's `Reader` and `Writer` (what `rustls::Stream` and clients like ureq
read and write through) do no socket I/O themselves, and Rust programs keep
their symbol table by default. `inspectRustls` in
`internal/discover/inspect.go` matches the mangled names of
`<rustls::conn::Reader as std::io::Read>::read` and the matching `write`,
in both v0 (`_R...`) and legacy (`_ZN...`) mangling. They return
`io::Result<usize>` in two registers: the discriminant in the first (0 for
`Ok`) and the byte count in the second (`RET_RUST_RESULT`, `RUST_RESULT_VALUE`
in `bpf/snoopy.c`). The program reads from the socket just before
`Reader::read` and writes just after `Writer::write`, on the same thread,
which gives each call its socket.

### How to tell it broke, and how to fix it

- **A tokio program shows only its writes:** aws-lc's functions weren't found,
  so snoopy fell back to `Writer::write`. List them and update `awsLCAEAD`
  in `internal/discover/inspect.go`, and `TestAwsLCSymbols`; for ring,
  `ringAEAD` and `TestRingSymbols`:

  ```bash
  nm <program> | grep -E 'EVP_AEAD_CTX_(seal|open)|4ring4aead9algorithm'
  ```

- **ring's records garbled, or nothing from them:** the functions'
  arguments moved, or how their result is returned. Rerun the bpftrace
  session above and update `RING_ARG` and `ring_*_enter`.

- **One direction or one TLS version missing:** aws-lc-rs may call another
  AEAD function for it. Rerun the bpftrace session above with all of
  `EVP_AEAD_CTX_*`'s variants probed.
- **Not attached:** list the names in a current build and update the
  patterns, and `TestRustlsSymbols`:

  ```bash
  nm --demangle <program> | grep -E 'rustls.*(Reader|Writer)'
  ```

- **Wrong sizes or no data:** the return layout may have changed. Disassemble
  `Reader::read`'s return paths, or put a tracefs return probe on it printing
  both return registers (`%ax` and `%dx` on x86-64, `%x0` and `%x1` on arm64)
  while reading a known amount.
- **To test:** `SNOOPY_TEST_RUSTLS=1` runs `TestRustls` and
  `TestRustlsAsync`, which build the clients in
  `internal/tracer/testdata/rustlsclient` (ring, synchronous) and
  `rustlsasync` (on tokio, built once with aws-lc-rs and once with ring)
  with cargo.

## HTTP/3 over quinn

### How it was found

quinn's packets go through rustls's provider like TLS records do, with the
packet header as associated data, so the record probes saw them once ring's
stopped skipping QUIC. Two things were different from Chromium. All of a
quinn endpoint's connections use one UDP socket, which isn't connected, so
the kernel doesn't know any peer; and tokio runs the encrypting, sending,
receiving and decrypting on different threads, so per-thread bookkeeping
gave packets the wrong connection's socket or peer, or none. bpftrace on the
client showed that quinn receives with `recvmmsg`, 32 datagrams at a time,
and copies each before decrypting it, so a receive's buffer doesn't lead to
its packet. But it encrypts each packet in place and sends from there, so a
send's first iovec base is the header of a packet snoopy saw encrypted
(`sealed_packets`). And encryption contexts' memory is reused between
connections on the socket, which first gave the second connection the
first's peer: so the peer is attached to the connection's IDs in user space
(`FN_QUIC_PACKET_SENT`, `output/quic_cid.go`), not to a context.

### How to tell it broke, and how to fix it

- **Responses show "peer":** no `FN_QUIC_PACKET_SENT` notices, so sends
  aren't found by their buffers. Check with bpftrace where `sendmsg`'s iovec
  starts relative to where `aes_gcm_seal` (or `EVP_AEAD_CTX_seal`) got the
  header (its associated data).
- **Two connections' streams mixed:** the IDs aren't being matched; their
  length or layout may have changed. `TestQUICConnectionsOnOneSocket`
  builds the packets.
- **To test:** `SNOOPY_TEST_RUSTLS=1` runs `TestQuinnHTTP3`, which builds
  `internal/tracer/testdata/quinnh3` with each provider and fetches from two
  servers at once over one socket.

## HTTP/3 over ngtcp2 (curl)

### How it was found

Fedora 44's curl does HTTP/3 through ngtcp2 1.22 with its OpenSSL crypto
library, `libngtcp2_crypto_ossl`, which exports the packet protection
functions curl hands ngtcp2. A bpftrace session in a Fedora chroot showed
that every packet goes through them, in both directions:

```bash
L=<root>/usr/lib64/libngtcp2_crypto_ossl.so.0
# arm64; the ninth argument (aadlen) is on the stack there, and from the
# seventh on x86-64
bpftrace -e "uprobe:$L:ngtcp2_crypto_encrypt { printf(\"enc len=%d aad=%x\n\", arg4, arg7); }
  uprobe:$L:ngtcp2_crypto_decrypt { printf(\"dec dest=%x len=%d\n\", arg0, arg4); }"
```

Encrypt works in place; decrypt writes the plaintext to `dest`, and its
length is the ciphertext's less the tag (`ngtcp2_crypto_aead.max_overhead`).

### How to tell it broke, and how to fix it

- **Not attached:** check the library still exports both functions
  (`nm -D --defined-only`), and that its file name still matches
  `libngtcp2_crypto_*.so*` in `libPatterns`.
- **Wrong lengths or garbage:** the arguments or `ngtcp2_crypto_aead` changed;
  compare with `ngtcp2_crypto.h` and rerun the bpftrace session.
- **To test:** `TestCurlHTTP3` with `SNOOPY_TEST_CURL_HTTP3` (see AGENTS.md).
  A Fedora root filesystem can be made without Docker from its container
  image, with `skopeo copy docker://registry.fedoraproject.org/fedora:latest
  dir:<dir>` and its layers unpacked, then `dnf install curl` chrooted in it.

## HTTP/3 over quic-go

### How it was found

A bpftrace session on the quic-go test program counted calls to every AEAD
method in it: `crypto/internal/fips140/aes/gcm.(*GCM).Seal` and `Open` ran
exactly as often as quic-go's own `(*xorNonceAEAD).Seal` and `Open`, so
every packet goes through them and they aren't inlined. Their arguments are
Go's register ABI: on arm64 the receiver is in x0 and the four slices in x1
to x12; on amd64 the nine registers run out after the nonce, so the
plaintext and the associated data are on the stack at 8 and 32 bytes above
the stack pointer:

```bash
B=<program>; F='"crypto/internal/fips140/aes/gcm.(*GCM).Seal"'
# amd64
bpftrace -e "uprobe:$B:$F { printf(\"pt=%d ad=%d\n\", *(uint64*)(reg(\"sp\")+16), *(uint64*)(reg(\"sp\")+40)); }"
# arm64
bpftrace -e "uprobe:$B:$F { printf(\"pt=%d ad=%d\n\", reg(\"r8\"), reg(\"r11\")); }"
```

### How to tell it broke, and how to fix it

- **A quic-go program shows only its TLS connections:** the functions weren't
  found. Check `go tool nm` for the names in `goAEADs` and `quicGoFunc`
  (`internal/discover/inspect.go`); Go moved AES-GCM in 1.24, and a release
  could again.
- **Garbage or nothing:** the arguments moved. Rerun the bpftrace session
  above and update `go_aead_args`.
- **To test:** `TestQuicGoHTTP3` builds `internal/tracer/testdata/quicgo`,
  its own module, so updating quic-go there doesn't touch snoopy's
  dependencies (`go get github.com/quic-go/quic-go@latest` in that
  directory).

## Go crypto/tls

### How it was found

- Functions are found by name in `.gopclntab`, which stripped Go binaries
  keep. Its function addresses are relative to `runtime.text`, which isn't the
  start of `.text` in programs linked with cgo (`pclntabTextStart`).
- Return probes corrupt Go's movable stacks, so snoopy disassembles each
  function and probes every `RET` instead (`FindReturns`).
- The entry probe goes after the stack check (`GoFunc.Body`):
  `runtime.morestack` restarts a function from the top when its stack grows,
  and a probe on the first instruction saw one call twice.
- The socket comes from walking pointers: `tls.Conn`'s first field is the
  `net.Conn` interface, whose data word (+8) points to a `net.TCPConn`, whose
  first field is the `*netFD`; `poll.FD.Sysfd` is at +16 in it, and the family
  and socket type at +56 and +64 (`go_conn_fd` in `bpf/snoopy.c`). The family
  and type are checked before the fd is used.

### How to tell it broke, and how to fix it

Build the integration tests with the new Go version and run them:
`TestGoCryptoTLS`, `TestNestedGo` and `TestGoStackGrowth`, plus the unit tests
`TestPclntabMatchesSymtab` and `TestGoBodyOffset`.

- **No fd or addresses:** compare the offsets above with the new Go's
  `src/crypto/tls/conn.go`, `src/net/net.go`, `src/net/fd_posix.go` and
  `src/internal/poll/fd_unix.go`.
- **Stripped binaries not found:** a new pclntab magic number; add it to
  `pclntabTextStart` with its header layout.
- **Not attached because of the prologue:** compare the new stack check with
  what `GoFunc.Body` expects (`go tool objdump -s 'crypto/tls.\(\*Conn\).Read' <binary>`).

## funcfind and golang.org/x/arch

funcfind's arm64 code and `freebl.go` decode instructions with
`golang.org/x/arch` and, in a few places, parse their printed form: frame and
stack offsets in `arm64StackArgs`, and immediates in `imm` and
`immShiftValue`. An update to `x/arch` that changes the format breaks those
quietly. After bumping it, run the unit tests (`TestArm64` covers the parsing
on hand-assembled code), then `TestBoringSSLBinaries` on an arm64 Electron
build with its symbols and `TestFreeblBinaries` on an arm64 freebl.

## The BPF program

- **Generated objects:** `internal/tracer/snoopy_*_bpfel.o` are committed and
  must match what clang 18 produces from `bpf/snoopy.c`; CI compares them.
  Regenerate with the container [above](#machines) rather than another clang.
- **Old kernels:** the verifier of 5.10 is the strictest one snoopy supports.
  After changing the program, run the [older kernels](#older-kernels). HANDOFF
  lists the verifier rules learned so far: zero every struct passed to a
  helper, and keep the chunk loop's shape.
- **New probes:** a function's 32-bit arguments have undefined upper halves,
  in registers and in stack slots. Truncate them (`(__u32)func_arg(ctx, n)`),
  as the arm64 `AES_AEAD` bug showed. And check every argument that changes
  what a call means: Firefox peeks at a byte of an idle connection with
  `PR_Recv(..., PR_MSG_PEEK)`, which snoopy took for data until it checked the
  flag, and which broke HTTP/2 decoding when the byte was read again.
- **`--pid`:** uprobes aren't attached per process. The BPF program filters
  on `traced_tgids`, and with BTF adds a process whose parent, or one of its
  parents up to 8 levels, is in it (`is_traced_tgid`). Without BTF, user
  space scans `/proc` for new children every second.

## HTTP decoding and compressed bodies

These follow published standards and rarely need fixing.

- **A body isn't decoded:** the note says why, once. Most often bytes of it
  weren't captured (raise `--max-size`), or it uses a shared dictionary (`dcb`,
  `dcz`), which can't be decoded.
- **A new Content-Encoding:** add it to `contentCodings` and to `inflate.run`
  in `internal/output/body.go`, with a test that encodes with the real
  encoder (see `body_test.go`).
- **To see what was actually sent:** `--hex` prints payloads as captured,
  without decoding, and `--full` shows whole bodies.
- **Connections that started before snoopy:** HTTP/2 is followed from the
  first call that starts with a frame (`http2Aligned` in
  `internal/output/payload.go`), without headers, and found again if the
  framing is lost. Firefox reads each frame's 9-byte header on its own, so a
  call of just a valid frame header counts. It's a heuristic over 9-byte
  headers, so if data that isn't HTTP/2 gets taken for it, make
  `http2Aligned` stricter rather than the decoder more forgiving.
