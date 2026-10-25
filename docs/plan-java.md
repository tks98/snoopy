# Plan: Java TLS support

Reviewed against `main` at `0434edb99cca338b30ffa7b45a3243168abd6063` on
2026-10-24. This is a proposed implementation, not a claim of Java support.

## Recommendation

First test agentless capture of native Java TLS providers (Netty tcnative
and Conscrypt). Then add explicit, opt-in SunJSSE support with a Java
instrumentation agent. Prototype framed writes to a dedicated `/dev/null`
descriptor as the bridge to Snoopy's syscall tracepoint, avoiding a custom
JNI library. Keep a JNI/uprobe bridge as a fallback if measured transport
cost or reliability warrants it. Reuse the existing ring buffer, event
assembly, filters, decoders and output formats.

This revision incorporates review feedback: native providers move to step
0, Go-based HotSpot attachment is part of the spike, and dynamic-loading
defaults are distinguished from explicit opt-in configuration. Transport
selection remains an experiment, not a demonstrated performance result.

Start with a feasibility spike on JDK 21 and 25. Ship an initial supported
matrix only after both `SSLSocket` and `SSLEngine` work on Linux amd64 and
arm64. Add JDK 17 after checking its class layouts and method signatures;
exercise newer JDKs in a canary. JDK 8/11, OpenJ9, native-image, Android,
alternative JSSE providers and Java HTTP/3 are separate follow-up work.

This changes the product contract for Java: it requires code loaded into
the JVM, and sometimes JVM startup options. The default native tracing
mode should remain unchanged. If support must require absolutely no agent
or JVM configuration, treat default JSSE as a separate research project rather
than promising it through this implementation.

## What the project already provides

| Area | Current implementation | Consequence for Java |
| --- | --- | --- |
| Discovery | `internal/discover/discover.go` scans executable files and a name-filtered set of mapped TLS libraries; `inspect.go:Inspect` examines ELF symbols, Go metadata and native signatures. | Adding `java` to a process-name list cannot expose Java methods. A JVM detector and agent lifecycle are needed. |
| Attachment | `internal/tracer/tracer.go:Attach` attaches uprobes to file-backed native code. Per-process links track process start time. | Reuse this for native providers; separately register agent transport sessions with process-lifetime checks. |
| Capture | `bpf/snoopy.c:emit` emits bounded chunks; `sys_enter` observes I/O for socket bookkeeping. | Add a framed Java transport path before ordinary socket bookkeeping. Distinguish original length from available captured bytes. |
| Event model | `internal/tracer/event.go:Event`, `assemble.go` and `sockets.go` provide completed calls, truncation and late socket notices. | Add JSSE read/write identities without renumbering existing functions. |
| Protocols | `internal/output` already decodes HTTP/1, HTTP/2, HPACK, gRPC and compressed bodies. | Feed correct plaintext streams into these decoders; no Java-specific HTTP decoder is needed. |
| Connection keys | `internal/output/decode.go:connOf` normally uses `ConnID`; record-provider events can use the FD. | Give both Java directions the same stable object identity, even without an FD. |
| Process watching | `WatchNewProcesses` retries discovery through 3 seconds after exec and can temporarily hold a process with ptrace. | JVM readiness needs its own bounded retry policy. Never wait for an agent to initialize while its JVM is held stopped. |
| Distribution | GoReleaser builds static Go binaries and a scratch image; BPF objects are committed. | Prefer a JAR plus Go attach code, with no host JDK or custom native library required. JNI remains a fallback with extra artifacts. |

The README and `docs/how-it-works.md` explicitly list OpenJDK JSSE as
unsupported. Step 0 should inventory real Netty tcnative and Conscrypt
artifacts, inspect symbols/signature matches, and capture controlled traffic.
Netty offers both dynamically linked OpenSSL and statically linked BoringSSL
variants; Conscrypt uses BoringSSL. Coverage must name the tested provider
and artifact, rather than imply that all Java applications are covered.
[Netty artifacts](https://netty.io/wiki/forked-tomcat-native.html),
[Conscrypt](https://github.com/google/conscrypt)

The mapped-library name filter can exclude these JNI libraries, but adding
patterns alone is not an acceptance criterion. Test hidden/stripped symbols,
shaded or randomly named extracted libraries, deleted mappings, delayed
loading beyond the current three-second rescan window, and memory-BIO
operation without socket addresses. Reuse native probes/signature finding
where verified; add provider-specific handling only with evidence. Avoid
double capture when native-provider support and JSSE instrumentation coexist.

## Approaches considered

| Approach | Assessment |
| --- | --- |
| Add native library patterns and symbols | Useful for specific JNI TLS providers, but does not solve default JSSE. Validate independently. |
| Probe JIT code or JVM interpreter internals directly | Poor first implementation: Snoopy's file-offset discovery does not represent dynamically generated Java code, and compilation, inlining, deoptimization and object movement introduce new dependencies. |
| Instrument JSSE and write framed buffers to `/dev/null` | First transport to prototype. Keeps kernel process attribution and existing BPF delivery without shipping JNI. Requires descriptor/session registration, framing, retry/loss handling and measurement of copies, allocation and syscalls. |
| Instrument JSSE and send events over a local socket | Alternative if syscall transport is unsuitable. Requires a second event ingress, peer authentication, backpressure, ordering and process/PID-namespace handling. |
| Instrument JSSE and emit through a native bridge | Fallback: retains the existing BPF transport but adds JNI transitions, copying, native-access configuration and release artifacts. Compare only if the first transport fails its acceptance gate. |
| Export TLS keys and decrypt packets | A different capture architecture requiring encrypted packet collection, TCP reconstruction and decryption; not the shortest route to plaintext events. |

The proposed flow is:

```text
SunJSSE socket/engine methods
  -> instrumented bootstrap helper (object identity, exact transferred bytes)
  -> bounded, framed write to a registered /dev/null descriptor
  -> snoopy sys_enter Java transport handler
  -> existing BPF ring buffer and tracer.Event
  -> existing HTTP/gRPC decoders, filters, redaction and exports
```

## Capture and identity design

**Socket path.** Prototype hooks in
`sun.security.ssl.SSLSocketImpl$AppInputStream.read(byte[], int, int)` and
`$AppOutputStream.write(byte[], int, int)`. The JDK 25 source has these
application-stream implementations. Capture only the returned byte count
for reads, and the requested range on successful writes. Avoid double
capture through the one-byte overloads. A write that throws after partial
progress needs an explicit loss/discontinuity policy; do not report its
entire argument as successfully transferred. Both stream objects must map
to the owning socket. [OpenJDK socket implementation](https://raw.githubusercontent.com/openjdk/jdk/jdk-25-ga/src/java.base/share/classes/sun/security/ssl/SSLSocketImpl.java)

**Engine path.** Prototype hooks in `sun.security.ssl.SSLEngineImpl`'s
canonical scatter/gather `wrap` and `unwrap` implementations. JDK 25's
simpler overloads delegate to them, so instrument one level only.
Record buffer positions at entry and capture the actual application ranges
consumed by `wrap` or produced by `unwrap`, checking the result counts.
Use duplicates when reading buffers; preserve positions, limits and marks.
Test direct, heap, sliced and read-only source buffers, offsets, partial
progress and calls that transfer zero application bytes. Capture no
handshake ciphertext. Reject DTLS for this first TCP-oriented release.
[OpenJDK engine implementation](https://raw.githubusercontent.com/openjdk/jdk/jdk-25-ga/src/java.base/share/classes/sun/security/ssl/SSLEngineImpl.java)

**Connection identity and order.** Allocate monotonic connection IDs using
a weak identity registry with reference-queue cleanup; do not use a moving
object address or `identityHashCode` alone. Share one ID across both
directions, and review its namespace against native handles and synthetic
FD keys. Track invocation state on the Java side so virtual-thread movement
between carrier threads cannot break entry/exit pairing. Preserve the
order of operations within each connection direction, including concurrent
callers; emit before the relevant serialization is released, or introduce
an explicit sequence/reorder mechanism. BPF TID is the executing OS thread,
not the Java virtual-thread identifier.

**Addresses.** Start with socket addresses obtained from the owning
`SSLSocket`; leave FD unknown unless reliably resolved. `SSLEngine` is
transport independent: its peer host/port can be hints, not the connected
socket. Initially emit engine events with `FD=-1` and unknown endpoints,
and document the impact on `--host`/`--port`. Add transport-specific
associations for JDK HttpClient and Netty later if needed. Do not infer a
connection from a worker thread's most recent socket. Snoopy already has
an addressless mode for other providers. [SSLEngine contract](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/net/ssl/SSLEngine.html)

**Syscall bridge (first experiment).** Write a contiguous header and bounded
payload through an unbuffered JDK file API, on the calling application
thread. Use a dedicated descriptor verified to refer to the null character
device, not merely a path named `/dev/null`. Register its process lifetime,
FD and session nonce through a control handshake. Reject unrelated writes
before reading payloads; a magic number alone is insufficient. Handle FD
close/reuse, session expiry and the no-BTF case explicitly.

Use a versioned header with connection ID, direction, call/sequence ID,
original size, captured size, fragment offset, duration and optional
endpoints. Bound allocations and reads by the capture budget. Define retry
and duplicate suppression, fragment ordering, and loss/discontinuity
reporting. Entry capture observes a transport attempt, not successful
delivery: account for failed/short writes and retries, adding an exit hook
if needed. Do not expose headers as TLS bytes or treat the transport FD as
the application's network FD. Route registered transport writes before
`note_thread_fd` and `record_fd`, including when BTF is absent.

The agent uses no custom native code, but JDK file I/O still uses JNI
internally. OpenJDK 25's `writeBytes` copies the Java array to native memory,
allocates for larger buffers, and loops over writes. Consequently, one
Java write is not a guarantee of one syscall, nor evidence of low overhead.
Measure allocations, syscall count and p99 latency with real capture sizes;
test that framing survives the actual write path.
[OpenJDK file writes](https://raw.githubusercontent.com/openjdk/jdk/jdk-25-ga/src/java.base/share/native/libjava/io_util.c)

**Native bridge (fallback).** Use an exported, non-inlined C function taking a pointer
to a fixed-width, versioned descriptor plus a bounded native data buffer.
Include direction, connection ID, original size, captured size, duration
and optional endpoints. Obtain PID/TID and event time in BPF. Copy only
the configured capture budget; keep the native buffer alive for the probe,
and never retain a raw Java heap pointer across JNI calls. A special Java
emit path must not read `original_size` bytes from a smaller captured
buffer. Preserve truncation and ring-buffer loss semantics; avoid falsely
measuring only the JNI call as TLS latency. Validate all descriptor fields
and keep BPF stack use and chunk-loop constraints intact.

## Agent lifecycle and user experience

Use `java.lang.instrument` with a narrow class/method allowlist, an isolated
bootstrap helper and a shaded bytecode transformer. Select the bytecode
library during the spike based on the tested JDK range. Do not instrument
all methods through global method-entry callbacks. Support both `premain`
and `agentmain`. Stock HotSpot 21 and 25 enable dynamic agent loading by
default: both tagged source trees set `EnableDynamicAgentLoading=true`.
The explicit `-XX:+EnableDynamicAgentLoading` option acknowledges loading
and suppresses its warning; it is not a prerequisite on those defaults.
Test default settings first. Explicitly disabled loading/attach, vendor
policies and later JDKs need distinct diagnostics; startup `-javaagent`
remains the fallback. Snoopy's own `--java` opt-in still applies.
[JDK 21 default](https://raw.githubusercontent.com/openjdk/jdk/jdk-21-ga/src/hotspot/share/runtime/globals.hpp),
[JDK 25 default](https://raw.githubusercontent.com/openjdk/jdk/jdk-25-ga/src/hotspot/share/runtime/globals.hpp),
[warning behavior](https://docs.oracle.com/en/java/javase/25/docs/api/java.instrument/java/lang/instrument/package-summary.html)

Use retransformation for already loaded classes, check capabilities, and
keep added state in helpers rather than changing existing class schemas.
Bootstrap classes must be able to resolve the helper. Request only the
module access actually needed; unsupported class shapes should disable
that adapter with a precise diagnostic. Instrumentation must preserve the
application's return values and exceptions. [Instrumentation API](https://docs.oracle.com/en/java/javase/25/docs/api/java.instrument/java/lang/instrument/Instrumentation.html)

Proposed CLI: `snoopy --java --pid PID`, initially requiring an explicit PID.
The flag authorizes loading Snoopy's agent into that selected JVM; broad
scanning must not silently inject agents into every JVM. Document child
process behavior separately rather than inheriting injection from existing
`--pid` descendant tracing. Detect embedded HotSpot via process mappings,
not just an executable named `java`. Report agent version, matched hooks,
readiness and partial coverage in verbose output.

Implement the Linux HotSpot attach client in Go during the spike so the
scratch image and tracing host need no JDK. A JDK helper can be a test
oracle, not a runtime dependency. Resolve host and target-namespace PIDs,
locate the target-visible attach socket/trigger paths, validate ownership,
check signal handling before SIGQUIT, bound waits and response sizes, and
handle the protocol version, load command and agent return status. Recheck
process identity to avoid PID reuse. Do not equate a short wire protocol
with trivial namespace/credential handling.
[OpenJDK Linux attach client](https://raw.githubusercontent.com/openjdk/jdk/jdk-25-ga/src/jdk.attach/linux/classes/sun/tools/attach/VirtualMachineImpl.java)

The JDK 25 listener validates peer credentials using matching effective
UID/GID **or root**; it is not a strict same-user-only rule. Test older
supported versions and user namespaces rather than generalizing this to
every JVM. Where credential or namespace changes are needed, isolate them
in a short-lived helper process instead of changing the main Go process.
Closing the attach socket does not unload or disable the agent.
[OpenJDK attach listener](https://raw.githubusercontent.com/openjdk/jdk/jdk-25-ga/src/hotspot/os/posix/attachListener_posix.cpp)

If JNI is selected, test native-access requirements on every supported JDK.
Newer JDKs expose `--enable-native-access` and native-access enforcement
controls; failure should produce the exact required launch configuration,
not an attempted bypass. [JDK native-access controls](https://docs.oracle.com/en/java/javase/26/docs/api/java.base/java/lang/doc-files/RestrictedMethods.html)

Load the agent disabled, register its transport (or attach the fallback
bridge probe), then enable capture with a versioned control handshake.
Include capture limits and a renewable session
lease. Stopping Snoopy, losing the lease, or losing the control connection
must stop copying data; agent initialization/callback failures must not
break application traffic. Test repeated enable/disable, multiple tracer
attempts and coexistence with other agents. Loaded classes and any native code can
remain until JVM exit: do not describe disabling as unloading the agent.
For launch-time capture, prepare the BPF consumer before enabling the agent
and define when the JVM is ready; dynamic attach cannot recover early bytes.

## Implementation sequence and acceptance gates

| Step | Deliverable and files | Exit criterion |
| --- | --- | --- |
| 0. Native providers | Artifact inventory, `internal/discover` patterns/finder changes only where needed, provider-pinned integration fixtures. | Verified agentless read/write capture for explicitly named Netty/Conscrypt artifacts, including late/deleted mappings; record unsupported variants and missing addresses. |
| 1. Feasibility | New `java/` socket/engine fixtures, framed `/dev/null` emitter, temporary BPF consumer and Go attach prototype. Inspect JDK 21/25 class signatures. | Both directions captured byte-for-byte after startup and dynamic attach under default JVM flags, including a warmed-up JVM, correct buffers and no duplicates. Demonstrate attach from a JDK-free tracing environment. Measure transport cost before selecting the final bridge. |
| 2. Capture integration | `java/`, `bpf/snoopy.c`, `internal/tracer/event.go`, `tracer.go`, `assemble.go` as needed, and JVM detection. Append JSSE library/function IDs and transport registration. | JSSE events traverse the normal ring/assembler/output path; framing, retries, truncation, loss, identity and addressless engine events work. Registered transport traffic cannot corrupt native socket tracking, with or without BTF. |
| 3. Attach and controls | Harden `internal/javaagent/` for Go attach, detection, artifacts, optional isolated helper and control lifecycle; `main.go`, flag tests and usage text. Keep JVM discovery distinct from an attachable ELF `Target`. | `--java --pid` handles readiness, failure, cleanup, reattach and PID reuse. No-agent JVMs and unsupported providers get truthful diagnostics. Agent setup never waits on a ptrace-stopped JVM. |
| 4. Compatibility and performance | Java fixture builds and Go integration tests; `.github/workflows/ci.yml`, canary coverage, benchmark scripts. | Required JDK/architecture tests actually run rather than skip. HTTP/1, HTTP/2 and gRPC work with known synthetic traffic; overhead is measured and acceptable. |
| 5. Packaging and containers | `Makefile`, `.goreleaser.yaml`, release workflow, Docker image and agent checksums; container attachment tests. | Reproducible JAR distribution with no tracing-host JDK; extra native artifacts only if JNI wins the spike. Document host/container coverage. Ordinary Go builds do not unexpectedly require Java/C toolchains. |
| 6. Document and release | README, `docs/usage.md`, `docs/how-it-works.md`, `docs/maintenance.md`, `docs/release-risks.md`, HANDOFF; Kubernetes docs when supported. | Publish explicit provider/JDK coverage and the Java-specific agent/configuration requirements. Remove the unsupported label only for tested combinations. |

Use separate, version-matched Java support artifacts first. Embedding them
in release binaries is an option after build reproducibility and extraction
are solved; it must also account for `go install`, which bypasses release
packaging. If JNI is selected, native bridge builds need amd64/arm64 and
a deliberate glibc/musl policy. Verify artifact integrity before staging.

Container support requires more than the existing `/proc/PID/root` file
lookup: resolve target PID and mount namespaces, target UID, the attach
socket, and paths the target JVM can read/load. Cover read-only roots,
unwritable or noexec temporary directories, missing `java.instrument`,
disabled attach, and minimal runtime images. Start with a mounted startup
agent where dynamic injection is unavailable. Defer automatic Kubernetes
injection and `kubectl-snoopy` flag propagation until these cases are tested.

## Effort estimates

Planning ranges for one engineer familiar with Snoopy, with working Linux
amd64/arm64 test environments. These are estimates, not commitments or
measurements; revise them after steps 0 and 1.

| Milestone | Estimate | Main uncertainty |
| --- | --- | --- |
| Native-provider inventory and first verified artifact | 1–2 working days | Discovery-only changes may suffice; hidden symbols or incompatible signatures may not. |
| Broader native-provider support, if finder/lifecycle work is needed | 3–5 additional days | Stripped builds, late loading, shading and fixture portability. |
| JSSE spike, syscall bridge and Go attach on JDK 21/25 | 5–10 working days | Bootstrap instrumentation, buffer/order correctness and transport registration. One week is an optimistic target. |
| Integration, lifecycle, CI and initial packaging after a successful spike | 10–15 working days | Failure semantics, performance and both architectures. |
| Broad container/Kubernetes hardening | 5–10 additional working days | User/mount/PID namespaces, minimal runtimes and staging permissions. |

An initial host release is roughly 3–6 engineering weeks if the spike
succeeds, with broader container support potentially extending that. If
the transport or JSSE hooks fail their gates, re-estimate instead of
treating the fallback JNI implementation as free.

## Validation

- **Traffic:** controlled TLS 1.2/1.3 clients and servers; `HttpsURLConnection`,
  JDK HttpClient HTTP/2, and Netty with the JDK provider. Assert negotiated
  protocol/provider so a fallback cannot masquerade as coverage. Include
  gRPC multiplexing, compression, keepalive, TLS-over-TLS and large bodies.
- **Correctness:** short/zero transfers, EOF, failures, scatter/gather,
  buffer reuse, many connections sharing threads, virtual threads, GC,
  reconnects and late attachment. Existing HPACK state cannot be recovered
  retroactively; retain the existing late-connection warning.
- **Lifecycle:** loaded/unloaded JSSE classes, warmed JIT code, other agents,
  default JVM settings, denied attach, native-access denial if JNI is used,
  matching UID/GID and root attachment, mismatched artifacts, tracer crash, lease
  expiry, disable/re-enable and process exit/reuse. Bound memory and helper
  queues; expose agent copy/drop errors as well as BPF losses.
- **Transport:** actual write syscall shape, short/failed/retried writes,
  malformed or unrelated frames, FD reuse, PID reuse, `/dev/null` identity,
  fragment loss, concurrent calls and native-provider coexistence. Check
  socket attribution with and without BTF and inspect per-call allocation.
- **Output:** text, brief, JSON `library: jsse`, HAR, pcap, redaction,
  `--count`, capture-size limits and endpoint filters. Verify that unknown
  addresses do not fabricate peers or cause confusing filtered silence.
- **Platform:** JDK 21/25 on amd64 and arm64 first, then 17 and a newer-JDK
  canary. Cross-check compilation and lint; run root integration in Linux.
  Every BPF change requires clang 18 regeneration of committed `.go`/`.o`
  artifacts and the repository's 5.10/5.15/6.1/6.6/6.12 validation.
- **Performance:** baseline, disabled agent, active capture and saturated
  consumer; measure throughput, CPU, p50/p99 latency, allocations, GC and
  dropped events. Set the release budget after the spike rather than claim
  an unmeasured overhead. Keep CI traffic synthetic and use `--quiet` for
  broad smoke tests, as required by AGENTS.md.

## Review verification

On the reviewed main revision, `GOOS=linux CGO_ENABLED=0 go vet ./...`
passed for both `GOARCH=arm64` and `GOARCH=amd64` from macOS. No Java code
was implemented, and Linux runtime/integration tests were not run as part
of this planning review. The JVM hooks, bridge overhead and container
attach behavior remain feasibility questions to resolve in the stages above.
The review revision checked tagged OpenJDK sources and current repository
code; it did not execute either transport or attach prototype. No runtime
performance or native-provider compatibility claims have been validated yet.
