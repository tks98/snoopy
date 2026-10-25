# Java spike: results

This is a historical record: what step 1 found, kept as it was written,
but for two facts corrected below (the frame header's size, and x86-64).
The agent has moved on since; docs/usage.md's Java section and HANDOFF.md
describe it as it is.

Step 1 of [plan-java.md](plan-java.md): can a Java agent hand SunJSSE's
plaintext to snoopy's syscall tracepoint through writes to `/dev/null`, and
can snoopy load that agent into a running JVM without a JDK? Run on Linux
arm64 (Ubuntu 26.04, kernel 7.0) with Temurin 21.0.13 and OpenJDK 25.0.4.
x86-64 wasn't run for the spike; CI's Java jobs now run the agent's tests
(`TestJSSE`) on JDK 17, 21 and 25, on x86-64 and arm64.

## What was built

- `java/agent`: the agent. `snoopy.agent.Agent` (premain and agentmain)
  instruments, with ASM 9.11.1, `SSLSocketImpl$AppOutputStream.write(byte[],
  int, int)`, `SSLSocketImpl$AppInputStream.read(byte[], int, int)` and
  `SSLEngineImpl`'s six-argument `wrap` and `unwrap`, at normal returns
  only. The added code calls `snoopy.hooks.Hooks`, which the manifest's
  `Boot-Class-Path` puts in the bootstrap loader, after `redefineModule`
  lets java.base read it. Hooks writes each capture as a frame (an 88-byte
  header, `struct java_frame` in `bpf/snoopy.c`, with the magic "SNPYJV01",
  a nonce, a connection ID, a sequence number, direction, kind, sizes,
  ports and addresses and the call's latency, then the payload) to a
  `FileOutputStream` on `/dev/null`. `java/build.sh` builds the two jars.
- `internal/javaagent` and `tools/javaattach`: the HotSpot attach client in
  Go. It reads the target's namespace PID from `/proc/PID/status`, checks
  that the JVM catches SIGQUIT (a JVM that doesn't, `-Xrs`, would die of
  it), creates `.attach_pidN` in the target's working directory or `/tmp`
  as the target's user, signals it, waits for `/tmp/.java_pidN` under
  `/proc/PID/root`, rechecks the process start time against PID reuse,
  and sends `load instrument false <jar>=<options>`.
- `java/spike`: an HTTPS echo server, an `SSLSocket` client and a
  `java.net.http.HttpClient` (SSLEngine) client that print what they sent
  and received, a bpftrace consumer for the frames and a checker that
  compares the two.

## Results

Both clients, on both JDKs, with the agent loaded at startup
(`-javaagent`) and loaded into a running JVM after 1,000 warm-up requests:
every request and response the `SSLSocket` client made, and every request
and response body of the `HttpClient` one, was in the frames exactly
once, byte for byte. Nothing was captured twice through the overloads. The
default JVM flags were enough for dynamic attach; both JDKs print the
"Dynamic loading of agents will be disallowed" warning.

The attach client ran from a `FROM scratch` image holding only the static
binary (`docker run --pid=host --privileged`), so no JDK on the tracing
side. Loading took 53 to 67 ms.

Transport cost, one thread, no BPF program attached (`java/spike/Bench.java`):

| Payload | JDK 21 mean / p99 | JDK 25 mean / p99 |
| --- | --- | --- |
| 64 B | 298 ns / 500 ns | 311 ns / 500 ns |
| 1 KiB | 365 ns / 542 ns | 497 ns / 1,250 ns |
| 4 KiB | 789 ns / 5,750 ns | 902 ns / 6,084 ns |
| 16 KiB | 1,646 ns / 4,875 ns | 1,583 ns / 4,791 ns |

Every frame was one `write` syscall, 16 KiB ones included (strace counted
1,600,061 writes for 1,600,000 frames plus startup). The p99 jumps at 4
KiB and up are probably allocation, since each frame is a new array and
JDK's `writeBytes` mallocs past 8 KiB; a reused buffer per thread should
help. The BPF side's cost is left out, since any bridge pays it.

I think this is good enough to keep the `/dev/null` bridge for step 2
rather than the JNI fallback.

## Things found along the way

- bpftrace's `tracepoint:syscalls:sys_enter_write` saw 2 of 24 frame
  writes on this kernel, while `raw_syscalls:sys_enter`, which snoopy's
  program uses, saw all of them. I haven't found out why. The consumer
  uses the raw tracepoint, and the per-syscall ones are probably worth
  avoiding for this.
- `FileDescriptor.fd` isn't readable by reflection from the agent
  (java.base doesn't open java.io), so the agent can't report its
  transport descriptor that way. Registering it from the BPF side, from
  the first frame with the session's nonce, seems simpler anyway, and is
  what the plan's control handshake would do.
- `SSLEngineImpl`'s and the socket streams' shapes are the same on 21 and
  25, and the four-argument `wrap` and `unwrap` delegate to the
  six-argument ones on both.

## Not done yet

(At the time. `TestJSSE` has since covered x86-64, JDK 17, virtual
threads, heap, direct, sliced and read-only buffers, HTTP/2, and JVMs of
another user, in a user namespace and in a container.)

x86-64; JDK 17; virtual threads; heap versus direct, sliced and read-only
buffers beyond what `HttpClient` uses; writes that throw part way; HTTP/2;
a non-root target JVM and a JVM in a container (the attach client handles
the namespace PID and target root, but only host processes were tried).
