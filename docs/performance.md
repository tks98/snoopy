# Performance

What snoopy costs the programs it traces, and the ones it doesn't. The short
version: each TLS call snoopy traces costs the calling program around 10 µs,
each call into a library snoopy is attached to costs every other program
using it around 4 µs, unless `--comm` or `--pid` is given, and every socket syscall on the machine a fraction of
a microsecond. Whether that matters depends on how much a program does per
call: these numbers come from servers doing nothing but answer, which is the
worst case.

## How it was measured

`docs/benchmark/run.sh` loads three servers with `wrk` (32 connections, 10 s
runs, the median of three) and reports their requests per second and
latency, without snoopy and with it in three modes:

- **off:** snoopy isn't running.
- **quiet:** `snoopy --comm <server> --quiet`: the server is traced, its
  calls captured and read, but nothing decoded or printed.
- **text:** `snoopy --comm <server>`: traced, decoded and printed as text
  (to `/dev/null`, so a disk or terminal isn't measured).
- **untraced:** `snoopy --comm nomatch --quiet`: snoopy runs, but traces
  nothing; this is what it costs the other programs on the machine.

The server, `wrk` and snoopy each had two CPUs of their own (`taskset`), so
the numbers show what the traced program pays in its own threads, and
snoopy's own CPU use is shown apart. `wrk` used a copy of libssl that snoopy
wasn't attached to. The machine was an Ubuntu 26.04 VM (Linux 7.0, arm64, 6
CPUs) under Parallels on an Apple Silicon Mac. A uprobe is a trap into the
kernel, which costs more in a VM than on bare metal; x86-64 hasn't been
measured.

## Results

| workload | mode | req/s | p50 µs | p99 µs | snoopy CPU | chunks lost |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| nginx HTTPS, 1 KiB | off | 171,807 | 178 | 329 | | |
| | quiet | 69,031 | 452 | 666 | 41% | 0 |
| | text | 84,142 | 372 | 548 | 113% | 413,321 |
| | untraced | 98,966 | 315 | 480 | 0% | 0 |
| nginx HTTPS, 256 KiB | off | 14,378 | 2,190 | 3,320 | | |
| | quiet | 6,556 | 4,780 | 6,600 | 77% | 0 |
| | text | 8,063 | 3,990 | 5,600 | 112% | 3,567,652 |
| | untraced | 9,120 | 3,520 | 4,840 | 0% | 0 |
| Go HTTPS, 1 KiB | off | 179,558 | 162 | 2,140 | | |
| | quiet | 62,198 | 512 | 1,860 | 38% | 0 |
| | text | 69,628 | 445 | 2,500 | 92% | 0 |
| | untraced | 170,017 | 171 | 2,060 | 0% | 0 |
| nginx HTTP, 1 KiB | off | 292,390 | 101 | 165 | | |
| | quiet | 268,575 | 110 | 176 | 0% | 0 |
| | text | 263,299 | 113 | 182 | 0% | 0 |
| | untraced | 264,553 | 113 | 183 | 0% | 0 |

"snoopy CPU" is the share of one CPU snoopy used, and "chunks lost" the
pieces of captured data the ring buffer had no room for, which snoopy warns
about.

## What it means

The costs are per call, so they're clearest as time per request: each of
these servers spends its two CPUs on its requests, so 2 CPUs divided by the
requests per second is the CPU time per request.

- **A traced call** costs the program about 9 µs (nginx: 11.6 µs per request
  without snoopy, 29.0 µs traced, for two TLS calls), and a Go program about
  as much (11.1 µs to 32.2 µs). It's paid in the program's own thread: a
  uprobe on the call's entry and one on its return, and copying its data.
  A server that spends a millisecond per request, as most real ones do,
  slows down by 2% or so; one that does nothing but answer, as here, by more
  than half.
- **Programs snoopy isn't tracing pay too, if they use a library it's
  attached to**, such as the system's OpenSSL, unless `--comm` or `--pid`
  is given: about 4 µs per call (nginx untraced: 20.2 µs per request). A
  uprobe set on a library's file makes every process using that file trap
  on it, and only then does snoopy's BPF program see that it isn't one to
  trace. With `--comm` or `--pid` (and kernel BTF), snoopy 2.6 attaches
  per process instead, so the others don't trap: nginx untraced, measured
  that way, cost 12.6 µs per request against 12.0 without snoopy, the rest
  being the syscall hook below. `--container` alone still attaches per
  file. Go and Rust programs snoopy hasn't attached to pay nothing for this
  (Go untraced: 11.8 µs).
- **Every socket syscall on the machine** costs a fraction of a microsecond
  more while snoopy runs, which is how it learns which socket a call used:
  plain HTTP nginx, with no TLS, went from 6.8 µs to 7.6 µs per request.
- **Large responses** are written as many TLS calls of 16 KiB, so they pay
  the per-call cost many times: 256 KiB responses lost about as much as 1 KiB
  ones, in proportion.
- **Text output keeps up with tens of thousands of calls a second.** Beyond
  that, the ring buffer fills and snoopy drops data and warns; the traced
  program isn't slowed down for it. `--quiet` with `--pcap`, or narrowing
  what's traced (`--comm`, `--pid`), keeps up with more. snoopy 2.6 made
  its decoding cheaper, after a profile showed most of its time going into
  checking and escaping text a rune at a time and decoding record headers
  with reflection: at these rates, 2.5 dropped 2,277,321 chunks of nginx's
  and 1,340,922 of Go's.

To measure on another machine, run `sudo docs/benchmark/run.sh`; its header
says what it needs.
