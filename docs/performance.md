# Performance

What snoopy costs the programs it traces, and the ones it doesn't. The short
version: each TLS call snoopy traces costs the calling program around 5 µs.
With `--comm` or `--pid`, other programs pay nothing for snoopy's probes;
without, each call another program makes into a library snoopy is attached
to costs it around 3 µs. Every socket syscall on the machine costs a
fraction of a microsecond more. Whether that matters depends on how much a
program does per call: these numbers come from servers doing nothing but
answer, which is the worst case.

## How it was measured

`docs/benchmark/run.sh` loads three servers with `wrk` (32 connections, 10 s
runs, the median of three) and reports their requests per second and
latency, without snoopy and with it in several modes:

- **off:** snoopy isn't running.
- **quiet:** `snoopy --comm <server> --quiet`: the server is traced, its
  calls captured and read, but nothing decoded or printed.
- **text:** `snoopy --comm <server>`: traced, decoded and printed as text
  (to `/dev/null`, so a disk or terminal isn't measured).
- **json** and **brief:** the same, with `--json` and `--brief`.
- **untraced:** `snoopy --comm nomatch --quiet`: snoopy runs, but traces
  nothing; this is what it costs the other programs on the machine.

The server, `wrk` and snoopy each had two CPUs of their own (`taskset`), so
the numbers show what the traced program pays in its own threads, and
snoopy's own CPU use is shown apart. `wrk` used a copy of libssl that snoopy
wasn't attached to. With `bpftool`, the script also prints each of snoopy's
BPF programs' average time per mode, from the kernel's BPF statistics. The
machine was an Ubuntu 26.04 VM (Linux 7.0, arm64, 6 CPUs) under Parallels on
an Apple Silicon Mac. A uprobe is a trap into the kernel, which costs more
in a VM than on bare metal. The Benchmark workflow runs the same script on
GitHub's x86-64 and arm64 runners, which have 4 CPUs and so give the server
one.

## Results

snoopy 2.6. The last column is the same measurement from before 2.6's BPF
changes (its faster decoding already in), for comparison.

| workload | mode | req/s | µs/req | p50 µs | p99 µs | snoopy CPU | chunks lost | before, µs/req |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| nginx HTTPS, 1 KiB | off | 175,237 | 11.4 | 173 | 326 | | | 11.6 |
| | quiet | 79,496 | 25.2 | 391 | 635 | 14% | 0 | 29.0 |
| | text | 77,977 | 25.6 | 400 | 601 | 113% | 39,488 | 23.8 |
| | json | 78,376 | 25.5 | 398 | 630 | 77% | 0 | |
| | brief | 78,477 | 25.5 | 398 | 643 | 68% | 0 | |
| | untraced | 159,645 | 12.5 | 191 | 332 | 0% | 0 | 20.2 |
| nginx HTTPS, 256 KiB | off | 14,315 | 139.7 | 2,200 | 3,170 | | | 139.1 |
| | quiet | 7,216 | 277.2 | 4,410 | 5,960 | 68% | 0 | 305.1 |
| | text | 7,546 | 265.0 | 4,190 | 6,060 | 113% | 3,220,636 | 248.0 |
| | json | 7,552 | 264.8 | 4,250 | 6,550 | 122% | 3,173,014 | |
| | brief | 7,205 | 277.6 | 4,410 | 6,300 | 98% | 0 | |
| | untraced | 13,713 | 145.8 | 2,270 | 4,070 | 0% | 0 | 219.3 |
| Go HTTPS, 1 KiB | off | 179,616 | 11.1 | 162 | 2,280 | | | 11.1 |
| | quiet | 74,218 | 26.9 | 416 | 2,200 | 13% | 0 | 32.2 |
| | text | 72,084 | 27.7 | 428 | 2,100 | 93% | 0 | 28.7 |
| | json | 73,108 | 27.4 | 423 | 2,200 | 62% | 0 | |
| | brief | 73,091 | 27.4 | 423 | 2,250 | 55% | 0 | |
| | untraced | 168,994 | 11.8 | 172 | 2,160 | 0% | 0 | 11.8 |
| nginx HTTP, 1 KiB | off | 287,836 | 6.9 | 103 | 167 | | | 6.8 |
| | quiet | 251,893 | 7.9 | 119 | 185 | 0% | 0 | 7.4 |
| | text | 248,714 | 8.0 | 121 | 192 | 0% | 0 | 7.6 |
| | json | 248,834 | 8.0 | 120 | 189 | 0% | 0 | |
| | brief | 249,594 | 8.0 | 120 | 187 | 0% | 0 | |
| | untraced | 251,410 | 8.0 | 119 | 190 | 0% | 0 | 7.6 |

"µs/req" is CPU time per request: each server spends its two CPUs on its
requests, so it's 2 CPUs divided by the requests per second. "snoopy CPU"
is the share of one CPU snoopy used, and "chunks lost" the pieces of
captured data the ring buffer had no room for, which snoopy warns about. A
mode that loses chunks can look cheaper than one that doesn't, since the
traced program doesn't wait for snoopy either way.

The BPF programs' own time per call, for nginx at 1 KiB traced: 180 to
210 ns at entry (`ssl_read_enter`, `ssl_write_enter`), 470 ns at return
(`tls_return`, which copies the data out), and 128 ns per syscall
(`sys_enter`). Before, `tls_return` took 2,024 ns.

## What it means

- **A traced call** costs the program about 5 µs: nginx makes three TLS
  calls per request here (two `SSL_read`s, one of which finds nothing yet,
  and an `SSL_write`), and went from 11.4 µs per request to 25.2 traced. A
  Go program pays about as much (11.1 µs to 26.9). It's paid in the
  program's own thread: a uprobe on the call's entry and one on its return,
  which is most of it, and copying its data. A server that spends a
  millisecond per request, as most real ones do, slows down by 1 to 2%; one
  that does nothing but answer, as here, by more than half. Before 2.6 a
  traced call cost about 6 µs: most of `tls_return`'s 2 µs was waking
  snoopy's reader after every record, which 2.6 does at most once a
  millisecond per CPU.
- **With `--comm` or `--pid`, programs snoopy isn't tracing pay nothing for
  its probes:** they're attached to the selected processes only, with the
  kernel's PID filter (this needs kernel BTF). nginx untraced cost 12.5 µs
  per request against 11.4 without snoopy, the rest being the syscall hook
  below. Without them, or with `--container` alone, the probes are on the
  library's file, so every process using it traps on them, and only then
  does snoopy's BPF program see that it isn't one to trace: about 3 µs per
  call (nginx untraced before 2.6, 20.2 µs per request), and about 7 µs on
  GitHub's x86-64 runner. Go and Rust programs snoopy hasn't attached to
  pay nothing for this either way.
- **Every socket syscall on the machine** costs a fraction of a microsecond
  more while snoopy runs, which is how it learns which socket a call used:
  plain HTTP nginx, with no TLS, went from 6.9 µs to 8.0 µs per request.
- **Large responses** are written as many TLS calls of 16 KiB, so they pay
  the per-call cost many times: 256 KiB responses lost about as much as 1 KiB
  ones, in proportion.
- **Output keeps up with tens of thousands of calls a second.** `--brief`
  kept up with everything here, `--json` with all but 256 KiB responses,
  and text lost under 1% at 1 KiB. Beyond that, the ring buffer fills
  and snoopy drops data and warns; the traced program isn't slowed down for
  it. `--quiet` with `--pcap`, or `--brief`, keeps up with more. At these
  rates, text output dropped 2,277,321 chunks of nginx's at 1 KiB in 2.5,
  before 2.6's faster decoding, and 413,321 before its BPF changes.

To measure on another machine, run `sudo docs/benchmark/run.sh`; its header
says what it needs.
