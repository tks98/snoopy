# Plan: making snoopy cheaper

Status: Steps 0 to 2 are done (#33, #34, #35), and
[performance.md](performance.md) has the results. Steps 3 and 4 haven't
been started.

[performance.md](performance.md) measured what snoopy costs; this is the plan
for bringing that down before adding features. Each step is measured with
`docs/benchmark/run.sh` before and after, and only kept if it helps; the
usual tests and the load check on 5.10 to 6.12 apply to every BPF change.

## Where the time goes

Measured on nginx serving 1 KiB over HTTPS, in the arm64 VM that
performance.md describes. Each request makes three TLS calls: two
`SSL_read`s (one finds nothing yet) and one `SSL_write`. Time per request is
the server's 2 CPUs divided by requests per second.

| configuration | µs per request | added |
| --- | ---: | ---: |
| nothing | 11.9 | |
| bpftrace, empty entry probes on `SSL_read` and `SSL_write` | 18.4 | 6.6 |
| bpftrace, empty return probes | 19.3 | 7.4 |
| bpftrace, empty entry and return probes | 19.9 | 8.0 |
| snoopy, not tracing nginx (`--comm nomatch`) | 22.1 | 10.2 |
| snoopy, tracing nginx (`--comm nginx --quiet`) | 30.8 | 18.9 |

The kernel's BPF statistics (`kernel.bpf_stats_enabled`) give each of
snoopy's programs' own time:

| program | not tracing | tracing |
| --- | ---: | ---: |
| `ssl_read_enter`, `ssl_write_enter` | 55 to 58 ns | about 210 ns |
| `tls_return`, which emits the data | 51 ns | 1,953 ns |
| `sys_enter`, on every syscall | 67 ns | 137 ns |

And on plain HTTP: 7.4 µs per request without snoopy, 7.7 µs with an empty
`sys_enter` program attached, 8.0 µs with snoopy's.

So:

1. **For programs snoopy isn't tracing, the probes themselves are the
   cost:** about 2.7 µs per call is the kernel's uprobe mechanism (a trap at
   entry, and a second one through the return trampoline), and snoopy's
   check that the process isn't one to trace is about 0.1 µs of it. A faster
   check can't help; only not trapping can.
2. **For traced calls, snoopy's own code is the largest part it controls:**
   `tls_return` takes about 2 µs, which is too much for copying 1 KiB.
3. **The syscall hook costs every process on the machine** about 5% of a
   syscall-heavy server's throughput just by being attached, and snoopy's
   program another 3 to 4%.
4. **User space** keeps up with tens of thousands of calls a second since
   #32, and drops data beyond that.

## Step 0: measure better (half a day)

- The benchmark prints each BPF program's run count and average time per
  mode, from `kernel.bpf_stats_enabled`, so every later step shows where it
  helped.
- Modes for `--json` and `--brief` too, which haven't been measured.
- Run it on GitHub's x86-64 runners too, from a `workflow_dispatch`
  workflow: they have 4 CPUs, so the script takes a smaller CPU layout. The
  only x86 machine at hand is emulated, and uprobes on x86 likely cost
  differently (recent kernels added a faster return path there, as far as
  I know only there). It would also catch a change that makes things
  slower.

## Step 1: the traced call's BPF cost (one to two days)

Find out what in `tls_return`'s 2 µs is spent, by timing pieces of it under
the BPF statistics, then fix what shows up. The suspects, cheapest first:

- **A ring buffer wakeup per record.** `bpf_ringbuf_submit` with no flags
  wakes the reader whenever it's caught up, which under load is almost every
  record, through `irq_work` and the scheduler (`try_to_wake_up` showed in
  the profile). Instead: submit with `BPF_RB_NO_WAKEUP`, and force a wakeup
  only once enough is waiting (`bpf_ringbuf_query`), with user space also
  reading on a short timer (it already polls every 200 ms), so output is
  delayed by at most that.
- **Finding the socket again on every call.** `track_conn` walks the fd
  table and reads the socket's addresses through several CO-RE reads each
  time, even when the connection's socket is already known and unchanged.
  It can stop as soon as the fd still holds the same file.
- **The process name** is read from the thread group leader on every event;
  user space already has a fallback that looks it up, and could cache it by
  PID.
- **Map traffic per call:** the call stack (`call_depth`, `active_calls`) is
  a hash map update and delete per call; task-local storage (Linux 5.11+,
  with the hash map kept for 5.10) may be cheaper.

The goal is a traced call costing what an untraced one does plus well under
a microsecond, apart from the copy itself.

## Step 2: probes only where they're needed (two to three days)

With `--pid` or `--comm`, attach uprobes per process, with the kernel's PID
filter, instead of per file: the kernel then only puts the breakpoint into
the processes asked for, and every other program using the same OpenSSL
stops paying 2.7 µs per call. This is the largest saving for anyone running
snoopy on a busy machine.

- At startup, the processes `--pid` or `--comm` select get their own links;
  new ones get theirs as they're found, which the hold from #25 makes
  reliable: they're held until attached.
- A process that forks without exec keeps its parent's breakpoints only
  until its first hit, when the kernel removes them as not its own, so new
  processes of traced ones need reporting too (`sched_process_fork`), and
  their first calls can be missed before they're held; exec'd ones are
  found by the exec watcher. (Found while doing it; first I thought children
  came along.)
- Many processes (a browser's dozens) mean many links; worth checking the
  cost of creating them and the kernel's limits.
- Without either option, everything is traced, so nothing changes.

The other way, uprobe sessions (Linux 6.13+, where the entry program can
skip the return probe), only saves the return trampoline, and the
measurements above show entry and return together cost little more than
either alone; it isn't worth the second code path.

## Step 3: the syscall hook (one to three days)

- **Cheaper program first:** return as early as possible for processes that
  aren't traced (with a filter, most), and look up fewer maps per syscall.
  Measured with an empty program as the floor.
- **Then, a spike on not hooking every syscall:** kprobes or fentry on the
  socket layer (`sock_sendmsg`, `sock_recvmsg`) only fire for socket I/O and
  leave other syscalls on their fast path. They see a `struct socket`, not
  an fd, so connections would be tied to sockets by their file, which
  `conn_infos` already keeps. Worth it only if the spike shows the 5% going
  away; the attribution logic is the most fragile code snoopy has.

## Step 4: user space (one to two days)

- Allocations per event (each chunk's data is copied into a new slice, then
  into strings for printing), the remaining byte-by-byte scans, and
  `fmt` in the printers, by profile.
- JSON and brief output, once Step 0 measures them.
- A `--buffer-size` flag, since the ring buffer's size decides how large a
  burst is absorbed before data is dropped.

## Order and what to expect

Step 0, then Step 1, which should help every traced program, then Step 2,
which helps everything else on the machine, then 3 and 4. Rough targets, in
the VM: a traced 1 KiB call from about 9 µs to under 5; untraced programs
paying nothing with `--pid` or `--comm`; the syscall hook under 3% on plain
HTTP; text output keeping up at 100,000 calls a second. performance.md gets
the new numbers as each step lands.
