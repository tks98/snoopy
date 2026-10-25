// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//go:build ignore

// snoopy's eBPF program.
//
// Uprobes on the plaintext read/write functions of TLS libraries record the
// buffer pointer on entry; the matching return probe copies the bytes that
// were actually transferred into a ring buffer, split into chunks of up to
// CHUNK_SIZE bytes. A syscall tracepoint that fires while a thread is inside
// a TLS call tells us which file descriptor (socket) the call used, and the
// socket's addresses are read from the kernel's struct sock (via CO-RE).
//
// Every struct passed to a helper is zeroed first: kernels before 6.3 reject
// programs that pass uninitialized stack memory, padding included.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define CHUNK_SIZE 16384 // one maximum-size TLS record
#define MAX_CHUNKS 64	 // CHUNK_SIZE * MAX_CHUNKS = 1 MiB per call
#define MAX_DEPTH 4	 // TLS calls nested in TLS calls, e.g. through an HTTPS proxy

// Keep in sync with the Function constants in internal/tracer/event.go.
enum fn_id {
	FN_SSL_READ = 1,
	FN_SSL_WRITE,
	FN_SSL_READ_EX,
	FN_SSL_WRITE_EX,
	FN_GNUTLS_RECORD_RECV,
	FN_GNUTLS_RECORD_SEND,
	FN_PR_READ,
	FN_PR_WRITE,
	FN_PR_RECV,
	FN_PR_SEND,
	FN_GO_READ,
	FN_GO_WRITE,
	FN_WOLFSSL_READ,
	FN_WOLFSSL_WRITE,
	FN_MBEDTLS_SSL_READ,
	FN_MBEDTLS_SSL_WRITE,
	FN_S2N_RECV,
	FN_S2N_SEND,
	FN_RUSTLS_READ,
	FN_RUSTLS_WRITE,
	FN_QUIC_SEND,
	FN_QUIC_RECV,
	FN_NSS_QUIC_SEND,
	FN_NSS_QUIC_RECV,
	// TLS records' plaintext, where a library encrypts and decrypts them
	// (rustls through aws-lc), for programs without another place to see it.
	FN_RECORD_SEND,
	FN_RECORD_RECV,
	// The same through ring.
	FN_RING_SEND,
	FN_RING_RECV,
	// QUIC packets in Rust programs (quinn), through aws-lc and ring.
	FN_AWSLC_QUIC_SEND,
	FN_AWSLC_QUIC_RECV,
	FN_RING_QUIC_SEND,
	FN_RING_QUIC_RECV,
	// QUIC packets through ngtcp2's crypto library (curl's HTTP/3).
	FN_NGTCP2_SEND,
	FN_NGTCP2_RECV,
	// QUIC packets through Go's AEADs (quic-go).
	FN_GO_QUIC_SEND,
	FN_GO_QUIC_RECV,
};

// A header-only record that isn't a call: a connection whose earlier events
// went out without a socket now has one, given in the header (fd, addresses).
#define FN_SOCKET_NOTICE 0xff
// Another: a QUIC packet was sent, with its header (as sent) and where to,
// for sockets that aren't connected, whose packets' peers only their sends
// say. User space tells the packet's connection by its header.
#define FN_QUIC_PACKET_SENT 0xfe

// How to interpret a function's return value.
enum ret_kind {
	RET_INT,     // int: bytes transferred, <= 0 on error
	RET_SSIZE,   // ssize_t: bytes transferred, < 0 on error
	RET_BOOL_EX, // 1 on success, byte count written through a size_t*
	RET_RUST_RESULT, // Rust's io::Result<usize>: Ok (0) or Err, then the byte count
	RET_SECSTATUS_U32, // NSS's SECSuccess (0), byte count written through an unsigned int*
	RET_BOOL_EX_TLS13, // RET_BOOL_EX, a TLS 1.3 record's inner plaintext (see tls13_content_len)
	RET_KNOWN_LEN, // nothing; the byte count, known at entry, is kept in len_ptr
	RET_KNOWN_LEN_TLS13, // RET_KNOWN_LEN, a TLS 1.3 record's inner plaintext
	RET_ZERO_KNOWN_LEN, // int: 0 on success; the byte count, known at entry, is kept in len_ptr
};

#define EVENT_FLAG_READ_ERROR 1 // the payload could not be copied

// Each ring buffer record is this header followed by chunk_len bytes of
// payload, in a record of one of the sizes defined below.
// A long header's flags, version and both connection IDs, at most 20 bytes
// each (RFC 9000, section 17.2).
#define QUIC_HEADER_MAX 47

struct event_header {
	__u64 timestamp_ns; // CLOCK_MONOTONIC when the call returned
	__u64 latency_ns;   // time spent inside the call
	__u64 conn_id;	    // the library's connection handle, e.g. SSL* or *tls.Conn
	__u32 pid;
	__u32 tid;
	__u32 size;	    // bytes transferred by the call
	__u32 captured;	    // bytes captured for the call (<= size)
	__u32 chunk_offset; // offset of this chunk within the captured bytes
	__u32 chunk_len;    // valid payload bytes in this record
	__s32 fd;	    // socket fd, or -1 if unknown
	__u16 family;	    // AF_INET, AF_INET6, or 0 if the addresses are unknown
	__u16 lport;
	__u16 rport;
	__u8 fn;	    // enum fn_id
	__u8 flags;
	__u8 laddr[16];	    // IPv4 addresses use the first 4 bytes
	__u8 raddr[16];
	// A QUIC packet's header, up to its source connection ID, which tells
	// connections on one socket apart; 0 bytes for other events.
	__u8 quic_header_len;
	__u8 quic_header[QUIC_HEADER_MAX];
	char comm[TASK_COMM_LEN]; // process name
	__u8 _pad[4];	    // so the payload starts at sizeof(struct event_header)
};

#define DEFINE_EVENT(size)                                                    \
	struct event_##size {                                                 \
		struct event_header h;                                        \
		__u8 data[size];                                              \
	}
DEFINE_EVENT(256);
DEFINE_EVENT(2048);
DEFINE_EVENT(16384); // CHUNK_SIZE

// Configuration, set from user space before the program is loaded.
const volatile bool filter_tgids = false; // trace only the processes in traced_tgids
const volatile __u32 max_capture = CHUNK_SIZE;
const volatile bool filter_comm = false;
const volatile char targ_comm[TASK_COMM_LEN] = {};
// Whether the kernel has BTF. Without it, the CO-RE reads of kernel structs
// (socket addresses, process names) can't be relocated and are skipped.
const volatile bool have_btf = false;
// snoopy's own PID namespace (the device and inode of /proc/self/ns/pid),
// unless it's the kernel's own, where both are 0. The PIDs user space is
// given, and gives, are as that namespace numbers them: in a container that
// shares a node's PID namespace, a kind node's say, they aren't the
// kernel's.
const volatile __u64 pidns_dev = 0;
const volatile __u64 pidns_ino = 0;

struct active_call {
	__u64 start_ns;
	__u64 conn;
	__u64 buf;
	__u64 len_ptr; // SSL_*_ex: where the byte count is written
	__u64 sp;      // stack pointer on entry (C libraries)
	__s32 fd;
	__u8 fn;
	__u8 ret;      // enum ret_kind
	__u8 ad_len;   // a QUIC packet's: its header, at ad
	__u8 _pad;
	__u64 ad;
};

// A thread (C libraries) or goroutine (Go) with TLS calls in flight.
// Goroutines can move between threads while blocked inside a call, so Go
// calls are tracked by the goroutine's g pointer instead of the thread.
struct depth_key {
	__u64 thread; // pid_tgid for C libraries, tgid for Go
	__u64 g;      // g pointer for Go, 0 for C libraries
};

struct call_key {
	__u64 thread;
	__u64 g;
	__u32 depth; // nesting level of the call
	__u32 _pad;
};

// Number of nested calls in flight per thread or goroutine.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct depth_key);
	__type(value, __u32);
} call_depth SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct call_key);
	__type(value, struct active_call);
} active_calls SEC(".maps");

// The socket last seen for each TLS connection. A TLS read that is served
// from the library's internal buffer makes no syscall, so remember it.
struct conn_key {
	__u64 tgid;
	__u64 conn;
};

struct conn_info {
	__s32 fd;
	__u16 family;
	__u16 lport;
	__u16 rport;
	__u8 laddr[16];
	__u8 raddr[16];
	__u8 _pad[2];
	// The socket's struct file, with BTF: the connection handle can be freed
	// and its memory reused for another connection (an AEAD context often
	// is), and the fd closed and reused for another socket.
	__u64 file;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct conn_info);
} conn_infos SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 << 20); // resized from user space
} events SEC(".maps");

// When each CPU last let a data record wake the reader. Waking it is an
// interrupt (irq_work), which under load cost more than the rest of
// emitting a record together, so it's done at most once per
// WAKEUP_INTERVAL_NS per CPU; user space also reads on a short timer, for
// records no wakeup followed.
#define WAKEUP_INTERVAL_NS 1000000
// bpf_ringbuf_submit's flags, from linux/bpf.h
#define BPF_RB_NO_WAKEUP 1
#define BPF_RB_FORCE_WAKEUP 2
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} last_wakeup SEC(".maps");

// PIDs of processes that executed a new program, so user space can attach
// to TLS libraries and programs that start after it did, and with probes
// per process, of those forked from a traced one; and with LOADED_LIBRARY
// set, followed by a thread's, of those that loaded a TLS library
// (note_library_load).
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 << 10);
} execs SEC(".maps");

// Counters for user space, by index.
enum counter {
	COUNTER_LOST,	       // chunks dropped because the ring buffer was full
	COUNTER_UNTRACKED_QUIC, // QUIC packets of contexts created before snoopy started
	COUNTER_COUNT,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, COUNTER_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

// With --pid, the processes to trace: the one given and those it starts.
// User space adds them as it finds them, and so does is_traced_tgid, with
// BTF, at a process's first call.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32); // tgid
	__type(value, __u8);
} traced_tgids SEC(".maps");

// Force bpf2go to emit a Go type for struct event_header.
const struct event_header *unused_event_header __attribute__((unused));

// The name of the current process (its main thread), which is what
// /proc/<pid>/comm shows. Threads can have names of their own.
static __always_inline void get_process_name(char *buf)
{
	if (have_btf) {
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		struct task_struct *leader = BPF_CORE_READ(task, group_leader);
		if (leader && !bpf_core_read(buf, TASK_COMM_LEN, &leader->comm))
			return;
	}
	bpf_get_current_comm(buf, TASK_COMM_LEN);
}

// MAX_PID_LEVELS bounds how deep in nested PID namespaces ns_nr looks.
#define MAX_PID_LEVELS 8

// ns_nr returns a PID's number in snoopy's PID namespace, or 0 if it has
// none there: the one at that namespace's level, which a process in a
// namespace below it (a pod's container, under a kind node's) has too.
// Needs BTF.
static __always_inline __u32 ns_nr(struct pid *pid)
{
	if (!pid)
		return 0;
	unsigned int level = BPF_CORE_READ(pid, level);
	for (unsigned int i = 0; i < MAX_PID_LEVELS; i++) {
		if (i > level)
			break;
		struct upid up;
		__builtin_memset(&up, 0, sizeof(up));
		if (bpf_core_read(&up, sizeof(up), &pid->numbers[i]))
			return 0;
		if (up.ns && BPF_CORE_READ(up.ns, ns.inum) == pidns_ino)
			return up.nr;
	}
	return 0;
}

// ns_tgid returns a task's TGID in snoopy's PID namespace, or 0 if it isn't
// in it or below it. Needs BTF.
static __always_inline __u32 ns_tgid(struct task_struct *task)
{
	if (!pidns_ino)
		return BPF_CORE_READ(task, tgid);
	return ns_nr(BPF_CORE_READ(task, group_leader, thread_pid));
}

// ns_pid_tgid returns the current thread's TGID and PID, as
// bpf_get_current_pid_tgid does, but in snoopy's PID namespace, or 0 if the
// thread isn't in it or below it. Only these go to user space; maps the
// program alone uses are keyed by the kernel's own. Without BTF,
// bpf_get_ns_current_pid_tgid only knows threads directly in the namespace.
static __always_inline __u64 ns_pid_tgid(void)
{
	if (!pidns_ino)
		return bpf_get_current_pid_tgid();
	if (have_btf) {
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		__u32 tgid = ns_tgid(task), pid = ns_nr(BPF_CORE_READ(task, thread_pid));
		if (!tgid || !pid)
			return 0;
		return (__u64)tgid << 32 | pid;
	}
	struct bpf_pidns_info ns;
	__builtin_memset(&ns, 0, sizeof(ns));
	if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)))
		return 0;
	return (__u64)ns.tgid << 32 | ns.pid;
}

// MAX_ANCESTORS is how far up its parents a process is looked for in
// traced_tgids.
#define MAX_ANCESTORS 8

// is_traced_tgid reports whether the current process is in traced_tgids, or
// descends from one that is and so is added to it: a process that forked
// without executing a program (as Chrome's network service does) comes to
// user space's notice only when it rescans /proc.
static __always_inline bool is_traced_tgid(__u32 tgid)
{
	if (bpf_map_lookup_elem(&traced_tgids, &tgid))
		return true;
	if (!have_btf)
		return false;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	for (int i = 0; i < MAX_ANCESTORS; i++) {
		task = BPF_CORE_READ(task, real_parent);
		if (!task)
			return false;
		__u32 parent = ns_tgid(task);
		if (parent <= 1) // init, or outside snoopy's PID namespace
			return false;
		if (bpf_map_lookup_elem(&traced_tgids, &parent)) {
			__u8 one = 1;
			bpf_map_update_elem(&traced_tgids, &tgid, &one, BPF_NOEXIST);
			return true;
		}
	}
	return false;
}

static __always_inline bool should_trace(__u64 pid_tgid)
{
	if (filter_tgids) {
		__u32 tgid = pidns_ino ? ns_pid_tgid() >> 32 : pid_tgid >> 32;
		if (!tgid || !is_traced_tgid(tgid))
			return false;
	}

	// --comm matches names that start with it.
	if (filter_comm) {
		char comm[TASK_COMM_LEN];
		get_process_name(comm);
		for (int i = 0; i < TASK_COMM_LEN; i++) {
			if (targ_comm[i] == 0)
				break;
			if (comm[i] != targ_comm[i])
				return false;
		}
	}
	return true;
}

static __always_inline void count(enum counter c)
{
	__u32 key = c;
	__u64 *n = bpf_map_lookup_elem(&counters, &key);
	if (n)
		*n += 1;
}

static __always_inline void count_lost(void)
{
	count(COUNTER_LOST);
}

#define AF_INET 2
#define AF_INET6 10
#define S_IFMT 0170000
#define S_IFSOCK 0140000

// Fills in the addresses of the current task's socket fd, if it is a TCP/IP
// socket: current->files->fdt->fd[fd]->private_data is its struct socket.
// Returns the current process's file at fd if it is a socket. Needs BTF.
// Returns the current process's file at fd, or NULL. Needs BTF.
static __always_inline struct file *file_at(__s32 fd)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt || fd < 0 || (unsigned int)fd >= BPF_CORE_READ(fdt, max_fds))
		return NULL;

	struct file **fds = BPF_CORE_READ(fdt, fd);
	struct file *file = NULL;
	if (bpf_core_read(&file, sizeof(file), &fds[fd]) || !file)
		return NULL;
	return file;
}

static __always_inline struct file *socket_file(__s32 fd)
{
	struct file *file = file_at(fd);
	if (!file || (BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT) != S_IFSOCK)
		return NULL;
	return file;
}

// Returns the address family of the socket at fd, or 0 if it isn't one.
// Needs BTF.
static __always_inline __u16 socket_family(__s32 fd)
{
	struct file *file = socket_file(fd);
	if (!file)
		return 0;
	struct socket *sock = BPF_CORE_READ(file, private_data);
	return BPF_CORE_READ(sock, sk, __sk_common.skc_family);
}

static __always_inline void resolve_socket(__s32 fd, struct conn_info *info)
{
	struct file *file = socket_file(fd);
	if (!file)
		return;
	info->file = (__u64)file;

	struct socket *sock = BPF_CORE_READ(file, private_data);
	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family == AF_INET) {
		BPF_CORE_READ_INTO(&info->laddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&info->raddr, sk, __sk_common.skc_daddr);
	} else if (family == AF_INET6 && bpf_core_field_exists(sk->__sk_common.skc_v6_daddr)) {
		BPF_CORE_READ_INTO(&info->laddr, sk, __sk_common.skc_v6_rcv_saddr);
		BPF_CORE_READ_INTO(&info->raddr, sk, __sk_common.skc_v6_daddr);
	} else {
		return;
	}
	info->family = family;
	info->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	// skc_dport is in network byte order; both supported arches are little-endian.
	info->rport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

// Records the socket a TLS connection is using. Returns whether it is a
// different socket than the one recorded before, if any.
static __always_inline bool track_conn(__u64 pid_tgid, __u64 conn, __s32 fd)
{
	if (!conn || fd < 0)
		return false;

	struct conn_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.tgid = pid_tgid >> 32;
	key.conn = conn;

	struct conn_info info;
	__builtin_memset(&info, 0, sizeof(info));
	info.fd = fd;
	if (have_btf)
		resolve_socket(fd, &info);

	// Once a socket is closed (e.g. reset by the peer), the kernel releases
	// its port and skc_num reads 0, yet buffered data can still be read.
	// Keep what we learned while it was open.
	struct conn_info *known = bpf_map_lookup_elem(&conn_infos, &key);
	bool changed = !known || known->fd != fd || known->file != info.file;
	if (!changed && known->family && (!info.family || !info.lport || !info.rport))
		return false;
	bpf_map_update_elem(&conn_infos, &key, &info, BPF_ANY);
	return changed;
}

// Copies one chunk into a ring buffer record of the smallest size that fits.
// Each chunk gets its own reserved record rather than being assembled in
// shared per-CPU space, where a preempted program could have its data
// overwritten. Returns 0, -1 if the payload couldn't be read, or -2 if the
// ring buffer is full.
#define OUTPUT_CHUNK(cap)                                                     \
	do {                                                                  \
		struct event_##cap *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0); \
		if (!r)                                                       \
			return -2;                                            \
		r->h = *h;                                                    \
		r->h.chunk_len = len;                                         \
		if (bpf_probe_read_user(r->data, len, src)) {                 \
			r->h.flags |= EVENT_FLAG_READ_ERROR;                  \
			r->h.chunk_len = 0;                                   \
			bpf_ringbuf_submit(r, flags);                         \
			return -1;                                            \
		}                                                             \
		bpf_ringbuf_submit(r, flags);                                 \
		return 0;                                                     \
	} while (0)

static __always_inline int output_full_chunk(const struct event_header *h, const void *src, __u64 flags)
{
	const __u32 len = CHUNK_SIZE;
	OUTPUT_CHUNK(16384);
}

// The last chunk of a call can be smaller. Only it picks a record size, so
// each iteration of the chunk loop has a single path that continues; the
// verifier would otherwise have to explore every combination of sizes.
static __always_inline int output_last_chunk(const struct event_header *h, const void *src, __u32 len,
					     __u64 flags)
{
	if (len <= 256)
		OUTPUT_CHUNK(256);
	if (len <= 2048)
		OUTPUT_CHUNK(2048);
	if (len <= CHUNK_SIZE)
		OUTPUT_CHUNK(16384);
	return -1;
}

// Reports whether what's known about a connection still holds: its fd is
// still the same socket. Without BTF, there's no telling.
static __always_inline bool conn_info_live(struct conn_info *info)
{
	return !have_btf || !info->file || (__u64)socket_file(info->fd) == info->file;
}

// The flags to submit a call's records with: no wakeup if this CPU woke the
// reader less than WAKEUP_INTERVAL_NS ago, else a forced one. Not the ring
// buffer's own choice, which wakes the reader only if it has read
// everything before the record: with records submitted without a wakeup
// still unread, it never would.
static __always_inline __u64 submit_flags(__u64 now)
{
	__u32 key = 0;
	__u64 *last = bpf_map_lookup_elem(&last_wakeup, &key);
	if (!last)
		return 0;
	if (now - *last < WAKEUP_INTERVAL_NS)
		return BPF_RB_NO_WAKEUP;
	*last = now;
	return BPF_RB_FORCE_WAKEUP;
}

static __always_inline void emit(struct active_call *call, __u64 pid_tgid, __s64 n)
{
	if (n <= 0)
		return;

	__u64 ns = pidns_ino ? ns_pid_tgid() : pid_tgid;
	if (!ns)
		return; // outside snoopy's PID namespace, where it can't be told apart

	struct event_header h;
	__builtin_memset(&h, 0, sizeof(h));
	__u64 now = bpf_ktime_get_ns();
	h.timestamp_ns = now;
	h.latency_ns = now - call->start_ns;
	h.conn_id = call->conn;
	h.pid = ns >> 32;
	h.tid = (__u32)ns;
	h.size = n > 0xffffffff ? 0xffffffff : (__u32)n;
	h.fn = call->fn;
	get_process_name(h.comm);

	h.fd = call->fd;
	struct conn_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.tgid = pid_tgid >> 32;
	key.conn = call->conn;
	struct conn_info *info = bpf_map_lookup_elem(&conn_infos, &key);
	if (info && (h.fd < 0 || h.fd == info->fd) && conn_info_live(info)) {
		h.fd = info->fd;
		h.family = info->family;
		h.lport = info->lport;
		h.rport = info->rport;
		__builtin_memcpy(h.laddr, info->laddr, sizeof(h.laddr));
		__builtin_memcpy(h.raddr, info->raddr, sizeof(h.raddr));
	}

	if (call->ad && call->ad_len) {
		__u32 len = call->ad_len;
		if (len > QUIC_HEADER_MAX)
			len = QUIC_HEADER_MAX;
		if (!bpf_probe_read_user(h.quic_header, len, (void *)call->ad))
			h.quic_header_len = len;
	}

	__u32 captured = h.size < max_capture ? h.size : max_capture;
	h.captured = captured;
	__u64 flags = submit_flags(now);

	for (__u32 i = 0; i < MAX_CHUNKS; i++) {
		__u32 off = i * CHUNK_SIZE;
		if (off >= captured)
			break;

		__u32 len = captured - off;
		const void *src = (const void *)(call->buf + off);
		h.chunk_offset = off;
		int err = len > CHUNK_SIZE ? output_full_chunk(&h, src, flags) : output_last_chunk(&h, src, len, flags);
		if (err == -2)
			count_lost();
		if (err || len <= CHUNK_SIZE)
			break;
	}
}

/* Bookkeeping for calls in flight */

static __always_inline __u32 get_depth(struct depth_key *dk)
{
	__u32 *depth = bpf_map_lookup_elem(&call_depth, dk);
	return depth ? *depth : 0;
}

static __always_inline void set_depth(struct depth_key *dk, __u32 depth)
{
	if (depth)
		bpf_map_update_elem(&call_depth, dk, &depth, BPF_ANY);
	else
		bpf_map_delete_elem(&call_depth, dk);
}

static __always_inline void call_key_at(struct call_key *key, struct depth_key *dk, __u32 depth)
{
	__builtin_memset(key, 0, sizeof(*key));
	key->thread = dk->thread;
	key->g = dk->g;
	key->depth = depth;
}

static __always_inline void push_call(struct depth_key *dk, __u32 depth, struct active_call *call)
{
	// Deeper nesting than this means returns were missed; start over.
	if (depth >= MAX_DEPTH)
		depth = 0;

	struct call_key key;
	call_key_at(&key, dk, depth);
	bpf_map_update_elem(&active_calls, &key, call, BPF_ANY);
	set_depth(dk, depth + 1);
}

// Calls that the innermost call is nested in (TLS tunneled through TLS) go
// over the same socket; give those that don't know theirs this one.
static __always_inline void propagate_fd(__u64 pid_tgid, struct depth_key *dk, __u32 depth, __s32 fd)
{
	struct call_key key;
	for (int i = 0; i < MAX_DEPTH; i++) {
		if ((__u32)i >= depth)
			break;
		call_key_at(&key, dk, i);
		struct active_call *call = bpf_map_lookup_elem(&active_calls, &key);
		if (call && call->fd < 0) {
			call->fd = fd;
			track_conn(pid_tgid, call->conn, fd);
		}
	}
}

/* C libraries (OpenSSL, GnuTLS, NSS, wolfSSL, Mbed TLS, s2n-tls) */

// The stack pointer a uretprobe sees, which is the entry stack pointer
// minus the popped return address on x86 and unchanged on arm64. Matching
// it pairs each return with its own call even when calls nest.
#if defined(__TARGET_ARCH_x86)
#define RETURN_TO_ENTRY_SP(sp) ((sp) - 8)
#define RUST_RESULT_VALUE(ctx) ((ctx)->dx) // second return register
#elif defined(__TARGET_ARCH_arm64)
#define RETURN_TO_ENTRY_SP(sp) (sp)
#define RUST_RESULT_VALUE(ctx) ((ctx)->user_regs.regs[1])
#endif

// enter_call_ad records a call in flight. fd is its socket if already known,
// or -1; otherwise a syscall made during the call tells. A QUIC packet's
// header is at ad, of ad_len bytes; ad is 0 for other calls.
static __always_inline int enter_call_ad(struct pt_regs *ctx, __u8 fn, __u8 ret, __u64 conn, const void *buf,
					 __u64 len_ptr, __s32 fd, __u64 ad, __u64 ad_len)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid))
		return 0;

	struct active_call call;
	__builtin_memset(&call, 0, sizeof(call));
	call.start_ns = bpf_ktime_get_ns();
	call.conn = conn;
	call.buf = (__u64)buf;
	call.len_ptr = len_ptr;
	call.sp = PT_REGS_SP(ctx);
	call.fd = fd;
	call.fn = fn;
	call.ret = ret;
	call.ad = ad;
	call.ad_len = ad_len > 0xff ? 0xff : ad_len;
	if (fd >= 0)
		track_conn(pid_tgid, conn, fd);

	struct depth_key dk;
	__builtin_memset(&dk, 0, sizeof(dk));
	dk.thread = pid_tgid;
	push_call(&dk, get_depth(&dk), &call);
	return 0;
}

// enter_call_ad without a QUIC packet's header.
static __always_inline int enter_call_fd(struct pt_regs *ctx, __u8 fn, __u8 ret, __u64 conn, const void *buf,
					 __u64 len_ptr, __s32 fd)
{
	return enter_call_ad(ctx, fn, ret, conn, buf, len_ptr, fd, 0, 0);
}

static __always_inline int enter_call(struct pt_regs *ctx, __u8 fn, __u8 ret, __u64 conn, const void *buf,
				      __u64 len_ptr)
{
	return enter_call_fd(ctx, fn, ret, conn, buf, len_ptr, -1);
}

// MAX_TLS13_PADDING bounds how much padding is looked through to find a TLS
// 1.3 record's content type. Libraries don't pad by default.
#define MAX_TLS13_PADDING 32
#define TLS_APPLICATION_DATA 0x17

// tls13_content_len returns the length of the application data in a TLS 1.3
// record's decrypted plaintext of n bytes at buf, which is the content, its
// real type and zero padding (RFC 8446, section 5.2). Records of other types
// (handshake messages, alerts) give -1, so they aren't emitted.
static __always_inline __s64 tls13_content_len(__u64 buf, __s64 n)
{
	for (int i = 1; i <= MAX_TLS13_PADDING; i++) {
		if (i > n)
			return -1;
		__u8 b = 0;
		if (bpf_probe_read_user(&b, 1, (void *)(buf + n - i)))
			return -1;
		if (b)
			return b == TLS_APPLICATION_DATA ? n - i : -1;
	}
	return -1;
}

static __always_inline int exit_call(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct depth_key dk;
	__builtin_memset(&dk, 0, sizeof(dk));
	dk.thread = pid_tgid;
	__u32 depth = get_depth(&dk);
	if (!depth)
		return 0;

	// Find this return's call, innermost first.
	__u64 sp = RETURN_TO_ENTRY_SP(PT_REGS_SP(ctx));
	struct call_key key;
	struct active_call call;
	__builtin_memset(&call, 0, sizeof(call));
	int found = -1;
	for (int i = MAX_DEPTH - 1; i >= 0; i--) {
		if ((__u32)i >= depth)
			continue;
		call_key_at(&key, &dk, i);
		struct active_call *active = bpf_map_lookup_elem(&active_calls, &key);
		if (active && active->sp == sp) {
			call = *active;
			found = i;
			break;
		}
	}
	if (found < 0)
		return 0;
	bpf_map_delete_elem(&active_calls, &key);
	set_depth(&dk, found); // calls nested deeper than this one never returned

	__s64 n;
	switch (call.ret) {
	case RET_INT:
		n = (int)PT_REGS_RC(ctx);
		break;
	case RET_SSIZE:
		n = (long)PT_REGS_RC(ctx);
		break;
	case RET_SECSTATUS_U32: {
		__u32 len = 0;
		if ((int)PT_REGS_RC(ctx) != 0 || !call.len_ptr ||
		    bpf_probe_read_user(&len, sizeof(len), (void *)call.len_ptr))
			return 0;
		n = len;
		break;
	}
	case RET_RUST_RESULT:
		// The discriminant's upper bits aren't defined if it's narrower than
		// the register.
		n = (__u8)PT_REGS_RC(ctx) == 0 ? (__s64)RUST_RESULT_VALUE(ctx) : 0;
		break;
	case RET_ZERO_KNOWN_LEN:
		n = (int)PT_REGS_RC(ctx) == 0 ? (__s64)call.len_ptr : 0;
		break;
	case RET_KNOWN_LEN:
	case RET_KNOWN_LEN_TLS13:
		n = (__s64)call.len_ptr;
		if (call.ret == RET_KNOWN_LEN_TLS13)
			n = tls13_content_len(call.buf, n);
		break;
	default: {
		__u64 len = 0;
		if ((int)PT_REGS_RC(ctx) != 1 || !call.len_ptr ||
		    bpf_probe_read_user(&len, sizeof(len), (void *)call.len_ptr))
			return 0;
		n = len;
		if (call.ret == RET_BOOL_EX_TLS13)
			n = tls13_content_len(call.buf, n);
	}
	}

	emit(&call, pid_tgid, n);
	return 0;
}

// Remember which fd the thread's innermost TLS call is doing I/O on.
static __always_inline int record_fd(__u64 fd)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct depth_key dk;
	__builtin_memset(&dk, 0, sizeof(dk));
	dk.thread = pid_tgid;
	__u32 depth = get_depth(&dk);
	if (!depth || depth > MAX_DEPTH)
		return 0;

	struct call_key key;
	call_key_at(&key, &dk, depth - 1);
	struct active_call *call = bpf_map_lookup_elem(&active_calls, &key);
	if (!call)
		return 0;
	call->fd = (__s32)fd;
	track_conn(pid_tgid, call->conn, call->fd);
	propagate_fd(pid_tgid, &dk, depth - 1, call->fd);
	return 0;
}

// Syscalls a TLS library may use to move data over its socket. They all take
// the file descriptor as their first argument. RECV_KIND says where a
// receive's buffer is: in its second argument, or in the first iovec of the
// iovec array, msghdr or (first) mmsghdr there; 0 for sends.
enum { RECV_BUF = 1, RECV_IOVEC, RECV_MSG, RECV_MMSG };
#if defined(__TARGET_ARCH_x86)
#define SYS_MMAP 9
#define SYSCALL_FD(regs) ((regs)->di)
#define SYSCALL_ARG1(regs) ((regs)->si)
#define SYSCALL_ARG2(regs) ((regs)->dx)
#define SYSCALL_ARG4(regs) ((regs)->r8)
#define IS_SOCKET_IO_SYSCALL(id)                                              \
	((id) == 0 /* read */ || (id) == 1 /* write */ ||                     \
	 (id) == 19 /* readv */ || (id) == 20 /* writev */ ||                 \
	 (id) == 44 /* sendto */ || (id) == 45 /* recvfrom */ ||              \
	 (id) == 46 /* sendmsg */ || (id) == 47 /* recvmsg */ ||              \
	 (id) == 299 /* recvmmsg */ || (id) == 307 /* sendmmsg */)
#define RECV_KIND(id)                                                         \
	((id) == 0 || (id) == 45 ? RECV_BUF : (id) == 19 ? RECV_IOVEC :       \
	 (id) == 47 ? RECV_MSG : (id) == 299 ? RECV_MMSG : 0)
#define IS_SENDTO(id) ((id) == 44)
#define IS_SENDMSG(id) ((id) == 46 || (id) == 307)
#define IS_DATAGRAM_IO(id) ((id) >= 44 && (id) <= 47 || (id) == 299 || (id) == 307)
#elif defined(__TARGET_ARCH_arm64)
#define SYS_MMAP 222
#define SYSCALL_FD(regs) ((regs)->orig_x0)
#define SYSCALL_ARG1(regs) ((regs)->user_regs.regs[1])
#define SYSCALL_ARG2(regs) ((regs)->user_regs.regs[2])
#define SYSCALL_ARG4(regs) ((regs)->user_regs.regs[4])
#define IS_SOCKET_IO_SYSCALL(id)                                              \
	((id) == 63 /* read */ || (id) == 64 /* write */ ||                   \
	 (id) == 65 /* readv */ || (id) == 66 /* writev */ ||                 \
	 (id) == 206 /* sendto */ || (id) == 207 /* recvfrom */ ||            \
	 (id) == 211 /* sendmsg */ || (id) == 212 /* recvmsg */ ||            \
	 (id) == 243 /* recvmmsg */ || (id) == 269 /* sendmmsg */)
#define RECV_KIND(id)                                                         \
	((id) == 63 || (id) == 207 ? RECV_BUF : (id) == 65 ? RECV_IOVEC :     \
	 (id) == 212 ? RECV_MSG : (id) == 243 ? RECV_MMSG : 0)
#define IS_SENDTO(id) ((id) == 206)
#define IS_SENDMSG(id) ((id) == 211 || (id) == 269)
#define IS_DATAGRAM_IO(id) ((id) == 206 || (id) == 207 || (id) == 211 || (id) == 212 || (id) == 243 || (id) == 269)
#endif

// Tells user space that a connection has a socket now: its writes are
// encrypted before the thread's next send shows which socket it is, so its
// first write went out without one.
static __always_inline void emit_socket_notice(__u64 pid_tgid, __u64 conn)
{
	struct conn_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.tgid = pid_tgid >> 32;
	key.conn = conn;
	struct conn_info *info = bpf_map_lookup_elem(&conn_infos, &key);
	if (!info)
		return;
	struct event_256 *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
	if (!r) {
		count_lost();
		return;
	}
	__builtin_memset(&r->h, 0, sizeof(r->h));
	__u64 ns = pidns_ino ? ns_pid_tgid() : pid_tgid;
	r->h.timestamp_ns = bpf_ktime_get_ns();
	r->h.conn_id = conn;
	r->h.pid = ns >> 32;
	r->h.tid = (__u32)ns;
	r->h.fn = FN_SOCKET_NOTICE;
	r->h.fd = info->fd;
	r->h.family = info->family;
	r->h.lport = info->lport;
	r->h.rport = info->rport;
	__builtin_memcpy(r->h.laddr, info->laddr, sizeof(r->h.laddr));
	__builtin_memcpy(r->h.raddr, info->raddr, sizeof(r->h.raddr));
	bpf_ringbuf_submit(r, 0);
}

// Threads that called functions which don't do the socket I/O themselves:
// rustls's Reader and Writer, and QUIC's packet encryption. On the same
// thread, the receive happens before them and the send just after. So for
// these threads, remember the last receive's socket, and which connection
// the next send is for.
struct io_thread {
	__u64 want_conn; // a connection that wrote, waiting for its socket
	__s32 last_fd;	 // the socket of the last receive
	// The receive buffer the last decrypted packet was found at the start
	// of, and its socket (see packet_fd).
	__s32 dgram_fd;
	__u64 dgram_start;
	__u64 dgram_end;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64); // pid_tgid
	__type(value, struct io_thread);
} io_threads SEC(".maps");

// Where these threads' receives put their data, and from which socket: a
// received QUIC packet may be decrypted later, after I/O on other sockets
// (Chrome reads packets in batches and yields to other work in between), but
// it is decrypted where it was received to.
struct recv_buf_key {
	__u64 tgid;
	__u64 buf;
};

struct recv_buf {
	__u64 file; // the socket's struct file, with BTF: the buffer may have
		    // been freed with its socket and reused since
	__s32 fd;
	__u32 len; // the buffer's size
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct recv_buf_key);
	__type(value, struct recv_buf);
} recv_bufs SEC(".maps");

// Where these processes' QUIC packets were encrypted, and for which
// connection: they're encrypted in place, so a send whose buffer starts at
// one sends it, to its connection's peer.
struct sealed_key {
	__u64 tgid;
	__u64 buf;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct sealed_key);
	__type(value, __u64); // the connection
} sealed_packets SEC(".maps");

// Processes that encrypted QUIC packets there, whose sends are looked up in
// sealed_packets, with the socket of their last receive: a packet is often
// decrypted on another thread than it was received on.
struct quic_proc {
	__s32 last_recv_fd;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32); // tgid
	__type(value, struct quic_proc);
} quic_procs SEC(".maps");

static __always_inline void note_sealed(__u64 pid_tgid, __u64 buf, __u64 conn)
{
	__u32 tgid = pid_tgid >> 32;
	struct quic_proc fresh = {.last_recv_fd = -1};
	bpf_map_update_elem(&quic_procs, &tgid, &fresh, BPF_NOEXIST);
	struct sealed_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.tgid = pid_tgid >> 32;
	key.buf = buf;
	bpf_map_update_elem(&sealed_packets, &key, &conn, BPF_ANY);
}

static __always_inline void note_recv_buf(__u64 pid_tgid, __s32 fd, int kind, struct pt_regs *regs)
{
	__u64 arg = 0, buf = 0, len = 0;
	if (bpf_probe_read_kernel(&arg, sizeof(arg), &SYSCALL_ARG1(regs)) || !arg)
		return;
	switch (kind) {
	case RECV_BUF:
		buf = arg;
		if (bpf_probe_read_kernel(&len, sizeof(len), &SYSCALL_ARG2(regs)))
			return;
		break;
	case RECV_MSG: // struct msghdr: msg_iov at 16
	case RECV_MMSG: // struct mmsghdr starts with one
		if (bpf_probe_read_user(&arg, sizeof(arg), (void *)(arg + 16)) || !arg)
			return;
		// fall through
	case RECV_IOVEC: { // struct iovec: iov_base, iov_len
		__u64 iov[2] = {};
		if (bpf_probe_read_user(iov, sizeof(iov), (void *)arg))
			return;
		buf = iov[0];
		len = iov[1];
		break;
	}
	}
	if (!buf)
		return;
	struct recv_buf_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.tgid = pid_tgid >> 32;
	key.buf = buf;
	struct recv_buf value;
	__builtin_memset(&value, 0, sizeof(value));
	value.fd = fd;
	value.len = len > 0xffffffff ? 0xffffffff : (__u32)len;
	if (have_btf)
		value.file = (__u64)socket_file(fd);
	bpf_map_update_elem(&recv_bufs, &key, &value, BPF_ANY);
}

// Returns the receive into buf, if its socket is still open.
static __always_inline struct recv_buf *recv_buf_at(__u64 pid_tgid, __u64 buf)
{
	struct recv_buf_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.tgid = pid_tgid >> 32;
	key.buf = buf;
	struct recv_buf *r = bpf_map_lookup_elem(&recv_bufs, &key);
	if (!r || (have_btf && (__u64)socket_file(r->fd) != r->file))
		return NULL;
	return r;
}

// Tells user space that the QUIC packet at buf, of the connection conn, was
// sent to the struct sockaddr at name.
static __always_inline void emit_packet_sent(__u64 pid_tgid, __u64 conn, __s32 fd, __u64 buf, __u64 name)
{
	// sockaddr_in: family, port, address; sockaddr_in6: family, port, flow
	// info, address.
	__u8 sa[24];
	__builtin_memset(sa, 0, sizeof(sa));
	if (bpf_probe_read_user(sa, sizeof(sa), (void *)name))
		return;
	__u16 family = sa[0] | sa[1] << 8;
	if (family != AF_INET && family != AF_INET6)
		return;
	struct event_256 *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
	if (!r) {
		count_lost();
		return;
	}
	__builtin_memset(&r->h, 0, sizeof(r->h));
	if (bpf_probe_read_user(r->h.quic_header, sizeof(r->h.quic_header), (void *)buf)) {
		bpf_ringbuf_discard(r, 0);
		return;
	}
	r->h.quic_header_len = sizeof(r->h.quic_header);
	__u64 ns = pidns_ino ? ns_pid_tgid() : pid_tgid;
	r->h.timestamp_ns = bpf_ktime_get_ns();
	r->h.conn_id = conn;
	r->h.pid = ns >> 32;
	r->h.tid = (__u32)ns;
	r->h.fn = FN_QUIC_PACKET_SENT;
	r->h.fd = fd;
	r->h.family = family;
	r->h.rport = sa[2] << 8 | sa[3];
	if (family == AF_INET)
		__builtin_memcpy(r->h.raddr, &sa[4], 4);
	else
		__builtin_memcpy(r->h.raddr, &sa[8], 16);
	bpf_ringbuf_submit(r, 0);
}

// A send of a QUIC packet, found by where the send's data starts, says which
// socket its connection is on, whichever thread sends it, and where it goes
// if the socket isn't connected: sendto's destination, or the (first)
// message's.
static __always_inline void note_packet_send(__u64 pid_tgid, __s32 fd, long id, struct pt_regs *regs)
{
	__u64 arg = 0, buf = 0, name = 0;
	if (bpf_probe_read_kernel(&arg, sizeof(arg), &SYSCALL_ARG1(regs)) || !arg)
		return;
	if (IS_SENDTO(id)) {
		buf = arg;
		bpf_probe_read_kernel(&name, sizeof(name), &SYSCALL_ARG4(regs));
	} else {
		// struct msghdr (or an mmsghdr's): msg_name at 0, msg_iov at 16,
		// whose first iovec's base is the data's start.
		__u64 iov = 0;
		if (bpf_probe_read_user(&name, sizeof(name), (void *)arg) ||
		    bpf_probe_read_user(&iov, sizeof(iov), (void *)(arg + 16)) || !iov ||
		    bpf_probe_read_user(&buf, sizeof(buf), (void *)iov))
			return;
	}
	if (!buf)
		return;
	struct sealed_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.tgid = pid_tgid >> 32;
	key.buf = buf;
	__u64 *found = bpf_map_lookup_elem(&sealed_packets, &key);
	if (!found)
		return;
	__u64 conn = *found;
	if (name)
		emit_packet_sent(pid_tgid, conn, fd, buf, name);
	if (track_conn(pid_tgid, conn, fd))
		emit_socket_notice(pid_tgid, conn);
}

// Per traced process: how many datagrams it sent or received on UDP sockets
// connected to port 443, HTTP/3's, up to QUIC_TRAFFIC_MAX, and how many
// QUIC packets it decrypted that couldn't be traced (Firefox's, from before
// snoopy). User space compares the first with the QUIC packets captured, to
// warn when a program's HTTP/3 isn't: its QUIC library isn't supported, or
// has changed.
struct quic_traffic {
	__u32 udp443;
	__u32 untracked;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32); // tgid
	__type(value, struct quic_traffic);
} quic_traffic SEC(".maps");

#define QUIC_TRAFFIC_MAX 64
#define SOCK_DGRAM 2
#define HTTPS_PORT_BE 0xbb01 // 443, in network byte order

static __always_inline void note_udp443(__u64 pid_tgid, __s32 fd, long id)
{
	if (!have_btf || !IS_DATAGRAM_IO(id))
		return;
	__u32 tgid = (pidns_ino ? ns_pid_tgid() : pid_tgid) >> 32; // user space reads these
	if (!tgid)
		return;
	struct quic_traffic *qt = bpf_map_lookup_elem(&quic_traffic, &tgid);
	if (qt && qt->udp443 >= QUIC_TRAFFIC_MAX)
		return;
	struct file *file = socket_file(fd);
	if (!file)
		return;
	struct socket *sock = BPF_CORE_READ(file, private_data);
	if (BPF_CORE_READ(sock, type) != SOCK_DGRAM || BPF_CORE_READ(sock, sk, __sk_common.skc_dport) != HTTPS_PORT_BE)
		return;
	if (qt) {
		__sync_fetch_and_add(&qt->udp443, 1);
		return;
	}
	struct quic_traffic fresh = {.udp443 = 1};
	bpf_map_update_elem(&quic_traffic, &tgid, &fresh, BPF_NOEXIST);
}

// For processes in quic_procs: their last receive's socket, and the sockets
// and peers of their QUIC packets' sends.
static __always_inline void note_quic_proc_io(__s32 fd, long id, struct pt_regs *regs)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct quic_proc *qp = bpf_map_lookup_elem(&quic_procs, &tgid);
	if (!qp)
		return;
	if (RECV_KIND(id)) {
		if (have_btf) {
			__u16 family = socket_family(fd);
			if (family != AF_INET && family != AF_INET6)
				return;
		}
		qp->last_recv_fd = fd;
	} else if (IS_SENDTO(id) || IS_SENDMSG(id)) {
		note_packet_send(pid_tgid, fd, id, regs);
	}
}

static __always_inline void note_thread_fd(__u64 fd, long id, struct pt_regs *regs)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct io_thread *rt = bpf_map_lookup_elem(&io_threads, &pid_tgid);
	if (!rt)
		return;
	// Only network sockets: not an event loop's wakeup pipe or eventfd, nor
	// Unix sockets for IPC (Chrome's Mojo).
	if (have_btf) {
		__u16 family = socket_family((__s32)fd);
		if (family != AF_INET && family != AF_INET6)
			return;
	}
	int kind = RECV_KIND(id);
	if (kind) {
		rt->last_fd = (__s32)fd;
		note_recv_buf(pid_tgid, (__s32)fd, kind, regs);
		return;
	}
	__u64 conn = rt->want_conn;
	if (conn) {
		rt->want_conn = 0;
		if (track_conn(pid_tgid, conn, (__s32)fd))
			emit_socket_notice(pid_tgid, conn);
	}
}

// sched:sched_process_exec, raised after a successful execve. It runs in the
// process itself, which by then has a single thread, so its PID is the TGID.
SEC("raw_tracepoint/sched_process_exec")
int sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 pid = ns_pid_tgid() >> 32;
	if (pid)
		bpf_ringbuf_output(&execs, &pid, sizeof(pid), 0);
	return 0;
}

// sched:sched_process_fork(struct task_struct *parent, struct task_struct
// *child), raised in the parent. With probes per process, a new process (not
// a thread) of a traced one needs its own, so user space is told of it the
// way it's told of execs. Needs BTF, which per-process probes need.
SEC("raw_tracepoint/sched_process_fork")
int sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
	if (!have_btf)
		return 0;
	struct task_struct *child = (struct task_struct *)ctx->args[1];
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (BPF_CORE_READ(child, tgid) == pid_tgid >> 32 || !should_trace(pid_tgid))
		return 0; // a thread, or not traced
	__u32 tgid = ns_tgid(child);
	if (!tgid)
		return 0;
	bpf_ringbuf_output(&execs, &tgid, sizeof(tgid), 0);
	return 0;
}

#define PROT_EXEC 4
// LOADED_LIBRARY marks a PID in execs that loaded a TLS library, rather than
// executed a program; the thread that did follows it.
#define LOADED_LIBRARY 0x80000000u

// The names TLS libraries' files start with, as user space looks for them
// (libPatterns in internal/discover): a process's mapping one is told of.
#define LIBNAME_MAX 20
static const char tls_library_names[][LIBNAME_MAX] = {
	"libssl.so", "libgnutls.so", "libnspr4.so", "libfreeblpriv3.so", "libwolfssl.so",
	"libmbedtls.so", "libs2n.so", "libngtcp2_crypto_", "libnetty_tcnative", "libconscrypt",
};

static __always_inline bool tls_library_name(const char *name)
{
	for (int i = 0; i < (int)(sizeof(tls_library_names) / LIBNAME_MAX); i++) {
		bool match = true;
		for (int j = 0; j < LIBNAME_MAX; j++) {
			char c = tls_library_names[i][j];
			if (!c)
				break;
			if (name[j] != c) {
				match = false;
				break;
			}
		}
		if (match)
			return true;
	}
	return false;
}

struct library_load {
	__u32 pid; // with LOADED_LIBRARY set
	__u32 tid;
};

// Tells user space when a process it traces maps a TLS library executable,
// which is how one is loaded, with the thread that did: one it loads late
// gets attached to, as the TLS library a JVM extracts and loads the first
// time it needs it (netty-tcnative, Conscrypt), and user space can hold that
// thread, about to use it, until it is. Needs BTF.
static __always_inline void note_library_load(struct pt_regs *regs)
{
	if (!have_btf)
		return;
	__u64 prot = 0, fd = 0;
	if (bpf_probe_read_kernel(&prot, sizeof(prot), &SYSCALL_ARG2(regs)) ||
	    bpf_probe_read_kernel(&fd, sizeof(fd), &SYSCALL_ARG4(regs)))
		return;
	if (!(prot & PROT_EXEC) || (__s32)fd < 0)
		return;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid))
		return;
	struct file *file = file_at((__s32)fd);
	if (!file)
		return;
	char name[LIBNAME_MAX];
	__builtin_memset(name, 0, sizeof(name));
	if (bpf_probe_read_kernel_str(name, sizeof(name), BPF_CORE_READ(file, f_path.dentry, d_name.name)) <= 0 ||
	    !tls_library_name(name))
		return;
	__u64 ns = ns_pid_tgid();
	if (!ns)
		return;
	struct library_load load = {.pid = (ns >> 32) | LOADED_LIBRARY, .tid = (__u32)ns};
	bpf_ringbuf_output(&execs, &load, sizeof(load), 0);
}

// raw_syscalls:sys_enter(struct pt_regs *regs, long id). A raw tracepoint
// needs neither tracefs nor BTF, unlike the per-syscall tracepoints.
SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	long id = (long)ctx->args[1];
	if (id == SYS_MMAP) {
		note_library_load((struct pt_regs *)ctx->args[0]);
		return 0;
	}
	if (!IS_SOCKET_IO_SYSCALL(id))
		return 0;

	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	__u64 fd = 0;
	if (bpf_probe_read_kernel(&fd, sizeof(fd), &SYSCALL_FD(regs)))
		return 0;
	note_thread_fd(fd, id, regs);
	note_quic_proc_io((__s32)fd, id, regs);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (should_trace(pid_tgid))
		note_udp443(pid_tgid, (__s32)fd, id);
	return record_fd(fd);
}

// OpenSSL, BoringSSL and LibreSSL.
// int SSL_read(SSL *ssl, void *buf, int num) and SSL_write alike.
// int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) and SSL_write_ex alike.

SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_enter, void *ssl, void *buf)
{
	return enter_call(ctx, FN_SSL_READ, RET_INT, (__u64)ssl, buf, 0);
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_enter, void *ssl, const void *buf)
{
	return enter_call(ctx, FN_SSL_WRITE, RET_INT, (__u64)ssl, buf, 0);
}

SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_read_ex_enter, void *ssl, void *buf, __u64 num, __u64 *readbytes)
{
	return enter_call(ctx, FN_SSL_READ_EX, RET_BOOL_EX, (__u64)ssl, buf, (__u64)readbytes);
}

SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_write_ex_enter, void *ssl, const void *buf, __u64 num, __u64 *written)
{
	return enter_call(ctx, FN_SSL_WRITE_EX, RET_BOOL_EX, (__u64)ssl, buf, (__u64)written);
}

// GnuTLS.
// ssize_t gnutls_record_recv(gnutls_session_t session, void *data, size_t data_size) and _send alike.

SEC("uprobe/gnutls_record_recv")
int BPF_UPROBE(gnutls_record_recv_enter, void *session, void *data)
{
	return enter_call(ctx, FN_GNUTLS_RECORD_RECV, RET_SSIZE, (__u64)session, data, 0);
}

SEC("uprobe/gnutls_record_send")
int BPF_UPROBE(gnutls_record_send_enter, void *session, const void *data)
{
	return enter_call(ctx, FN_GNUTLS_RECORD_SEND, RET_SSIZE, (__u64)session, data, 0);
}

// NSS (via NSPR). PR_Read and friends are used for all kinds of descriptors;
// only layered ones (the SSL layer sits on top of a TCP socket) carry TLS
// plaintext.
// PRInt32 PR_Read(PRFileDesc *fd, void *buf, PRInt32 amount) and PR_Write,
// PR_Recv, PR_Send alike in their first three arguments.

#define PR_DESC_LAYERED 4

static __always_inline bool nspr_is_layered(const void *fd)
{
	// struct PRFileDesc { const PRIOMethods *methods; ... }
	// struct PRIOMethods { PRDescType file_type; ... }
	__u64 methods = 0;
	__u32 type = 0;
	if (bpf_probe_read_user(&methods, sizeof(methods), fd) || !methods)
		return false;
	if (bpf_probe_read_user(&type, sizeof(type), (void *)methods))
		return false;
	return type == PR_DESC_LAYERED;
}

#define NSPR_PROBE(fn_name, fn)                                               \
	SEC("uprobe/" #fn_name)                                               \
	int BPF_UPROBE(fn_name##_enter, void *fd, void *buf)                  \
	{                                                                     \
		if (!nspr_is_layered(fd))                                     \
			return 0;                                             \
		return enter_call(ctx, fn, RET_INT, (__u64)fd, buf, 0);       \
	}

NSPR_PROBE(PR_Read, FN_PR_READ)
NSPR_PROBE(PR_Write, FN_PR_WRITE)
NSPR_PROBE(PR_Send, FN_PR_SEND)

#define PR_MSG_PEEK 0x2

// PRInt32 PR_Recv(PRFileDesc *fd, void *buf, PRInt32 amount, PRIntn flags,
// PRIntervalTime timeout). Firefox peeks at a byte to check that an idle
// connection is alive; the byte is read again later.
SEC("uprobe/PR_Recv")
int BPF_UPROBE(PR_Recv_enter, void *fd, void *buf, int amount, int flags)
{
	if ((flags & PR_MSG_PEEK) || !nspr_is_layered(fd))
		return 0;
	return enter_call(ctx, FN_PR_RECV, RET_INT, (__u64)fd, buf, 0);
}

// wolfSSL. wolfSSL_recv and wolfSSL_send call these, so they aren't probed.
// int wolfSSL_read(WOLFSSL *ssl, void *data, int sz) and wolfSSL_write alike.

SEC("uprobe/wolfSSL_read")
int BPF_UPROBE(wolfssl_read_enter, void *ssl, void *data)
{
	return enter_call(ctx, FN_WOLFSSL_READ, RET_INT, (__u64)ssl, data, 0);
}

SEC("uprobe/wolfSSL_write")
int BPF_UPROBE(wolfssl_write_enter, void *ssl, const void *data)
{
	return enter_call(ctx, FN_WOLFSSL_WRITE, RET_INT, (__u64)ssl, data, 0);
}

// Mbed TLS.
// int mbedtls_ssl_read(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len) and _write alike.

SEC("uprobe/mbedtls_ssl_read")
int BPF_UPROBE(mbedtls_ssl_read_enter, void *ssl, void *buf)
{
	return enter_call(ctx, FN_MBEDTLS_SSL_READ, RET_INT, (__u64)ssl, buf, 0);
}

SEC("uprobe/mbedtls_ssl_write")
int BPF_UPROBE(mbedtls_ssl_write_enter, void *ssl, const void *buf)
{
	return enter_call(ctx, FN_MBEDTLS_SSL_WRITE, RET_INT, (__u64)ssl, buf, 0);
}

// s2n-tls. s2n_sendv takes an array of buffers and isn't probed.
// ssize_t s2n_recv(struct s2n_connection *conn, void *buf, ssize_t size, s2n_blocked_status *blocked)
// and s2n_send alike.

SEC("uprobe/s2n_recv")
int BPF_UPROBE(s2n_recv_enter, void *conn, void *buf)
{
	return enter_call(ctx, FN_S2N_RECV, RET_SSIZE, (__u64)conn, buf, 0);
}

SEC("uprobe/s2n_send")
int BPF_UPROBE(s2n_send_enter, void *conn, const void *buf)
{
	return enter_call(ctx, FN_S2N_SEND, RET_SSIZE, (__u64)conn, buf, 0);
}

// rustls.
// fn <Reader as Read>::read(&mut self, buf: &mut [u8]) -> io::Result<usize>
// fn <Writer as Write>::write(&mut self, buf: &[u8]) -> io::Result<usize>
// Both are short-lived wrappers whose first field points into the
// connection (its plaintext buffer for Reader, the connection for Writer),
// which serves as the connection's handle.

static __always_inline __u64 rust_conn(const void *self)
{
	__u64 conn = 0;
	bpf_probe_read_user(&conn, sizeof(conn), self);
	return conn;
}

static __always_inline struct io_thread *io_thread(__u64 pid_tgid)
{
	struct io_thread *rt = bpf_map_lookup_elem(&io_threads, &pid_tgid);
	if (rt)
		return rt;
	struct io_thread fresh;
	__builtin_memset(&fresh, 0, sizeof(fresh));
	fresh.last_fd = -1;
	bpf_map_update_elem(&io_threads, &pid_tgid, &fresh, BPF_NOEXIST);
	return bpf_map_lookup_elem(&io_threads, &pid_tgid);
}

SEC("uprobe/rustls_read")
int BPF_UPROBE(rustls_read_enter, const void *self, void *buf)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid))
		return 0;
	struct io_thread *rt = io_thread(pid_tgid);
	__s32 fd = rt ? rt->last_fd : -1;
	return enter_call_fd(ctx, FN_RUSTLS_READ, RET_RUST_RESULT, rust_conn(self), buf, 0, fd);
}

SEC("uprobe/rustls_write")
int BPF_UPROBE(rustls_write_enter, const void *self, const void *buf)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid))
		return 0;
	__u64 conn = rust_conn(self);
	struct io_thread *rt = io_thread(pid_tgid);
	if (rt)
		rt->want_conn = conn;
	return enter_call(ctx, FN_RUSTLS_WRITE, RET_RUST_RESULT, conn, buf, 0);
}

// QUIC (HTTP/3) encrypts and decrypts each packet with an AEAD whose
// associated data is the packet's header, and whose plaintext is the
// packet's frames. The same AEAD functions also protect TLS records, which
// are left out by their associated data: TLS 1.3's is the 5-byte record
// header (content type, then 03 03 or 03 01), TLS 1.2's 13 bytes ending in
// type, version (03 0x) and length. QUIC's fixed bit (0x40) can't be relied
// on: peers may grease it (RFC 9287). Anything else that isn't QUIC is left
// for user space, which only accepts what parses as QUIC frames.
// int EVP_AEAD_CTX_seal(const EVP_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
//     size_t max_out_len, const uint8_t *nonce, size_t nonce_len,
//     const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len)
// and EVP_AEAD_CTX_open alike. ctx identifies a connection's direction.

// func_arg returns a function's i-th (0-based) integer argument at its entry.
static __always_inline __u64 func_arg(struct pt_regs *ctx, int i)
{
	__u64 v = 0;
#if defined(__TARGET_ARCH_x86)
	switch (i) {
	case 0: return ctx->di;
	case 1: return ctx->si;
	case 2: return ctx->dx;
	case 3: return ctx->cx;
	case 4: return ctx->r8;
	case 5: return ctx->r9;
	}
	// The rest on the stack, above the return address.
	bpf_probe_read_user(&v, sizeof(v), (void *)(PT_REGS_SP(ctx) + 8 * (i - 5)));
#elif defined(__TARGET_ARCH_arm64)
	if (i < 8)
		return ctx->user_regs.regs[i];
	bpf_probe_read_user(&v, sizeof(v), (void *)(PT_REGS_SP(ctx) + 8 * (i - 8)));
#endif
	return v;
}

// What an AEAD call protects, told by its associated data: a QUIC packet
// (its header), a TLS 1.3 record (its 5-byte header), or a TLS 1.2 record
// (sequence number, type, version and length: 13 bytes).
enum aad_kind {
	AAD_NONE,
	AAD_QUIC,
	AAD_TLS13,
	AAD_TLS12_DATA,	 // application data
	AAD_TLS12_OTHER, // handshake messages, alerts
};

static __always_inline int classify_aad(__u64 ad, __u64 ad_len)
{
	__u8 b[13];
	__builtin_memset(b, 0, sizeof(b));
	if (!ad || ad_len < 2 || ad_len > 128)
		return AAD_NONE;
	if (bpf_probe_read_user(b, ad_len < sizeof(b) ? 2 : sizeof(b), (void *)ad))
		return AAD_NONE;
	if (ad_len == 5 && b[0] >= 0x14 && b[0] <= 0x18 && b[1] == 0x03)
		return AAD_TLS13;
	// A TLS 1.2 record's starts with its sequence number, whose top byte is
	// never set in practice, which a 13-byte QUIC header's first byte always
	// is: the packet number length is in it.
	if (ad_len == 13 && b[0] == 0 && b[9] == 0x03 && b[10] <= 0x04)
		return b[8] == TLS_APPLICATION_DATA ? AAD_TLS12_DATA : AAD_TLS12_OTHER;
	return AAD_QUIC;
}

static __always_inline bool is_quic_aad(__u64 ad, __u64 ad_len)
{
	return classify_aad(ad, ad_len) == AAD_QUIC;
}

static __always_inline bool is_quic_packet(struct pt_regs *ctx)
{
	return is_quic_aad(func_arg(ctx, 8), func_arg(ctx, 9));
}

// The socket a packet being decrypted came in on. If the packet starts a
// receive buffer, as with one packet per datagram decrypted where it was
// received to, the receive into that buffer says; otherwise, the thread's
// last receive. The packet starts with its header, ad, which may have been
// copied elsewhere to remove header protection (Chrome does), but then the
// ciphertext still follows the original.
// A datagram may hold several packets (coalesced during the handshake):
// the ones after the first are decrypted next, from the same buffer.
static __always_inline __s32 packet_fd(__u64 pid_tgid, struct io_thread *rt, __u64 in, __u64 ad, __u64 ad_len)
{
	__u64 start = in - ad_len;
	struct recv_buf *r = recv_buf_at(pid_tgid, start);
	if (!r) {
		start = ad;
		r = recv_buf_at(pid_tgid, start);
	}
	if (!rt)
		return r ? r->fd : -1;
	if (r) {
		rt->dgram_fd = r->fd;
		rt->dgram_start = start;
		rt->dgram_end = start + r->len;
		return r->fd;
	}
	if (rt->dgram_start && in > rt->dgram_start && in < rt->dgram_end)
		return rt->dgram_fd;
	if (rt->last_fd >= 0)
		return rt->last_fd;
	__u32 tgid = pid_tgid >> 32;
	struct quic_proc *qp = bpf_map_lookup_elem(&quic_procs, &tgid);
	return qp ? qp->last_recv_fd : -1;
}

// BoringSSL's and aws-lc's AEAD functions:
// int EVP_AEAD_CTX_seal(const EVP_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
//     size_t max_out_len, const uint8_t *nonce, size_t nonce_len,
//     const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len)
// and EVP_AEAD_CTX_open alike, and
// int EVP_AEAD_CTX_seal_scatter(const EVP_AEAD_CTX *ctx, uint8_t *out,
//     uint8_t *out_tag, size_t *out_tag_len, size_t max_out_tag_len,
//     const uint8_t *nonce, size_t nonce_len, const uint8_t *in, size_t in_len,
//     const uint8_t *extra_in, size_t extra_in_len, const uint8_t *ad, size_t ad_len),
// which aws-lc-rs uses for TLS 1.2. seal doesn't call the exported
// seal_scatter, so the two don't see a record twice.

// seal_enter emits n bytes of the plaintext being sealed, at buf. Sealing
// is often in place, so it's copied at entry. What's sealed goes out with
// the thread's next send, which tells the context's socket.
static __always_inline int seal_enter(__u64 pid_tgid, __u8 fn, __u64 conn, __u64 buf, __s64 n, __u64 ad,
				      __u64 ad_len)
{
	struct io_thread *rt = io_thread(pid_tgid);
	if (rt)
		rt->want_conn = conn;
	struct active_call call;
	__builtin_memset(&call, 0, sizeof(call));
	call.start_ns = bpf_ktime_get_ns();
	call.conn = conn;
	call.buf = buf;
	call.fd = -1;
	call.fn = fn;
	call.ad = ad;
	call.ad_len = ad_len > 0xff ? 0xff : ad_len;
	emit(&call, pid_tgid, n);
	return 0;
}

// open_enter records a call whose plaintext is emitted on return: open
// returns 1 and writes the plaintext's length through out_len.
static __always_inline int open_enter(struct pt_regs *ctx, __u64 pid_tgid, __u8 fn, __u8 ret, bool quic)
{
	struct io_thread *rt = io_thread(pid_tgid);
	__u64 ad = func_arg(ctx, 8), ad_len = func_arg(ctx, 9);
	__s32 fd = packet_fd(pid_tgid, rt, func_arg(ctx, 6), ad, ad_len);
	return enter_call_ad(ctx, fn, ret, func_arg(ctx, 0), (void *)func_arg(ctx, 1), func_arg(ctx, 2), fd,
			     quic ? ad : 0, ad_len);
}

// In Chromium, only QUIC packets: its TLS records are seen at SSL_read and
// SSL_write.
SEC("uprobe/EVP_AEAD_CTX_seal")
int quic_seal_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid) || !is_quic_packet(ctx))
		return 0;
	return seal_enter(pid_tgid, FN_QUIC_SEND, func_arg(ctx, 0), func_arg(ctx, 6), (__s64)func_arg(ctx, 7),
			  func_arg(ctx, 8), func_arg(ctx, 9));
}

SEC("uprobe/EVP_AEAD_CTX_open")
int quic_open_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid) || !is_quic_packet(ctx))
		return 0;
	return open_enter(ctx, pid_tgid, FN_QUIC_RECV, RET_BOOL_EX, true);
}

// In programs whose plaintext has no other place to be seen, like rustls
// under tokio, where the reads are inlined: TLS records' application data
// too. A TLS 1.3 record's real type is at the end of its plaintext.
// record_seal_enter handles a seal of n bytes at in, with associated data
// ad of ad_len bytes, under the encryption context conn: a TLS record, as
// fn, or a QUIC packet, as quic_fn.
static __always_inline int record_seal_enter(__u8 fn, __u8 quic_fn, __u64 conn, __u64 in, __s64 n, __u64 ad,
					     __u64 ad_len)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid))
		return 0;
	switch (classify_aad(ad, ad_len)) {
	case AAD_QUIC:
		note_sealed(pid_tgid, ad, conn); // the packet starts with its header
		return seal_enter(pid_tgid, quic_fn, conn, in, n, ad, ad_len);
	case AAD_TLS13:
		n = tls13_content_len(in, n);
		if (n > 0)
			return seal_enter(pid_tgid, fn, conn, in, n, 0, 0);
		break;
	case AAD_TLS12_DATA:
		return seal_enter(pid_tgid, fn, conn, in, n, 0, 0);
	}
	io_thread(pid_tgid); // so the thread's receives are seen from the handshake on
	return 0;
}

SEC("uprobe/EVP_AEAD_CTX_seal")
int aead_seal_enter(struct pt_regs *ctx)
{
	return record_seal_enter(FN_RECORD_SEND, FN_AWSLC_QUIC_SEND, func_arg(ctx, 0), func_arg(ctx, 6),
				 (__s64)func_arg(ctx, 7),
				 func_arg(ctx, 8), func_arg(ctx, 9));
}

SEC("uprobe/EVP_AEAD_CTX_seal_scatter")
int aead_seal_scatter_enter(struct pt_regs *ctx)
{
	return record_seal_enter(FN_RECORD_SEND, FN_AWSLC_QUIC_SEND, func_arg(ctx, 0), func_arg(ctx, 7),
				 (__s64)func_arg(ctx, 8),
				 func_arg(ctx, 11), func_arg(ctx, 12));
}

SEC("uprobe/EVP_AEAD_CTX_open")
int aead_open_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid))
		return 0;
	switch (classify_aad(func_arg(ctx, 8), func_arg(ctx, 9))) {
	case AAD_QUIC:
		return open_enter(ctx, pid_tgid, FN_AWSLC_QUIC_RECV, RET_BOOL_EX, true);
	case AAD_TLS13:
		return open_enter(ctx, pid_tgid, FN_RECORD_RECV, RET_BOOL_EX_TLS13, false);
	case AAD_TLS12_DATA:
		return open_enter(ctx, pid_tgid, FN_RECORD_RECV, RET_BOOL_EX, false);
	}
	io_thread(pid_tgid);
	return 0;
}

// ring's AEAD functions, which rustls's ring provider calls through
// function pointers in ring::aead::Algorithm (ring 0.17):
// fn aes_gcm_seal(key: &KeyInner, nonce: Nonce, aad: Aad<&[u8]>,
//     in_out: &mut [u8], cpu: cpu::Features) -> Result<Tag, Unspecified>
// fn aes_gcm_open(key: &KeyInner, nonce: Nonce, aad: Aad<&[u8]>,
//     in_out: &mut [u8], src: RangeFrom<usize>, cpu: cpu::Features)
//     -> Result<Tag, Unspecified>
// and chacha20_poly1305_seal and _open alike. Both encrypt and decrypt in
// place: open moves the plaintext of in_out[src..] to the start of in_out.
// It doesn't check the tag, its caller does, so a forged record shows as
// the bytes it decrypts to. The result is too big for registers, so it's
// returned through a hidden pointer, which x86-64 passes as the first
// argument and arm64 in a register of its own. quinn encrypts its QUIC
// packets with them too.
#if defined(__TARGET_ARCH_x86)
#define RING_ARG(i) ((i) + 1)
#elif defined(__TARGET_ARCH_arm64)
#define RING_ARG(i) (i)
#endif

SEC("uprobe/ring_aead_seal")
int ring_seal_enter(struct pt_regs *ctx)
{
	return record_seal_enter(FN_RING_SEND, FN_RING_QUIC_SEND, func_arg(ctx, RING_ARG(0)), func_arg(ctx, RING_ARG(4)),
				 (__s64)func_arg(ctx, RING_ARG(5)), func_arg(ctx, RING_ARG(2)),
				 func_arg(ctx, RING_ARG(3)));
}

// ring_open handles an open of the len bytes at in_out, whose ciphertext
// starts at src.
static __always_inline int ring_open(struct pt_regs *ctx, __u64 in_out, __u64 len, __u64 src)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid))
		return 0;
	__u64 ad = func_arg(ctx, RING_ARG(2)), ad_len = func_arg(ctx, RING_ARG(3));
	__u8 fn = FN_RING_RECV, ret;
	switch (classify_aad(ad, ad_len)) {
	case AAD_QUIC:
		fn = FN_RING_QUIC_RECV;
		ret = RET_KNOWN_LEN;
		break;
	case AAD_TLS13:
		ret = RET_KNOWN_LEN_TLS13;
		break;
	case AAD_TLS12_DATA:
		ret = RET_KNOWN_LEN;
		break;
	default:
		io_thread(pid_tgid);
		return 0;
	}
	if (src > len)
		return 0;
	struct io_thread *rt = io_thread(pid_tgid);
	__s32 fd = packet_fd(pid_tgid, rt, in_out + src, ad, ad_len);
	return enter_call_ad(ctx, fn, ret, func_arg(ctx, RING_ARG(0)), (void *)in_out, len - src, fd,
			     fn == FN_RING_QUIC_RECV ? ad : 0, ad_len);
}

SEC("uprobe/ring_aead_open")
int ring_open_enter(struct pt_regs *ctx)
{
	return ring_open(ctx, func_arg(ctx, RING_ARG(4)), func_arg(ctx, RING_ARG(5)), func_arg(ctx, RING_ARG(6)));
}

// ring 0.16's (rustls 0.20 and early 0.21), in ring::aead::aes_gcm and
// ring::aead::chacha20_poly1305, take the ciphertext's start before in_out,
// and return their Tag the same way:
// fn aes_gcm_open(key: &aead::KeyInner, nonce: Nonce, aad: Aad<&[u8]>,
//     in_prefix_len: usize, in_out: &mut [u8], cpu: cpu::Features) -> Tag
// Their seal functions' arguments are 0.17's.
SEC("uprobe/ring016_aead_open")
int ring016_open_enter(struct pt_regs *ctx)
{
	return ring_open(ctx, func_arg(ctx, RING_ARG(5)), func_arg(ctx, RING_ARG(6)), func_arg(ctx, RING_ARG(4)));
}

// ngtcp2's crypto library (libngtcp2_crypto_ossl and its siblings for other
// TLS libraries), which ngtcp2 programs like curl give ngtcp2 as its packet
// protection callbacks:
// int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
//     const ngtcp2_crypto_aead_ctx *aead_ctx, const uint8_t *plaintext,
//     size_t plaintextlen, const uint8_t *nonce, size_t noncelen,
//     const uint8_t *aad, size_t aadlen)
// and ngtcp2_crypto_decrypt alike, with the ciphertext, which ends with the
// tag, for the plaintext. struct ngtcp2_crypto_aead is the TLS library's
// cipher and its tag size (max_overhead). Both return 0 on success.
#define NGTCP2_AEAD_MAX_OVERHEAD 8

SEC("uprobe/ngtcp2_crypto_encrypt")
int ngtcp2_encrypt_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid) || !is_quic_aad(func_arg(ctx, 7), func_arg(ctx, 8)))
		return 0;
	return seal_enter(pid_tgid, FN_NGTCP2_SEND, func_arg(ctx, 2), func_arg(ctx, 3), (__s64)func_arg(ctx, 4),
			  func_arg(ctx, 7), func_arg(ctx, 8));
}

SEC("uprobe/ngtcp2_crypto_decrypt")
int ngtcp2_decrypt_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 ad = func_arg(ctx, 7), ad_len = func_arg(ctx, 8);
	if (!should_trace(pid_tgid) || !is_quic_aad(ad, ad_len))
		return 0;
	__u64 tag = 0, in = func_arg(ctx, 3), len = func_arg(ctx, 4);
	if (bpf_probe_read_user(&tag, sizeof(tag), (void *)(func_arg(ctx, 1) + NGTCP2_AEAD_MAX_OVERHEAD)) || tag > len)
		return 0;
	struct io_thread *rt = io_thread(pid_tgid);
	__s32 fd = packet_fd(pid_tgid, rt, in, ad, ad_len);
	return enter_call_ad(ctx, FN_NGTCP2_RECV, RET_ZERO_KNOWN_LEN, func_arg(ctx, 2), (void *)func_arg(ctx, 0),
			     len - tag, fd, ad, ad_len);
}

// NSS's freebl, whose AES-GCM Firefox's QUIC stack (neqo) calls directly;
// the functions are found through freebl's exported function table. The
// direction is set when a context is created, so remember it.
// AESContext *AES_CreateContext(const unsigned char *key, const unsigned char *iv,
//     int mode, int encrypt, unsigned int keylen, unsigned int blocklen)
// SECStatus AES_AEAD(AESContext *cx, unsigned char *output, unsigned int *outputLen,
//     unsigned int maxOutputLen, const unsigned char *input, unsigned int inputLen,
//     void *params, unsigned int paramsLen, const unsigned char *aad, unsigned int aadLen)

#define NSS_AES_GCM 4

struct aes_ctx_key {
	__u64 tgid;
	__u64 ctx;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct aes_ctx_key);
	__type(value, __u8); // 1 if it encrypts
} aes_gcm_ctxs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64); // pid_tgid
	__type(value, __u8); // encrypt flag + 1, for a GCM context being created
} aes_creating SEC(".maps");

SEC("uprobe/AES_CreateContext")
int aes_create_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid) || (int)func_arg(ctx, 2) != NSS_AES_GCM)
		return 0;
	__u8 encrypt = (int)func_arg(ctx, 3) ? 2 : 1;
	bpf_map_update_elem(&aes_creating, &pid_tgid, &encrypt, BPF_ANY);
	io_thread(pid_tgid); // so the thread's receives are seen from now on
	return 0;
}

SEC("uretprobe/AES_CreateContext")
int aes_create_return(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u8 *encrypt = bpf_map_lookup_elem(&aes_creating, &pid_tgid);
	if (!encrypt)
		return 0;
	struct aes_ctx_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.tgid = pid_tgid >> 32;
	key.ctx = PT_REGS_RC(ctx);
	__u8 value = *encrypt - 1;
	bpf_map_delete_elem(&aes_creating, &pid_tgid);
	if (key.ctx)
		bpf_map_update_elem(&aes_gcm_ctxs, &key, &value, BPF_ANY);
	return 0;
}

SEC("uprobe/AES_AEAD")
int aes_aead_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	// aadLen is an unsigned int: the rest of its register or stack slot is
	// undefined.
	if (!should_trace(pid_tgid) || !is_quic_aad(func_arg(ctx, 8), (__u32)func_arg(ctx, 9)))
		return 0;
	struct aes_ctx_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.tgid = pid_tgid >> 32;
	key.ctx = func_arg(ctx, 0);
	__u8 *encrypt = bpf_map_lookup_elem(&aes_gcm_ctxs, &key);
	if (!encrypt) { // created before snoopy started: direction unknown
		count(COUNTER_UNTRACKED_QUIC);
		__u32 tgid = pid_tgid >> 32;
		struct quic_traffic *qt = bpf_map_lookup_elem(&quic_traffic, &tgid);
		if (qt)
			__sync_fetch_and_add(&qt->untracked, 1);
		else {
			struct quic_traffic fresh = {.untracked = 1};
			bpf_map_update_elem(&quic_traffic, &tgid, &fresh, BPF_NOEXIST);
		}
		return 0;
	}
	struct io_thread *rt = io_thread(pid_tgid);
	if (!*encrypt) {
		__s32 fd = packet_fd(pid_tgid, rt, func_arg(ctx, 4), func_arg(ctx, 8), (__u32)func_arg(ctx, 9));
		return enter_call_ad(ctx, FN_NSS_QUIC_RECV, RET_SECSTATUS_U32, key.ctx, (void *)func_arg(ctx, 1),
				     func_arg(ctx, 2), fd, func_arg(ctx, 8), (__u32)func_arg(ctx, 9));
	}
	if (rt)
		rt->want_conn = key.ctx;
	// Copy the plaintext now, in case it is encrypted in place.
	struct active_call call;
	__builtin_memset(&call, 0, sizeof(call));
	call.start_ns = bpf_ktime_get_ns();
	call.conn = key.ctx;
	call.buf = func_arg(ctx, 4);
	call.fd = -1;
	call.fn = FN_NSS_QUIC_SEND;
	call.ad = func_arg(ctx, 8);
	call.ad_len = (__u32)func_arg(ctx, 9) > 0xff ? 0xff : (__u32)func_arg(ctx, 9);
	emit(&call, pid_tgid, (__s64)(__u32)func_arg(ctx, 5));
	return 0;
}

// One return probe serves every function above: the entry probe recorded how
// to interpret the return value.
SEC("uretprobe/tls_return")
int tls_return(struct pt_regs *ctx)
{
	return exit_call(ctx);
}

/* Go crypto/tls */

// Go's register ABI (Go 1.17+): integer arguments and results in
// RAX, RBX, RCX, ... on amd64 and R0, R1, R2, ... on arm64. The current
// goroutine's g pointer lives in R14 (amd64) or R28 (arm64).
#if defined(__TARGET_ARCH_x86)
#define GO_ARG1(x) ((x)->ax)
#define GO_ARG2(x) ((x)->bx)
#define GO_RET1(x) ((x)->ax)
#define GO_RET2(x) ((x)->bx)
#define GO_RET4(x) ((x)->di)
#define GO_G(x) ((x)->r14)
#elif defined(__TARGET_ARCH_arm64)
#define GO_ARG1(x) ((x)->user_regs.regs[0])
#define GO_ARG2(x) ((x)->user_regs.regs[1])
#define GO_RET1(x) ((x)->user_regs.regs[0])
#define GO_RET2(x) ((x)->user_regs.regs[1])
#define GO_RET4(x) ((x)->user_regs.regs[3])
#define GO_G(x) ((x)->user_regs.regs[28])
#endif

// Best-effort socket fd of a *tls.Conn whose underlying net.Conn is a
// *net.TCPConn: tls.Conn.conn is the first field, an interface whose data
// word points at a struct starting with *netFD. The layouts have been stable
// since Go 1.12:
//
//	netFD   {pfd poll.FD; family int; sotype int; ...}    (family at 56)
//	poll.FD {fdmu fdMutex (16 bytes); Sysfd int; ...}     (56 bytes)
//
// Checking family and sotype guards against other net.Conn implementations,
// whose memory would otherwise be misread as an fd.
static __always_inline __s32 go_conn_fd(__u64 tls_conn)
{
	__u64 conn = 0, netfd = 0;
	__s64 sysfd = -1, family = 0, sotype = 0;
	if (bpf_probe_read_user(&conn, sizeof(conn), (void *)(tls_conn + 8)) || !conn)
		return -1;
	if (bpf_probe_read_user(&netfd, sizeof(netfd), (void *)conn) || !netfd)
		return -1;
	if (bpf_probe_read_user(&sysfd, sizeof(sysfd), (void *)(netfd + 16)) ||
	    bpf_probe_read_user(&family, sizeof(family), (void *)(netfd + 56)) ||
	    bpf_probe_read_user(&sotype, sizeof(sotype), (void *)(netfd + 64)))
		return -1;
	if ((family != AF_INET && family != AF_INET6) || sotype != 1 /* SOCK_STREAM */)
		return -1;
	if (sysfd < 0 || sysfd > (1 << 20))
		return -1;
	return (__s32)sysfd;
}

static __always_inline int go_enter(struct pt_regs *ctx, __u8 fn)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid))
		return 0;

	struct depth_key dk;
	__builtin_memset(&dk, 0, sizeof(dk));
	dk.thread = pid_tgid >> 32;
	dk.g = GO_G(ctx);
	__u32 depth = get_depth(&dk);

	__u64 conn = GO_ARG1(ctx);
	struct active_call call;
	__builtin_memset(&call, 0, sizeof(call));
	call.start_ns = bpf_ktime_get_ns();
	call.conn = conn;
	call.buf = GO_ARG2(ctx);
	call.fd = go_conn_fd(conn);
	call.fn = fn;

	if (call.fd >= 0) {
		track_conn(pid_tgid, conn, call.fd);
		propagate_fd(pid_tgid, &dk, depth, call.fd);
	}
	push_call(&dk, depth, &call);
	return 0;
}

// Attached to every RET instruction of the function: uretprobes corrupt Go
// stacks, which the runtime moves when they grow. For the same reason the
// stack pointer can't identify the call, so calls are matched by depth.
static __always_inline int go_exit(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct depth_key dk;
	__builtin_memset(&dk, 0, sizeof(dk));
	dk.thread = pid_tgid >> 32;
	dk.g = GO_G(ctx);
	__u32 depth = get_depth(&dk);
	if (!depth)
		return 0;
	set_depth(&dk, depth - 1);

	struct call_key key;
	call_key_at(&key, &dk, depth - 1);
	struct active_call *active = bpf_map_lookup_elem(&active_calls, &key);
	if (!active)
		return 0;
	struct active_call call = *active;
	bpf_map_delete_elem(&active_calls, &key);
	emit(&call, pid_tgid, (__s64)GO_RET1(ctx));
	return 0;
}

// Go's AEADs, in programs that use quic-go, which encrypts and decrypts
// each QUIC packet with them:
// func (g *gcm.GCM) Seal(dst, nonce, plaintext, data []byte) []byte
// func (g *gcm.GCM) Open(dst, nonce, ciphertext, data []byte) ([]byte, error)
// (crypto/internal/fips140/aes/gcm) and ChaCha20-Poly1305's alike. The
// receiver and four slices are thirteen words: on arm64 they're all in
// registers; on amd64, which has nine, the third and fourth slices go on
// the stack, above the return address. The entry probes go after the stack
// check, where the stack pointer is still the entry's.
struct go_aead_args {
	__u64 text, text_len, ad, ad_len;
};

static __always_inline void go_aead_args(struct pt_regs *ctx, struct go_aead_args *a)
{
#if defined(__TARGET_ARCH_x86)
	__u64 stack[5] = {};
	bpf_probe_read_user(stack, sizeof(stack), (void *)(PT_REGS_SP(ctx) + 8));
	a->text = stack[0];
	a->text_len = stack[1];
	a->ad = stack[3];
	a->ad_len = stack[4];
#elif defined(__TARGET_ARCH_arm64)
	a->text = ctx->user_regs.regs[7];
	a->text_len = ctx->user_regs.regs[8];
	a->ad = ctx->user_regs.regs[10];
	a->ad_len = ctx->user_regs.regs[11];
#endif
}

// Go programs use AES-GCM for other things too, so the associated data has
// to look like a QUIC packet's header (RFC 9000, section 17), not just be
// unlike a TLS record's: the fixed bit set, and a long header's version 1
// or 2.
static __always_inline bool go_quic_header(__u64 ad, __u64 ad_len)
{
	__u8 h[5] = {};
	if (classify_aad(ad, ad_len) != AAD_QUIC || ad_len < sizeof(h) ||
	    bpf_probe_read_user(h, sizeof(h), (void *)ad) || !(h[0] & 0x40))
		return false;
	if (!(h[0] & 0x80))
		return true;
	__u32 version = (__u32)h[1] << 24 | (__u32)h[2] << 16 | (__u32)h[3] << 8 | h[4];
	return version == 1 || version == 0x6b3343cf;
}

SEC("uprobe/go_aead_seal")
int go_aead_seal_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid))
		return 0;
	struct go_aead_args a = {};
	go_aead_args(ctx, &a);
	if (!go_quic_header(a.ad, a.ad_len))
		return 0;
	note_sealed(pid_tgid, a.ad, GO_ARG1(ctx)); // the packet starts with its header
	return seal_enter(pid_tgid, FN_GO_QUIC_SEND, GO_ARG1(ctx), a.text, (__s64)a.text_len, a.ad, a.ad_len);
}

// Open's plaintext is its result, read at its RET instructions. It's called
// for TLS records too, from inside (*tls.Conn).Read, whose call is matched
// to its return by depth, so every call is recorded, and only QUIC packets
// emitted (fn 0 isn't).
SEC("uprobe/go_aead_open")
int go_aead_open_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid))
		return 0;
	struct depth_key dk;
	__builtin_memset(&dk, 0, sizeof(dk));
	dk.thread = pid_tgid >> 32;
	dk.g = GO_G(ctx);
	__u32 depth = get_depth(&dk);

	struct go_aead_args a = {};
	go_aead_args(ctx, &a);
	struct active_call call;
	__builtin_memset(&call, 0, sizeof(call));
	call.start_ns = bpf_ktime_get_ns();
	call.conn = GO_ARG1(ctx);
	call.fd = -1;
	if (go_quic_header(a.ad, a.ad_len)) {
		call.fn = FN_GO_QUIC_RECV;
		call.ad = a.ad;
		call.ad_len = a.ad_len > 0xff ? 0xff : a.ad_len;
		call.fd = packet_fd(pid_tgid, io_thread(pid_tgid), a.text, a.ad, a.ad_len);
		if (call.fd >= 0)
			track_conn(pid_tgid, call.conn, call.fd);
	}
	push_call(&dk, depth, &call);
	return 0;
}

SEC("uprobe/go_aead_open_return")
int go_aead_open_return(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct depth_key dk;
	__builtin_memset(&dk, 0, sizeof(dk));
	dk.thread = pid_tgid >> 32;
	dk.g = GO_G(ctx);
	__u32 depth = get_depth(&dk);
	if (!depth)
		return 0;
	set_depth(&dk, depth - 1);

	struct call_key key;
	call_key_at(&key, &dk, depth - 1);
	struct active_call *active = bpf_map_lookup_elem(&active_calls, &key);
	if (!active)
		return 0;
	struct active_call call = *active;
	bpf_map_delete_elem(&active_calls, &key);
	if (!call.fn || GO_RET4(ctx)) // not a QUIC packet, or it didn't authenticate
		return 0;
	call.buf = GO_RET1(ctx);
	emit(&call, pid_tgid, (__s64)GO_RET2(ctx));
	return 0;
}

// func (c *tls.Conn) Read(b []byte) (int, error) and Write alike.
SEC("uprobe/go_tls_read")
int go_tls_read_enter(struct pt_regs *ctx)
{
	return go_enter(ctx, FN_GO_READ);
}

SEC("uprobe/go_tls_write")
int go_tls_write_enter(struct pt_regs *ctx)
{
	return go_enter(ctx, FN_GO_WRITE);
}

SEC("uprobe/go_tls_return")
int go_tls_return(struct pt_regs *ctx)
{
	return go_exit(ctx);
}
