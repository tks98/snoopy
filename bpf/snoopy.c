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

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define CHUNK_SIZE 16384 // one maximum-size TLS record
#define MAX_CHUNKS 64	 // CHUNK_SIZE * MAX_CHUNKS = 1 MiB per call

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
};

// How to interpret a function's return value.
enum ret_kind {
	RET_INT,     // int: bytes transferred, <= 0 on error
	RET_SSIZE,   // ssize_t: bytes transferred, < 0 on error
	RET_BOOL_EX, // 1 on success, byte count written through a size_t*
};

#define EVENT_FLAG_READ_ERROR 1 // the payload could not be copied

struct event {
	__u64 timestamp_ns; // CLOCK_MONOTONIC when the call returned
	__u64 latency_ns;   // time spent inside the call
	__u64 conn_id;	    // SSL*, gnutls_session_t, PRFileDesc* or *tls.Conn
	__u32 pid;
	__u32 tid;
	__u32 size;	    // bytes transferred by the call
	__u32 captured;	    // bytes captured for the call (<= size)
	__u32 chunk_offset; // offset of data[] within the captured bytes
	__u32 chunk_len;    // valid bytes in data[]
	__s32 fd;	    // socket fd, or -1 if unknown
	__u16 family;	    // AF_INET, AF_INET6, or 0 if the addresses are unknown
	__u16 lport;
	__u16 rport;
	__u8 fn;	    // enum fn_id
	__u8 flags;
	__u8 laddr[16];	    // IPv4 addresses use the first 4 bytes
	__u8 raddr[16];
	char comm[TASK_COMM_LEN];
	__u8 data[CHUNK_SIZE];
};

// Configuration, set from user space before the program is loaded.
const volatile __u32 targ_tgid = 0;
const volatile __u32 max_capture = CHUNK_SIZE;
const volatile bool filter_comm = false;
const volatile char targ_comm[TASK_COMM_LEN] = {};
// Off on kernels without BTF, where the CO-RE socket lookup can't be relocated.
const volatile bool resolve_addrs = false;

struct active_call {
	__u64 start_ns;
	__u64 conn;
	__u64 buf;
	__u64 len_ptr; // SSL_*_ex: where the byte count is written
	__s32 fd;
	__u8 fn;
	__u8 ret;      // enum ret_kind
};

// In-flight C library calls, keyed by pid_tgid.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct active_call);
} active_calls SEC(".maps");

// Goroutines can move between threads while blocked inside a call, so Go
// calls are keyed by the goroutine's g pointer instead of the thread.
struct go_key {
	__u64 tgid;
	__u64 g;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct go_key);
	__type(value, struct active_call);
} go_active_calls SEC(".maps");

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
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct conn_info);
} conn_infos SEC(".maps");

// Scratch space for building events; too large for the BPF stack.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 << 20); // resized from user space
} events SEC(".maps");

// Chunks that could not be written because the ring buffer was full.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost_events SEC(".maps");

// Force bpf2go to emit a Go type for struct event.
const struct event *unused_event __attribute__((unused));

static __always_inline bool should_trace(__u64 pid_tgid)
{
	if (targ_tgid && (__u32)(pid_tgid >> 32) != targ_tgid)
		return false;

	if (filter_comm) {
		char comm[TASK_COMM_LEN];
		bpf_get_current_comm(comm, sizeof(comm));
		for (int i = 0; i < TASK_COMM_LEN; i++) {
			if (comm[i] != targ_comm[i])
				return false;
			if (comm[i] == 0)
				break;
		}
	}
	return true;
}

static __always_inline void count_lost(void)
{
	__u32 zero = 0;
	__u64 *lost = bpf_map_lookup_elem(&lost_events, &zero);
	if (lost)
		*lost += 1;
}

#define AF_INET 2
#define AF_INET6 10
#define S_IFMT 0170000
#define S_IFSOCK 0140000

// Fills in the addresses of the current task's socket fd, if it is a TCP/IP
// socket: current->files->fdt->fd[fd]->private_data is its struct socket.
static __always_inline void resolve_socket(__s32 fd, struct conn_info *info)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt || fd < 0 || (unsigned int)fd >= BPF_CORE_READ(fdt, max_fds))
		return;

	struct file **fds = BPF_CORE_READ(fdt, fd);
	struct file *file = NULL;
	if (bpf_core_read(&file, sizeof(file), &fds[fd]) || !file)
		return;
	if ((BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT) != S_IFSOCK)
		return;

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

// Records the socket a TLS connection is using.
static __always_inline void track_conn(__u64 pid_tgid, __u64 conn, __s32 fd)
{
	if (!conn || fd < 0)
		return;

	struct conn_key key = { .tgid = pid_tgid >> 32, .conn = conn };
	struct conn_info info = { .fd = fd };
	if (resolve_addrs)
		resolve_socket(fd, &info);

	// Once a socket is closed (e.g. reset by the peer), the kernel releases
	// its port and skc_num reads 0, yet buffered data can still be read.
	// Keep what we learned while it was open.
	struct conn_info *known = bpf_map_lookup_elem(&conn_infos, &key);
	if (known && known->fd == fd && known->family && (!info.family || !info.lport || !info.rport))
		return;
	bpf_map_update_elem(&conn_infos, &key, &info, BPF_ANY);
}

static __always_inline void emit(struct active_call *call, __u64 pid_tgid, __s64 n)
{
	if (n <= 0)
		return;

	__u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&scratch, &zero);
	if (!e)
		return;

	__u64 now = bpf_ktime_get_ns();
	e->timestamp_ns = now;
	e->latency_ns = now - call->start_ns;
	e->conn_id = call->conn;
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->size = n > 0xffffffff ? 0xffffffff : (__u32)n;
	e->fn = call->fn;
	e->flags = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	e->fd = call->fd;
	e->family = 0;
	struct conn_key key = { .tgid = pid_tgid >> 32, .conn = call->conn };
	struct conn_info *info = bpf_map_lookup_elem(&conn_infos, &key);
	if (info && (e->fd < 0 || e->fd == info->fd)) {
		e->fd = info->fd;
		e->family = info->family;
		e->lport = info->lport;
		e->rport = info->rport;
		__builtin_memcpy(e->laddr, info->laddr, sizeof(e->laddr));
		__builtin_memcpy(e->raddr, info->raddr, sizeof(e->raddr));
	}

	__u32 captured = e->size < max_capture ? e->size : max_capture;
	e->captured = captured;

	for (__u32 i = 0; i < MAX_CHUNKS; i++) {
		__u32 off = i * CHUNK_SIZE;
		if (off >= captured)
			break;

		__u32 len = captured - off;
		if (len > CHUNK_SIZE)
			len = CHUNK_SIZE;

		e->chunk_offset = off;
		e->chunk_len = len;
		if (bpf_probe_read_user(e->data, len, (void *)(call->buf + off))) {
			e->flags |= EVENT_FLAG_READ_ERROR;
			e->chunk_len = 0;
			len = 0;
		}

		if (bpf_ringbuf_output(&events, e, __builtin_offsetof(struct event, data) + len, 0)) {
			count_lost();
			break;
		}
		if (e->flags & EVENT_FLAG_READ_ERROR)
			break;
	}
}

/* C libraries (OpenSSL, GnuTLS, NSS) */

static __always_inline int enter_call(__u8 fn, __u8 ret, __u64 conn, const void *buf, __u64 len_ptr)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!should_trace(pid_tgid))
		return 0;

	struct active_call call = {
		.start_ns = bpf_ktime_get_ns(),
		.conn = conn,
		.buf = (__u64)buf,
		.len_ptr = len_ptr,
		.fd = -1,
		.fn = fn,
		.ret = ret,
	};
	bpf_map_update_elem(&active_calls, &pid_tgid, &call, BPF_ANY);
	return 0;
}

static __always_inline int exit_call(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct active_call *active = bpf_map_lookup_elem(&active_calls, &pid_tgid);
	if (!active)
		return 0;

	struct active_call call = *active;
	bpf_map_delete_elem(&active_calls, &pid_tgid);

	__s64 n;
	switch (call.ret) {
	case RET_INT:
		n = (int)PT_REGS_RC(ctx);
		break;
	case RET_SSIZE:
		n = (long)PT_REGS_RC(ctx);
		break;
	default: {
		__u64 len = 0;
		if ((int)PT_REGS_RC(ctx) != 1 || !call.len_ptr ||
		    bpf_probe_read_user(&len, sizeof(len), (void *)call.len_ptr))
			return 0;
		n = len;
	}
	}

	emit(&call, pid_tgid, n);
	return 0;
}

// Remember which fd a TLS call is doing I/O on.
static __always_inline int record_fd(__u64 fd)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct active_call *call = bpf_map_lookup_elem(&active_calls, &pid_tgid);
	if (!call)
		return 0;

	call->fd = (__s32)fd;
	track_conn(pid_tgid, call->conn, call->fd);
	return 0;
}

// Syscalls a TLS library may use to move data over its socket. They all take
// the file descriptor as their first argument.
#if defined(__TARGET_ARCH_x86)
#define SYSCALL_FD(regs) ((regs)->di)
#define IS_SOCKET_IO_SYSCALL(id)                                              \
	((id) == 0 /* read */ || (id) == 1 /* write */ ||                     \
	 (id) == 19 /* readv */ || (id) == 20 /* writev */ ||                 \
	 (id) == 44 /* sendto */ || (id) == 45 /* recvfrom */ ||              \
	 (id) == 46 /* sendmsg */ || (id) == 47 /* recvmsg */)
#elif defined(__TARGET_ARCH_arm64)
#define SYSCALL_FD(regs) ((regs)->orig_x0)
#define IS_SOCKET_IO_SYSCALL(id)                                              \
	((id) == 63 /* read */ || (id) == 64 /* write */ ||                   \
	 (id) == 65 /* readv */ || (id) == 66 /* writev */ ||                 \
	 (id) == 206 /* sendto */ || (id) == 207 /* recvfrom */ ||            \
	 (id) == 211 /* sendmsg */ || (id) == 212 /* recvmsg */)
#endif

// raw_syscalls:sys_enter(struct pt_regs *regs, long id). A raw tracepoint
// needs neither tracefs nor BTF, unlike the per-syscall tracepoints.
SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	long id = (long)ctx->args[1];
	if (!IS_SOCKET_IO_SYSCALL(id))
		return 0;

	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	__u64 fd = 0;
	if (bpf_probe_read_kernel(&fd, sizeof(fd), &SYSCALL_FD(regs)))
		return 0;
	return record_fd(fd);
}

// OpenSSL, BoringSSL and LibreSSL.
// int SSL_read(SSL *ssl, void *buf, int num) and SSL_write alike.
// int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) and SSL_write_ex alike.

SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_enter, void *ssl, void *buf)
{
	return enter_call(FN_SSL_READ, RET_INT, (__u64)ssl, buf, 0);
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_enter, void *ssl, const void *buf)
{
	return enter_call(FN_SSL_WRITE, RET_INT, (__u64)ssl, buf, 0);
}

SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_read_ex_enter, void *ssl, void *buf, __u64 num, __u64 *readbytes)
{
	return enter_call(FN_SSL_READ_EX, RET_BOOL_EX, (__u64)ssl, buf, (__u64)readbytes);
}

SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_write_ex_enter, void *ssl, const void *buf, __u64 num, __u64 *written)
{
	return enter_call(FN_SSL_WRITE_EX, RET_BOOL_EX, (__u64)ssl, buf, (__u64)written);
}

// GnuTLS.
// ssize_t gnutls_record_recv(gnutls_session_t session, void *data, size_t data_size) and _send alike.

SEC("uprobe/gnutls_record_recv")
int BPF_UPROBE(gnutls_record_recv_enter, void *session, void *data)
{
	return enter_call(FN_GNUTLS_RECORD_RECV, RET_SSIZE, (__u64)session, data, 0);
}

SEC("uprobe/gnutls_record_send")
int BPF_UPROBE(gnutls_record_send_enter, void *session, const void *data)
{
	return enter_call(FN_GNUTLS_RECORD_SEND, RET_SSIZE, (__u64)session, data, 0);
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
		return enter_call(fn, RET_INT, (__u64)fd, buf, 0);            \
	}

NSPR_PROBE(PR_Read, FN_PR_READ)
NSPR_PROBE(PR_Write, FN_PR_WRITE)
NSPR_PROBE(PR_Recv, FN_PR_RECV)
NSPR_PROBE(PR_Send, FN_PR_SEND)

// One return probe serves every C function: the entry probe recorded how
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
#define GO_G(x) ((x)->r14)
#elif defined(__TARGET_ARCH_arm64)
#define GO_ARG1(x) ((x)->user_regs.regs[0])
#define GO_ARG2(x) ((x)->user_regs.regs[1])
#define GO_RET1(x) ((x)->user_regs.regs[0])
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

	struct go_key key = { .tgid = pid_tgid >> 32, .g = GO_G(ctx) };
	__u64 conn = GO_ARG1(ctx);
	struct active_call call = {
		.start_ns = bpf_ktime_get_ns(),
		.conn = conn,
		.buf = GO_ARG2(ctx),
		.fd = go_conn_fd(conn),
		.fn = fn,
	};
	track_conn(pid_tgid, conn, call.fd);
	bpf_map_update_elem(&go_active_calls, &key, &call, BPF_ANY);
	return 0;
}

// Attached to every RET instruction of the function: uretprobes corrupt Go
// stacks, which the runtime moves when they grow.
static __always_inline int go_exit(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct go_key key = { .tgid = pid_tgid >> 32, .g = GO_G(ctx) };
	struct active_call *active = bpf_map_lookup_elem(&go_active_calls, &key);
	if (!active)
		return 0;

	struct active_call call = *active;
	bpf_map_delete_elem(&go_active_calls, &key);
	emit(&call, pid_tgid, (__s64)GO_RET1(ctx));
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
