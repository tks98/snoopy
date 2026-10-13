/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * A minimal, hand-written subset of the kernel types snoopy's BPF program
 * needs. Using this instead of a full bpftool-generated vmlinux.h keeps the
 * repository small and lets `go generate` run without kernel headers.
 *
 * Types marked with preserve_access_index are relocated against the running
 * kernel's BTF when the program is loaded (CO-RE), so they only need the
 * fields snoopy reads, in any order. The others are fixed ABI.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef _Bool bool;
enum {
	false = 0,
	true = 1,
};

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
};

/* uprobe context. The layout is the kernel's, which is fixed ABI. */
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
struct pt_regs {
	struct user_pt_regs user_regs;
	__u64 orig_x0;
};
#else
#error "snoopy only supports x86_64 and arm64"
#endif

/* Context of raw tracepoints: the tracepoint's arguments. */
struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

/* Just enough to get from the current task to its process name and to a
 * socket's addresses. */
typedef unsigned short umode_t;

struct in6_addr {
	__u8 s6_addr[16];
};

struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct socket {
	struct sock *sk;
} __attribute__((preserve_access_index));

struct inode {
	umode_t i_mode;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
	void *private_data;
} __attribute__((preserve_access_index));

struct fdtable {
	unsigned int max_fds;
	struct file **fd;
} __attribute__((preserve_access_index));

struct files_struct {
	struct fdtable *fdt;
} __attribute__((preserve_access_index));

struct task_struct {
	struct files_struct *files;
	struct task_struct *group_leader;
	char comm[16];
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */
