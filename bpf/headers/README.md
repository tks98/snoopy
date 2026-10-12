# BPF headers

- `bpf_helpers.h`, `bpf_helper_defs.h`, `bpf_tracing.h`, `bpf_core_read.h`:
  copied unmodified from [libbpf](https://github.com/libbpf/libbpf) v1.3.0
  (`src/`), licensed `LGPL-2.1 OR BSD-2-Clause`.
- `vmlinux.h`: a hand-written subset of the kernel types snoopy needs,
  instead of a multi-megabyte bpftool-generated one. Fields of types marked
  `preserve_access_index` are relocated against the running kernel's BTF at
  load time, so only the fields snoopy reads need to be declared.
