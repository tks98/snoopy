package tracer

// Compiles bpf/snoopy.c into BPF objects for amd64 and arm64 and generates Go
// bindings for them. The generated files are committed, so building snoopy
// only needs a Go toolchain; regenerating needs clang and llvm-strip.
//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type event_header snoopy ../../bpf/snoopy.c -- -I../../bpf/headers -O2 -g -Wall -Werror -mcpu=v3
