#!/bin/bash
# Downloads kernels for run.sh from Cilium's CI kernel images
# (ghcr.io/cilium/ci-kernels), with Docker, into $KERNEL_DIR (by default
# ~/.cache/snoopy-kernels), one directory per version:
#
#   tools/loadcheck/fetch.sh 5.10 5.15 6.1 6.6 6.12
set -euo pipefail

dir=${KERNEL_DIR:-$HOME/.cache/snoopy-kernels}
case $(uname -m) in
x86_64) platform=linux/amd64 ;;
aarch64) platform=linux/arm64 ;;
*) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
for v in "$@"; do
	mkdir -p "$dir/$v"
	[ -s "$dir/$v/vmlinuz" ] && continue
	# The images have no command; one is needed to create a container.
	c=$(docker create --platform "$platform" "ghcr.io/cilium/ci-kernels:$v" /none)
	docker cp "$c:/boot/vmlinuz" "$dir/$v/vmlinuz"
	docker rm "$c" >/dev/null
	echo "$v: $dir/$v/vmlinuz"
done
