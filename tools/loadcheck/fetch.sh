#!/bin/bash
# Downloads kernels for run.sh from Cilium's CI kernel images
# (ghcr.io/cilium/ci-kernels), with Docker, into $KERNEL_DIR (by default
# ~/.cache/snoopy-kernels), one directory per version:
#
#   tools/loadcheck/fetch.sh 5.10 5.15 6.1 6.6 6.12
#
# The images' tags move to each version's latest patch release, so each is
# pulled by the digest of the image (for both architectures) it had when
# pinned here. To move one on, take its digest from
#
#   docker buildx imagetools inspect ghcr.io/cilium/ci-kernels:6.12
set -euo pipefail

declare -A digest=(
	[5.10]=sha256:38f4199b35356d64c7fb23d12e7c1dd66e985ef908c7d2c0233443c18c802ab6
	[5.15]=sha256:7d9a08c9fc1d74fce394755475fd32e1b38867895596091619eefe89da5061e9
	[6.1]=sha256:680483dda002764070c24871dd2ec4a9bb8cd4cef1d08fcedc76f28dab826f18
	[6.6]=sha256:9b76ec0da53cad94789ee62b0a77e4ea01a85e9e7dea42917864112253b796bd
	[6.12]=sha256:5e49f3eb0d9ac7c8ba2b973b84c30dfe32ad7021ea7bf6a1c1a7a80244c6ed40
)
dir=${KERNEL_DIR:-$HOME/.cache/snoopy-kernels}
case $(uname -m) in
x86_64) platform=linux/amd64 ;;
aarch64) platform=linux/arm64 ;;
*) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
for v in "$@"; do
	if [ -z "${digest[$v]:-}" ]; then
		echo "no digest for kernel $v; add one to $0" >&2
		exit 1
	fi
	mkdir -p "$dir/$v"
	[ -s "$dir/$v/vmlinuz" ] && continue
	# The images have no command; one is needed to create a container.
	c=$(docker create --platform "$platform" "ghcr.io/cilium/ci-kernels:$v@${digest[$v]}" /none)
	docker cp "$c:/boot/vmlinuz" "$dir/$v/vmlinuz"
	docker rm "$c" >/dev/null
	echo "$v: $dir/$v/vmlinuz"
done
