#!/bin/bash
# Loads snoopy's BPF programs under each kernel fetch.sh has downloaded, and
# each vimto has (`make integration-vm KERNEL=...`), booting each in QEMU with
# loadcheck as init. Catches what the verifier of an older kernel
# rejects, and works where vimto doesn't (its 5.10 runs fail on an overlayfs
# xattr). Needs qemu-system for this machine's architecture, and cpio.
set -euo pipefail

cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
CGO_ENABLED=0 go build -o "$tmp/init" ./tools/loadcheck
(cd "$tmp" && echo init | cpio -o -H newc 2>/dev/null | gzip > initrd.gz)

case $(uname -m) in
x86_64) qemu=(qemu-system-x86_64 -machine q35 -cpu max) console=ttyS0 ;;
aarch64) qemu=(qemu-system-aarch64 -machine virt -cpu max) console=ttyAMA0 ;;
*) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
[ -e /dev/kvm ] && qemu+=(-enable-kvm)

failed=0
shopt -s nullglob
kernels=("${KERNEL_DIR:-$HOME/.cache/snoopy-kernels}"/*/vmlinuz "$HOME"/.cache/vimto/*/contents/boot/vmlinuz)
if [ ${#kernels[@]} -eq 0 ]; then
	echo "no kernels; download some with tools/loadcheck/fetch.sh 5.10 6.1 ..." >&2
	exit 1
fi
for kernel in "${kernels[@]}"; do
	# QEMU reads stdin with -nographic, so it gets /dev/null.
	out=$(timeout 600 "${qemu[@]}" -m 1G -smp 1 -nographic -no-reboot -kernel "$kernel" \
		-initrd "$tmp/initrd.gz" -append "console=$console panic=-1 quiet" < /dev/null 2>&1 || true)
	if ! grep -a LOADCHECK <<< "$out" | cut -c1-300; then
		echo "$kernel: no output" && tail -5 <<< "$out"
		failed=1
	fi
	grep -aq FAILED <<< "$out" && failed=1
done
exit $failed
