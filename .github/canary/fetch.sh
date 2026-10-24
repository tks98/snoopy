#!/bin/bash
# Downloads the latest release of a program snoopy finds by signature, with
# its symbols, for the canary workflow (.github/workflows/canary.yml), and
# prints the path=symbols spec that TestBoringSSLBinaries (SNOOPY_BORINGSSL_TEST)
# or TestFreeblBinaries (SNOOPY_FREEBL_TEST) take. Or makes a Fedora root
# filesystem with an HTTP/3 curl, for TestCurlHTTP3, and prints its path.
#
#   fetch.sh chrome stable|beta <dir>
#   fetch.sh electron x64|arm64 <dir>
#   fetch.sh firefox linux64|linux64-aarch64 <dir>
#   fetch.sh fedora <dir>        (as root, with Docker)
#
# Progress goes to stderr. When a release's symbols aren't published (yet),
# the spec has none, so the test only checks that the finder gives one
# answer, and a warning says so.
set -euo pipefail

what=$1 variant=${2:-} dir=${3:-${2:-}}
mkdir -p "$dir"
cd "$dir"
log() { echo "fetch.sh: $*" >&2; }
warn() { echo "::warning::$*" >&2; }

case $what in
chrome)
	version=$(curl -fsS "https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/$variant/versions" |
		python3 -c 'import json, sys; print(json.load(sys.stdin)["versions"][0]["version"])')
	log "Chrome $variant $version"
	curl -fsSL -o chrome.deb "https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-$variant/google-chrome-${variant}_${version}-1_amd64.deb"
	dpkg-deb -x chrome.deb pkg
	rm chrome.deb
	binary=$(find "$PWD/pkg/opt/google" -name chrome -type f | head -1)
	if curl -fsSL -o debug.zip "https://edgedl.me.gvt1.com/chrome/linux/symbols/google-chrome-debug-info-linux64-$version.zip"; then
		unzip -q -p debug.zip 'debug-info/chrome.debug' 'chrome.debug' > chrome.debug 2>/dev/null || true
		[ -s chrome.debug ] || { echo '::error::no chrome.debug in the debug-info zip' >&2; exit 1; }
		rm debug.zip
		echo "$binary=$PWD/chrome.debug"
	else
		warn "no debug symbols for Chrome $version yet; only checking that one answer is found"
		echo "$binary"
	fi
	;;
electron)
	auth=()
	if [ -n "${GH_TOKEN:-}" ]; then
		auth=(-H "Authorization: Bearer $GH_TOKEN") # CI's runners share an unauthenticated rate limit
	fi
	tag=$(curl -fsS "${auth[@]}" https://api.github.com/repos/electron/electron/releases/latest |
		python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])')
	log "Electron $tag $variant"
	base="https://github.com/electron/electron/releases/download/$tag/electron-$tag-linux-$variant"
	curl -fsSL -o electron.zip "$base.zip"
	unzip -q electron.zip electron
	rm electron.zip
	if curl -fsSL -o symbols.zip "$base-symbols.zip"; then
		# Only the lines the test needs: the file is hundreds of megabytes.
		unzip -p symbols.zip 'breakpad_symbols/electron/*/electron.sym' |
			grep -E '^(MODULE|FUNC (m )?[0-9a-f]+ [0-9a-f]+ [0-9a-f]+ (SSL_read|SSL_write|EVP_AEAD_CTX_seal|EVP_AEAD_CTX_open)$)' > electron.sym
		rm symbols.zip
		echo "$PWD/electron=$PWD/electron.sym"
	else
		warn "no symbols for Electron $tag $variant; only checking that one answer is found"
		echo "$PWD/electron"
	fi
	;;
firefox)
	curl -fsSL -o firefox.tar "https://download.mozilla.org/?product=firefox-latest-ssl&os=$variant&lang=en-US"
	tar -xf firefox.tar firefox/libfreeblpriv3.so firefox/application.ini
	rm firefox.tar
	log "Firefox $(grep -m1 '^Version=' firefox/application.ini | cut -d= -f2) $variant"
	lib=$PWD/firefox/libfreeblpriv3.so
	# Mozilla's symbol server knows a library by its Breakpad ID: the build
	# ID's first 16 bytes as a GUID, upper case, and a 0.
	id=$(readelf -n "$lib" | awk '/Build ID/ {print $3}')
	bid=$(python3 -c 'import sys; b = bytes.fromhex(sys.argv[1])[:16]; print((b[3::-1] + b[5:3:-1] + b[7:5:-1] + b[8:]).hex().upper() + "0")' "$id")
	if curl -fsSL -o freebl.sym "https://symbols.mozilla.org/libfreeblpriv3.so/$bid/libfreeblpriv3.so.sym"; then
		if gzip -t freebl.sym 2>/dev/null; then
			mv freebl.sym freebl.sym.gz && gunzip freebl.sym.gz
		fi
		echo "$lib=$PWD/freebl.sym"
	else
		warn "no symbols for this Firefox's freebl; only checking that one answer is found"
		echo "$lib"
	fi
	;;
fedora)
	root=$PWD/root
	container=$(docker create registry.fedoraproject.org/fedora:latest)
	mkdir -p "$root"
	docker export "$container" | tar -C "$root" -xf -
	docker rm "$container" > /dev/null
	cp /etc/resolv.conf "$root/etc/resolv.conf"
	mount -t proc proc "$root/proc"
	mount --bind /dev "$root/dev"
	chroot "$root" dnf -y -q install curl >&2
	chroot "$root" curl -V | head -1 >&2
	if ! chroot "$root" curl -V | grep -q HTTP3; then
		echo "::error::Fedora's curl has no HTTP/3 any more" >&2
		exit 1
	fi
	echo "$root"
	;;
*)
	echo "usage: fetch.sh chrome|electron|firefox|fedora ..." >&2
	exit 2
	;;
esac
