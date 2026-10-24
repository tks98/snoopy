#!/bin/bash
# Measures what snoopy costs the programs it traces, and those it doesn't:
# requests per second and latency of HTTPS servers under load, without
# snoopy and with it in several modes. docs/performance.md has the results.
#
# Run it as root on Ubuntu with snoopy on PATH, Go, and wrk and nginx
# installed, on a machine with at least 6 CPUs:
#
#   sudo apt-get install wrk nginx
#   sudo docs/benchmark/run.sh [seconds per run]
#
# MODES picks some of the modes (off quiet text untraced), e.g. MODES=text.
#
# The server, wrk and snoopy each get their own two CPUs (taskset), so the
# numbers show the cost the traced program pays, in its own threads (a
# uprobe stops the thread that hits it), apart from snoopy's own CPU use,
# which is reported on its own. wrk uses OpenSSL too, and snoopy attaches
# to the system's libssl whatever --comm says, so wrk gets a copy of its
# own, which isn't probed: uprobes are per file.
set -euo pipefail

secs=${1:-10}
runs=3
for tool in snoopy wrk nginx go taskset; do
	command -v $tool >/dev/null || { echo "needs $tool on PATH" >&2; exit 1; }
done
[ "$(nproc)" -ge 6 ] || { echo "needs 6 CPUs" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
cleanup() {
	pkill -f "nginx -c $tmp" 2>/dev/null || true
	pkill -f "$tmp/server" 2>/dev/null || true
	pkill -x snoopy 2>/dev/null || true
	rm -rf "$tmp"
}
trap cleanup EXIT

(cd "$here/server" && go build -o "$tmp/server" .)
mkdir "$tmp/wrklib"
cp "$(ldd "$(command -v wrk)" | awk '/libssl/ { print $3 }')" "$tmp/wrklib/"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost \
	-keyout "$tmp/key.pem" -out "$tmp/cert.pem" 2>/dev/null
head -c 1024 /dev/zero | tr '\0' a > "$tmp/1k"
head -c 262144 /dev/zero | tr '\0' a > "$tmp/256k"
chmod 755 "$tmp" && chmod 644 "$tmp"/1k "$tmp"/256k # nginx's workers aren't root
cat > "$tmp/nginx.conf" <<NGINX
worker_processes 2;
pid $tmp/nginx.pid;
error_log $tmp/error.log;
events { worker_connections 1024; }
http {
	access_log off;
	server {
		listen 127.0.0.1:8080;
		listen 127.0.0.1:8444 ssl;
		ssl_certificate $tmp/cert.pem;
		ssl_certificate_key $tmp/key.pem;
		root $tmp;
	}
}
NGINX

# One wrk run: prints requests/s, p50 and p99 latency in µs. Any response
# that isn't a success means the setup is broken, and the numbers wrong.
load() {
	LD_LIBRARY_PATH=$tmp/wrklib taskset -c 2,3 wrk -t2 -c32 -d"${secs}s" --latency "$1" 2>/dev/null > "$tmp/wrk"
	if grep -q "Non-2xx" "$tmp/wrk"; then
		echo "$1: $(grep Non-2xx "$tmp/wrk")" >&2
		exit 1
	fi
	awk '
		/Requests\/sec/ { rps = $2 }
		/^ +50%/ { p50 = $2 } /^ +99%/ { p99 = $2 }
		function us(v) { if (v ~ /us$/) return v + 0; if (v ~ /ms$/) return v * 1000; if (v ~ /s$/) return v * 1e6; return v }
		END { printf "%d %d %d\n", rps, us(p50), us(p99) }' "$tmp/wrk"
}

# snoopy's CPU time in seconds, from /proc.
cpu() { awk '{ printf "%.2f", ($14 + $15) / 100 }' "/proc/$1/stat"; }

# measure NAME URL COMM: each mode, the median of $runs runs.
measure() {
	local name=$1 url=$2 comm=$3
	for mode in ${MODES:-off quiet text untraced}; do
		local sn="" args=()
		case $mode in
		quiet) args=(--comm "$comm" --quiet) ;;
		text) args=(--comm "$comm" --no-color) ;;
		untraced) args=(--comm nomatch --quiet) ;;
		esac
		if [ $mode != off ]; then
			# Text output is formatted in full but not kept: at these rates
			# it would fill a disk in seconds.
			taskset -c 4,5 snoopy "${args[@]}" > /dev/null 2> "$tmp/err" &
			sn=$!
			until grep -qs tracing "$tmp/err"; do
				kill -0 $sn 2>/dev/null || { cat "$tmp/err" >&2; exit 1; }
				sleep 0.2
			done
		fi
		load "$url" > /dev/null # warm up, and attach to what's new
		local before=0
		[ -n "$sn" ] && before=$(cpu $sn)
		for _ in $(seq $runs); do load "$url"; done | sort -n | sed -n "$(( (runs + 1) / 2 ))p" > "$tmp/median"
		local snoopycpu=- lost=-
		if [ -n "$sn" ]; then
			snoopycpu=$(awk -v a="$before" -v b="$(cpu $sn)" -v t=$((runs * secs)) 'BEGIN { printf "%.0f%%", (b - a) / t * 100 }')
			kill -INT $sn
			wait $sn 2>/dev/null || true
			# Chunks the ring buffer had no room for, which snoopy warns about.
			lost=$(grep -oE '[0-9]+ chunks dropped' "$tmp/err" | tail -1 | cut -d' ' -f1 || true)
			lost=${lost:-0}
		fi
		read -r rps p50 p99 < "$tmp/median"
		printf "%-22s %-9s %9s %8s %8s %8s %10s\n" "$name" "$mode" "$rps" "$p50" "$p99" "$snoopycpu" "$lost"
	done
}

taskset -c 0,1 nginx -c "$tmp/nginx.conf"
taskset -c 0,1 "$tmp/server" -addr 127.0.0.1:8443 -size 1024 2>/dev/null & # it logs wrk closing connections mid-handshake
sleep 1
printf "%-22s %-9s %9s %8s %8s %8s %10s\n" workload mode "req/s" "p50 µs" "p99 µs" "snoopy" "lost"
measure "nginx HTTPS 1 KiB" https://127.0.0.1:8444/1k nginx
measure "nginx HTTPS 256 KiB" https://127.0.0.1:8444/256k nginx
measure "Go HTTPS 1 KiB" https://127.0.0.1:8443/ server
measure "nginx HTTP 1 KiB" http://127.0.0.1:8080/1k nginx
