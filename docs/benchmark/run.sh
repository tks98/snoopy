#!/bin/bash
# Measures what snoopy costs the programs it traces, and those it doesn't:
# requests per second and latency of HTTPS servers under load, without
# snoopy and with it in several modes. docs/performance.md has the results.
#
# Run it as root on Ubuntu with snoopy on PATH, Go, and wrk and nginx
# installed, on a machine with at least 4 CPUs (6 or more are better):
#
#   sudo apt-get install wrk nginx
#   sudo docs/benchmark/run.sh [seconds per run]
#
# MODES picks some of the modes (off quiet text json brief untraced), e.g.
# MODES="off text".
#
# The server, wrk and snoopy each get CPUs of their own (taskset), so the
# numbers show the cost the traced program pays, in its own threads (a
# uprobe stops the thread that hits it), apart from snoopy's own CPU use,
# which is reported on its own. wrk uses OpenSSL too, and snoopy attaches
# to the system's libssl whatever --comm says, so wrk gets a copy of its
# own, which isn't probed: uprobes are per file. With bpftool, each mode
# also shows the average time of each of snoopy's BPF programs, from the
# kernel's statistics.
set -euo pipefail

secs=${1:-10}
runs=3
for tool in snoopy wrk nginx go taskset; do
	command -v $tool >/dev/null || { echo "needs $tool on PATH" >&2; exit 1; }
done
cpus=$(nproc)
if [ "$cpus" -ge 6 ]; then
	server_cpus=0,1 load_cpus=2,3 snoopy_cpus=4,5
elif [ "$cpus" -ge 4 ]; then
	server_cpus=0 load_cpus=1,2 snoopy_cpus=3
else
	echo "needs 4 CPUs" >&2
	exit 1
fi
nserver=$(tr ',' '\n' <<< "$server_cpus" | wc -l)
stats=false
bpftool version >/dev/null 2>&1 && stats=true # Ubuntu's is a wrapper that can fail
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
bpf_stats_was=$(sysctl -n kernel.bpf_stats_enabled 2>/dev/null || echo 0)
cleanup() {
	pkill -f "nginx -c $tmp" 2>/dev/null || true
	pkill -f "$tmp/server" 2>/dev/null || true
	pkill -x snoopy 2>/dev/null || true
	sysctl -qw kernel.bpf_stats_enabled="$bpf_stats_was" 2>/dev/null || true
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
worker_processes $nserver;
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
	LD_LIBRARY_PATH=$tmp/wrklib taskset -c $load_cpus wrk -t2 -c32 -d"${secs}s" --latency "$1" 2>/dev/null > "$tmp/wrk"
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

# progstats PID: the run counts and times of a process's BPF programs, as
# "id name runs ns" lines. The kernel keeps them per program, and shows them
# in the fdinfo of each program fd the process holds (link fds name a
# program too, but without the counts); bpftool gives the names.
progstats() {
	for f in /proc/$1/fdinfo/*; do
		awk '/^prog_id:/ { i = $2 } /^run_cnt:/ { c = $2 } /^run_time_ns:/ { t = $2 }
			END { if (i != "" && c != "") print i, c, t }' "$f" 2>/dev/null
	done | sort -u | join - <(bpftool prog show 2>/dev/null |
		awk -F'[: ]+' '/^[0-9]+:/ { print $1, ($3 == "name" ? $4 : "?") }' | sort) |
		awk '{ print $1, $4, $2, $3 }'
}

# measure NAME URL COMM: each mode, the median of $runs runs.
measure() {
	local name=$1 url=$2 comm=$3
	for mode in ${MODES:-off quiet text json brief untraced}; do
		local sn="" args=()
		case $mode in
		quiet) args=(--comm "$comm" --quiet) ;;
		text) args=(--comm "$comm" --no-color) ;;
		json) args=(--comm "$comm" --json) ;;
		brief) args=(--comm "$comm" --brief --no-color) ;;
		untraced) args=(--comm nomatch --quiet) ;;
		esac
		if [ $mode != off ]; then
			# Output is formatted in full but not kept: at these rates it
			# would fill a disk in seconds.
			taskset -c $snoopy_cpus snoopy "${args[@]}" > /dev/null 2> "$tmp/err" &
			sn=$!
			until grep -qs tracing "$tmp/err"; do
				kill -0 $sn 2>/dev/null || { cat "$tmp/err" >&2; exit 1; }
				sleep 0.2
			done
		fi
		load "$url" > /dev/null # warm up, and attach to what's new
		local before=0
		if [ -n "$sn" ]; then
			before=$(cpu $sn)
			$stats && progstats $sn > "$tmp/stats.before"
		fi
		for _ in $(seq $runs); do load "$url"; done | sort -n | sed -n "$(( (runs + 1) / 2 ))p" > "$tmp/median"
		local snoopycpu=- lost=-
		if [ -n "$sn" ]; then
			snoopycpu=$(awk -v a="$before" -v b="$(cpu $sn)" -v t=$((runs * secs)) 'BEGIN { printf "%.0f%%", (b - a) / t * 100 }')
			$stats && progstats $sn > "$tmp/stats.after"
			# Why, if there are none, for machines that differ.
			local nostats="$(grep -ls '^prog_id' /proc/$sn/fdinfo/* 2>/dev/null | wc -l) program fds, bpftool says: $(bpftool prog show 2>&1 | head -1)"
			kill -INT $sn
			wait $sn 2>/dev/null || true
			# Chunks the ring buffer had no room for, which snoopy warns about.
			lost=$(grep -oE '[0-9]+ chunks dropped' "$tmp/err" | tail -1 | cut -d' ' -f1 || true)
			lost=${lost:-0}
		fi
		read -r rps p50 p99 < "$tmp/median"
		local perreq
		perreq=$(awk -v n="$nserver" -v r="$rps" 'BEGIN { printf "%.1f", r ? n * 1e6 / r : 0 }')
		printf "%-22s %-9s %9s %7s %8s %8s %8s %10s\n" "$name" "$mode" "$rps" "$perreq" "$p50" "$p99" "$snoopycpu" "$lost"
		# Each program that ran more than a thousand times: its average.
		if [ -n "$sn" ] && $stats; then
			join <(sort "$tmp/stats.before") <(sort "$tmp/stats.after") | awk '
				{ n = $6 - $3; if (n > 1000) printf "%s %s ns × %d, ", $2, int(($7 - $4) / n), n }' |
				sed 's/, $//; s/^/    BPF: /' | grep . || true
			[ -s "$tmp/stats.after" ] || echo "    BPF: no statistics; $nostats"
		fi
	done
}

if $stats; then
	sysctl -qw kernel.bpf_stats_enabled=1
fi
taskset -c $server_cpus nginx -c "$tmp/nginx.conf"
taskset -c $server_cpus "$tmp/server" -addr 127.0.0.1:8443 -size 1024 2>/dev/null & # it logs wrk closing connections mid-handshake
sleep 1
echo "$cpus CPUs: server on $server_cpus, wrk on $load_cpus, snoopy on $snoopy_cpus; $(uname -r) $(uname -m)"
printf "%-22s %-9s %9s %7s %8s %8s %8s %10s\n" workload mode "req/s" "µs/req" "p50 µs" "p99 µs" "snoopy" "lost"
measure "nginx HTTPS 1 KiB" https://127.0.0.1:8444/1k nginx
measure "nginx HTTPS 256 KiB" https://127.0.0.1:8444/256k nginx
measure "Go HTTPS 1 KiB" https://127.0.0.1:8443/ server
measure "nginx HTTP 1 KiB" http://127.0.0.1:8080/1k nginx
