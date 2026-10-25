#!/bin/bash
# Measures what snoopy --java costs a JVM: requests per second and latency
# of the JDK's own HTTPS server (SunJSSE, through SSLEngine) under load,
# without snoopy's agent, with it and snoopy, and with the agent left idle
# after snoopy stopped. docs/performance.md has the results.
#
# Run it as root with snoopy on PATH, wrk, and a JDK 17 or later, on a
# machine with at least 4 CPUs, from a source tree (for the agent, which it
# builds with java/build.sh):
#
#   sudo docs/benchmark/java.sh [seconds per run]
#
# The server, wrk and snoopy each get CPUs of their own, as in run.sh. A
# fresh JVM is warmed up before each measurement.
set -euo pipefail

secs=${1:-10}
runs=3
for tool in snoopy wrk java keytool taskset go; do
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
here=$(cd "$(dirname "$0")" && pwd)
sh "$here/../../java/build.sh" >/dev/null
agent=$here/../../java/out
tmp=$(mktemp -d)
cleanup() {
	pkill -f "JavaServer.java" 2>/dev/null || true
	pkill -x snoopy 2>/dev/null || true
	rm -rf "$tmp"
}
trap cleanup EXIT
(cd "$here/../.." && go build -o "$tmp/javaattach" ./tools/javaattach)
keytool -genkeypair -alias server -keyalg EC -dname CN=localhost -validity 1 -storetype PKCS12 \
	-keystore "$tmp/server.p12" -storepass benchpass >/dev/null 2>&1

load() {
	taskset -c $load_cpus wrk -t2 -c32 -d"${secs}s" --latency "$1" 2>/dev/null > "$tmp/wrk"
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
cpu() { awk '{ printf "%.2f", ($14 + $15) / 100 }' "/proc/$1/stat"; }

# measure NAME PATH: each mode in a JVM of its own, warmed up before and
# after the mode is set up, the median of $runs runs. idle is the agent
# loaded and told to stop by a snoopy that came and went; agent (not by
# default) is the agent writing frames that nothing reads, its own cost.
measure() {
	local name=$1 path=$2 url=https://127.0.0.1:8445$2
	for mode in ${MODES:-off quiet text idle}; do
		taskset -c $server_cpus java JavaServer.java 8445 "$tmp/server.p12" benchpass $((nserver * 4)) > "$tmp/server.out" 2>&1 &
		local jvm=$! sn="" args=()
		until grep -qs ready "$tmp/server.out"; do sleep 0.2; done
		load "$url" > /dev/null # JIT warm-up
		case $mode in
		agent) "$tmp/javaattach" $jvm "$(cd "$agent" && pwd)/snoopy-agent.jar" nonce=1 >/dev/null ;;
		quiet | idle) args=(--java --pid $jvm --java-agent "$agent" --quiet) ;;
		text) args=(--java --pid $jvm --java-agent "$agent" --no-color) ;;
		esac
		if [ ${#args[@]} -gt 0 ]; then
			taskset -c $snoopy_cpus snoopy "${args[@]}" > /dev/null 2> "$tmp/err" &
			sn=$!
			until grep -qs tracing "$tmp/err"; do
				kill -0 $sn 2>/dev/null || { cat "$tmp/err" >&2; exit 1; }
				sleep 0.2
			done
		fi
		if [ $mode = idle ]; then
			kill -INT $sn
			wait $sn 2>/dev/null || true
			sn=""
		fi
		load "$url" > /dev/null # warm up again, instrumented
		local before=0
		[ -n "$sn" ] && before=$(cpu $sn)
		for _ in $(seq $runs); do load "$url"; done | sort -n | sed -n "$(( (runs + 1) / 2 ))p" > "$tmp/median"
		local snoopycpu=- lost=-
		if [ -n "$sn" ]; then
			snoopycpu=$(awk -v a="$before" -v b="$(cpu $sn)" -v t=$((runs * secs)) 'BEGIN { printf "%.0f%%", (b - a) / t * 100 }')
			kill -INT $sn
			wait $sn 2>/dev/null || true
			lost=$(grep -oE '[0-9]+ chunks dropped' "$tmp/err" | tail -1 | cut -d' ' -f1 || true)
			lost=${lost:-0}
		fi
		kill $jvm
		wait $jvm 2>/dev/null || true
		read -r rps p50 p99 < "$tmp/median"
		local perreq
		perreq=$(awk -v n="$nserver" -v r="$rps" 'BEGIN { printf "%.1f", r ? n * 1e6 / r : 0 }')
		printf "%-22s %-6s %9s %7s %8s %8s %8s %10s\n" "$name" "$mode" "$rps" "$perreq" "$p50" "$p99" "$snoopycpu" "$lost"
	done
}

cd "$here"
echo "$cpus CPUs: server on $server_cpus, wrk on $load_cpus, snoopy on $snoopy_cpus; $(uname -r) $(uname -m); $(java -version 2>&1 | head -1)"
printf "%-22s %-6s %9s %7s %8s %8s %8s %10s\n" workload mode "req/s" "µs/req" "p50 µs" "p99 µs" "snoopy" "lost"
measure "JSSE HTTPS 1 KiB" /1k
measure "JSSE HTTPS 256 KiB" /256k
