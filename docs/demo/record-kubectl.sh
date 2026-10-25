#!/bin/bash
# Records docs/kubectl-demo.gif: kubectl snoopy on the demo app in
# docs/demo/kubectl-demo.yaml, first decoded with --redact, then --brief. It
# runs on a virtual X display, so nothing on the real screen is recorded.
#
# Run it on Linux with kubectl's current context a cluster (kind will do)
# that has the demo app (kubectl apply -f docs/demo/kubectl-demo.yaml), with
# kubectl-snoopy on PATH, and Xvfb, xterm, xdotool, ffmpeg and gifsicle:
#
#   sudo apt-get install xvfb xterm xdotool ffmpeg gifsicle
#   docs/demo/record-kubectl.sh [output.gif]
#
# The traffic is the demo app's own, made up, but watch the GIF before
# publishing it anyway.
set -euo pipefail

out=$(realpath "${1:-docs/kubectl-demo.gif}")
command -v kubectl-snoopy >/dev/null || { echo "kubectl-snoopy isn't on PATH" >&2; exit 1; }
kubectl rollout status -n shop deploy/checkout --timeout=120s >/dev/null
tmp=$(mktemp -d)

# The screen: one terminal, 176x40 characters with 7x15-pixel cells and
# 8-pixel borders, in UTF-8 (snoopy prints µs).
width=1248 height=616
export DISPLAY=:98 LANG=C.UTF-8 LC_ALL=C.UTF-8

cleanup() {
	pkill -f 'xterm -title kubectl' || true
	pkill -f "Xvfb $DISPLAY" || true
}
trap 'cleanup; rm -rf "$tmp"' EXIT
cleanup

cat > "$tmp/rc" <<'EOF'
PS1='$ '
EOF
Xvfb $DISPLAY -screen 0 ${width}x${height}x24 -dpi 96 -ac -nolisten tcp -br >/dev/null 2>&1 &
for _ in $(seq 1 50); do xdotool getdisplaygeometry >/dev/null 2>&1 && break; sleep 0.1; done
xterm -title kubectl -u8 -fa 'DejaVu Sans Mono' -fs 9 -bg '#0d1117' -fg '#e6edf3' -cr '#e6edf3' -b 8 -bw 0 \
	-geometry 176x40+0+0 -e bash --rcfile "$tmp/rc" -i &
sleep 2

type_in() {
	xdotool search --name '^kubectl$' windowfocus --sync
	xdotool type --delay 55 "$1"
	sleep 0.4
	xdotool key Return
}
interrupt() {
	xdotool search --name '^kubectl$' windowfocus --sync
	xdotool key ctrl+c
}

ffmpeg -loglevel error -y -f x11grab -video_size ${width}x${height} -framerate 12 -i $DISPLAY "$tmp/demo.mp4" &
ffmpeg_pid=$!
sleep 1

type_in "kubectl get pods -n shop"
sleep 3
type_in "kubectl snoopy deploy/checkout -n shop --redact"
sleep 16
interrupt
sleep 4
type_in "clear; kubectl snoopy deploy/checkout -n shop --brief --redact"
sleep 12
interrupt
sleep 3

kill -INT $ffmpeg_pid
wait $ffmpeg_pid || true
ffmpeg -loglevel error -y -i "$tmp/demo.mp4" -vf "fps=10,palettegen=max_colors=64" "$tmp/palette.png"
ffmpeg -loglevel error -y -i "$tmp/demo.mp4" -i "$tmp/palette.png" -lavfi "fps=10 [x]; [x][1:v] paletteuse=dither=none" "$tmp/demo.gif"
gifsicle -O3 --lossy=30 "$tmp/demo.gif" -o "$out"
echo "wrote $out ($(du -h "$out" | cut -f1))"
