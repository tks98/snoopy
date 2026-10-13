#!/bin/bash
# Records docs/demo.gif: snoopy in a terminal on the left, and Chromium on the
# right, opened from a second terminal, loading three sites. Everything runs
# on a virtual X display, so nothing on the real screen is recorded.
#
# Run it as root on Ubuntu with snoopy in /usr/local/bin, the Chromium snap,
# a desktop user (uid 1000) logged in, and Xvfb, xterm, xdotool, ffmpeg and
# gifsicle installed:
#
#   sudo apt-get install xvfb xterm xdotool ffmpeg gifsicle
#   sudo docs/demo/record.sh [output.gif]
#
# It also saves what snoopy printed, outside the repository, and says where.
# Read it before publishing a new GIF, since the GIF shows everything the
# browser sent, and watch the GIF: on a slow machine or network a page can
# load late, or Chromium can fall back from HTTP/3 to HTTP/2. Then run it
# again.
set -euo pipefail

out=$(realpath "${1:-docs/demo.gif}")
capture=$(mktemp /tmp/snoopy-demo-capture.XXXXXX)
command -v snoopy >/dev/null || { echo "snoopy isn't on PATH" >&2; exit 1; }
user=$(getent passwd 1000 | cut -d: -f1)
home=$(getent passwd 1000 | cut -d: -f6)
profile=$home/snoopy-demo-profile
tmp=$(mktemp -d)
chmod 755 "$tmp"

# The screen: the snoopy terminal is 152x59 characters (1080 pixels wide
# with 7-pixel cells and 8-pixel borders), Chromium is 520x690, and the
# second terminal fills the 520x210 below it.
width=1600 height=900 left=1080 browser=690
export DISPLAY=:99

cleanup() {
	pkill -f "$profile" || true
	pkill -f 'xterm -title (snoopy|chromium)' || true
	pkill -f "Xvfb $DISPLAY" || true
	sleep 1
}
trap 'cleanup; rm -rf "$tmp" "$profile"' EXIT

start_display() {
	cleanup
	Xvfb $DISPLAY -screen 0 ${width}x${height}x24 -dpi 96 -ac -nolisten tcp -br >/dev/null 2>&1 &
	for _ in $(seq 1 50); do xdotool getdisplaygeometry >/dev/null 2>&1 && break; sleep 0.1; done
	local style=(-fa 'DejaVu Sans Mono' -fs 9 -bg '#0d1117' -fg '#e6edf3' -cr '#e6edf3' -b 8 -bw 0)
	xterm -title snoopy "${style[@]}" -geometry 152x59+0+0 -e bash --rcfile "$tmp/root-rc" -i &
	sudo -u "$user" -H env DISPLAY=$DISPLAY XDG_RUNTIME_DIR=/run/user/1000 \
		xterm -title chromium "${style[@]}" -geometry 72x13+$left+$browser -e bash --rcfile "$tmp/user-rc" -i &
	sleep 2
}

# Types a command into a terminal, by title.
type_in() {
	xdotool search --name "^$1\$" windowfocus --sync
	xdotool type --delay 55 "$2"
	sleep 0.3
	xdotool key Return
}

cat > "$tmp/root-rc" <<'EOF'
PS1='$ '
EOF
# The demo types "chromium URL". The flags place the window, use a fresh
# profile, and turn off Chromium's own background requests (updates, sync,
# suggestions), which would crowd out the sites' traffic.
cat > "$tmp/user-rc" <<EOF
PS1='\$ '
chromium() {
	( /snap/bin/chromium --user-data-dir=$profile --no-first-run --no-default-browser-check \\
		--password-store=basic --hide-crash-restore-bubble --force-device-scale-factor=1 \\
		--disable-background-networking --disable-component-update --disable-sync \\
		--disable-domain-reliability --no-pings \\
		--disable-features=OptimizationHints,OptimizationGuideModelDownloading,OptimizationHintsFetching,Translate,MediaRouter \\
		--window-position=$left,0 --window-size=$((width - left)),$browser "\$@" >/dev/null 2>&1 & )
}
EOF
chmod 644 "$tmp"/*-rc

# Off camera, visit the HTTP/3 test page once: Chromium remembers that the
# site speaks HTTP/3, so the visit on camera uses it.
rm -rf "$profile"
start_display
type_in chromium 'chromium https://cloudflare-quic.com'
sleep 12
pkill -TERM -f "$profile" || true
sleep 4

start_display
# The same capture as the one on screen, to check what the GIF shows.
snoopy --comm chrome --brief --no-color > "$capture" 2> "$tmp/audit.err" &
audit=$!
until grep -qs tracing "$tmp/audit.err"; do
	kill -0 $audit 2>/dev/null || { cat "$tmp/audit.err" >&2; exit 1; }
	sleep 0.2
done
ffmpeg -loglevel error -y -f x11grab -draw_mouse 0 -framerate 10 -video_size ${width}x${height} -i $DISPLAY \
	-c:v libx264rgb -qp 0 -preset ultrafast "$tmp/recording.mkv" &
recorder=$!
sleep 1.5
type_in snoopy 'sudo snoopy --comm chrome --brief'
sleep 3
type_in chromium 'chromium https://example.com'
sleep 10
type_in chromium 'chromium https://en.wikipedia.org/wiki/EBPF'
sleep 14
type_in chromium 'chromium https://cloudflare-quic.com'
sleep 12
xdotool search --name '^snoopy$' windowfocus --sync key ctrl+c
sleep 3
kill -INT $recorder; wait $recorder || true
kill -INT $audit; wait $audit || true

# 1.5 times as fast, at 10 frames a second, with one 128-color palette.
ffmpeg -loglevel error -y -i "$tmp/recording.mkv" -vf "setpts=PTS/1.5,fps=10,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" "$tmp/demo.gif"
gifsicle -O3 "$tmp/demo.gif" -o "$out"
chmod 644 "$out"
echo "wrote $out ($(du -h "$out" | cut -f1)); what snoopy printed is in $capture ($(wc -l < "$capture") calls)"
