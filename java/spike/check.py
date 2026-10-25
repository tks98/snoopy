# Compares what the spike's clients printed they sent and received (W/R
# lines for SSLSocket, WB/RB for SSLEngine bodies) with the frames the
# consumer saw (F lines), for process PID. Usage:
#   python3 check.py CLIENT_OUT FRAMES_OUT PID [FIRST_ROUND]
import re, sys, collections

def unhex(s):
    return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", s.replace("\\x", "")))

frames = collections.defaultdict(list)  # (conn, dir) -> [(seq, payload, orig)]
for line in open(sys.argv[2]):
    p = line.split()
    if p[0] != "F" or p[-1] != sys.argv[3] or int(p[1]) == 0:
        continue
    conn, seq, d, kind, orig, cap = map(int, p[1:7])
    frames[(conn, d)].append((seq, unhex(" ".join(p[7:-1])), orig))
streams = {k: b"".join(f[1] for f in sorted(v)) for k, v in frames.items()}
writes = [v for (c, d), v in streams.items() if d == 0]
reads = [v for (c, d), v in streams.items() if d == 1]

first = int(sys.argv[4]) if len(sys.argv) > 4 else 0
ok = True
lines = [l.split() for l in open(sys.argv[1]) if l[:2] in ("W ", "R ", "WB", "RB")]
rounds = collections.Counter()
for kind, h in lines:
    rounds[kind] += 1
    if rounds[kind] - 1 < first:
        continue  # before the agent was attached
    want = bytes.fromhex(h)
    pool = writes if kind.startswith("W") else reads
    if kind in ("W", "R"):
        n = sum(1 for s in pool if s == want)  # a whole connection's stream
    else:
        n = sum(s.count(want) for s in pool)  # a body within the stream
    status = "ok" if n == 1 else "MISSING" if n == 0 else "DUPLICATED x%d" % n
    ok &= n == 1
    print("%-2s %-14s %5d bytes %s" % (kind, want[:14].decode("ascii", "replace"), len(want), status))
print("frames:", sum(len(v) for v in frames.values()), "connections:", len({c for c, _ in frames}))
sys.exit(0 if ok else 1)
