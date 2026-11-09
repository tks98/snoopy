package output

import (
	"fmt"
	"slices"
	"strings"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// folding is how Brief keeps a large body from taking a line per call: a
// 128 KiB download over HTTP/2 is 32 DATA calls. Once a body's first call
// is shown, calls that only carry more of it are folded (counted, not
// shown), and the call that ends it is shown with how many were folded.
// --verbose shows them all.
type folding struct {
	runs   map[bodyKey]*bodyRun
	folded int // calls folded so far
}

// bodyKey is a body: one direction of a connection's stream (0 for
// HTTP/1.x, which has one body at a time).
type bodyKey struct {
	conn   harConnKey
	dir    tracer.Direction
	stream uint64
}

// bodyRun is a body whose first bytes were shown, and what of it was
// folded since.
type bodyRun struct {
	calls, bytes int
}

// bodyRef is what a call carries of a body: how many of its bytes, and
// whether it ends it.
type bodyRef struct {
	key  bodyKey
	n    int
	ends bool
}

const maxBodyRuns = 4096

// bodyRefs returns the bodies an event's data carries, and whether that's
// all it carries.
func bodyRefs(ev *tracer.Event, dc decoded) (refs []bodyRef, onlyBody bool) {
	conn, dir := connKey(ev, dc), ev.Function.Direction()
	ends := map[uint64]bool{}
	for _, end := range streamEnds(dc) {
		ends[end.id] = true
	}
	onlyBody = true
	switch {
	case dc.isQUIC:
		for _, it := range dc.quic {
			switch {
			case it.housekeeping():
			case strings.HasPrefix(it.HTTP3, "DATA") && it.Err == "":
				refs = append(refs, bodyRef{bodyKey{conn, dir, it.Stream}, len(it.Data), ends[it.Stream]})
			default:
				onlyBody = false
			}
		}
	case dc.isHTTP2:
		for _, f := range dc.http2 {
			switch {
			case f.housekeeping():
			case f.Type == "DATA" && len(f.GRPC) == 0:
				refs = append(refs, bodyRef{bodyKey{conn, dir, uint64(f.Stream)}, len(f.Data), ends[uint64(f.Stream)]})
			default:
				onlyBody = false
			}
		}
	case dc.http1 != nil:
		for _, s := range dc.http1 {
			if !s.inBody {
				onlyBody = false
				continue
			}
			refs = append(refs, bodyRef{bodyKey{conn, dir, 0}, len(s.payload), s.ends})
		}
	default:
		onlyBody = false
	}
	return refs, onlyBody && len(refs) > 0
}

// fold reports whether an event only carries more of bodies already
// shown, and none of their ends: if so, it's counted and not shown.
func (f *folding) fold(ev *tracer.Event, dc decoded) bool {
	refs, onlyBody := bodyRefs(ev, dc)
	if !onlyBody || slices.ContainsFunc(refs, func(r bodyRef) bool { return r.ends || f.runs[r.key] == nil }) {
		return false
	}
	for _, r := range refs {
		run := f.runs[r.key]
		run.calls++
		run.bytes += r.n
	}
	f.folded++
	return true
}

// shown notes the bodies a shown event carries, and returns what to add to
// its line for those it ends that had calls folded.
func (f *folding) shown(ev *tracer.Event, dc decoded) string {
	refs, _ := bodyRefs(ev, dc)
	var notes []string
	for _, r := range refs {
		run := f.runs[r.key]
		switch {
		case r.ends && run != nil:
			if run.calls > 0 {
				notes = append(notes, fmt.Sprintf("+%d %s folded, %d bytes", run.calls, plural(run.calls, "call", "calls"), run.bytes))
			}
			delete(f.runs, r.key)
		case !r.ends && run == nil:
			if f.runs == nil || len(f.runs) >= maxBodyRuns {
				f.runs = map[bodyKey]*bodyRun{}
			}
			f.runs[r.key] = &bodyRun{}
		}
	}
	if len(notes) == 0 {
		return ""
	}
	return " [" + strings.Join(notes, "; ") + "]"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
