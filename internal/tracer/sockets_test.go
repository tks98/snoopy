package tracer

import (
	"net/netip"
	"testing"
	"time"
)

func TestSocketWaiter(t *testing.T) {
	w := newSocketWaiter()
	now := time.Now()
	ev := func(fn Function, conn uint64, fd int32, data string) *Event {
		return &Event{Function: fn, PID: 1, ConnID: conn, FD: fd, Data: []byte(data)}
	}
	names := func(evs []*Event) (out []string) {
		for _, e := range evs {
			out = append(out, string(e.Data))
		}
		return out
	}

	// Writes without a socket are held, per connection; other events pass.
	if got := w.add(ev(FuncQUICSend, 0xa, -1, "a1"), now); got != nil {
		t.Fatalf("held write delivered: %v", names(got))
	}
	if got := w.add(ev(FuncQUICSend, 0xa, -1, "a2"), now); got != nil {
		t.Fatalf("held write delivered: %v", names(got))
	}
	if got := names(w.add(ev(FuncQUICRecv, 0xb, -1, "b1"), now)); len(got) != 1 {
		t.Fatalf("read was held: %v", got)
	}

	// The notice fills in the socket and releases them in order.
	h := rawHeader{Pid: 1, ConnID: 0xa, Fd: 7, Family: afInet, Lport: 5000, Rport: 443, Fn: fnSocketNotice}
	copy(h.Laddr[:], []byte{10, 0, 0, 2})
	copy(h.Raddr[:], []byte{192, 0, 2, 1})
	released := w.notice(mustParse(t, record(h, "")))
	if got := names(released); len(got) != 2 || got[0] != "a1" || got[1] != "a2" {
		t.Fatalf("notice released %v", got)
	}
	for _, e := range released {
		if e.FD != 7 || e.Remote != netip.MustParseAddrPort("192.0.2.1:443") || e.Local.Port() != 5000 {
			t.Errorf("socket not filled in: %+v", e)
		}
	}
	if got := w.notice(mustParse(t, record(h, ""))); got != nil {
		t.Errorf("second notice released %v", names(got))
	}

	// A later event with the socket releases what's held before it.
	w.add(ev(FuncRustlsWrite, 0xc, -1, "c1"), now)
	got := w.add(ev(FuncRustlsWrite, 0xc, 9, "c2"), now)
	if names(got)[0] != "c1" || got[0].FD != 9 || len(got) != 2 {
		t.Errorf("got %v", names(got))
	}

	// With no notice, held events go out as they are once they've waited.
	w.add(ev(FuncNSSQUICSend, 0xd, -1, "d1"), now)
	if got := w.expire(now.Add(100*time.Millisecond), 300*time.Millisecond); got != nil {
		t.Errorf("expired early: %v", names(got))
	}
	if got := w.expire(now.Add(300*time.Millisecond), 300*time.Millisecond); len(got) != 1 || got[0].FD != -1 {
		t.Errorf("expire: %v", names(got))
	}
}
