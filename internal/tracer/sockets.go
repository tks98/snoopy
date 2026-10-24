package tracer

import (
	"net/netip"
	"time"
)

// fnSocketNotice is FN_SOCKET_NOTICE in bpf/snoopy.c: a record that isn't a
// call, saying which socket a connection uses.
const fnSocketNotice = 0xff

// fnQUICPacketSent is FN_QUIC_PACKET_SENT: another, saying where a QUIC
// packet on a socket that isn't connected was sent. It's delivered as an
// event of FuncQUICPacketSent.
const fnQUICPacketSent = 0xfe

// learnsSocketLater reports whether the function's data is encrypted before
// the thread's next socket syscall shows which socket it goes out on, so a
// connection's first write can't have one when it's emitted.
func (f Function) learnsSocketLater() bool {
	switch f {
	case FuncRustlsWrite, FuncQUICSend, FuncNSSQUICSend, FuncRecordSend, FuncRingSend, FuncAwsLCQUICSend, FuncRingQUICSend,
		FuncNGTCP2Send:
		return true
	}
	return false
}

// socketWaiter holds back events that went out without a socket until the
// BPF program says which socket their connection uses, which normally comes
// right behind them, so they can be delivered with it. Each connection's
// events stay in order; events of other connections aren't held up.
type socketWaiter struct {
	held map[connKey]*heldEvents
}

type connKey struct {
	pid  uint32
	conn uint64
}

type heldEvents struct {
	events []*Event
	since  time.Time
}

const maxHeldPerConn = 64

func newSocketWaiter() *socketWaiter {
	return &socketWaiter{held: map[connKey]*heldEvents{}}
}

// add returns the events to deliver now that ev is complete: none if it is
// held, and otherwise its connection's held events before it.
func (w *socketWaiter) add(ev *Event, now time.Time) []*Event {
	key := connKey{ev.PID, ev.ConnID}
	h := w.held[key]
	if ev.FD < 0 && ev.Function.learnsSocketLater() {
		if h == nil {
			h = &heldEvents{since: now}
			w.held[key] = h
		}
		h.events = append(h.events, ev)
		if len(h.events) < maxHeldPerConn {
			return nil
		}
		delete(w.held, key)
		return h.events
	}
	if h == nil {
		return []*Event{ev}
	}
	// The connection's socket became known without a notice (it was lost,
	// or the event came from a function that sees the socket itself).
	delete(w.held, key)
	if ev.FD >= 0 {
		fill(h.events, ev.FD, ev.Local, ev.Remote)
	}
	return append(h.events, ev)
}

// notice handles a socket notice and returns the events it releases.
func (w *socketWaiter) notice(c chunk) []*Event {
	key := connKey{c.Pid, c.ConnID}
	h := w.held[key]
	if h == nil {
		return nil
	}
	delete(w.held, key)
	local, remote := c.addresses()
	fill(h.events, c.Fd, local, remote)
	return h.events
}

func fill(events []*Event, fd int32, local, remote netip.AddrPort) {
	for _, ev := range events {
		if ev.FD < 0 {
			ev.FD, ev.Local, ev.Remote = fd, local, remote
		}
	}
}

// expire returns events that have waited longer than maxAge, without a
// socket.
func (w *socketWaiter) expire(now time.Time, maxAge time.Duration) []*Event {
	var out []*Event
	for key, h := range w.held {
		if now.Sub(h.since) >= maxAge {
			out = append(out, h.events...)
			delete(w.held, key)
		}
	}
	return out
}
