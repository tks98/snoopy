package output

import (
	"net/netip"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// QUIC servers, and clients like quinn's, can run many connections over one
// UDP socket, which the socket alone can't tell apart. Their packets'
// connection IDs can (RFC 9000, section 5.1): a long header, sent during the
// handshake, has both the destination's and the source's; a short header has
// only the destination's, whose length its receiver chose. So a connection is
// learned from its long headers, the IDs it issues later from its
// NEW_CONNECTION_ID frames, and its short headers are matched against the
// IDs learned. A connection whose handshake wasn't seen, or which uses
// zero-length IDs, is followed by its socket instead, as Chromium's and
// Firefox's are anyway.

// cidConn is a connection identified by its connection IDs.
type cidConn struct {
	id   uint64
	peer netip.AddrPort // where its packets are sent, once that's seen
}

type cidKey struct {
	pid uint32
	// One of the process's own IDs, which packets it receives are sent
	// to, rather than one of its peer's.
	own bool
	id  string
}

type cidLenKey struct {
	pid uint32
	own bool
}

// maxCIDs bounds the IDs remembered; past it, they're forgotten and
// connections are followed by socket until their next handshake.
const maxCIDs = 1 << 16

type cidConns struct {
	conns map[cidKey]*cidConn
	lens  map[cidLenKey][]int // the lengths of the IDs in conns
	next  uint64
}

func newCIDConns() *cidConns {
	return &cidConns{conns: map[cidKey]*cidConn{}, lens: map[cidLenKey][]int{}}
}

// of returns the connection of a QUIC packet event, or nil if it isn't
// known by its IDs.
func (c *cidConns) of(ev *tracer.Event) *cidConn {
	h := ev.QUICHeader
	if len(h) == 0 {
		return nil
	}
	send := ev.Function.Direction() == tracer.Write
	if h[0]&0x80 == 0 {
		// A short header: flags, then the receiver's ID.
		own := !send
		for _, n := range c.lens[cidLenKey{ev.PID, own}] {
			if len(h) >= 1+n {
				if cc := c.conns[cidKey{ev.PID, own, string(h[1 : 1+n])}]; cc != nil {
					return cc
				}
			}
		}
		return nil
	}
	// A long header: flags, version, then each ID after its length. Version
	// negotiation packets (version 0) aren't encrypted, so aren't seen.
	if len(h) < 6 {
		return nil
	}
	dlen := int(h[5])
	if len(h) < 7+dlen {
		return nil
	}
	dcid := h[6 : 6+dlen]
	slen := int(h[6+dlen])
	if len(h) < 7+dlen+slen {
		return nil
	}
	scid := h[7+dlen : 7+dlen+slen]
	own, peer := dcid, scid
	if send {
		own, peer = scid, dcid
	}
	if len(own) == 0 || len(peer) == 0 {
		return nil
	}
	cc := c.conns[cidKey{ev.PID, true, string(own)}]
	if cc == nil {
		cc = c.conns[cidKey{ev.PID, false, string(peer)}]
	}
	if cc == nil {
		c.next++
		cc = &cidConn{id: c.next}
	}
	// The client's first Initial packets go to an ID it made up, which the
	// server takes as its own; both stay with the connection.
	c.add(ev.PID, true, own, cc)
	c.add(ev.PID, false, peer, cc)
	return cc
}

// add remembers an ID of a connection's: one of the process's own, or one
// of its peer's.
func (c *cidConns) add(pid uint32, own bool, id []byte, cc *cidConn) {
	if len(id) == 0 {
		return
	}
	if len(c.conns) >= maxCIDs {
		clear(c.conns)
		clear(c.lens)
	}
	c.conns[cidKey{pid, own, string(id)}] = cc
	lk := cidLenKey{pid, own}
	for _, n := range c.lens[lk] {
		if n == len(id) {
			return
		}
	}
	c.lens[lk] = append(c.lens[lk], len(id))
}

// sent takes in a tracer.FuncQUICPacketSent: where a packet of its
// connection was sent.
func (c *quicConns) sent(ev *tracer.Event) {
	if cc := c.cids.of(ev); cc != nil && knownAddr(ev.Remote) {
		cc.peer = ev.Remote
	}
}

// learn takes in what a packet of a known connection tells about it: the IDs
// its sender issued in NEW_CONNECTION_ID frames, and its peer's address if
// its socket is connected. On one that isn't, packets have none (it's
// 0.0.0.0:0 or [::]:0), and get the connection's, from where its packets
// were sent (sent).
func (c *cidConns) learn(ev *tracer.Event, cc *cidConn, issued [][]byte) {
	send := ev.Function.Direction() == tracer.Write
	for _, id := range issued {
		c.add(ev.PID, send, id, cc)
	}
	switch {
	case send && knownAddr(ev.Remote):
		cc.peer = ev.Remote
	case !knownAddr(ev.Remote) && cc.peer.IsValid():
		ev.Remote = cc.peer
	}
}
