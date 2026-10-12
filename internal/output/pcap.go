package output

import (
	"bufio"
	"encoding/binary"
	"hash/fnv"
	"io"
	"net/netip"
	"time"

	"github.com/tks98/snoopy/internal/tracer"
)

// Pcap writes the plaintext of each TLS connection as a synthetic TCP
// stream in a pcap file, so Wireshark and similar tools can dissect the
// protocol inside (e.g. `wireshark -d tcp.port==443,http capture.pcap`).
//
// Real addresses are used when snoopy could resolve the socket; otherwise the
// traced process is 127.0.0.1 and its peer 127.0.0.2:443. Each new connection
// starts with a synthetic three-way handshake. Bytes that were not captured
// (see --max-size) still advance the sequence numbers, so Wireshark shows
// them as missing. If both ends of a connection are traced, only the first
// one seen is written, as the other sees the same bytes.
type Pcap struct {
	w        *bufio.Writer
	streams  map[streamKey]*tcpStream
	ipID     uint16
	nextPort uint16 // for connections without known addresses
}

// maxStreams bounds the connections Pcap remembers; it doesn't see them
// close, so the least recently used one is ended when the limit is reached.
const maxStreams = 16384

// streamKey identifies a TCP connection by its endpoints (lowest first), or,
// if the addresses are unknown, by the process and TLS connection.
type streamKey struct {
	a, b netip.AddrPort
	pid  uint32
	conn uint64
}

type owner struct {
	pid  uint32
	conn uint64
}

type tcpStream struct {
	owner               owner
	local, remote       netip.AddrPort
	localSeq, remoteSeq uint32
	lastSeen            time.Time
}

const (
	pcapMagicNanos = 0xa1b23c4d
	linktypeRaw    = 101 // raw IPv4/IPv6
	maxSegment     = 32 << 10

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpPSH = 0x08
	tcpACK = 0x10
)

// NewPcap writes the pcap file header and returns a writer for events.
func NewPcap(w io.Writer) (*Pcap, error) {
	p := &Pcap{w: bufio.NewWriter(w), streams: map[streamKey]*tcpStream{}}
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:], pcapMagicNanos)
	binary.LittleEndian.PutUint16(hdr[4:], 2) // version 2.4
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 1<<18) // snaplen
	binary.LittleEndian.PutUint32(hdr[20:], linktypeRaw)
	if _, err := p.w.Write(hdr[:]); err != nil {
		return nil, err
	}
	return p, p.w.Flush()
}

func (p *Pcap) Print(ev *tracer.Event) error {
	// QUIC events are packets of frames, not a byte stream.
	if ev.Size == 0 || ev.Function.IsQUIC() {
		return nil
	}
	key := streamKey{pid: ev.PID, conn: ev.ConnID}
	if hasAddresses(ev) {
		key = streamKey{a: ev.Local, b: ev.Remote}
		if ev.Remote.Compare(ev.Local) < 0 {
			key.a, key.b = key.b, key.a
		}
	}
	s := p.streams[key]
	if s == nil {
		if len(p.streams) >= maxStreams {
			p.evictOldest(ev.Time)
		}
		s = p.newStream(ev)
		p.streams[key] = s
		p.handshake(s, ev.Time)
	}
	if s.owner != (owner{ev.PID, ev.ConnID}) {
		return nil // the other end of a connection we already write
	}
	s.lastSeen = ev.Time

	src, dst := s.local, s.remote
	seq, ack := &s.localSeq, &s.remoteSeq
	if ev.Function.Direction() == tracer.Read {
		src, dst = dst, src
		seq, ack = ack, seq
	}

	start := *seq
	for off := 0; off < len(ev.Data); off += maxSegment {
		end := min(off+maxSegment, len(ev.Data))
		p.packet(ev.Time, src, dst, start+uint32(off), *ack, tcpPSH|tcpACK, ev.Data[off:end])
	}
	*seq = start + ev.Size
	return p.w.Flush()
}

// Close ends each stream with a FIN and flushes the file. It does not close
// the underlying writer.
func (p *Pcap) Close() error {
	now := time.Now()
	for _, s := range p.streams {
		p.packet(now, s.local, s.remote, s.localSeq, s.remoteSeq, tcpFIN|tcpACK, nil)
	}
	return p.w.Flush()
}

func (p *Pcap) newStream(ev *tracer.Event) *tcpStream {
	var id [12]byte
	binary.LittleEndian.PutUint64(id[:], ev.ConnID)
	binary.LittleEndian.PutUint32(id[8:], ev.PID)
	h := fnv.New32a()
	h.Write(id[:])
	sum := h.Sum32()

	s := &tcpStream{
		owner:     owner{ev.PID, ev.ConnID},
		local:     ev.Local,
		remote:    ev.Remote,
		localSeq:  sum,
		remoteSeq: sum * 31,
		lastSeen:  ev.Time,
	}
	if !hasAddresses(ev) {
		// Hand out local ports in turn, so concurrent connections don't
		// end up with the same addresses.
		if p.nextPort < 10000 {
			p.nextPort = 10000
		}
		s.local = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), p.nextPort)
		s.remote = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 2}), 443)
		p.nextPort++
	}
	return s
}

// evictOldest ends the least recently used stream.
func (p *Pcap) evictOldest(now time.Time) {
	var oldestKey streamKey
	var oldest *tcpStream
	for k, s := range p.streams {
		if oldest == nil || s.lastSeen.Before(oldest.lastSeen) {
			oldestKey, oldest = k, s
		}
	}
	if oldest != nil {
		p.packet(now, oldest.local, oldest.remote, oldest.localSeq, oldest.remoteSeq, tcpFIN|tcpACK, nil)
		delete(p.streams, oldestKey)
	}
}

func hasAddresses(ev *tracer.Event) bool {
	return ev.Local.IsValid() && ev.Remote.IsValid() && ev.Local.Addr().Is4() == ev.Remote.Addr().Is4()
}

func (p *Pcap) handshake(s *tcpStream, t time.Time) {
	p.packet(t, s.local, s.remote, s.localSeq, 0, tcpSYN, nil)
	p.packet(t, s.remote, s.local, s.remoteSeq, s.localSeq+1, tcpSYN|tcpACK, nil)
	s.localSeq++
	s.remoteSeq++
	p.packet(t, s.local, s.remote, s.localSeq, s.remoteSeq, tcpACK, nil)
}

func (p *Pcap) packet(t time.Time, src, dst netip.AddrPort, seq, ack uint32, flags byte, payload []byte) {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], src.Port())
	binary.BigEndian.PutUint16(tcp[2:], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 5 << 4 // header length: 5 words
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535) // window
	copy(tcp[20:], payload)

	var pkt []byte
	if src.Addr().Is4() {
		ip := make([]byte, 20)
		ip[0] = 0x45 // IPv4, 5-word header
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
		p.ipID++
		binary.BigEndian.PutUint16(ip[4:], p.ipID)
		binary.BigEndian.PutUint16(ip[6:], 0x4000) // don't fragment
		ip[8] = 64                                 // TTL
		ip[9] = 6                                  // TCP
		s4, d4 := src.Addr().As4(), dst.Addr().As4()
		copy(ip[12:], s4[:])
		copy(ip[16:], d4[:])
		binary.BigEndian.PutUint16(ip[10:], checksum(ip, 0))

		pseudo := append(append(append([]byte{}, s4[:]...), d4[:]...), 0, 6, byte(len(tcp)>>8), byte(len(tcp)))
		binary.BigEndian.PutUint16(tcp[16:], checksum(tcp, sum16(pseudo)))
		pkt = append(ip, tcp...)
	} else {
		ip := make([]byte, 40)
		ip[0] = 0x60 // IPv6
		binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)))
		ip[6] = 6  // next header: TCP
		ip[7] = 64 // hop limit
		s6, d6 := src.Addr().As16(), dst.Addr().As16()
		copy(ip[8:], s6[:])
		copy(ip[24:], d6[:])

		pseudo := make([]byte, 40)
		copy(pseudo, s6[:])
		copy(pseudo[16:], d6[:])
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(tcp)))
		pseudo[39] = 6
		binary.BigEndian.PutUint16(tcp[16:], checksum(tcp, sum16(pseudo)))
		pkt = append(ip, tcp...)
	}

	var rec [16]byte
	binary.LittleEndian.PutUint32(rec[0:], uint32(t.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(t.Nanosecond()))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))
	// bufio.Writer errors are sticky; Print and Close report them on Flush.
	_, _ = p.w.Write(rec[:])
	_, _ = p.w.Write(pkt)
}

// sum16 is the one's-complement sum of b as big-endian 16-bit words.
func sum16(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// checksum is the Internet checksum of b, with initial a partial sum.
func checksum(b []byte, initial uint32) uint16 {
	sum := initial + sum16(b)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
