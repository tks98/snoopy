package tracer

import (
	"net/netip"
	"time"

	"github.com/tks98/snoopy/v2/internal/discover"
)

// Function is a traced TLS function. Keep in sync with enum fn_id in
// bpf/snoopy.c.
type Function uint8

const (
	FuncSSLRead Function = iota + 1
	FuncSSLWrite
	FuncSSLReadEx
	FuncSSLWriteEx
	FuncGnuTLSRecv
	FuncGnuTLSSend
	FuncPRRead
	FuncPRWrite
	FuncPRRecv
	FuncPRSend
	FuncGoRead
	FuncGoWrite
	FuncWolfSSLRead
	FuncWolfSSLWrite
	FuncMbedTLSRead
	FuncMbedTLSWrite
	FuncS2NRecv
	FuncS2NSend
	FuncRustlsRead
	FuncRustlsWrite
	FuncQUICSend
	FuncQUICRecv
	FuncNSSQUICSend
	FuncNSSQUICRecv
	FuncRecordSend
	FuncRecordRecv
	FuncRingSend
	FuncRingRecv
	FuncAwsLCQUICSend
	FuncAwsLCQUICRecv
	FuncRingQUICSend
	FuncRingQUICRecv
	FuncNGTCP2Send
	FuncNGTCP2Recv
	FuncGoQUICSend
	FuncGoQUICRecv
)

// FuncQUICPacketSent isn't a call but a notice: a QUIC packet was sent from
// a socket that isn't connected (quinn's), to Remote. Its QUICHeader is the
// packet's header as sent, which tells its connection, and it has no data.
// It's for following connections, not for showing.
const FuncQUICPacketSent Function = fnQUICPacketSent

var functionNames = map[Function]string{
	FuncSSLRead:      "SSL_read",
	FuncSSLWrite:     "SSL_write",
	FuncSSLReadEx:    "SSL_read_ex",
	FuncSSLWriteEx:   "SSL_write_ex",
	FuncGnuTLSRecv:   "gnutls_record_recv",
	FuncGnuTLSSend:   "gnutls_record_send",
	FuncPRRead:       "PR_Read",
	FuncPRWrite:      "PR_Write",
	FuncPRRecv:       "PR_Recv",
	FuncPRSend:       "PR_Send",
	FuncGoRead:       "crypto/tls.(*Conn).Read",
	FuncGoWrite:      "crypto/tls.(*Conn).Write",
	FuncWolfSSLRead:  "wolfSSL_read",
	FuncWolfSSLWrite: "wolfSSL_write",
	FuncMbedTLSRead:  "mbedtls_ssl_read",
	FuncMbedTLSWrite: "mbedtls_ssl_write",
	FuncS2NRecv:      "s2n_recv",
	FuncS2NSend:      "s2n_send",
	FuncRustlsRead:   "rustls::Reader::read",
	FuncRustlsWrite:  "rustls::Writer::write",
	FuncQUICSend:     "EVP_AEAD_CTX_seal",
	FuncQUICRecv:     "EVP_AEAD_CTX_open",
	FuncNSSQUICSend:  "AES_AEAD (encrypt)",
	FuncNSSQUICRecv:  "AES_AEAD (decrypt)",
	FuncRecordSend:   "EVP_AEAD_CTX_seal (TLS)",
	FuncRecordRecv:   "EVP_AEAD_CTX_open (TLS)",
	FuncRingSend:     "ring::aead seal (TLS)",
	FuncRingRecv:     "ring::aead open (TLS)",
	// In Rust programs (quinn).
	FuncAwsLCQUICSend: "EVP_AEAD_CTX_seal",
	FuncAwsLCQUICRecv: "EVP_AEAD_CTX_open",
	FuncRingQUICSend:  "ring::aead seal",
	FuncRingQUICRecv:  "ring::aead open",
	FuncNGTCP2Send:    "ngtcp2_crypto_encrypt",
	FuncNGTCP2Recv:    "ngtcp2_crypto_decrypt",
	FuncGoQUICSend:    "cipher.AEAD.Seal",
	FuncGoQUICRecv:    "cipher.AEAD.Open",

	FuncQUICPacketSent: "QUIC packet sent",
}

func (f Function) String() string {
	if name, ok := functionNames[f]; ok {
		return name
	}
	return "unknown"
}

// Library returns the TLS library the function belongs to.
func (f Function) Library() discover.Library {
	switch f {
	case FuncSSLRead, FuncSSLWrite, FuncSSLReadEx, FuncSSLWriteEx, FuncQUICSend, FuncQUICRecv:
		return discover.OpenSSL
	case FuncGnuTLSRecv, FuncGnuTLSSend:
		return discover.GnuTLS
	case FuncPRRead, FuncPRWrite, FuncPRRecv, FuncPRSend, FuncNSSQUICSend, FuncNSSQUICRecv:
		return discover.NSS
	case FuncGoRead, FuncGoWrite, FuncGoQUICSend, FuncGoQUICRecv:
		return discover.GoTLS
	case FuncWolfSSLRead, FuncWolfSSLWrite:
		return discover.WolfSSL
	case FuncMbedTLSRead, FuncMbedTLSWrite:
		return discover.MbedTLS
	case FuncS2NRecv, FuncS2NSend:
		return discover.S2N
	case FuncNGTCP2Send, FuncNGTCP2Recv:
		return discover.NGTCP2
	case FuncRustlsRead, FuncRustlsWrite, FuncRecordSend, FuncRecordRecv, FuncRingSend, FuncRingRecv,
		FuncAwsLCQUICSend, FuncAwsLCQUICRecv, FuncRingQUICSend, FuncRingQUICRecv:
		return discover.Rustls
	}
	return 0
}

// IsQUIC reports whether the function's data is the frames of a QUIC packet
// (HTTP/3), captured where the packet is encrypted or decrypted.
func (f Function) IsQUIC() bool {
	switch f {
	case FuncQUICSend, FuncQUICRecv, FuncNSSQUICSend, FuncNSSQUICRecv,
		FuncAwsLCQUICSend, FuncAwsLCQUICRecv, FuncRingQUICSend, FuncRingQUICRecv, FuncNGTCP2Send, FuncNGTCP2Recv,
		FuncGoQUICSend, FuncGoQUICRecv:
		return true
	}
	return false
}

// IsRecord reports whether the function's data is the plaintext of TLS
// records, captured where they are encrypted or decrypted. Each direction of
// a connection has its own encryption context, so the context, which is the
// event's ConnID, differs between a connection's reads and writes.
func (f Function) IsRecord() bool {
	return f == FuncRecordSend || f == FuncRecordRecv || f == FuncRingSend || f == FuncRingRecv
}

// Direction is whether data was received or sent.
type Direction int

const (
	Read  Direction = iota // received from the peer
	Write                  // sent to the peer
)

func (d Direction) String() string {
	if d == Write {
		return "write"
	}
	return "read"
}

// Direction returns whether the function receives or sends data.
func (f Function) Direction() Direction {
	switch f {
	case FuncSSLWrite, FuncSSLWriteEx, FuncGnuTLSSend, FuncPRWrite, FuncPRSend, FuncGoWrite,
		FuncWolfSSLWrite, FuncMbedTLSWrite, FuncS2NSend, FuncRustlsWrite, FuncQUICSend, FuncNSSQUICSend,
		FuncRecordSend, FuncRingSend, FuncAwsLCQUICSend, FuncRingQUICSend, FuncQUICPacketSent, FuncNGTCP2Send,
		FuncGoQUICSend:
		return Write
	}
	return Read
}

// Event is one completed call to a TLS read or write function.
type Event struct {
	Time     time.Time
	Latency  time.Duration // time spent inside the call
	Function Function
	PID      uint32
	TID      uint32
	Comm     string // process name, truncated to 15 bytes by the kernel
	ConnID   uint64 // library connection handle, stable for a connection's lifetime
	FD       int32  // socket file descriptor, or -1 if unknown

	// Size is the number of plaintext bytes the call transferred. Data holds
	// the captured bytes, which may be fewer (see Truncated).
	Size uint32
	Data []byte
	// QUICHeader is a QUIC packet's header, up to its source connection ID
	// if it has one, which tells connections sharing a socket apart.
	QUICHeader []byte

	// ReadError is set if the payload could not be copied from the process.
	ReadError bool
	// Incomplete is set if part of the payload was dropped because the ring
	// buffer was full.
	Incomplete bool

	// Filled in by enrichment, if available.
	ContainerID string
	Local       netip.AddrPort
	Remote      netip.AddrPort
}

// Truncated reports whether fewer bytes were captured than transferred.
func (e *Event) Truncated() bool {
	return len(e.Data) < int(e.Size)
}
