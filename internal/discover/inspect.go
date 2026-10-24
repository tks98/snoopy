package discover

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

// readSymbols is the function whose presence identifies each C library.
var readSymbols = []struct {
	lib    Library
	symbol string
}{
	{OpenSSL, "SSL_read"},
	{GnuTLS, "gnutls_record_recv"},
	{NSS, "PR_Read"},
	{WolfSSL, "wolfSSL_read"},
	{MbedTLS, "mbedtls_ssl_read"},
	{S2N, "s2n_recv"},
	// The same in each of its builds for a TLS library
	// (libngtcp2_crypto_ossl, _gnutls, _wolfssl, _boringssl, _quictls).
	{NGTCP2, "ngtcp2_crypto_decrypt"},
}

const (
	goReadFunc  = "crypto/tls.(*Conn).Read"
	goWriteFunc = "crypto/tls.(*Conn).Write"
)

var (
	errNoFunc   = errors.New("function not found")
	errWrongArc = errors.New("built for a different architecture")
)

// GoInfo describes where to probe a Go binary's crypto/tls, and, in
// programs that use quic-go, the AEADs that encrypt their QUIC packets.
type GoInfo struct {
	Version string // Go version the binary was built with
	Read    GoFunc // zero if the program has no crypto/tls connections
	Write   GoFunc
	Seals   []GoFunc
	Opens   []GoFunc
}

// goAEADs are the AEADs' methods, by type: AES-GCM since Go 1.24, and
// ChaCha20-Poly1305, which crypto/tls vendors and quic-go also imports.
var goAEADs = []string{
	"crypto/internal/fips140/aes/gcm.(*GCM)",
	"vendor/golang.org/x/crypto/chacha20poly1305.(*chacha20poly1305)",
	"golang.org/x/crypto/chacha20poly1305.(*chacha20poly1305)",
}

// quicGoFunc is in programs that use quic-go, which are the only ones whose
// AEADs are probed: Go programs use AES-GCM for other things too, and every
// TLS record goes through it.
const quicGoFunc = "github.com/quic-go/quic-go/internal/handshake.(*updatableAEAD).Open"

// GoFunc locates one Go function inside an executable.
type GoFunc struct {
	Offset  uint64   // file offset of the function's first instruction
	Body    uint64   // offset of the first instruction after the stack check, relative to Offset
	Returns []uint64 // offsets of its RET instructions, relative to Offset
}

// Inspect reports which supported TLS implementations a file contains.
func Inspect(path string) ([]Target, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if f.Machine != hostMachine() {
		return nil, errWrongArc
	}

	var targets []Target
	gi, err := inspectGo(path, f)
	if err != nil {
		return nil, err
	}
	if gi != nil {
		t := Target{Path: path, Library: GoTLS, Go: gi}
		if len(gi.Seals) > 0 {
			t.Note = "QUIC through quic-go"
		}
		targets = append(targets, t)
	}

	if ri := inspectRustls(f); ri != nil {
		t := Target{Path: path, Library: Rustls, Rust: ri}
		switch {
		case len(ri.Seals) > 0 && len(ri.Opens) > 0:
			t.Note = "records through aws-lc"
		case ri.AtRecords():
			t.Note = "records through ring"
		}
		targets = append(targets, t)
	}

	defined := definedFuncs(f)
	for _, rs := range readSymbols {
		if defined[rs.symbol] {
			targets = append(targets, Target{Path: path, Library: rs.lib})
		}
	}
	if offsets, err := findFreebl(f); err == nil {
		targets = append(targets, Target{Path: path, Library: NSS, Offsets: offsets, Note: "freebl, for QUIC"})
	}
	if !defined["SSL_read"] {
		offsets, err := cachedFindBoringSSL(path, f)
		switch {
		case err == nil:
			t := Target{Path: path, Library: OpenSSL, Offsets: offsets, Note: "BoringSSL found by signature"}
			if offsets["EVP_AEAD_CTX_seal"] == 0 {
				t.Limits = "BoringSSL's QUIC packet encryption wasn't found in this build, so its HTTP/3 isn't traced"
			}
			targets = append(targets, t)
		case !errors.Is(err, errNotBoringSSL):
			targets = append(targets, Target{Path: path, Library: OpenSSL, Problem: fmt.Errorf(
				"BoringSSL is linked in, but its functions couldn't be told apart (%w), so this build can't be traced; see docs/maintenance.md", err)})
		}
	}
	return targets, nil
}

func hostMachine() elf.Machine {
	if runtime.GOARCH == "arm64" {
		return elf.EM_AARCH64
	}
	return elf.EM_X86_64
}

// definedFuncs returns the names of the functions a file defines (as
// opposed to imports) among the ones we look for.
func definedFuncs(f *elf.File) map[string]bool {
	want := map[string]bool{}
	for _, rs := range readSymbols {
		want[rs.symbol] = true
	}

	out := map[string]bool{}
	add := func(syms []elf.Symbol) {
		for _, s := range syms {
			if want[s.Name] && s.Section != elf.SHN_UNDEF && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
				out[s.Name] = true
			}
		}
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		add(syms)
	}
	if syms, err := f.Symbols(); err == nil {
		add(syms)
	}
	return out
}

// inspectGo returns nil, nil if the file is not a Go binary or doesn't use
// crypto/tls.
func inspectGo(path string, f *elf.File) (*GoInfo, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, nil
	}

	gi := &GoInfo{Version: bi.GoVersion}
	if _, _, err := goFuncBounds(f, quicGoFunc); err == nil {
		for _, typ := range goAEADs {
			seal, err := FindGoFunc(f, typ+".Seal")
			if errors.Is(err, errNoFunc) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("%s.Seal: %w", typ, err)
			}
			open, err := FindGoFunc(f, typ+".Open")
			if err != nil {
				return nil, fmt.Errorf("%s.Open: %w", typ, err)
			}
			gi.Seals = append(gi.Seals, seal)
			gi.Opens = append(gi.Opens, open)
		}
	}

	read, err := FindGoFunc(f, goReadFunc)
	switch {
	case errors.Is(err, errNoFunc) && len(gi.Seals) == 0:
		return nil, nil
	case errors.Is(err, errNoFunc):
	case err != nil:
		return nil, fmt.Errorf("%s: %w", goReadFunc, err)
	default:
		write, err := FindGoFunc(f, goWriteFunc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", goWriteFunc, err)
		}
		gi.Read, gi.Write = read, write
	}

	// The register-based calling convention snoopy relies on arrived in
	// Go 1.17 on amd64 and Go 1.18 on arm64.
	minor := goMinorVersion(bi.GoVersion)
	if minor > 0 && (minor < 17 || (f.Machine == elf.EM_AARCH64 && minor < 18)) {
		return nil, fmt.Errorf("built with %s, which predates Go's register ABI", bi.GoVersion)
	}
	return gi, nil
}

// goMinorVersion turns "go1.22.3" into 22, or 0 if unknown.
func goMinorVersion(v string) int {
	v, ok := strings.CutPrefix(v, "go1.")
	if !ok {
		return 0
	}
	if i := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		v = v[:i]
	}
	n, _ := strconv.Atoi(v)
	return n
}

// FindGoFunc locates a Go function and its RET instructions. It uses the
// symbol table if present and falls back to .gopclntab, which survives
// stripping.
func FindGoFunc(f *elf.File, name string) (GoFunc, error) {
	start, end, err := goFuncBounds(f, name)
	if err != nil {
		return GoFunc{}, err
	}

	var text *elf.Section
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_EXECINSTR != 0 && s.Addr <= start && end <= s.Addr+s.Size {
			text = s
			break
		}
	}
	if text == nil {
		return GoFunc{}, fmt.Errorf("no executable section contains %#x", start)
	}
	code := make([]byte, end-start)
	if _, err := text.ReadAt(code, int64(start-text.Addr)); err != nil {
		return GoFunc{}, err
	}
	// A probe in the wrong place would corrupt the traced program, so make
	// sure this really is the start of a Go function.
	body, err := goBodyOffset(f.Machine, code)
	if err != nil {
		return GoFunc{}, fmt.Errorf("%s at %#x: %w", name, start, err)
	}

	rets, err := FindReturns(f.Machine, code)
	if err != nil {
		return GoFunc{}, err
	}
	off, err := fileOffset(f, start)
	if err != nil {
		return GoFunc{}, err
	}
	return GoFunc{Offset: off, Body: body, Returns: rets}, nil
}

func goFuncBounds(f *elf.File, name string) (start, end uint64, err error) {
	start, end, err = symtabBounds(f, name)
	if err == nil {
		return start, end, nil
	}
	return pclntabBounds(f, name)
}

func symtabBounds(f *elf.File, name string) (start, end uint64, err error) {
	syms, err := f.Symbols()
	if err != nil {
		return 0, 0, err
	}
	for _, s := range syms {
		if s.Name == name && s.Size > 0 {
			return s.Value, s.Value + s.Size, nil
		}
	}
	return 0, 0, errNoFunc
}

func pclntabBounds(f *elf.File, name string) (start, end uint64, err error) {
	pcln := f.Section(".gopclntab")
	text := f.Section(".text")
	if pcln == nil || text == nil {
		return 0, 0, errNoFunc
	}
	data, err := pcln.Data()
	if err != nil {
		return 0, 0, err
	}
	textStart := text.Addr
	if ts, ok := pclntabTextStart(data); ok {
		textStart = ts
	} else if ts, ok := moduledataTextStart(f, pcln.Addr, data); ok {
		textStart = ts
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, textStart))
	if err != nil {
		return 0, 0, err
	}
	fn := table.LookupFunc(name)
	if fn == nil {
		return 0, 0, errNoFunc
	}
	return fn.Entry, fn.End, nil
}

// pclntabTextStart returns the address of runtime.text recorded in a Go
// 1.18 to 1.25 pclntab header, which function offsets are relative to. It
// is not the start of .text when the program was linked externally (cgo),
// where C code comes first. Go 1.26 leaves the field zero, since it needed a
// relocation; moduledataTextStart finds the address then.
func pclntabTextStart(pclntab []byte) (uint64, bool) {
	// magic uint32; pad1, pad2, minLC, ptrSize uint8; nfunc int; nfiles uint; textStart uintptr
	if len(pclntab) < 8 {
		return 0, false
	}
	switch binary.LittleEndian.Uint32(pclntab) {
	case 0xfffffff0, 0xfffffff1: // Go 1.18-1.19, 1.20+
	default:
		return 0, false // older formats store absolute addresses
	}
	ptrSize := int(pclntab[7])
	off := 8 + 2*ptrSize
	if ptrSize != 8 || len(pclntab) < off+8 {
		return 0, false
	}
	ts := binary.LittleEndian.Uint64(pclntab[off:])
	return ts, ts != 0
}

// moduledataTextStart finds runtime.text in the runtime's moduledata for
// the main program: a struct in a data section whose first field points
// to the pclntab header, and whose text field is 22 words in (after
// pcHeader, six slices, findfunctab, minpc and maxpc), as it has been since
// Go 1.16. The pointer to the function name table, the next field, must
// agree with the header, and the address must be in executable code.
func moduledataTextStart(f *elf.File, pclntabAddr uint64, pclntab []byte) (uint64, bool) {
	const (
		funcnameOffsetAt = 32     // in the pcHeader, for 8-byte pointers
		textWord         = 22     // in the moduledata
		size             = 24 * 8 // through etext
	)
	if len(pclntab) < funcnameOffsetAt+8 || pclntab[7] != 8 {
		return 0, false
	}
	funcnametab := pclntabAddr + binary.LittleEndian.Uint64(pclntab[funcnameOffsetAt:])
	// .noptrdata, or .go.module when the system linker linked the program.
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_PROGBITS || sec.Flags&(elf.SHF_ALLOC|elf.SHF_WRITE) != elf.SHF_ALLOC|elf.SHF_WRITE {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		for off := 0; off+size <= len(data); off += 8 {
			word := func(i int) uint64 { return binary.LittleEndian.Uint64(data[off+8*i:]) }
			if word(0) != pclntabAddr || word(1) != funcnametab {
				continue
			}
			text, etext := word(textWord), word(textWord+1)
			if text < etext && inExecutableSection(f, text) {
				return text, true
			}
		}
	}
	return 0, false
}

func inExecutableSection(f *elf.File, addr uint64) bool {
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_EXECINSTR != 0 && addr >= s.Addr && addr < s.Addr+s.Size {
			return true
		}
	}
	return false
}

// goBodyOffset verifies that code starts like a Go function that checks for
// stack growth, comparing the stack pointer to g.stackguard0 (16 bytes into
// the g, which lives in R14 on amd64 and R28 on arm64) and branching to
// runtime.morestack. It returns the offset of the instruction after that
// branch. morestack grows the stack and restarts the function from its first
// instruction, so a probe there can fire twice for one call; after the
// branch, it fires once.
func goBodyOffset(machine elf.Machine, code []byte) (uint64, error) {
	switch machine {
	case elf.EM_X86_64:
		// [LEA R12, [RSP-framesize]]; CMP RSP or R12, [R14+16]; JBE morestack
		sawCheck := false
		for off, i := 0, 0; i < 3 && off < len(code); i++ {
			inst, err := x86asm.Decode(code[off:], 64)
			if err != nil {
				break
			}
			off += inst.Len
			if sawCheck {
				if inst.Op == x86asm.JBE {
					return uint64(off), nil
				}
				break
			}
			for _, arg := range inst.Args {
				if m, ok := arg.(x86asm.Mem); ok && inst.Op == x86asm.CMP && m.Base == x86asm.R14 && m.Disp == 16 {
					sawCheck = true
				}
			}
		}
	case elf.EM_AARCH64:
		// MOVD 16(R28), R16; [SUB $framesize, RSP, R17]; CMP R16, RSP or R17; BLS morestack
		if len(code) < 4 {
			break
		}
		if inst, err := arm64asm.Decode(code[:4]); err != nil || !strings.HasSuffix(inst.String(), "[X28,#16]") {
			break
		}
		for off := 4; off < 16 && off+4 <= len(code); off += 4 {
			inst, err := arm64asm.Decode(code[off : off+4])
			if err != nil {
				break
			}
			if c, ok := inst.Args[0].(arm64asm.Cond); ok && inst.Op == arm64asm.B && c.Value == 9 /* LS */ && !c.Invert {
				return uint64(off + 4), nil
			}
		}
	}
	return 0, errors.New("doesn't start with a Go stack check; not attaching")
}

// FindReturns returns the offsets of the return instructions in code.
func FindReturns(machine elf.Machine, code []byte) ([]uint64, error) {
	var rets []uint64
	switch machine {
	case elf.EM_X86_64:
		for off := 0; off < len(code); {
			inst, err := x86asm.Decode(code[off:], 64)
			if err != nil {
				off++
				continue
			}
			if inst.Op == x86asm.RET {
				rets = append(rets, uint64(off))
			}
			off += inst.Len
		}
	case elf.EM_AARCH64:
		for off := 0; off+4 <= len(code); off += 4 {
			inst, err := arm64asm.Decode(code[off : off+4])
			if err == nil && inst.Op == arm64asm.RET {
				rets = append(rets, uint64(off))
			}
		}
	default:
		return nil, fmt.Errorf("unsupported architecture %s", machine)
	}
	if len(rets) == 0 {
		return nil, errors.New("no return instructions found")
	}
	return rets, nil
}

// fileOffset converts a virtual address to an offset in the file, which is
// what uprobes are attached by.
func fileOffset(f *elf.File, addr uint64) (uint64, error) {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Vaddr <= addr && addr < p.Vaddr+p.Memsz {
			return addr - p.Vaddr + p.Off, nil
		}
	}
	return 0, fmt.Errorf("address %#x is not in an executable segment", addr)
}

// RustInfo locates rustls's plaintext in a Rust program. With rustls's
// default crypto provider, aws-lc-rs, that's where aws-lc encrypts and
// decrypts each record: its EVP_AEAD_CTX_seal and EVP_AEAD_CTX_open, C
// functions whose names aws-lc-sys prefixes with its version. With the ring
// provider, it's ring's AES-GCM and ChaCha20-Poly1305 functions, which ring
// calls through function pointers, so they're never inlined. Otherwise it's
// the read method of rustls's Reader and the write method of its Writer,
// mangled Rust symbols that async programs (tokio-rustls) inline away.
// There may be several of each if more than one version is linked in.
// Programs stripped of their symbol table can't be traced.
type RustInfo struct {
	Seals    []uint64 // file offsets of aws-lc's EVP_AEAD_CTX_seal
	Scatters []uint64 // EVP_AEAD_CTX_seal_scatter, which it uses for TLS 1.2
	Opens    []uint64 // and EVP_AEAD_CTX_open
	// File offsets of ring's aes_gcm_seal and chacha20_poly1305_seal, and
	// of their open functions.
	RingSeals []uint64
	RingOpens []uint64
	Reads     []uint64 // file offsets of <rustls Reader as Read>::read
	Writes    []uint64 // file offsets of <rustls Writer as Write>::write
}

// AtRecords reports whether the program's TLS is seen where its records
// are encrypted and decrypted, rather than at rustls's Reader and Writer.
func (ri *RustInfo) AtRecords() bool {
	return len(ri.Seals) > 0 && len(ri.Opens) > 0 || len(ri.RingSeals) > 0 && len(ri.RingOpens) > 0
}

// awsLCAEAD matches aws-lc's AEAD functions as aws-lc-sys names them, e.g.
// aws_lc_0_46_0_EVP_AEAD_CTX_open.
var awsLCAEAD = regexp.MustCompile(`^aws_lc_[0-9_]+_EVP_AEAD_CTX_(seal|open|seal_scatter)$`)

// ringAEAD matches ring's AEAD functions in either mangling (see below), e.g.
//
//	_RNvNtNtCs3UTaxMUTQMS_4ring4aead9algorithm12aes_gcm_seal
//	_ZN4ring4aead9algorithm22chacha20_poly1305_open17h0123456789abcdefE
var ringAEAD = regexp.MustCompile(`^_R.*4ring4aead9algorithm(12aes_gcm|22chacha20_poly1305)_(seal|open)$` +
	`|^_ZN4ring4aead9algorithm(12aes_gcm|22chacha20_poly1305)_(seal|open)17h[0-9a-f]{16}E$`)

// The symbols, in Rust's v0 mangling (the default since Rust 1.9x) and the
// legacy one, e.g.
//
//	_RNvXs2_NtNtCs1eO8RepwP5M_6rustls4conn10connectionNtB5_6ReaderNtNtNtCscoGKTY0KSTf_5alloc2io4read4Read4read
//	_ZN66_$LT$rustls..conn..connection..Reader$u20$as$u20$std..io..Read$GT$4read17h0123456789abcdefE
var (
	rustlsRead = regexp.MustCompile(`^_R.*6rustls.*4conn.*6Reader.*4Read4read$` +
		`|^_ZN.*rustls\.\.conn\.\.(connection\.\.)?Reader\$u20\$as\$u20\$[a-z]+\.\.io\.\.(read\.\.)?Read\$GT\$4read17h[0-9a-f]{16}E$`)
	rustlsWrite = regexp.MustCompile(`^_R.*6rustls.*4conn.*6Writer.*5Write5write$` +
		`|^_ZN.*rustls\.\.conn\.\.(connection\.\.)?Writer\$u20\$as\$u20\$[a-z]+\.\.io\.\.(write\.\.)?Write\$GT\$5write17h[0-9a-f]{16}E$`)
)

func inspectRustls(f *elf.File) *RustInfo {
	syms, err := f.Symbols()
	if err != nil {
		return nil
	}
	var ri RustInfo
	hasRustls := false
	for _, s := range syms {
		if s.Section == elf.SHN_UNDEF || elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			continue
		}
		var list *[]uint64
		switch {
		case strings.HasPrefix(s.Name, "aws_lc_") && awsLCAEAD.MatchString(s.Name):
			switch {
			case strings.HasSuffix(s.Name, "_seal"):
				list = &ri.Seals
			case strings.HasSuffix(s.Name, "_seal_scatter"):
				list = &ri.Scatters
			default:
				list = &ri.Opens
			}
		case strings.Contains(s.Name, "4ring4aead9algorithm") && ringAEAD.MatchString(s.Name):
			list = &ri.RingSeals
			if strings.Contains(s.Name, "_open") {
				list = &ri.RingOpens
			}
		case !strings.Contains(s.Name, "rustls"):
			continue
		case rustlsRead.MatchString(s.Name):
			list = &ri.Reads
		case rustlsWrite.MatchString(s.Name):
			list = &ri.Writes
		default:
			hasRustls = true
			continue
		}
		if off, err := fileOffset(f, s.Value); err == nil && !slices.Contains(*list, off) {
			*list = append(*list, off)
		}
	}
	hasRustls = hasRustls || len(ri.Reads) > 0 || len(ri.Writes) > 0
	if !hasRustls || !ri.AtRecords() && len(ri.Reads) == 0 && len(ri.Writes) == 0 {
		return nil // aws-lc or ring without rustls is another library's to trace
	}
	return &ri
}
