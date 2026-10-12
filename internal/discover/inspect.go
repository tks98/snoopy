package discover

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
	"runtime"
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
}

const (
	goReadFunc  = "crypto/tls.(*Conn).Read"
	goWriteFunc = "crypto/tls.(*Conn).Write"
)

var (
	errNoFunc   = errors.New("function not found")
	errWrongArc = errors.New("built for a different architecture")
)

// GoInfo describes where to probe a Go binary's crypto/tls.
type GoInfo struct {
	Version string // Go version the binary was built with
	Read    GoFunc
	Write   GoFunc
}

// GoFunc locates one Go function inside an executable.
type GoFunc struct {
	Offset  uint64   // file offset of the function's first instruction
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
		targets = append(targets, Target{Path: path, Library: GoTLS, Go: gi})
	}

	defined := definedFuncs(f)
	for _, rs := range readSymbols {
		if defined[rs.symbol] {
			targets = append(targets, Target{Path: path, Library: rs.lib})
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

	read, err := FindGoFunc(f, goReadFunc)
	if errors.Is(err, errNoFunc) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", goReadFunc, err)
	}
	write, err := FindGoFunc(f, goWriteFunc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", goWriteFunc, err)
	}

	// The register-based calling convention snoopy relies on arrived in
	// Go 1.17 on amd64 and Go 1.18 on arm64.
	minor := goMinorVersion(bi.GoVersion)
	if minor > 0 && (minor < 17 || (f.Machine == elf.EM_AARCH64 && minor < 18)) {
		return nil, fmt.Errorf("built with %s, which predates Go's register ABI", bi.GoVersion)
	}
	return &GoInfo{Version: bi.GoVersion, Read: read, Write: write}, nil
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

	rets, err := FindReturns(f.Machine, code)
	if err != nil {
		return GoFunc{}, err
	}
	off, err := fileOffset(f, start)
	if err != nil {
		return GoFunc{}, err
	}
	return GoFunc{Offset: off, Returns: rets}, nil
}

func goFuncBounds(f *elf.File, name string) (start, end uint64, err error) {
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if s.Name == name && s.Size > 0 {
				return s.Value, s.Value + s.Size, nil
			}
		}
	}

	pcln := f.Section(".gopclntab")
	text := f.Section(".text")
	if pcln == nil || text == nil {
		return 0, 0, errNoFunc
	}
	data, err := pcln.Data()
	if err != nil {
		return 0, 0, err
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		return 0, 0, err
	}
	fn := table.LookupFunc(name)
	if fn == nil {
		return 0, 0, errNoFunc
	}
	return fn.Entry, fn.End, nil
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
