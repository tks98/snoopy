// Package funcfind locates functions in stripped binaries by what they
// reference. A function without a symbol still loads the addresses of the
// strings it uses (an error message, a source file name) and still passes
// the same constants to the functions it calls, so a library's functions can
// be recognized from those, independently of the compiler's code layout.
//
// The building blocks are generic: find a string, the instructions that
// load its address, the functions containing them, and the constants passed
// as call arguments right after. A signature for a particular library
// combines them (see discover's BoringSSL support).
//
// x86-64 and arm64 are supported. Functions start at direct call targets
// (with a frame pointer prologue, on x86-64), so functions only ever called
// indirectly aren't found; an x86-64 binary built without frame pointers
// has its functions start where its table of their unwind information
// (.eh_frame_hdr) says.
package funcfind

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
)

// ErrUnsupported means the binary's architecture isn't supported.
var ErrUnsupported = errors.New("funcfind: unsupported architecture")

// maxFuncSize bounds how far a function's start or end is searched for.
const maxFuncSize = 64 << 10

// Binary is the code and read-only data of an ELF file, indexed for search.
// Sections are read when first needed, so a binary that doesn't contain the
// string a search starts from costs little more than reading its data.
type Binary struct {
	f        *elf.File
	arm64    bool
	text     []byte // read by code()
	textAddr uint64
	data     []segment // allocated, non-executable sections; read by segments()
	loads    []elf.ProgHeader
	callers  map[uint64]int // direct call targets, built on first use
	starts   []uint64       // x86-64 functions' starts from .eh_frame_hdr, read by fdeStarts()
	fdes     int            // whether to use starts: 0 not decided yet, 1 yes, -1 no
	// absolute is set for an executable that isn't position-independent,
	// whose code can load an address as a 32-bit immediate.
	absolute bool
}

type segment struct {
	addr uint64
	data []byte
}

// Func is a function found in a Binary.
type Func struct {
	Start, End uint64 // [Start, End): End is where the next function starts
	Callers    int    // number of direct call sites
}

// Size is the function's size in bytes, including any padding at its end.
func (fn *Func) Size() uint64 { return fn.End - fn.Start }

// Open prepares f for searching. f must stay open while the Binary is used.
func Open(f *elf.File) (*Binary, error) {
	if f.Machine != elf.EM_X86_64 && f.Machine != elf.EM_AARCH64 {
		return nil, ErrUnsupported
	}
	text := f.Section(".text")
	if text == nil {
		return nil, errors.New("funcfind: no .text section")
	}
	b := &Binary{f: f, arm64: f.Machine == elf.EM_AARCH64, textAddr: text.Addr, absolute: f.Type == elf.ET_EXEC}
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			b.loads = append(b.loads, p.ProgHeader)
		}
	}
	return b, nil
}

func (b *Binary) segments() []segment {
	if b.data == nil && b.f != nil {
		b.data = []segment{}
		for _, s := range b.f.Sections {
			if s.Type != elf.SHT_PROGBITS || s.Flags&elf.SHF_ALLOC == 0 || s.Flags&elf.SHF_EXECINSTR != 0 {
				continue
			}
			if d, err := s.Data(); err == nil {
				b.data = append(b.data, segment{s.Addr, d})
			}
		}
	}
	return b.data
}

func (b *Binary) code() []byte {
	if b.text == nil && b.f != nil {
		b.text, _ = b.f.Section(".text").Data()
	}
	return b.text
}

// FindString returns the address of the first NUL-terminated string in the
// binary's data that ends with suffix (e.g. a source file name, whose
// directory depends on the build).
func (b *Binary) FindString(suffix string) (uint64, bool) {
	needle := append([]byte(suffix), 0)
	for _, s := range b.segments() {
		if i := bytes.Index(s.data, needle); i >= 0 {
			// Back to the string's start: the bytes before it may be other
			// data, with no NUL in between (Conscrypt's x86-64 build has a
			// table there).
			start := i
			for start > 0 && s.data[start-1] >= 0x20 && s.data[start-1] < 0x7f {
				start--
			}
			return s.addr + uint64(start), true
		}
	}
	return 0, false
}

// Refs returns the addresses of the instructions that load addr into a
// register: lea reg, [rip+disp] on x86-64; on arm64, the add that completes
// an adrp and add pair.
func (b *Binary) Refs(addr uint64) []uint64 {
	if b.arm64 {
		return b.arm64Refs(addr)
	}
	return b.x86Refs(addr)
}

func (b *Binary) inText(a uint64) bool {
	return a >= b.textAddr && a < b.textAddr+uint64(len(b.code()))
}

// directCallers counts the direct call sites of each address.
func (b *Binary) directCallers() map[uint64]int {
	if b.callers == nil {
		if b.arm64 {
			b.callers = b.arm64Callers()
		} else {
			b.callers = b.x86Callers()
		}
	}
	return b.callers
}

func (b *Binary) align() uint64 {
	if b.arm64 {
		return arm64Align
	}
	return x86Align
}

// isStart reports whether a function starts at a.
func (b *Binary) isStart(a uint64) bool {
	if a%b.align() != 0 || !b.inText(a) || b.directCallers()[a] == 0 {
		return false
	}
	return b.arm64 || b.x86Prologue(a)
}

// isBoundary reports whether a function starts at a, as far as finding the
// end of the one before goes: that includes functions that aren't called
// directly, where they're recognizable.
func (b *Binary) isBoundary(a uint64) bool {
	return b.isStart(a) || b.arm64 && b.arm64Entry(a)
}

// FuncAt returns the function containing the instruction at pc.
func (b *Binary) FuncAt(pc uint64) (*Func, bool) {
	if b.useFDEs() {
		return b.fdeFuncAt(pc)
	}
	align := b.align()
	start := pc &^ (align - 1)
	for start > b.textAddr && !b.isStart(start) && pc-start < maxFuncSize {
		start -= align
	}
	if !b.isStart(start) {
		return nil, false
	}
	end := start + align
	for b.inText(end) && !b.isBoundary(end) && end-start < maxFuncSize {
		end += align
	}
	if pc >= end { // in a function that isn't called directly
		return nil, false
	}
	return &Func{Start: start, End: end, Callers: b.directCallers()[start]}, true
}

// Calls returns the targets of the direct calls in fn.
func (b *Binary) Calls(fn *Func) []uint64 {
	if b.arm64 {
		return b.arm64Calls(fn)
	}
	return b.x86Calls(fn)
}

// ConstArgsNear returns, for each reference in fn to addr, the constant
// loaded into call argument n (0-based) within the next few instructions,
// e.g. the error code passed along with a file name to an error-reporting
// function. References without such a constant are skipped.
func (b *Binary) ConstArgsNear(fn *Func, addr uint64, n int) ([]int64, error) {
	if b.arm64 {
		return b.arm64ConstArgsNear(fn, addr, n)
	}
	return b.x86ConstArgsNear(fn, addr, n)
}

// ReadsArgs reports whether, on some path from fn's entry, it reads its
// first n argument registers before overwriting them or making a call,
// which would clobber them: whether it takes (and uses) at least n
// arguments. That tells a library function apart from a caller it was
// inlined into, which has a different signature. Both sides of conditional
// branches are followed, since an early error check may come first.
func (b *Binary) ReadsArgs(fn *Func, n int) bool {
	if b.arm64 {
		return b.arm64ReadsArgs(fn, n)
	}
	return b.x86ReadsArgs(fn, n)
}

// StackArgs returns how many arguments fn takes in all, judging by the
// stack arguments it reads: the first six (x86-64) or eight (arm64) are
// passed in registers and the rest on the stack. A function that reads none
// returns 0.
func (b *Binary) StackArgs(fn *Func) int {
	if b.arm64 {
		return b.arm64StackArgs(fn)
	}
	return b.x86StackArgs(fn)
}

// FileOffset converts an address to an offset in the file, which is what
// uprobes are attached by.
func (b *Binary) FileOffset(addr uint64) (uint64, error) {
	for _, p := range b.loads {
		if p.Flags&elf.PF_X != 0 && p.Vaddr <= addr && addr < p.Vaddr+p.Filesz {
			return addr - p.Vaddr + p.Off, nil
		}
	}
	return 0, fmt.Errorf("funcfind: address %#x is not in an executable segment", addr)
}

// BuildID returns the GNU build ID of f, which identifies its exact build,
// or nil if it has none.
func BuildID(f *elf.File) []byte {
	for _, p := range f.Progs {
		if p.Type != elf.PT_NOTE {
			continue
		}
		data, err := io.ReadAll(p.Open())
		if err != nil {
			continue
		}
		// Notes: namesz, descsz, type (4 bytes each), name, desc; 4-byte aligned.
		for len(data) >= 12 {
			namesz := f.ByteOrder.Uint32(data[0:])
			descsz := f.ByteOrder.Uint32(data[4:])
			typ := f.ByteOrder.Uint32(data[8:])
			nameEnd := 12 + (int(namesz)+3)&^3
			descEnd := nameEnd + (int(descsz)+3)&^3
			if nameEnd > len(data) || descEnd > len(data) {
				break
			}
			if typ == 3 /* NT_GNU_BUILD_ID */ && string(data[12:12+namesz]) == "GNU\x00" {
				return data[nameEnd : nameEnd+int(descsz)]
			}
			data = data[descEnd:]
		}
	}
	return nil
}
