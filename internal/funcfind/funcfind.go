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
// Only x86-64 is supported. Function boundaries are found from frame
// pointer prologues at direct call targets, so functions without a frame
// pointer, or only ever called indirectly, aren't found.
package funcfind

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/arch/x86/x86asm"
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
	text     []byte // read by code()
	textAddr uint64
	data     []segment // allocated, non-executable sections; read by segments()
	loads    []elf.ProgHeader
	callers  map[uint64]int // direct call targets, built on first use
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
	if f.Machine != elf.EM_X86_64 {
		return nil, ErrUnsupported
	}
	text := f.Section(".text")
	if text == nil {
		return nil, errors.New("funcfind: no .text section")
	}
	b := &Binary{f: f, textAddr: text.Addr}
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
			start := bytes.LastIndexByte(s.data[:i], 0) + 1
			return s.addr + uint64(start), true
		}
	}
	return 0, false
}

// Refs returns the addresses of the instructions that load addr into a
// register: lea reg, [rip+disp].
func (b *Binary) Refs(addr uint64) []uint64 {
	var out []uint64
	code := b.code()
	for i := 0; i+7 <= len(code); i++ {
		// REX.W (+R) 8D /r with mod=00, r/m=101: RIP-relative.
		if (code[i] == 0x48 || code[i] == 0x4c) && code[i+1] == 0x8d && code[i+2]&0xc7 == 0x05 {
			pc := b.textAddr + uint64(i)
			if pc+7+uint64(int64(int32(binary.LittleEndian.Uint32(code[i+3:])))) == addr {
				out = append(out, pc)
			}
		}
	}
	return out
}

func (b *Binary) inText(a uint64) bool {
	return a >= b.textAddr && a < b.textAddr+uint64(len(b.code()))
}

// directCallers counts the direct call sites (call rel32) of each address.
func (b *Binary) directCallers() map[uint64]int {
	if b.callers != nil {
		return b.callers
	}
	b.callers = map[uint64]int{}
	code := b.code()
	for i := 0; i+5 <= len(code); i++ {
		if code[i] == 0xe8 {
			t := b.textAddr + uint64(i) + 5 + uint64(int64(int32(binary.LittleEndian.Uint32(code[i+1:]))))
			if b.inText(t) {
				b.callers[t]++
			}
		}
	}
	return b.callers
}

var (
	prologue       = []byte{0x55, 0x48, 0x89, 0xe5}                         // push rbp; mov rbp, rsp
	prologueEndbr  = []byte{0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5} // endbr64 first (CET)
	funcAlignment  = uint64(16)
	maxConstWindow = 6 // instructions after a reference searched for an argument
)

// isStart reports whether a function starts at a: it's aligned, opens with
// a frame pointer prologue, and is called directly.
func (b *Binary) isStart(a uint64) bool {
	if a%funcAlignment != 0 || !b.inText(a) || b.directCallers()[a] == 0 {
		return false
	}
	code := b.code()[a-b.textAddr:]
	return bytes.HasPrefix(code, prologue) || bytes.HasPrefix(code, prologueEndbr)
}

// FuncAt returns the function containing the instruction at pc.
func (b *Binary) FuncAt(pc uint64) (*Func, bool) {
	start := pc &^ (funcAlignment - 1)
	for start > b.textAddr && !b.isStart(start) && pc-start < maxFuncSize {
		start -= funcAlignment
	}
	if !b.isStart(start) {
		return nil, false
	}
	end := start + funcAlignment
	for b.inText(end) && !b.isStart(end) && end-start < maxFuncSize {
		end += funcAlignment
	}
	return &Func{Start: start, End: end, Callers: b.directCallers()[start]}, true
}

// insts decodes the instructions of fn, calling visit with each one and its
// address, until visit returns false. Undecodable bytes are skipped.
func (b *Binary) insts(fn *Func, visit func(ip uint64, inst x86asm.Inst) bool) {
	text := b.code()
	body := text[fn.Start-b.textAddr : min(fn.End, b.textAddr+uint64(len(text)))-b.textAddr]
	for off := 0; off < len(body); {
		inst, err := x86asm.Decode(body[off:], 64)
		if err != nil {
			off++
			continue
		}
		if !visit(fn.Start+uint64(off), inst) {
			return
		}
		off += inst.Len
	}
}

// Calls returns the targets of the direct calls in fn.
func (b *Binary) Calls(fn *Func) []uint64 {
	var out []uint64
	b.insts(fn, func(ip uint64, inst x86asm.Inst) bool {
		if inst.Op == x86asm.CALL {
			if rel, ok := inst.Args[0].(x86asm.Rel); ok {
				if t := ip + uint64(inst.Len) + uint64(int64(rel)); !slices.Contains(out, t) {
					out = append(out, t)
				}
			}
		}
		return true
	})
	return out
}

// argRegs are the integer argument registers of the System V calling
// convention, in their 32-bit forms, which constants are usually loaded
// into.
var argRegs = []x86asm.Reg{x86asm.EDI, x86asm.ESI, x86asm.EDX, x86asm.ECX, x86asm.R8L, x86asm.R9L}

// ConstArgsNear returns, for each reference in fn to addr, the constant
// loaded into call argument n (0-based) within the next few instructions,
// e.g. the error code passed along with a file name to an error-reporting
// function. References without such a constant are skipped.
func (b *Binary) ConstArgsNear(fn *Func, addr uint64, n int) ([]int64, error) {
	if n < 0 || n >= len(argRegs) {
		return nil, fmt.Errorf("funcfind: no argument register %d", n)
	}
	reg64 := map[x86asm.Reg]x86asm.Reg{x86asm.EDI: x86asm.RDI, x86asm.ESI: x86asm.RSI, x86asm.EDX: x86asm.RDX,
		x86asm.ECX: x86asm.RCX, x86asm.R8L: x86asm.R8, x86asm.R9L: x86asm.R9}[argRegs[n]]
	var out []int64
	after := -1
	b.insts(fn, func(ip uint64, inst x86asm.Inst) bool {
		if inst.Op == x86asm.LEA {
			if m, ok := inst.Args[1].(x86asm.Mem); ok && m.Base == x86asm.RIP &&
				ip+uint64(inst.Len)+uint64(int64(int32(m.Disp))) == addr {
				after = 0
				return true
			}
		}
		if after < 0 {
			return true
		}
		if inst.Op == x86asm.MOV && (inst.Args[0] == argRegs[n] || inst.Args[0] == reg64) {
			if imm, ok := inst.Args[1].(x86asm.Imm); ok {
				out = append(out, int64(imm))
				after = -1
				return true
			}
		}
		if after++; after > maxConstWindow || inst.Op == x86asm.CALL || inst.Op == x86asm.JMP || inst.Op == x86asm.RET {
			after = -1
		}
		return true
	})
	return out, nil
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

// argFamilies maps each size of the argument registers to its index.
var argFamilies = map[x86asm.Reg]int{
	x86asm.RDI: 0, x86asm.EDI: 0, x86asm.DI: 0, x86asm.DIB: 0,
	x86asm.RSI: 1, x86asm.ESI: 1, x86asm.SI: 1, x86asm.SIB: 1,
	x86asm.RDX: 2, x86asm.EDX: 2, x86asm.DX: 2, x86asm.DL: 2,
	x86asm.RCX: 3, x86asm.ECX: 3, x86asm.CX: 3, x86asm.CL: 3,
	x86asm.R8: 4, x86asm.R8L: 4, x86asm.R8W: 4, x86asm.R8B: 4,
	x86asm.R9: 5, x86asm.R9L: 5, x86asm.R9W: 5, x86asm.R9B: 5,
}

// ReadsArgs reports whether, on some path from fn's entry, it reads its
// first n argument registers before overwriting them or making a call,
// which would clobber them: whether it takes (and uses) at least n
// arguments. That tells a library function apart from a caller it was
// inlined into, which has a different signature. Both sides of conditional
// branches are followed, since an early error check may come first.
func (b *Binary) ReadsArgs(fn *Func, n int) bool {
	if n > len(argRegs) {
		return false
	}
	budget := 512 // instructions to look at, over all paths
	var walk func(ip uint64, read, dead uint8) bool
	walk = func(ip uint64, read, dead uint8) bool {
		all := uint8(1)<<n - 1
		for ; ip >= fn.Start && ip < fn.End && budget > 0; budget-- {
			inst, ok := b.decode(ip)
			if !ok {
				return false
			}
			// Registers read: every register operand except a destination
			// that is only written, and the base and index of memory operands.
			writeOnly, zeroing := false, false
			switch inst.Op {
			case x86asm.MOV, x86asm.MOVZX, x86asm.MOVSX, x86asm.MOVSXD, x86asm.LEA, x86asm.POP:
				writeOnly = true
			case x86asm.XOR, x86asm.SUB: // xor reg, reg zeroes it without reading it
				zeroing = inst.Args[0] != nil && inst.Args[0] == inst.Args[1]
				writeOnly = zeroing
			}
			mark := func(r x86asm.Reg) {
				if i, ok := argFamilies[r]; ok && i < n && dead&(1<<i) == 0 {
					read |= 1 << i
				}
			}
			for i, a := range inst.Args {
				if zeroing {
					break
				}
				switch a := a.(type) {
				case x86asm.Reg:
					if i > 0 || !writeOnly {
						mark(a)
					}
				case x86asm.Mem:
					mark(a.Base)
					mark(a.Index)
				}
			}
			if r, ok := inst.Args[0].(x86asm.Reg); ok && writeOnly {
				if i, ok := argFamilies[r]; ok && i < n && read&(1<<i) == 0 {
					dead |= 1 << i
				}
			}
			if read == all {
				return true
			}
			next := ip + uint64(inst.Len)
			switch inst.Op {
			case x86asm.CALL, x86asm.RET:
				return false // a call clobbers the argument registers
			case x86asm.JMP:
				rel, ok := inst.Args[0].(x86asm.Rel)
				if !ok {
					return false
				}
				next += uint64(int64(rel))
			case x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE, x86asm.JE, x86asm.JG, x86asm.JGE, x86asm.JL,
				x86asm.JLE, x86asm.JNE, x86asm.JNO, x86asm.JNP, x86asm.JNS, x86asm.JO, x86asm.JP, x86asm.JS:
				if rel, ok := inst.Args[0].(x86asm.Rel); ok && walk(next+uint64(int64(rel)), read, dead) {
					return true
				}
			}
			ip = next
		}
		return false
	}
	return walk(fn.Start, 0, 0)
}

// decode decodes the instruction at ip.
func (b *Binary) decode(ip uint64) (x86asm.Inst, bool) {
	text := b.code()
	if ip < b.textAddr || ip >= b.textAddr+uint64(len(text)) {
		return x86asm.Inst{}, false
	}
	inst, err := x86asm.Decode(text[ip-b.textAddr:], 64)
	return inst, err == nil
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
