package funcfind

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"

	"golang.org/x/arch/x86/x86asm"
)

var (
	prologue       = []byte{0x55, 0x48, 0x89, 0xe5}                         // push rbp; mov rbp, rsp
	prologueEndbr  = []byte{0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5} // endbr64 first (CET)
	maxConstWindow = 6                                                      // instructions after a reference searched for an argument
)

// x86Align is the alignment of functions, as compilers pad them.
const x86Align = 16

// x86Refs finds the instructions loading addr into a register: lea reg,
// [rip+disp] in position-independent code, and in a program that isn't
// (Bun's), where addresses fit in 32 bits, mov r32, imm32.
func (b *Binary) x86Refs(addr uint64) []uint64 {
	var out []uint64
	code := b.code()
	abs := b.absolute && addr < 1<<32
	for i := 0; i+7 <= len(code); i++ {
		pc := b.textAddr + uint64(i)
		// REX.W (+R) 8D /r with mod=00, r/m=101: RIP-relative.
		if (code[i] == 0x48 || code[i] == 0x4c) && code[i+1] == 0x8d && code[i+2]&0xc7 == 0x05 {
			if pc+7+uint64(int64(int32(binary.LittleEndian.Uint32(code[i+3:])))) == addr {
				out = append(out, pc)
			}
		}
		// B8+rd id, or with REX.B (41) for r8d to r15d.
		if abs && code[i]&0xf8 == 0xb8 && uint64(binary.LittleEndian.Uint32(code[i+1:])) == addr {
			if i > 0 && code[i-1] == 0x41 {
				pc--
			}
			out = append(out, pc)
		}
	}
	return out
}

// x86LoadsAddr reports whether inst, at ip, loads addr into a register,
// as an immediate too if abs (see Binary.absolute).
func x86LoadsAddr(ip uint64, inst x86asm.Inst, addr uint64, abs bool) bool {
	switch inst.Op {
	case x86asm.LEA:
		m, ok := inst.Args[1].(x86asm.Mem)
		return ok && m.Base == x86asm.RIP && ip+uint64(inst.Len)+uint64(int64(int32(m.Disp))) == addr
	case x86asm.MOV:
		_, isReg := inst.Args[0].(x86asm.Reg)
		imm, ok := inst.Args[1].(x86asm.Imm)
		return abs && isReg && ok && uint64(uint32(imm)) == addr && addr < 1<<32
	}
	return false
}

// x86Callers counts the direct call sites (call rel32) of each address.
func (b *Binary) x86Callers() map[uint64]int {
	callers := map[uint64]int{}
	code := b.code()
	for i := 0; i+5 <= len(code); i++ {
		if code[i] == 0xe8 {
			t := b.textAddr + uint64(i) + 5 + uint64(int64(int32(binary.LittleEndian.Uint32(code[i+1:]))))
			if b.inText(t) && (len(callers) < maxCallTargets || callers[t] > 0) {
				callers[t]++
			}
		}
	}
	return callers
}

// x86Prologue reports whether the code at a opens with a frame pointer
// prologue.
func (b *Binary) x86Prologue(a uint64) bool {
	if !b.inText(a) {
		return false
	}
	code := b.code()[a-b.textAddr:]
	return bytes.HasPrefix(code, prologue) || bytes.HasPrefix(code, prologueEndbr)
}

// insts decodes the instructions of fn, calling visit with each one and its
// address, until visit returns false. Undecodable bytes are skipped.
func (b *Binary) insts(fn *Func, visit func(ip uint64, inst x86asm.Inst) bool) {
	end := min(fn.End, b.textEnd())
	if fn.Start < b.textAddr || fn.Start >= end {
		return
	}
	body := b.code()[fn.Start-b.textAddr : end-b.textAddr]
	for off := 0; off < len(body); {
		inst, err := decodeX86(body[off:])
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

func (b *Binary) x86Calls(fn *Func) []uint64 {
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

func (b *Binary) x86ConstArgsNear(fn *Func, addr uint64, n int) ([]int64, error) {
	if n < 0 || n >= len(argRegs) {
		return nil, fmt.Errorf("funcfind: no argument register %d", n)
	}
	reg64 := map[x86asm.Reg]x86asm.Reg{x86asm.EDI: x86asm.RDI, x86asm.ESI: x86asm.RSI, x86asm.EDX: x86asm.RDX,
		x86asm.ECX: x86asm.RCX, x86asm.R8L: x86asm.R8, x86asm.R9L: x86asm.R9}[argRegs[n]]
	var out []int64
	after := -1
	b.insts(fn, func(ip uint64, inst x86asm.Inst) bool {
		if x86LoadsAddr(ip, inst, addr, b.absolute) {
			after = 0
			return true
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

// argFamilies maps each size of the argument registers to its index.
var argFamilies = map[x86asm.Reg]int{
	x86asm.RDI: 0, x86asm.EDI: 0, x86asm.DI: 0, x86asm.DIB: 0,
	x86asm.RSI: 1, x86asm.ESI: 1, x86asm.SI: 1, x86asm.SIB: 1,
	x86asm.RDX: 2, x86asm.EDX: 2, x86asm.DX: 2, x86asm.DL: 2,
	x86asm.RCX: 3, x86asm.ECX: 3, x86asm.CX: 3, x86asm.CL: 3,
	x86asm.R8: 4, x86asm.R8L: 4, x86asm.R8W: 4, x86asm.R8B: 4,
	x86asm.R9: 5, x86asm.R9L: 5, x86asm.R9W: 5, x86asm.R9B: 5,
}

func (b *Binary) x86ReadsArgs(fn *Func, n int) bool {
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
	inst, err := decodeX86(text[ip-b.textAddr:])
	return inst, err == nil
}

var endbr64 = []byte{0xf3, 0x0f, 0x1e, 0xfa}

// decodeX86 decodes one instruction, including endbr64 (CET builds start
// functions with it), which x86asm doesn't know: it's decoded as a no-op.
func decodeX86(code []byte) (x86asm.Inst, error) {
	if bytes.HasPrefix(code, endbr64) {
		return x86asm.Inst{Op: x86asm.NOP, Len: len(endbr64)}, nil
	}
	return x86asm.Decode(code, 64)
}

// x86StackArgs counts stack arguments read, which with a frame pointer are
// at [rbp+16], [rbp+24] and so on.
func (b *Binary) x86StackArgs(fn *Func) int {
	most := 0
	b.insts(fn, func(ip uint64, inst x86asm.Inst) bool {
		for _, a := range inst.Args {
			if m, ok := a.(x86asm.Mem); ok && m.Base == x86asm.RBP && m.Index == 0 {
				if d := int64(int32(m.Disp)); d >= 16 && (d-16)%8 == 0 && d < 16+8*64 {
					most = max(most, len(argRegs)+int(d-16)/8+1)
				}
			}
		}
		return true
	})
	return most
}
