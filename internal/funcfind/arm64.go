package funcfind

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

// Instructions are 4 bytes and aligned, and so are functions.
const arm64Align = 4

const (
	arm64ArgRegs     = 8 // x0-x7
	arm64RefWindow   = 8 // instructions after an adrp searched for its add
	arm64ConstWindow = 8 // instructions after a reference searched for an argument
	arm64Paciasp     = 0xd503233f
	arm64BtiC        = 0xd503245f
	arm64BtiJC       = 0xd50324df
	arm64Nop         = 0xd503201f
)

func (b *Binary) word(a uint64) (uint32, bool) {
	code := b.code()
	if a < b.textAddr || a+4 > b.textAddr+uint64(len(code)) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(code[a-b.textAddr:]), true
}

func (b *Binary) arm64Decode(a uint64) (arm64asm.Inst, bool) {
	code := b.code()
	if a < b.textAddr || a+4 > b.textAddr+uint64(len(code)) {
		return arm64asm.Inst{}, false
	}
	inst, err := arm64asm.Decode(code[a-b.textAddr:])
	return inst, err == nil
}

// arm64Refs finds the adrp and add pairs that compute addr, returning the
// adds' addresses (or the adrp's, for an address at the start of a page).
func (b *Binary) arm64Refs(addr uint64) []uint64 {
	return b.arm64RefsIn(b.textAddr, b.textAddr+uint64(len(b.code())), addr)
}

func (b *Binary) arm64RefsIn(start, end, addr uint64) []uint64 {
	var out []uint64
	code := b.code()[start-b.textAddr : end-b.textAddr]
	page, lo := addr&^0xfff, uint32(addr&0xfff)
	for i := 0; i+4 <= len(code); i += 4 {
		w := binary.LittleEndian.Uint32(code[i:])
		if w&0x9f000000 != 0x90000000 { // adrp xd, page
			continue
		}
		pc := start + uint64(i)
		imm := int64(w>>29&3|(w>>5&0x7ffff)<<2) << 43 >> 31 // sign-extended, times 4096
		if pc&^0xfff+uint64(imm) != page {
			continue
		}
		if lo == 0 {
			out = append(out, pc)
			continue
		}
		rd := w & 31
		for j := i + 4; j < i+4*arm64RefWindow && j+4 <= len(code); j += 4 {
			v := binary.LittleEndian.Uint32(code[j:])
			if v&0xffc00000 == 0x91000000 && v>>5&31 == rd && v>>10&0xfff == lo { // add xd, xn, #lo
				out = append(out, start+uint64(j))
				break
			}
		}
	}
	return out
}

// arm64Callers counts the direct call sites (bl) of each address.
func (b *Binary) arm64Callers() map[uint64]int {
	callers := map[uint64]int{}
	code := b.code()
	for i := 0; i+4 <= len(code); i += 4 {
		if w := binary.LittleEndian.Uint32(code[i:]); w&0xfc000000 == 0x94000000 {
			t := b.textAddr + uint64(i) + uint64(int64(w&0x3ffffff)<<38>>36)
			if b.inText(t) {
				callers[t]++
			}
		}
	}
	return callers
}

// arm64Entry reports whether a function that might not be called directly
// starts at a: with branch protection, functions start with paciasp or bti,
// and this one follows an unconditional branch or return (and padding).
func (b *Binary) arm64Entry(a uint64) bool {
	if w, ok := b.word(a); !ok || w != arm64Paciasp && w != arm64BtiC && w != arm64BtiJC {
		return false
	}
	for p := a - 4; p >= b.textAddr && a-p <= 64; p -= 4 {
		v, _ := b.word(p)
		switch {
		case v == arm64Nop || v == 0: // padding
		case v&0xfffffc1f == 0xd65f0000, v == 0xd65f0bff, v == 0xd65f0fff: // ret, retaa, retab
			return true
		case v&0xfc000000 == 0x14000000, v&0xfffffc1f == 0xd61f0000: // b, br
			return true
		case v&0xffe0001f == 0xd4200000: // brk
			return true
		default:
			return false
		}
	}
	return false
}

func (b *Binary) arm64Calls(fn *Func) []uint64 {
	var out []uint64
	for a := fn.Start; a < fn.End; a += 4 {
		if w, ok := b.word(a); ok && w&0xfc000000 == 0x94000000 {
			if t := a + uint64(int64(w&0x3ffffff)<<38>>36); !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	return out
}

func (b *Binary) arm64ConstArgsNear(fn *Func, addr uint64, n int) ([]int64, error) {
	if n < 0 || n >= arm64ArgRegs {
		return nil, fmt.Errorf("funcfind: no argument register %d", n)
	}
	var out []int64
	for _, ref := range b.arm64RefsIn(fn.Start, fn.End, addr) {
		for a := ref + 4; a < fn.End && a < ref+4+4*arm64ConstWindow; a += 4 {
			inst, ok := b.arm64Decode(a)
			if !ok || arm64Branches(inst.Op) {
				break
			}
			if v, ok := arm64Const(inst, n); ok {
				out = append(out, v)
				break
			}
			if _, written := arm64Operands(inst); written&(1<<n) != 0 {
				break // set to something else
			}
		}
	}
	return out, nil
}

// arm64Const returns the constant that inst moves into register n.
func arm64Const(inst arm64asm.Inst, n int) (int64, bool) {
	if inst.Op != arm64asm.MOV {
		return 0, false
	}
	if r, ok := inst.Args[0].(arm64asm.Reg); !ok || gpr(r) != n {
		return 0, false
	}
	switch v := inst.Args[1].(type) {
	case arm64asm.Imm:
		if r := inst.Args[0].(arm64asm.Reg); r >= arm64asm.W0 && r <= arm64asm.W30 {
			return int64(int32(v.Imm)), true
		}
		return int64(v.Imm), true
	case arm64asm.Imm64:
		return int64(v.Imm), true
	case arm64asm.Reg:
		if v == arm64asm.WZR || v == arm64asm.XZR {
			return 0, true
		}
	}
	return 0, false
}

// gpr returns the number of a general-purpose register, or -1.
func gpr(r arm64asm.Reg) int {
	switch {
	case r >= arm64asm.W0 && r <= arm64asm.W30:
		return int(r - arm64asm.W0)
	case r >= arm64asm.X0 && r <= arm64asm.X30:
		return int(r - arm64asm.X0)
	}
	return -1
}

var gprName = regexp.MustCompile(`\b[WX]([0-9]+)\b`)

// arm64Operands returns the argument registers (x0-x7) that an instruction
// reads and writes, as bit sets.
func arm64Operands(inst arm64asm.Inst) (read, written uint8) {
	op := inst.Op.String()
	dests := 1 // leading operands that are only written
	switch {
	case strings.HasPrefix(op, "ST") && !strings.HasPrefix(op, "STX") && !strings.HasPrefix(op, "STLX"),
		arm64Branches(inst.Op), slices.Contains([]string{"CMP", "CMN", "TST", "CCMP", "CCMN", "HINT", "NOP",
			"PRFM", "PRFUM", "DMB", "DSB", "ISB", "MSR", "SYS", "BRK", "SVC"}, op):
		dests = 0
	case slices.Contains([]string{"LDP", "LDNP", "LDPSW", "LDXP", "LDAXP"}, op):
		dests = 2
	case slices.Contains([]string{"MOVK", "BFI", "BFXIL", "BFM"}, op): // write part of the register
		dests = 0
		if r, ok := inst.Args[0].(arm64asm.Reg); ok && gpr(r) >= 0 && gpr(r) < arm64ArgRegs {
			written |= 1 << gpr(r)
		}
	}
	for i, a := range inst.Args {
		if a == nil {
			break
		}
		if i < dests {
			if r, ok := a.(arm64asm.Reg); ok && gpr(r) >= 0 && gpr(r) < arm64ArgRegs {
				written |= 1 << gpr(r)
			}
			continue
		}
		var regs []int
		if r, ok := a.(arm64asm.Reg); ok {
			regs = []int{gpr(r)}
		} else {
			for _, m := range gprName.FindAllStringSubmatch(a.String(), -1) {
				n, _ := strconv.Atoi(m[1])
				regs = append(regs, n)
			}
		}
		for _, r := range regs {
			if r >= 0 && r < arm64ArgRegs {
				read |= 1 << r
			}
		}
	}
	return read, written
}

// arm64Branches reports whether op changes the flow of control.
func arm64Branches(op arm64asm.Op) bool {
	switch op {
	case arm64asm.B, arm64asm.BL, arm64asm.BR, arm64asm.BLR, arm64asm.RET,
		arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ:
		return true
	}
	return false
}

// pcRel returns the target of a branch at ip.
func pcRel(ip uint64, inst arm64asm.Inst) (uint64, bool) {
	for _, a := range inst.Args {
		if rel, ok := a.(arm64asm.PCRel); ok {
			return ip + uint64(int64(rel)), true
		}
	}
	return 0, false
}

func (b *Binary) arm64ReadsArgs(fn *Func, n int) bool {
	if n > arm64ArgRegs {
		return false
	}
	all := uint8(1)<<n - 1
	budget := 512 // instructions to look at, over all paths
	var walk func(ip uint64, read, dead uint8) bool
	walk = func(ip uint64, read, dead uint8) bool {
		for ; ip >= fn.Start && ip < fn.End && budget > 0; budget-- {
			inst, ok := b.arm64Decode(ip)
			if !ok {
				return false
			}
			r, w := arm64Operands(inst)
			read |= r &^ dead & all
			dead |= w &^ read & all
			if read == all {
				return true
			}
			next := ip + 4
			switch inst.Op {
			case arm64asm.BL, arm64asm.BLR, arm64asm.BR, arm64asm.RET:
				return false // a call clobbers the argument registers
			case arm64asm.B:
				target, ok := pcRel(ip, inst)
				if !ok {
					return false
				}
				if _, conditional := inst.Args[0].(arm64asm.Cond); !conditional {
					next = target
				} else if walk(target, read, dead) {
					return true
				}
			case arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ:
				if target, ok := pcRel(ip, inst); ok && walk(target, read, dead) {
					return true
				}
			}
			ip = next
		}
		return false
	}
	return walk(fn.Start, 0, 0)
}

var (
	frameMem   = regexp.MustCompile(`\[(SP|X29)(?:,#(-?[0-9]+))?\]`)
	immOperand = regexp.MustCompile(`^#(0x[0-9a-f]+|[0-9]+)(?:, LSL #([0-9]+))?$`)
)

// imm returns the value of an immediate operand, e.g. "#0x40, LSL #12".
func imm(a arm64asm.Arg) (int64, bool) {
	m := immOperand.FindStringSubmatch(a.String())
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseInt(m[1], 0, 64)
	if err != nil {
		return 0, false
	}
	if m[2] != "" {
		shift, _ := strconv.Atoi(m[2])
		v <<= shift
	}
	return v, true
}

// arm64StackArgs counts the stack arguments read. They are at the stack
// pointer on entry: the prologue's frame setup gives where that is relative
// to sp and the frame pointer, x29, afterwards.
func (b *Binary) arm64StackArgs(fn *Func) int {
	var spDelta, fpDelta int64 = 0, -1 // how far below the entry sp they point
	inPrologue := true
	most := 0
	for a := fn.Start; a < fn.End; a += 4 {
		inst, ok := b.arm64Decode(a)
		if !ok {
			continue
		}
		s := inst.String()
		if inPrologue {
			switch {
			case arm64Branches(inst.Op):
				inPrologue = false
			case inst.Op == arm64asm.SUB && strings.HasPrefix(s, "SUB SP, SP, #"):
				if v, ok := imm(inst.Args[2]); ok {
					spDelta += v
				}
			case strings.HasPrefix(s, "STP ") || strings.HasPrefix(s, "STR "):
				if m := frameMem.FindStringSubmatch(s); m != nil && m[1] == "SP" && strings.HasSuffix(s, "]!") {
					v, _ := strconv.ParseInt(m[2], 10, 64)
					spDelta -= v // pre-indexed: [sp, #-n]!
				}
			case strings.HasPrefix(s, "ADD X29, SP, #"):
				if v, ok := imm(inst.Args[2]); ok {
					fpDelta = spDelta - v
				}
			case s == "MOV X29, SP":
				fpDelta = spDelta
			}
		}
		if !strings.HasPrefix(s, "LD") || strings.HasSuffix(s, "]!") || strings.Contains(s, "],") {
			continue // not a load, or one that moves the base register
		}
		m := frameMem.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		off, _ := strconv.ParseInt(m[2], 10, 64)
		delta := spDelta
		if m[1] == "X29" {
			if delta = fpDelta; delta < 0 {
				continue
			}
		}
		if off < delta || off >= delta+8*64 || (off-delta)%8 != 0 {
			continue
		}
		slots := 1
		if strings.HasPrefix(s, "LDP X") {
			slots = 2
		}
		most = max(most, arm64ArgRegs+int(off-delta)/8+slots)
	}
	return most
}
