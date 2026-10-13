package discover

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

// NSS's freebl library does the actual cryptography for everything built on
// NSS. Firefox's QUIC stack (neqo, through the nss_rs crate) calls its AES-GCM
// functions directly, not through any exported PK11_ or SSL_ function: it
// creates contexts with AES_CreateContext and seals and opens packets with
// AES_AEAD. Those aren't exported either, but FREEBL_GetVector is: it returns
// a table of freebl's functions (struct FREEBLVectorStr in lib/freebl/loader.h)
// whose layout is part of NSS's ABI, so entries keep their positions.
const (
	freeblVectorAESCreateContext = 31  // p_AES_CreateContext
	freeblVectorAESAEAD          = 238 // p_AES_AEAD, since FREEBL_VERSION 0x0322
)

// findFreebl returns the file offsets of AES_CreateContext and AES_AEAD in a
// freebl library.
func findFreebl(f *elf.File) (map[string]uint64, error) {
	syms, err := f.DynamicSymbols()
	if err != nil {
		return nil, err
	}
	var getVector *elf.Symbol
	for i, s := range syms {
		if s.Name == "FREEBL_GetVector" && s.Section != elf.SHN_UNDEF {
			getVector = &syms[i]
		}
	}
	if getVector == nil {
		return nil, errors.New("not freebl")
	}
	code, err := readAt(f, getVector.Value, 128)
	if err != nil {
		return nil, err
	}
	// FREEBL_GetVector returns the table's address, after a self-test: the
	// last address the function computes that holds a plausible header.
	var table uint64
	for _, addr := range loadedAddresses(f.Machine, getVector.Value, code) {
		if hdr, err := readAt(f, addr, 4); err == nil {
			length, version := binary.LittleEndian.Uint16(hdr), binary.LittleEndian.Uint16(hdr[2:])
			if version>>8 == 0x03 && int(length) >= 8+8*(freeblVectorAESAEAD-1) {
				table = addr
			}
		}
	}
	if table == 0 {
		return nil, errors.New("freebl: function table not found")
	}
	out := map[string]uint64{}
	for name, index := range map[string]int{"AES_CreateContext": freeblVectorAESCreateContext, "AES_AEAD": freeblVectorAESAEAD} {
		// Two unsigned shorts (length, version), then pointers from byte 8.
		addr, err := pointerAt(f, table+8+8*uint64(index-2))
		if err != nil {
			return nil, fmt.Errorf("freebl: %s: %w", name, err)
		}
		off, err := fileOffset(f, addr)
		if err != nil {
			return nil, fmt.Errorf("freebl: %s: %w", name, err)
		}
		out[name] = off
	}
	return out, nil
}

// loadedAddresses returns the addresses that code (starting at addr)
// computes PC-relatively: lea reg, [rip+disp] on x86-64; adr, and adrp
// followed by add, on arm64.
func loadedAddresses(machine elf.Machine, addr uint64, code []byte) []uint64 {
	var out []uint64
	switch machine {
	case elf.EM_X86_64:
		for off := 0; off < len(code); {
			if bytes.HasPrefix(code[off:], []byte{0xf3, 0x0f, 0x1e, 0xfa}) { // endbr64, unknown to x86asm
				off += 4
				continue
			}
			inst, err := x86asm.Decode(code[off:], 64)
			if err != nil {
				break
			}
			if m, ok := inst.Args[1].(x86asm.Mem); ok && inst.Op == x86asm.LEA && m.Base == x86asm.RIP {
				out = append(out, addr+uint64(off+inst.Len)+uint64(int64(int32(m.Disp))))
			}
			if inst.Op == x86asm.RET {
				break
			}
			off += inst.Len
		}
	case elf.EM_AARCH64:
		pages := map[arm64asm.Reg]uint64{}
		for off := 0; off+4 <= len(code); off += 4 {
			inst, err := arm64asm.Decode(code[off : off+4])
			if err != nil {
				continue
			}
			pc := addr + uint64(off)
			switch inst.Op {
			case arm64asm.ADR:
				if rel, ok := inst.Args[1].(arm64asm.PCRel); ok {
					out = append(out, pc+uint64(int64(rel)))
				}
			case arm64asm.ADRP:
				if rel, ok := inst.Args[1].(arm64asm.PCRel); ok {
					if r, ok := inst.Args[0].(arm64asm.Reg); ok {
						pages[r] = pc&^0xfff + uint64(int64(rel))
					}
				}
			case arm64asm.ADD:
				dst, ok1 := inst.Args[0].(arm64asm.RegSP)
				src, ok2 := inst.Args[1].(arm64asm.RegSP)
				imm, ok3 := inst.Args[2].(arm64asm.ImmShift)
				if page, known := pages[arm64asm.Reg(src)]; ok1 && ok2 && ok3 && known {
					out = append(out, page+uint64(immShiftValue(imm)))
					delete(pages, arm64asm.Reg(dst))
				}
			case arm64asm.RET:
				return out
			}
		}
	}
	return out
}

// immShiftValue returns the value of an arm64 "#imm, LSL #shift" operand.
func immShiftValue(imm arm64asm.ImmShift) uint64 {
	var v, shift uint64
	if _, err := fmt.Sscanf(imm.String(), "#%v, LSL #%v", &v, &shift); err == nil {
		return v << shift
	}
	if _, err := fmt.Sscanf(imm.String(), "#%v", &v); err == nil {
		return v
	}
	return 0
}

// readAt reads n bytes at a virtual address from the file.
func readAt(f *elf.File, addr uint64, n int) ([]byte, error) {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Vaddr <= addr && addr+uint64(n) <= p.Vaddr+p.Filesz {
			b := make([]byte, n)
			_, err := p.ReadAt(b, int64(addr-p.Vaddr))
			return b, err
		}
	}
	return nil, fmt.Errorf("address %#x not in the file", addr)
}

// pointerAt returns the value a pointer at addr has once relocated, relative
// to the load address: the addend of its R_*_RELATIVE relocation, or for
// packed (RELR) and REL relocations, the value stored in place.
func pointerAt(f *elf.File, addr uint64) (uint64, error) {
	relative := map[elf.Machine]uint32{elf.EM_X86_64: uint32(elf.R_X86_64_RELATIVE), elf.EM_AARCH64: uint32(elf.R_AARCH64_RELATIVE)}[f.Machine]
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		for i := 0; i+24 <= len(data); i += 24 {
			off := f.ByteOrder.Uint64(data[i:])
			info := f.ByteOrder.Uint64(data[i+8:])
			if off == addr && uint32(info) == relative {
				return f.ByteOrder.Uint64(data[i+16:]), nil
			}
		}
	}
	b, err := readAt(f, addr, 8)
	if err != nil {
		return 0, err
	}
	if v := f.ByteOrder.Uint64(b); v != 0 {
		return v, nil
	}
	return 0, fmt.Errorf("no relocated pointer at %#x", addr)
}
