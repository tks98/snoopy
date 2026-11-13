package funcfind

import (
	"encoding/binary"
	"slices"
)

// Pointer encodings (DW_EH_PE_*) used in .eh_frame_hdr.
const (
	ehUdata4  = 0x03
	ehSdata4  = 0x0b
	ehUdata8  = 0x04
	ehSdata8  = 0x0c
	ehDatarel = 0x30
)

// fdeStarts returns the start of every function that has unwind
// information, from the binary search table in .eh_frame_hdr, sorted, or
// nil without one. Shared libraries and most programs have it, also when
// they're stripped and built without frame pointers (Conscrypt's x86-64
// build), which leaves call targets and prologues as the only other way to
// tell where functions start.
func (b *Binary) fdeStarts() []uint64 {
	if b.starts != nil || b.f == nil {
		return b.starts
	}
	b.starts = []uint64{}
	s := b.f.Section(".eh_frame_hdr")
	if s == nil || !readable(s) {
		return b.starts
	}
	d, err := s.Data()
	if err != nil {
		return b.starts
	}
	for _, a := range ehFrameHdrStarts(s.Addr, d) {
		if b.inText(a) {
			b.starts = append(b.starts, a)
		}
	}
	slices.Sort(b.starts)
	b.starts = slices.Compact(b.starts)
	return b.starts
}

// fdeFuncAt returns the function containing pc by fdeStarts: it ends where
// the next one starts.
func (b *Binary) fdeFuncAt(pc uint64) (*Func, bool) {
	starts := b.fdeStarts()
	i, found := slices.BinarySearch(starts, pc)
	if !found {
		i--
	}
	if i < 0 || !b.inText(pc) {
		return nil, false
	}
	end := b.textEnd()
	if i+1 < len(starts) {
		end = starts[i+1]
	}
	if end-starts[i] > maxFuncSize {
		return nil, false
	}
	return &Func{Start: starts[i], End: end, Callers: b.directCallers()[starts[i]]}, true
}

// ehFrameHdrStarts returns the initial locations in the binary search table
// of an .eh_frame_hdr section at addr, with contents d.
func ehFrameHdrStarts(addr uint64, d []byte) []uint64 {
	// version 1; then the encodings of eh_frame_ptr, fde_count and the table
	if len(d) < 4 || d[0] != 1 {
		return nil
	}
	ptrSize := map[byte]int{ehUdata4: 4, ehSdata4: 4, ehUdata8: 8, ehSdata8: 8}[d[1]&0x0f]
	// The table is (initial location, FDE address) pairs, relative to the
	// section's start: compilers and linkers write datarel sdata4 only.
	if ptrSize == 0 || d[2] != ehUdata4 || d[3] != ehDatarel|ehSdata4 || len(d) < 4+ptrSize+4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(d[4+ptrSize:]))
	table := d[4+ptrSize+4:]
	if n < 0 || len(table)/8 < n {
		return nil
	}
	out := make([]uint64, n)
	for i := range out {
		out[i] = addr + uint64(int64(int32(binary.LittleEndian.Uint32(table[8*i:]))))
	}
	return out
}

// useFDEs reports whether functions start where fdeStarts says, rather than
// at call targets with a frame pointer prologue: for an x86-64 binary with
// the table, where most call targets have no such prologue. With frame
// pointers (Chrome), the prologues are kept to, as a function's parts that
// the compiler split off (its cold code) have their own unwind information.
func (b *Binary) useFDEs() bool {
	if b.fdes == 0 {
		b.fdes = -1
		if !b.arm64 && len(b.fdeStarts()) > 0 {
			with, all := 0, 0
			for a := range b.directCallers() {
				all++
				if a%x86Align == 0 && b.x86Prologue(a) {
					with++
				}
			}
			if with < all/2 {
				b.fdes = 1
			}
		}
	}
	return b.fdes > 0
}
