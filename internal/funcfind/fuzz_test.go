package funcfind

import (
	"encoding/binary"
	"slices"
	"testing"
)

// fuzzBinary is a Binary of the given code and data, as Open would make of a
// file, with the string BoringSSL's search starts from at the start of its
// data.
func fuzzBinary(text, data []byte, flags byte, lo uint16) *Binary {
	seg := append([]byte("xx/ssl/ssl_lib.cc\x00"), data...)
	return &Binary{arm64: flags&1 != 0, text: text, textAddr: 0x10000 + uint64(lo&0x3f), absolute: flags&2 != 0,
		data: []segment{{addr: 0x80000, data: seg}}, starts: []uint64{}}
}

// exercise runs a search the way discover's BoringSSL support does.
func exercise(b *Binary, pcs ...uint64) {
	addr, ok := b.FindString("/ssl/ssl_lib.cc")
	if !ok {
		return
	}
	for _, ref := range append(b.Refs(addr), pcs...) {
		fn, ok := b.FuncAt(ref)
		if !ok {
			continue
		}
		_, _ = b.ConstArgsNear(fn, addr, 2)
		b.Calls(fn)
		b.ReadsArgs(fn, 3)
		b.StackArgs(fn)
	}
}

// Binaries come from any process traced, so no code may crash the search.
func FuzzFuncfind(f *testing.F) {
	// arm64: bl; adrp x0; add x0, x0, #2; mov w2, #0x6f; ret
	var arm []byte
	for _, w := range []uint32{0x94000001, 0xb0000380, 0x91000800, 0x52800de2, 0xd65f03c0} {
		arm = binary.LittleEndian.AppendUint32(arm, w)
	}
	f.Add(arm, []byte{}, byte(1), uint16(0), uint16(8))
	f.Add(arm[:14], []byte{}, byte(1), uint16(0), uint16(4))
	// x86-64: call; padding; push rbp; mov rbp, rsp; lea rax, [rip]; mov edx, 0x6f; ret
	x86 := []byte{0xe8, 0x0b, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xba, 0x6f, 0, 0, 0, 0xc3}
	f.Add(x86, []byte{}, byte(0), uint16(0), uint16(20))
	f.Add(x86, []byte{1, 2, 3}, byte(2), uint16(5), uint16(0))
	f.Fuzz(func(t *testing.T, text, data []byte, flags byte, lo, pc uint16) {
		if len(text) == 0 {
			return
		}
		text = text[:len(text):len(text)] // as Section.Data returns it, so reading past it panics
		b := fuzzBinary(text, data, flags, lo)
		if flags&4 != 0 { // functions where data, as an .eh_frame_hdr, says
			for _, a := range ehFrameHdrStarts(b.textAddr, data) {
				if b.inText(a) {
					b.starts = append(b.starts, a)
				}
			}
			slices.Sort(b.starts)
			b.starts = slices.Compact(b.starts)
		}
		exercise(b, b.textAddr+uint64(pc)%uint64(len(text)))
	})
}

// An arm64 .text whose size isn't a multiple of 4: the last function ended
// past it, and finding references in that function sliced beyond it.
func TestArm64ShortText(t *testing.T) {
	a := newA64(0x10000)
	a.branch("bl", "f")
	a.label("f")
	a.adrpAdd(0, 0x80002)
	text := append(a.finish(), 0xaa, 0xbb)
	text = text[:len(text):len(text)]
	b := &Binary{arm64: true, text: text, textAddr: 0x10000, data: []segment{{0x80000, []byte("xx/ssl/ssl_lib.cc\x00")}}}
	addr, _ := b.FindString("/ssl/ssl_lib.cc")
	refs := b.Refs(addr)
	if len(refs) != 1 {
		t.Fatalf("references to %#x: %#x", addr, refs)
	}
	fn, ok := b.FuncAt(refs[0])
	if !ok {
		t.Fatal("no function at the reference")
	}
	if end := b.textAddr + uint64(len(text)); fn.End > end {
		t.Errorf("function ends at %#x, after .text, which ends at %#x", fn.End, end)
	}
	if _, err := b.ConstArgsNear(fn, addr, 2); err != nil {
		t.Error(err)
	}
}
