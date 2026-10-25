package funcfind

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// An .eh_frame_hdr's table gives where functions start, also those that
// aren't called directly or have no frame pointer prologue.
func TestFDEStarts(t *testing.T) {
	const hdrAddr, textAddr = 0x5000, 0x1000
	hdr := []byte{1, 0x1b, ehUdata4, ehDatarel | ehSdata4} // eh_frame_ptr is pcrel sdata4
	hdr = binary.LittleEndian.AppendUint32(hdr, 0x100)
	hdr = binary.LittleEndian.AppendUint32(hdr, 3)
	for _, start := range []uint64{0x1000, 0x1030, 0x1100} {
		hdr = binary.LittleEndian.AppendUint32(hdr, uint32(int32(int64(start)-hdrAddr)))
		hdr = binary.LittleEndian.AppendUint32(hdr, 0) // the FDE's address
	}
	starts := ehFrameHdrStarts(hdrAddr, hdr)
	if !reflect.DeepEqual(starts, []uint64{0x1000, 0x1030, 0x1100}) {
		t.Fatalf("starts: %#x", starts)
	}
	if got := ehFrameHdrStarts(hdrAddr, hdr[:len(hdr)-1]); got != nil {
		t.Errorf("a truncated table: %#x", got)
	}

	b := &Binary{text: make([]byte, 0x200), textAddr: textAddr, starts: starts}
	for pc, want := range map[uint64]*Func{
		0x1000: {Start: 0x1000, End: 0x1030},
		0x1045: {Start: 0x1030, End: 0x1100},
		0x11ff: {Start: 0x1100, End: 0x1200}, // the last ends with the code
	} {
		if fn, ok := b.FuncAt(pc); !ok || *fn != *want {
			t.Errorf("FuncAt(%#x): %+v %v, want %+v", pc, fn, ok, want)
		}
	}
	if fn, ok := b.FuncAt(0x1200); ok {
		t.Errorf("FuncAt past the code: %+v", fn)
	}
}

// A string can follow other data with no NUL in between.
func TestFindStringAfterData(t *testing.T) {
	b := &Binary{data: []segment{{0x2000, []byte("\x00\x02\x02\x03\x05\x08\x01\x05/w/boringssl/ssl/ssl_lib.cc\x00")}}}
	if addr, ok := b.FindString("/ssl/ssl_lib.cc"); !ok || addr != 0x2008 {
		t.Errorf("FindString: %#x %v", addr, ok)
	}
}
