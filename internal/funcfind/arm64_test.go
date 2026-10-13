package funcfind

import (
	"debug/elf"
	"encoding/binary"
	"reflect"
	"testing"
)

// a64 builds arm64 code at a known address, with labels for branch targets.
type a64 struct {
	base   uint64
	words  []uint32
	labels map[string]uint64
	fixups []a64fixup
}

type a64fixup struct {
	at    int // index of the instruction
	kind  string
	label string
}

func newA64(base uint64) *a64 { return &a64{base: base, labels: map[string]uint64{}} }

func (a *a64) pc() uint64        { return a.base + 4*uint64(len(a.words)) }
func (a *a64) label(name string) { a.labels[name] = a.pc() }
func (a *a64) w(ws ...uint32)    { a.words = append(a.words, ws...) }

// branch emits bl, b or cbnz x8 to a label.
func (a *a64) branch(kind, label string) {
	a.fixups = append(a.fixups, a64fixup{len(a.words), kind, label})
	a.w(map[string]uint32{"bl": 0x94000000, "b": 0x14000000, "cbnz x8": 0xb5000008}[kind])
}

// adrpAdd emits adrp xd, addr; add xd, xd, #lo12(addr).
func (a *a64) adrpAdd(rd uint32, addr uint64) {
	imm := uint32((addr&^0xfff - a.pc()&^0xfff) >> 12)
	a.w(0x90000000 | imm&3<<29 | imm>>2&0x7ffff<<5 | rd)
	a.w(0x91000000 | uint32(addr&0xfff)<<10 | rd<<5 | rd)
}

func movz(rd, imm uint32) uint32 { return 0x52800000 | imm<<5 | rd } // mov wd, #imm

const (
	a64Ret        = 0xd65f03c0
	a64Paciasp    = 0xd503233f
	a64FrameEnter = 0xa9bf7bfd // stp x29, x30, [sp, #-16]!
	a64FrameFP    = 0x910003fd // mov x29, sp
	a64FrameLeave = 0xa8c17bfd // ldp x29, x30, [sp], #16
)

func (a *a64) finish() []byte {
	for _, f := range a.fixups {
		pc := a.base + 4*uint64(f.at)
		off := uint32(int64(a.labels[f.label]-pc) / 4)
		if f.kind == "cbnz x8" {
			a.words[f.at] |= off & 0x7ffff << 5
		} else {
			a.words[f.at] |= off & 0x3ffffff
		}
	}
	b := make([]byte, 4*len(a.words))
	for i, w := range a.words {
		binary.LittleEndian.PutUint32(b[4*i:], w)
	}
	return b
}

const (
	a64Text = 0x10000
	a64Data = 0x23000
	a64Str  = a64Data + 0x101 // "x/ssl/ssl_lib.cc", in another page than the code
)

// arm64Binary has the same shape as testBinary, compiled for arm64.
func arm64Binary(t *testing.T) (*Binary, map[string]uint64) {
	t.Helper()
	a := newA64(a64Text)
	a.label("main")
	for _, fn := range []string{"report", "helper", "read3", "tenargs"} {
		a.branch("bl", fn)
	}
	a.w(a64Ret)

	a.label("report")
	a.w(a64Paciasp, a64FrameEnter, a64FrameFP)
	a.adrpAdd(3, a64Str)
	a.w(movz(0, 0x10), 0x2a1f03e1, movz(2, 0x6f), movz(4, 0x3d4)) // mov w0, #16; mov w1, wzr; mov w2, #0x6f; mov w4
	a.branch("bl", "helper")
	a.w(a64FrameLeave, a64Ret)

	a.label("helper")
	a.w(a64Ret)

	// read3(x, buf, num): an error check first, whose path overwrites the
	// argument registers; the arguments are used past it.
	a.label("read3")
	a.w(a64Paciasp, a64FrameEnter, a64FrameFP)
	a.w(0xf9400000 | 19<<10 | 0<<5 | 8) // ldr x8, [x0, #0x98]
	a.branch("cbnz x8", "read3.err")
	a.w(0x2a0203f5, 0xaa0103f4, 0xaa0003f3) // mov w21, w2; mov x20, x1; mov x19, x0
	a.branch("bl", "helper")
	a.w(a64FrameLeave, a64Ret)
	a.label("read3.err")
	a.w(movz(0, 0x10), 0x2a1f03e1, movz(2, 0x42))
	a.branch("bl", "helper")
	a.w(a64FrameLeave, a64Ret)

	// tenargs: a frame below its stack arguments, which it reads through x29.
	a.label("tenargs")
	a.w(a64Paciasp)
	a.w(0xd10003ff | 0x40<<10)                   // sub sp, sp, #0x40
	a.w(0xa9017bfd)                              // stp x29, x30, [sp, #16]
	a.w(0x910003fd | 0x10<<10)                   // add x29, sp, #0x10: x29 is entry sp - 0x30
	a.w(0xa9400000 | 6<<15 | 10<<10 | 29<<5 | 9) // ldp x9, x10, [x29, #48]: the 9th and 10th
	a.w(0xf9400000 | 1<<10 | 29<<5 | 11)         // ldr x11, [x29, #8]: a local
	a.w(0xa9417bfd, 0x910003ff|0x40<<10, a64Ret) // ldp x29, x30, [sp, #16]; add sp, sp, #0x40; ret

	// uncalled: only ever called through a pointer.
	a.label("uncalled")
	a.w(a64Paciasp, a64FrameEnter, a64FrameFP)
	a.adrpAdd(3, a64Str)
	a.w(movz(2, 0x99), a64FrameLeave, a64Ret)
	code := a.finish()

	return &Binary{
		arm64:    true,
		text:     code,
		textAddr: a64Text,
		data:     []segment{{a64Data, append(make([]byte, 0x100), "\x00x/ssl/ssl_lib.cc\x00"...)}},
		loads:    []elf.ProgHeader{{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Vaddr: a64Text, Off: 0x400, Filesz: uint64(len(code))}},
	}, a.labels
}

func TestArm64(t *testing.T) {
	b, at := arm64Binary(t)
	report, helper := at["report"], at["helper"]

	addr, ok := b.FindString("/ssl/ssl_lib.cc")
	if !ok || addr != a64Str {
		t.Fatalf("FindString: %#x %v", addr, ok)
	}
	refs := b.Refs(addr)
	if !reflect.DeepEqual(refs, []uint64{report + 16, at["uncalled"] + 16}) {
		t.Fatalf("Refs: %#x", refs)
	}

	fn, ok := b.FuncAt(refs[0])
	if !ok || fn.Start != report || fn.End != helper || fn.Callers != 1 {
		t.Fatalf("FuncAt: %+v %v", fn, ok)
	}
	if fn, ok := b.FuncAt(refs[1]); ok {
		t.Errorf("found a function that isn't called directly: %+v", fn)
	}
	if fn, ok := b.FuncAt(at["tenargs"] + 8); !ok || fn.End != at["uncalled"] {
		t.Errorf("tenargs: %+v %v, want it to end where an uncalled function starts", fn, ok)
	}

	for n, want := range map[int][]int64{0: {0x10}, 1: {0}, 2: {0x6f}, 4: {0x3d4}, 5: nil} {
		got, err := b.ConstArgsNear(fn, addr, n)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ConstArgsNear arg %d: %v %v, want %v", n, got, err, want)
		}
	}
	if calls := b.Calls(fn); !reflect.DeepEqual(calls, []uint64{helper}) {
		t.Errorf("Calls: %#x", calls)
	}
	if off, err := b.FileOffset(report); err != nil || off != report-a64Text+0x400 {
		t.Errorf("FileOffset: %#x %v", off, err)
	}

	for _, tc := range []struct {
		fn   string
		n    int
		want bool
	}{
		{"read3", 3, true}, // past the error path
		{"read3", 4, false},
		{"report", 1, false}, // sets w0 first
		{"tenargs", 1, false},
	} {
		fn, ok := b.FuncAt(at[tc.fn])
		if !ok {
			t.Fatalf("%s not found", tc.fn)
		}
		if got := b.ReadsArgs(fn, tc.n); got != tc.want {
			t.Errorf("ReadsArgs(%s, %d) = %v", tc.fn, tc.n, got)
		}
	}

	for name, want := range map[string]int{"tenargs": 10, "read3": 0, "report": 0} {
		fn, _ := b.FuncAt(at[name])
		if got := b.StackArgs(fn); got != want {
			t.Errorf("StackArgs(%s) = %d, want %d", name, got, want)
		}
	}
}
