package funcfind

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"reflect"
	"testing"
)

// asm builds x86-64 code at a known address, with labels for call targets.
type asm struct {
	base   uint64
	code   bytes.Buffer
	labels map[string]uint64
	fixups []fixup
}

type fixup struct {
	at    int // offset of the rel32/disp32 field
	next  int // offset of the next instruction, which it's relative to
	label string
	addr  uint64 // used if label is empty
}

func newAsm(base uint64) *asm { return &asm{base: base, labels: map[string]uint64{}} }

func (a *asm) pc() uint64            { return a.base + uint64(a.code.Len()) }
func (a *asm) label(name string)     { a.labels[name] = a.pc() }
func (a *asm) bytes(b ...byte)       { a.code.Write(b) }
func (a *asm) imm32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// align pads with int3 to a 16-byte boundary, as compilers do between functions.
func (a *asm) align() {
	for a.pc()%16 != 0 {
		a.bytes(0xcc)
	}
}

func (a *asm) call(label string) {
	a.bytes(0xe8)
	a.fixups = append(a.fixups, fixup{at: a.code.Len(), next: a.code.Len() + 4, label: label})
	a.bytes(0, 0, 0, 0)
}

// leaRCX emits lea rcx, [rip+addr].
func (a *asm) leaRCX(addr uint64) {
	a.bytes(0x48, 0x8d, 0x0d)
	a.fixups = append(a.fixups, fixup{at: a.code.Len(), next: a.code.Len() + 4, addr: addr})
	a.bytes(0, 0, 0, 0)
}

func (a *asm) finish() []byte {
	b := a.code.Bytes()
	for _, f := range a.fixups {
		target := f.addr
		if f.label != "" {
			target = a.labels[f.label]
		}
		binary.LittleEndian.PutUint32(b[f.at:], uint32(int32(int64(target)-int64(a.base+uint64(f.next)))))
	}
	return b
}

const (
	textAddr = 0x1000
	dataAddr = 0x2000
	str      = dataAddr + 1 // "x/ssl/ssl_lib.cc", after a NUL
)

// testBinary has the shape funcfind looks for: report() loads a file name and
// passes constants to an error function, like BoringSSL's OPENSSL_PUT_ERROR.
// It returns the functions' addresses by name.
func testBinary(t *testing.T) (*Binary, map[string]uint64) {
	t.Helper()
	a := newAsm(textAddr)
	// main: no frame pointer, calls the others.
	a.label("main")
	a.call("report")
	a.call("helper")
	a.call("read3")
	a.call("onearg")
	a.call("eightargs")
	a.call("cet3")
	a.bytes(0xc3) // ret
	a.align()
	a.label("report")
	a.bytes(0x55, 0x48, 0x89, 0xe5) // push rbp; mov rbp, rsp
	a.leaRCX(str)
	a.bytes(0xbf)
	a.bytes(a.imm32(0x10)...) // mov edi, 0x10
	a.bytes(0x31, 0xf6)       // xor esi, esi
	a.bytes(0xba)
	a.bytes(a.imm32(0x6f)...) // mov edx, 0x6f
	a.bytes(0x41, 0xb8)
	a.bytes(a.imm32(0x3d4)...) // mov r8d, 0x3d4
	a.call("helper")
	a.bytes(0x5d, 0xc3) // pop rbp; ret
	a.align()
	a.label("helper")
	a.bytes(0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3)
	a.align()
	// read3(x, buf, num): an error check comes first, and its error path
	// overwrites the argument registers; the arguments are used past the je.
	a.label("read3")
	a.bytes(0x55, 0x48, 0x89, 0xe5)                         // push rbp; mov rbp, rsp
	a.bytes(0x48, 0x83, 0xbf, 0x98, 0x00, 0x00, 0x00, 0x00) // cmp qword [rdi+0x98], 0
	a.bytes(0x74, 0x11)                                     // je +17
	a.bytes(0xbf)
	a.bytes(a.imm32(0x10)...) // mov edi, 0x10
	a.bytes(0x31, 0xf6)       // xor esi, esi
	a.bytes(0xba)
	a.bytes(a.imm32(0x42)...) // mov edx, 0x42
	a.call("helper")          // 5 bytes: 17 in all since the je
	a.bytes(0x89, 0xd3)       // mov ebx, edx
	a.bytes(0x49, 0x89, 0xf7) // mov r15, rsi
	a.bytes(0x49, 0x89, 0xfe) // mov r14, rdi
	a.call("helper")
	a.bytes(0x5d, 0xc3)
	a.align()
	// eightargs(...): reads its 7th and 8th arguments from the stack.
	a.label("eightargs")
	a.bytes(0x55, 0x48, 0x89, 0xe5)
	a.bytes(0x48, 0x8b, 0x45, 0x10) // mov rax, [rbp+0x10]
	a.bytes(0x48, 0x8b, 0x4d, 0x18) // mov rcx, [rbp+0x18]
	a.bytes(0x48, 0x8b, 0x55, 0xf8) // mov rdx, [rbp-8]: a local, not an argument
	a.bytes(0x5d, 0xc3)
	a.align()
	// onearg(x): uses only its first argument, then sets up its own call.
	a.label("onearg")
	a.bytes(0x55, 0x48, 0x89, 0xe5)
	a.bytes(0x48, 0x8b, 0x07) // mov rax, [rdi]
	a.bytes(0x31, 0xf6)       // xor esi, esi
	a.bytes(0xba)
	a.bytes(a.imm32(1)...) // mov edx, 1
	a.call("helper")
	a.bytes(0x5d, 0xc3)
	a.align()
	// cet3(x, buf, num): like read3 without the check, in a CET build.
	a.label("cet3")
	a.bytes(0xf3, 0x0f, 0x1e, 0xfa) // endbr64
	a.bytes(0x55, 0x48, 0x89, 0xe5) // push rbp; mov rbp, rsp
	a.bytes(0x89, 0xd3)             // mov ebx, edx
	a.bytes(0x49, 0x89, 0xf7)       // mov r15, rsi
	a.bytes(0x49, 0x89, 0xfe)       // mov r14, rdi
	a.call("helper")
	a.bytes(0x5d, 0xc3)
	a.align()
	code := a.finish()

	return &Binary{
		text:     code,
		textAddr: textAddr,
		data:     []segment{{dataAddr, []byte("\x00x/ssl/ssl_lib.cc\x00")}},
		loads:    []elf.ProgHeader{{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Vaddr: textAddr, Off: 0x400, Filesz: uint64(len(code))}},
	}, a.labels
}

func TestFind(t *testing.T) {
	b, at := testBinary(t)
	report, helper := at["report"], at["helper"]

	addr, ok := b.FindString("/ssl/ssl_lib.cc")
	if !ok || addr != str {
		t.Fatalf("FindString: %#x %v", addr, ok)
	}
	if _, ok := b.FindString("/ssl/missing.cc"); ok {
		t.Error("found a string that isn't there")
	}

	refs := b.Refs(str)
	if !reflect.DeepEqual(refs, []uint64{report + 4}) {
		t.Fatalf("Refs: %#x", refs)
	}

	fn, ok := b.FuncAt(refs[0])
	if !ok || fn.Start != report || fn.End != helper || fn.Callers != 1 {
		t.Fatalf("FuncAt: %+v %v", fn, ok)
	}
	if _, ok := b.FuncAt(0x1001); ok {
		t.Error("found a function in code without a frame pointer prologue")
	}
	if h, ok := b.FuncAt(helper); !ok || h.Callers != 6 {
		t.Errorf("helper: %+v %v", h, ok)
	}

	for n, want := range map[int][]int64{0: {0x10}, 1: nil, 2: {0x6f}, 4: {0x3d4}} {
		got, err := b.ConstArgsNear(fn, str, n)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ConstArgsNear arg %d: %v %v, want %v", n, got, err, want)
		}
	}
	if _, err := b.ConstArgsNear(fn, str, 9); err == nil {
		t.Error("accepted a nonexistent argument register")
	}

	if calls := b.Calls(fn); !reflect.DeepEqual(calls, []uint64{helper}) {
		t.Errorf("Calls: %#x", calls)
	}

	if off, err := b.FileOffset(report + 4); err != nil || off != report+4-textAddr+0x400 {
		t.Errorf("FileOffset: %#x %v", off, err)
	}
	if _, err := b.FileOffset(dataAddr); err == nil {
		t.Error("FileOffset accepted a data address")
	}
}

func TestOpenUnsupported(t *testing.T) {
	if _, err := Open(&elf.File{FileHeader: elf.FileHeader{Machine: elf.EM_RISCV}}); err != ErrUnsupported {
		t.Errorf("got %v", err)
	}
}

func TestReadsArgs(t *testing.T) {
	b, at := testBinary(t)
	for _, tc := range []struct {
		fn   string
		n    int
		want bool
	}{
		{"read3", 3, true}, // past the error path
		{"read3", 4, false},
		{"onearg", 1, true},
		{"onearg", 2, false}, // writes esi, edx without reading them
		{"report", 1, false}, // overwrites edi first
		{"cet3", 3, true},    // past endbr64
	} {
		fn, ok := b.FuncAt(at[tc.fn])
		if !ok {
			t.Fatalf("%s not found", tc.fn)
		}
		if got := b.ReadsArgs(fn, tc.n); got != tc.want {
			t.Errorf("ReadsArgs(%s, %d) = %v", tc.fn, tc.n, got)
		}
	}
}

func TestStackArgs(t *testing.T) {
	b, at := testBinary(t)
	for name, want := range map[string]int{"eightargs": 8, "read3": 0, "report": 0} {
		fn, ok := b.FuncAt(at[name])
		if !ok {
			t.Fatalf("%s not found", name)
		}
		if got := b.StackArgs(fn); got != want {
			t.Errorf("StackArgs(%s) = %d, want %d", name, got, want)
		}
	}
}

// An executable that isn't position-independent (Bun's) loads addresses as
// 32-bit immediates; a position-independent one's mov imm32 is a number.
func TestAbsoluteRefs(t *testing.T) {
	a := newAsm(textAddr)
	a.label("report")
	a.bytes(0x55, 0x48, 0x89, 0xe5) // push rbp; mov rbp, rsp
	a.bytes(0xb9)
	a.bytes(a.imm32(str)...) // mov ecx, str
	a.bytes(0xba)
	a.bytes(a.imm32(0x77)...) // mov edx, 0x77
	a.call("helper")
	a.bytes(0x5d, 0xc3)
	a.align()
	a.label("helper")
	a.bytes(0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3)
	a.align()
	a.label("caller")
	a.bytes(0x55, 0x48, 0x89, 0xe5)
	a.call("report")
	a.bytes(0x5d, 0xc3)
	code := a.finish()
	for _, absolute := range []bool{true, false} {
		b := &Binary{text: code, textAddr: textAddr, absolute: absolute,
			data: []segment{{dataAddr, []byte("\x00x/ssl/ssl_lib.cc\x00")}}}
		refs := b.Refs(str)
		if !absolute {
			if len(refs) != 0 {
				t.Errorf("position-independent: refs %#x", refs)
			}
			continue
		}
		if !reflect.DeepEqual(refs, []uint64{a.labels["report"] + 4}) {
			t.Fatalf("Refs: %#x", refs)
		}
		fn, ok := b.FuncAt(refs[0])
		if !ok {
			t.Fatal("no function")
		}
		if got, err := b.ConstArgsNear(fn, str, 2); err != nil || !reflect.DeepEqual(got, []int64{0x77}) {
			t.Errorf("ConstArgsNear: %v %v", got, err)
		}
	}
}
