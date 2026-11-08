package tracer

import (
	"debug/elf"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func TestGroupUprobes(t *testing.T) {
	ret, readEnter, writeEnter := new(ebpf.Program), new(ebpf.Program), new(ebpf.Program)
	goRet := new(ebpf.Program)
	probes := []uprobe{
		{name: "SSL_read", prog: ret, ret: true, first: true},           // 0
		{name: "SSL_read", prog: readEnter},                             // 1
		{name: "SSL_write", prog: ret, ret: true, first: true},          // 2
		{name: "SSL_write", prog: writeEnter},                           // 3
		{name: "Read", prog: goRet, offset: 0x40, first: true},          // 4: a uprobe on a RET
		{name: "Read", prog: readEnter, offset: 0x10},                   // 5
		{name: "Write", prog: goRet, offset: 0x80, first: true},         // 6
		{name: "Write", prog: ret, ret: true},                           // 7: same program, not first
		{name: "AES_CreateContext", prog: ret, ret: false, first: true}, // 8: same program, not a uretprobe
	}
	got := groupUprobes(probes)
	want := [][]int{{0, 2}, {4, 6}, {8}, {1, 5}, {3}, {7}}
	if !slices.EqualFunc(got, want, slices.Equal[[]int]) {
		t.Errorf("groups %v, want %v", got, want)
	}
	// Every probe is in exactly one group, and each group shares a program
	// and kind, which is what one uprobe_multi link can attach.
	seen := map[int]bool{}
	for _, g := range got {
		for _, i := range g {
			if seen[i] {
				t.Errorf("probe %d in two groups", i)
			}
			seen[i] = true
			if p, q := probes[g[0]], probes[i]; p.prog != q.prog || p.ret != q.ret {
				t.Errorf("group %v mixes probes %d and %d", g, g[0], i)
			}
		}
	}
	if len(seen) != len(probes) {
		t.Errorf("%d of %d probes grouped", len(seen), len(probes))
	}
}

func TestAttachedNames(t *testing.T) {
	probes := []uprobe{{name: "a"}, {name: "a"}, {name: "b"}, {name: "c"}, {name: "c"}}
	for _, tc := range []struct {
		done []bool
		want []string
	}{
		{[]bool{true, true, true, true, true}, []string{"a", "b", "c"}},
		{[]bool{true, false, true, true, true}, []string{"b", "c"}}, // a's return probe without its entry
		{[]bool{true, true, false, false, false}, []string{"a"}},
		{[]bool{false, false, false, false, false}, nil},
	} {
		if got := attachedNames(probes, tc.done); !slices.Equal(got, tc.want) {
			t.Errorf("done %v: %v, want %v", tc.done, got, tc.want)
		}
	}
}

// symbolOffsets must find functions where cilium/ebpf would for a uprobe
// on their name, which it did before snoopy resolved them itself.
func TestSymbolOffsets(t *testing.T) {
	// Shared libraries, with dynamic symbols only (go test strips its own
	// binary of its symbol table). Go programs are attached to at the
	// offsets discover finds instead.
	var files []string
	for _, pattern := range []string{
		"/usr/lib/*-linux-gnu/libssl.so.*", "/usr/lib64/libssl.so.*",
		"/usr/lib/*-linux-gnu/libc.so.6", "/usr/lib64/libc.so.6", "/lib64/libc.so.6",
	} {
		found, _ := filepath.Glob(pattern)
		files = append(files, found...)
	}
	if len(files) == 0 {
		t.Skip("no libssl or libc to read")
	}
	for _, path := range files {
		offsets, err := symbolOffsets(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(offsets) == 0 {
			t.Fatalf("%s: no functions", path)
		}
		ex, err := link.OpenExecutable(path)
		if err != nil {
			t.Fatal(err)
		}
		// cilium/ebpf's own lookup only goes the other way, from an
		// address to its symbol: it must lead back to the same offset,
		// from the start of a function snoopy found there too.
		checked := 0
		for name, off := range offsets {
			sym, err := ex.Symbol(off)
			if err != nil {
				t.Errorf("%s: %s at %#x: %v", path, name, off, err)
				continue
			}
			if sym.Offset != 0 || offsets[sym.Symbol] != off {
				t.Errorf("%s: %s at %#x is %s+%#x to cilium/ebpf", path, name, off, sym.Symbol, sym.Offset)
			}
			if checked++; checked == 2000 {
				break
			}
		}
		t.Logf("%s: %d functions, %d checked", path, len(offsets), checked)
	}

	// Imports, at address zero, aren't functions of the file's own.
	f, err := elf.Open(files[len(files)-1])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	offsets, _ := symbolOffsets(files[len(files)-1])
	syms, _ := f.DynamicSymbols()
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Value == 0 {
			if _, ok := offsets[s.Name]; ok {
				t.Errorf("import %s has an offset", s.Name)
			}
		}
	}
}
