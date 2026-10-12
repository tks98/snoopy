package discover

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestMappedLibraries(t *testing.T) {
	f, err := os.Open("testdata/maps")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got := MappedLibraries(f)
	want := []Mapping{
		{"/usr/lib/x86_64-linux-gnu/libssl.so.3", "7f3e1d200000-7f3e1d222000", false},
		{"/usr/lib/x86_64-linux-gnu/libgnutls.so.30.37.1", "7f3e1d400000-7f3e1d5c0000", false},
		{"/opt/my app/lib/libnspr4.so", "7f3e1d600000-7f3e1d640000", false},
		{"/usr/lib/x86_64-linux-gnu/libwolfssl.so.42.0.0", "7f3e1d740000-7f3e1d780000", false},
		{"/usr/lib/x86_64-linux-gnu/libmbedtls.so.14", "7f3e1d790000-7f3e1d7a0000", false},
		{"/usr/local/lib/libs2n.so.1", "7f3e1d7a0000-7f3e1d7c0000", false},
		{"/tmp/libssl.so.1.1", "7f3e1d800000-7f3e1d840000", true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestGoMinorVersion(t *testing.T) {
	for v, want := range map[string]int{
		"go1.22.3": 22, "go1.17": 17, "go1.25rc1": 25, "devel go1.26-abc": 0, "": 0,
	} {
		if got := goMinorVersion(v); got != want {
			t.Errorf("goMinorVersion(%q) = %d, want %d", v, got, want)
		}
	}
}

func TestFindReturns(t *testing.T) {
	// push rbp; mov rbp,rsp; pop rbp; ret; xor eax,eax; ret
	x86 := []byte{0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3, 0x31, 0xc0, 0xc3}
	got, err := FindReturns(elf.EM_X86_64, x86)
	if err != nil || !reflect.DeepEqual(got, []uint64{5, 8}) {
		t.Errorf("x86: got %v, %v", got, err)
	}

	// nop; ret; mov x0, #0; ret
	arm := le32(0xd503201f, 0xd65f03c0, 0xd2800000, 0xd65f03c0)
	got, err = FindReturns(elf.EM_AARCH64, arm)
	if err != nil || !reflect.DeepEqual(got, []uint64{4, 12}) {
		t.Errorf("arm64: got %v, %v", got, err)
	}

	if _, err := FindReturns(elf.EM_X86_64, []byte{0x90, 0x90}); err == nil {
		t.Error("expected an error for code without returns")
	}
}

func le32(words ...uint32) []byte {
	b := make([]byte, 4*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint32(b[4*i:], w)
	}
	return b
}

// buildGoFixture compiles testdata/gotls for the given architecture.
func buildGoFixture(t *testing.T, goarch string, strip bool) string {
	t.Helper()
	ldflags := ""
	if strip {
		ldflags = "-s -w"
	}
	return buildFixture(t, "./testdata/gotls", ldflags, "GOARCH="+goarch, "CGO_ENABLED=0")
}

func buildFixture(t *testing.T, pkg, ldflags string, env ...string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds a Go program")
	}
	out := filepath.Join(t.TempDir(), "fixture")
	cmd := exec.Command("go", "build", "-o", out, "-ldflags="+ldflags, pkg)
	cmd.Env = append(append(os.Environ(), "GOOS=linux"), env...)
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, msg)
	}
	return out
}

// Stripped binaries are located through .gopclntab. It must agree with the
// symbol table, also for cgo programs, whose C code precedes Go's in .text.
func TestPclntabMatchesSymtab(t *testing.T) {
	builds := map[string]func(t *testing.T) string{
		"amd64": func(t *testing.T) string { return buildGoFixture(t, "amd64", false) },
		"arm64": func(t *testing.T) string { return buildGoFixture(t, "arm64", false) },
		"cgo-external": func(t *testing.T) string {
			if _, err := exec.LookPath("cc"); err != nil {
				t.Skip("no C compiler")
			}
			return buildFixture(t, "./testdata/gotlscgo", "-linkmode=external", "CGO_ENABLED=1")
		},
	}
	for name, build := range builds {
		t.Run(name, func(t *testing.T) {
			f, err := elf.Open(build(t))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			for _, fn := range []string{goReadFunc, goWriteFunc} {
				s1, e1, err := symtabBounds(f, fn)
				if err != nil {
					t.Fatal(err)
				}
				s2, e2, err := pclntabBounds(f, fn)
				if err != nil {
					t.Fatal(err)
				}
				// pclntab's end includes the alignment padding after the function.
				if s1 != s2 || e2 < e1 || e2-e1 >= 32 {
					t.Errorf("%s: symtab [%#x, %#x), pclntab [%#x, %#x)", fn, s1, e1, s2, e2)
				}
			}
		})
	}
}

func TestGoBodyOffset(t *testing.T) {
	for _, tc := range []struct {
		name    string
		machine elf.Machine
		code    []byte
		want    uint64 // 0: must be rejected
	}{
		// CMP RSP, [R14+0x10]; JBE; PUSH RBP
		{"x86", elf.EM_X86_64, []byte{0x49, 0x3b, 0x66, 0x10, 0x0f, 0x86, 0x7a, 0x03, 0x00, 0x00, 0x55}, 10},
		// LEA R12, [RSP-0x48]; CMP R12, [R14+0x10]; JBE; PUSH RBP
		{"x86 large frame", elf.EM_X86_64, []byte{0x4c, 0x8d, 0x64, 0x24, 0xb8, 0x4d, 0x3b, 0x66, 0x10, 0x0f, 0x86, 0x93, 0x07, 0x00, 0x00, 0x55}, 15},
		// MOVD 16(R28), R16; CMP R16, RSP; BLS; MOVD.W R30, -112(RSP)
		{"arm64", elf.EM_AARCH64, le32(0xf9400b90, 0xeb3063ff, 0x54001909, 0xf8190ffe), 12},
		// MOVD 16(R28), R16; SUB $80, RSP, R17; CMP R16, R17; BLS
		{"arm64 large frame", elf.EM_AARCH64, le32(0xf9400b90, 0xd10143f1, 0xeb10023f, 0x540033c9), 16},
		// Mid-function code: MOV RDX, [RSP+0x80]; NOP
		{"x86 mid-function", elf.EM_X86_64, []byte{0x48, 0x8b, 0x94, 0x24, 0x80, 0x00, 0x00, 0x00, 0x90}, 0},
		// CMP RSP, [R14+0x10] without the branch
		{"x86 no branch", elf.EM_X86_64, []byte{0x49, 0x3b, 0x66, 0x10, 0x90}, 0},
		// NOP
		{"arm64 mid-function", elf.EM_AARCH64, le32(0xd503201f), 0},
		// MOVD 16(R28), R16; CMP R16, RSP; NOP
		{"arm64 no branch", elf.EM_AARCH64, le32(0xf9400b90, 0xeb3063ff, 0xd503201f), 0},
	} {
		got, err := goBodyOffset(tc.machine, tc.code)
		switch {
		case tc.want == 0 && err == nil:
			t.Errorf("%s: accepted code that doesn't start with a stack check", tc.name)
		case tc.want != 0 && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case got != tc.want:
			t.Errorf("%s: body at %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestFindGoFunc(t *testing.T) {
	for _, tc := range []struct {
		goarch string
		strip  bool
		ret    func([]byte) bool
	}{
		{"amd64", false, func(b []byte) bool { return b[0] == 0xc3 }},
		{"amd64", true, func(b []byte) bool { return b[0] == 0xc3 }},
		{"arm64", false, func(b []byte) bool { return binary.LittleEndian.Uint32(b) == 0xd65f03c0 }},
		{"arm64", true, func(b []byte) bool { return binary.LittleEndian.Uint32(b) == 0xd65f03c0 }},
	} {
		name := tc.goarch
		if tc.strip {
			name += "-stripped"
		}
		t.Run(name, func(t *testing.T) {
			path := buildGoFixture(t, tc.goarch, tc.strip)
			f, err := elf.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if tc.strip {
				if _, err := f.Symbols(); err == nil {
					t.Fatal("fixture still has a symbol table")
				}
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{goReadFunc, goWriteFunc} {
				fn, err := FindGoFunc(f, name)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if len(fn.Returns) == 0 {
					t.Fatalf("%s: no returns", name)
				}
				if fn.Body == 0 || fn.Body > 16 {
					t.Errorf("%s: stack check ends at %d", name, fn.Body)
				}
				// The offsets are file offsets: check the bytes there.
				for _, r := range fn.Returns {
					if !tc.ret(raw[fn.Offset+r:]) {
						t.Errorf("%s: no return instruction at file offset %#x", name, fn.Offset+r)
					}
				}
			}
			if _, err := FindGoFunc(f, "main.doesNotExist"); err == nil {
				t.Error("found a function that doesn't exist")
			}
		})
	}
}

func TestInspectGoBinary(t *testing.T) {
	path := buildGoFixture(t, runtime.GOARCH, false)
	targets, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Library != GoTLS || targets[0].Go == nil {
		t.Fatalf("got %+v", targets)
	}
	if targets[0].Go.Version != runtime.Version() {
		t.Errorf("version %q, want %q", targets[0].Go.Version, runtime.Version())
	}
}

func TestInspectOtherArchitecture(t *testing.T) {
	other := "arm64"
	if runtime.GOARCH == "arm64" {
		other = "amd64"
	}
	if _, err := Inspect(buildGoFixture(t, other, false)); err == nil {
		t.Error("expected an error for a foreign architecture")
	}
}

func TestInspectNonGoFiles(t *testing.T) {
	notELF := filepath.Join(t.TempDir(), "x")
	os.WriteFile(notELF, []byte("#!/bin/sh\n"), 0o755)
	if _, err := Inspect(notELF); err == nil {
		t.Error("expected an error for a non-ELF file")
	}

	for _, lib := range systemLibraries() {
		targets, err := Inspect(lib)
		if err != nil {
			t.Errorf("%s: %v", lib, err)
			continue
		}
		if len(targets) != 1 || targets[0].Library == GoTLS {
			t.Errorf("%s: got %+v", lib, targets)
		}
	}
}

func TestFind(t *testing.T) {
	path := buildGoFixture(t, runtime.GOARCH, true)
	targets, warnings, err := Find(Options{Extra: []string{path, path}, NoScan: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	found := 0
	for _, target := range targets {
		if target.Path == path {
			found++
		}
	}
	if found != 1 {
		t.Errorf("--lib target found %d times in %+v", found, targets)
	}

	if _, _, err := Find(Options{Extra: []string{"/does/not/exist"}}); err == nil {
		t.Error("expected an error for a missing --lib")
	}
	if _, _, err := Find(Options{PID: 1 << 30}); err == nil {
		t.Error("expected an error for a missing process")
	}

	notTLS := filepath.Join(t.TempDir(), "plain")
	os.WriteFile(notTLS, []byte("not a binary"), 0o644)
	_, warnings, err = Find(Options{Extra: []string{notTLS}, NoScan: true})
	if err != nil || len(warnings) != 1 {
		t.Errorf("want one warning for a non-TLS --lib, got %v, %v", warnings, err)
	}
}
