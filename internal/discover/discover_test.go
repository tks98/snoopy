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
	want := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libgnutls.so.30.37.1",
		"/opt/my app/lib/libnspr4.so",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
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
	if testing.Short() {
		t.Skip("builds a Go program")
	}
	out := filepath.Join(t.TempDir(), "gotls-"+goarch)
	args := []string{"build", "-o", out}
	if strip {
		args = append(args, "-ldflags=-s -w")
	}
	cmd := exec.Command("go", append(args, "./testdata/gotls")...)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, msg)
	}
	return out
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
