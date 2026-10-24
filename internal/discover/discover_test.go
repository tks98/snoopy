package discover

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
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
			// Go 1.26 no longer records runtime.text in the pclntab header,
			// so it comes from the moduledata.
			syms, err := f.Symbols()
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(syms, func(s elf.Symbol) bool { return s.Name == "runtime.text" })
			if i < 0 {
				t.Fatal("no runtime.text symbol")
			}
			text := syms[i].Value
			pcln := f.Section(".gopclntab")
			data, err := pcln.Data()
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := moduledataTextStart(f, pcln.Addr, data); !ok || got != text {
				t.Errorf("moduledata's text is %#x (found: %v), runtime.text %#x", got, ok, text)
			}
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

func TestRustlsSymbols(t *testing.T) {
	for _, tc := range []struct {
		name        string
		read, write bool
	}{
		// From a rustls 0.23 build with rustc 1.99 (v0 mangling).
		{"_RNvXs2_NtNtCs1eO8RepwP5M_6rustls4conn10connectionNtB5_6ReaderNtNtNtCscoGKTY0KSTf_5alloc2io4read4Read4read", true, false},
		{"_RNvXs5_NtNtCs1eO8RepwP5M_6rustls4conn10connectionNtB5_6WriterNtNtNtCslpfLnFkgLmC_4core2io5write5Write5write", false, true},
		// Legacy mangling, older rustls and Rust.
		{"_ZN66_$LT$rustls..conn..connection..Reader$u20$as$u20$std..io..Read$GT$4read17h0123456789abcdefE", true, false},
		{"_ZN55_$LT$rustls..conn..Writer$u20$as$u20$std..io..Write$GT$5write17h0ee1e61402b1a37cE", false, true},
		// Other methods and types.
		{"_ZN66_$LT$rustls..conn..connection..Reader$u20$as$u20$std..io..Read$GT$10read_exact17h0123456789abcdefE", false, false},
		{"_RNvXs3_NtNtCs1eO8RepwP5M_6rustls4conn10connectionNtB5_6ReaderNtNtCscoGKTY0KSTf_5alloc2io7BufRead8fill_buf", false, false},
		{"_ZN58_$LT$std..io..buffered..BufReader$u20$as$u20$std..io..Read$GT$4read17h0123456789abcdefE", false, false},
	} {
		if got := rustlsRead.MatchString(tc.name); got != tc.read {
			t.Errorf("read %v for %s", got, tc.name)
		}
		if got := rustlsWrite.MatchString(tc.name); got != tc.write {
			t.Errorf("write %v for %s", got, tc.name)
		}
	}
}

func TestAwsLCSymbols(t *testing.T) {
	for name, want := range map[string]bool{
		// From aws-lc-sys 0.46 (aws-lc-rs 1.18), with rustls 0.23.
		"aws_lc_0_46_0_EVP_AEAD_CTX_open": true,
		"aws_lc_0_46_0_EVP_AEAD_CTX_seal": true,
		// Used for TLS 1.2; seal doesn't call it.
		"aws_lc_0_46_0_EVP_AEAD_CTX_seal_scatter": true,
		// Called by open: probing it too would show each record twice.
		"aws_lc_0_46_0_EVP_AEAD_CTX_open_gather": false,
		// BoringSSL's own, without the prefix, belong to its SSL_read.
		"EVP_AEAD_CTX_open": false,
	} {
		if got := awsLCAEAD.MatchString(name); got != want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestRingSymbols(t *testing.T) {
	for name, want := range map[string]bool{
		// From ring 0.17.14, with rustls 0.23.
		"_RNvNtNtCs6Mth2B0oH5X_4ring4aead9algorithm12aes_gcm_seal":           true,
		"_RNvNtNtCs6Mth2B0oH5X_4ring4aead9algorithm12aes_gcm_open":           true,
		"_RNvNtNtCs6Mth2B0oH5X_4ring4aead9algorithm22chacha20_poly1305_seal": true,
		"_RNvNtNtCs6Mth2B0oH5X_4ring4aead9algorithm22chacha20_poly1305_open": true,
		"_ZN4ring4aead9algorithm12aes_gcm_seal17h0123456789abcdefE":          true,
		// Key setup, and the method that calls open.
		"_RNvNtNtCs6Mth2B0oH5X_4ring4aead9algorithm16aes_gcm_init_128":                    false,
		"_RNvMs_NtNtCs6Mth2B0oH5X_4ring4aead9algorithmNtB4_9Algorithm11open_within":       false,
		"_RNvNtNtCs6Mth2B0oH5X_4ring4aead9algorithm22chacha20_poly1305_init":              false,
		"_ZN4ring4aead9algorithm12aes_gcm_seal17h0123456789abcdefE.llvm.1234567890123456": false,
	} {
		if got := ringAEAD.MatchString(name); got != want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// TestBoringSSLBinaries runs findBoringSSL on real binaries, which are too
// large to keep here, e.g. Chrome, Brave or Edge from their .deb packages:
//
//	SNOOPY_BORINGSSL_TEST=chrome=chrome.debug,brave go test -run BoringSSLBinaries ./internal/discover
//
// A debug file after "=" (from Chrome's debug-info zips) is checked against.
func TestBoringSSLBinaries(t *testing.T) {
	spec := os.Getenv("SNOOPY_BORINGSSL_TEST")
	if spec == "" {
		t.Skip("set SNOOPY_BORINGSSL_TEST to binaries to check")
	}
	for _, item := range strings.Split(spec, ",") {
		path, debug, _ := strings.Cut(item, "=")
		t.Run(filepath.Base(path), func(t *testing.T) {
			f, err := elf.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			got, err := findBoringSSL(f, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("SSL_read %#x, SSL_write %#x, EVP_AEAD_CTX_seal %#x, EVP_AEAD_CTX_open %#x",
				got["SSL_read"], got["SSL_write"], got["EVP_AEAD_CTX_seal"], got["EVP_AEAD_CTX_open"])
			if debug == "" {
				return
			}
			checked := 0
			for name, addr := range debugSymbols(t, debug) {
				if name != "SSL_read" && name != "SSL_write" && name != "EVP_AEAD_CTX_seal" && name != "EVP_AEAD_CTX_open" {
					continue
				}
				want, err := fileOffset(f, addr)
				if err != nil {
					t.Fatal(err)
				}
				if got[name] != want {
					t.Errorf("%s at %#x, debug symbols say %#x", name, got[name], want)
				}
				checked++
			}
			if checked != 4 {
				t.Errorf("debug file has %d of the 4 functions", checked)
			}
		})
	}
}

// debugSymbols returns the function addresses in an ELF debug file or a
// Breakpad symbol file (what Electron publishes; Chrome's are on
// chrome-symbols too).
func debugSymbols(t *testing.T, path string) map[string]uint64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]uint64{}
	if bytes.HasPrefix(data, []byte("MODULE ")) {
		// FUNC [m] address size parameter_size name
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 || fields[0] != "FUNC" {
				continue
			}
			if fields[1] == "m" {
				fields = fields[1:]
			}
			if addr, err := strconv.ParseUint(fields[1], 16, 64); err == nil {
				out[strings.Join(fields[4:], " ")] = addr
			}
		}
		return out
	}
	d, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	syms, err := d.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range syms {
		out[s.Name] = s.Value
	}
	return out
}

// TestFreeblBinaries runs findFreebl on real freebl libraries:
//
//	SNOOPY_FREEBL_TEST=/usr/lib/x86_64-linux-gnu/libfreeblpriv3.so=libfreeblpriv3.debug go test -run FreeblBinaries ./internal/discover
//
// A file with symbols after "=" (for distribution builds, debuginfod has them)
// is checked against.
func TestFreeblBinaries(t *testing.T) {
	spec := os.Getenv("SNOOPY_FREEBL_TEST")
	if spec == "" {
		t.Skip("set SNOOPY_FREEBL_TEST to freebl libraries to check")
	}
	for _, item := range strings.Split(spec, ",") {
		path, debug, _ := strings.Cut(item, "=")
		t.Run(path, func(t *testing.T) {
			f, err := elf.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			got, err := findFreebl(f)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("AES_CreateContext %#x, AES_AEAD %#x", got["AES_CreateContext"], got["AES_AEAD"])
			if debug == "" {
				return
			}
			checked := 0
			for name, addr := range debugSymbols(t, debug) {
				if want, ok := got[name]; ok {
					off, err := fileOffset(f, addr)
					if err != nil || off != want {
						t.Errorf("%s at %#x, symbols say %#x", name, want, off)
					}
					checked++
				}
			}
			if checked != 2 {
				t.Errorf("symbols have %d of the 2 functions", checked)
			}
		})
	}
}

// A program that has BoringSSL's file name in it, but not BoringSSL's
// functions, is reported as a problem instead of being attached to.
func TestBoringSSLProblem(t *testing.T) {
	var cc string
	for _, name := range []string{"cc", "gcc", "clang"} {
		if p, err := exec.LookPath(name); err == nil {
			cc = p
			break
		}
	}
	if cc == "" || runtime.GOOS != "linux" {
		t.Skip("needs a C compiler on Linux")
	}
	dir := t.TempDir()
	src, bin := filepath.Join(dir, "x.c"), filepath.Join(dir, "x")
	code := `#include <stdio.h>
int main(void) { printf("%s %d\n", "third_party/boringssl/src/ssl/ssl_lib.cc", 0xd7); return 0; }
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-O0", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("compile: %v: %s", err, out)
	}
	targets, err := Inspect(bin)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Problem == nil || !strings.Contains(targets[0].Problem.Error(), "can't be traced") {
		t.Fatalf("got %+v", targets)
	}
	t.Log(targets[0].Problem)
}

func TestDescendants(t *testing.T) {
	proc := t.TempDir()
	for pid, stat := range map[int]string{
		1:  "1 (init) S 0 1 1",
		10: "10 (chrome) S 1 10 10",
		11: "11 (chrome (net) x) S 10 10 10", // a name with parentheses and a space
		12: "12 (cat) S 11 10 10",
		20: "20 (other) S 1 20 20",
	} {
		dir := filepath.Join(proc, strconv.Itoa(pid))
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat+" 0 -1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := descendants(proc, 10)
	slices.Sort(got)
	if !slices.Equal(got, []int{10, 11, 12}) {
		t.Errorf("descendants of 10: %v", got)
	}
	if !isDescendant(proc, 12, 10) || isDescendant(proc, 20, 10) || isDescendant(proc, 10, 10) {
		t.Error("isDescendant is wrong")
	}
}
