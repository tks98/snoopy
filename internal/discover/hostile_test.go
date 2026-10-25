package discover

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Files come from every process traced, including ones an attacker in a
// container controls: these are made to crash, exhaust or mislead snoopy.

// hostGoFixture returns the contents of testdata/gotls built for this
// machine, with its symbol table.
func hostGoFixture(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile(buildGoFixture(t, runtime.GOARCH, false))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// sectionHeader returns the offset in the file of a section's header.
func sectionHeader(t testing.TB, data []byte, name string) (int, *elf.File) {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	shoff := int(binary.LittleEndian.Uint64(data[0x28:]))
	for i, s := range f.Sections {
		if s.Name == name {
			return shoff + 64*i, f
		}
	}
	t.Fatalf("no section %s", name)
	return 0, nil
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// A symbol whose value and size wrap around, or are huge: reading the
// function took a slice of that size.
func TestFindGoFuncBadSize(t *testing.T) {
	seed := hostGoFixture(t)
	symtab, f := sectionHeader(t, seed, ".symtab")
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	symOff := int(binary.LittleEndian.Uint64(seed[symtab+24:]))
	idx := -1
	for i, s := range syms {
		if s.Name == goReadFunc {
			idx = i + 1 // Symbols leaves out the null symbol
		}
	}
	if idx < 0 {
		t.Fatalf("no %s", goReadFunc)
	}
	for _, size := range []uint64{^uint64(0) - 15, 1 << 40, 64 << 20} {
		data := bytes.Clone(seed)
		binary.LittleEndian.PutUint64(data[symOff+24*idx+16:], size)
		targets, err := Inspect(writeTemp(t, data))
		if err == nil {
			for _, tg := range targets {
				if tg.Library == GoTLS && tg.Problem == nil {
					t.Errorf("size %#x: found %+v", size, tg)
				}
			}
		}
		var panicked *errPanic
		if errors.As(err, &panicked) || len(targets) > 0 && errors.As(targets[0].Problem, &panicked) {
			t.Errorf("size %#x: %v", size, panicked)
		}
	}
}

// A compressed .text: debug/elf can read it only through Open, and left
// the section without a ReaderAt, which reading the function dereferenced.
func TestCompressedText(t *testing.T) {
	data := hostGoFixture(t)
	text, _ := sectionHeader(t, data, ".text")
	flags := binary.LittleEndian.Uint64(data[text+8:])
	binary.LittleEndian.PutUint64(data[text+8:], flags|uint64(elf.SHF_COMPRESSED))
	if _, err := Inspect(writeTemp(t, data)); err == nil || !strings.Contains(err.Error(), "compressed") {
		t.Errorf("Inspect: %v", err)
	}
	// Not through openELF, which rejects it first.
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Skip(err) // the compression header made no sense to it
	}
	if err := guard(func() { _, err = FindGoFunc(f, goReadFunc) }); err != nil {
		t.Error(err)
	}
}

// Sections and headers claiming sizes a sparse file can have but no real
// program does aren't read.
func TestImplausibleSizes(t *testing.T) {
	seed := hostGoFixture(t)
	t.Run("section", func(t *testing.T) {
		data := bytes.Clone(seed)
		sh, _ := sectionHeader(t, data, ".gopclntab")
		binary.LittleEndian.PutUint64(data[sh+32:], 8<<30)
		if _, err := Inspect(writeTemp(t, data)); !errors.Is(err, errTooLarge) {
			t.Errorf("Inspect: %v", err)
		}
	})
	t.Run("section names", func(t *testing.T) {
		data := bytes.Clone(seed)
		shstrndx := int(binary.LittleEndian.Uint16(data[62:]))
		shoff := int(binary.LittleEndian.Uint64(data[0x28:]))
		binary.LittleEndian.PutUint64(data[shoff+64*shstrndx+32:], 8<<30)
		if _, err := Inspect(writeTemp(t, data)); !errors.Is(err, errTooLarge) {
			t.Errorf("Inspect: %v", err)
		}
	})
	t.Run("program headers", func(t *testing.T) {
		data := bytes.Clone(seed)
		binary.LittleEndian.PutUint16(data[54:], 0xffff) // e_phentsize
		binary.LittleEndian.PutUint16(data[56:], 0xffff) // e_phnum
		if _, err := Inspect(writeTemp(t, data)); !errors.Is(err, errTooLarge) {
			t.Errorf("Inspect: %v", err)
		}
	})
	t.Run("symbol table", func(t *testing.T) {
		data := bytes.Clone(seed)
		sh, _ := sectionHeader(t, data, ".symtab")
		binary.LittleEndian.PutUint64(data[sh+32:], maxSymtabSize+24)
		f, err := elf.NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := symbols(f); !errors.Is(err, errTooLarge) {
			t.Errorf("symbols: %v", err)
		}
	})
}

// A panic in a file's analysis is an error about that file.
func TestGuard(t *testing.T) {
	var s []int
	err := guard(func() { _ = s[3] })
	var panicked *errPanic
	if !errors.As(err, &panicked) || !strings.Contains(err.Error(), "TestGuard") || !strings.Contains(err.Error(), "index out of range") {
		t.Errorf("guard: %v", err)
	}
	if err := guard(func() {}); err != nil {
		t.Errorf("guard without a panic: %v", err)
	}
}

// Paths from a process are resolved in its root: an absolute symlink in it
// points within it, and ".." stops at it.
func TestOpenInRoot(t *testing.T) {
	host, root := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(host, "libssl.so.3"), []byte("host"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "usr"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "libcrypto.so.3"), []byte("container"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(host, filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}
	if fd, err := openInRoot(root, "/usr/libcrypto.so.3"); err != nil {
		t.Errorf("a file in the root: %v", err)
	} else {
		unix.Close(fd)
	}
	for _, name := range []string{"/lib/libssl.so.3", strings.Repeat("../", 20) + host + "/libssl.so.3"} {
		if fd, err := openInRoot(root, name); err == nil {
			unix.Close(fd)
			t.Errorf("%s was opened outside the root", name)
		}
	}
	// Our own process's root is ours, so a path in it is the same file.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if fd, err := OpenPath(fmt.Sprintf("/proc/%d/root%s", os.Getpid(), self)); err != nil {
		t.Errorf("OpenPath of a path in a process's root: %v", err)
	} else {
		unix.Close(fd)
	}
}

// Names and search paths from a process's files can't lead out of its
// root, and aren't globs.
func TestFindLibraryLiteral(t *testing.T) {
	host, root := t.TempDir(), t.TempDir()
	for _, dir := range []string{host, filepath.Join(root, "opt")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "libssl.so.3"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := inRoot("/proc/7/root", "../../../etc/libssl.so.3"); got != "/proc/7/root/etc/libssl.so.3" {
		t.Errorf("inRoot: %s", got)
	}
	if got := findLibrary(root, "libssl.so.3", []string{"/opt"}); got != "/opt/libssl.so.3" {
		t.Errorf("in a search directory: %q", got)
	}
	for _, c := range []struct {
		name string
		dirs []string
	}{
		{"libssl.so.3", []string{strings.Repeat("../", 20) + host}},
		{"libssl.so*", []string{"/opt"}},
		{"libssl.so.3", []string{"/o*"}},
		{"../opt/libssl.so.3", []string{"/usr"}},
	} {
		if got := findLibrary(root, c.name, c.dirs); got != "" {
			t.Errorf("%s in %q: found %s", c.name, c.dirs, got)
		}
	}
}

// What a Watcher remembers is bounded, but never so that a file attached to
// for every process is returned again.
func TestWatcherBounded(t *testing.T) {
	for _, perProcess := range []bool{false, true} {
		w := newWatcher(t.TempDir(), perProcess)
		attached := fileID{ino: 1}
		w.remember(attached, []Target{{Path: "/lib/libssl.so.3", Library: OpenSSL}})
		for i := range 3 * maxSeen {
			w.remember(fileID{ino: uint64(i + 2)}, nil)
			w.knownRoot(fileID{ino: uint64(i + 2)})
		}
		if w.seen.len() > maxSeen || w.roots.len() > maxSeen {
			t.Errorf("perProcess %v: %d files and %d roots remembered", perProcess, w.seen.len(), w.roots.len())
		}
		if _, ok := w.lookup(attached); ok == perProcess {
			t.Errorf("perProcess %v: file attached to remembered: %v", perProcess, ok)
		}
		if _, ok := w.lookup(fileID{ino: 3*maxSeen + 1}); !ok {
			t.Errorf("perProcess %v: most recent file forgotten", perProcess)
		}
	}
}

// fuzzPatch applies 7-byte patches to seed: a region (the ELF header, the
// section headers, .gopclntab, .symtab, .note.go.buildid, or anywhere), a
// 4-byte offset in it and a 2-byte value.
func fuzzPatch(seed, p []byte) []byte {
	b := bytes.Clone(seed)
	f, err := elf.NewFile(bytes.NewReader(seed))
	if err != nil {
		return b
	}
	shoff := binary.LittleEndian.Uint64(seed[0x28:])
	region := func(r byte) (uint64, uint64) {
		name := map[byte]string{2: ".gopclntab", 3: ".symtab", 4: ".note.go.buildid"}[r%6]
		switch s := f.Section(name); {
		case r%6 == 0:
			return 0, 0x400
		case r%6 == 1:
			return shoff, uint64(len(f.Sections)) * 64
		case s != nil:
			return s.Offset, max(s.FileSize, 1)
		}
		return 0, uint64(len(seed))
	}
	for ; len(p) >= 7; p = p[7:] {
		start, n := region(p[0])
		if off := start + uint64(binary.LittleEndian.Uint32(p[1:]))%n; off+2 <= uint64(len(b)) {
			copy(b[off:], p[5:7])
		}
	}
	return b
}

// No file may crash snoopy, or make it read gigabytes.
func FuzzInspectELF(f *testing.F) {
	seed := hostGoFixture(f)
	f.Add([]byte{})
	f.Add([]byte{1, 0x20, 0, 0, 0, 0xff, 0xff})
	f.Add([]byte{3, 0x10, 0, 0, 0, 0xff, 0xff, 2, 8, 0, 0, 0, 0x10, 0x00})
	path := filepath.Join(f.TempDir(), "bin")
	f.Fuzz(func(t *testing.T, p []byte) {
		data := fuzzPatch(seed, p)
		if ef, err := elf.NewFile(bytes.NewReader(data)); err == nil && checkHeaders(bytes.NewReader(data)) == nil && checkSections(ef) == nil {
			// The analyses, without Inspect's guard.
			definedFuncs(ef)
			inspectRustls(ef)
			_, _ = findFreebl(ef)
			hasQUICStack(ef)
			_, _ = findBoringSSL(ef, nil)
			_, _ = FindGoFunc(ef, goReadFunc)
			_, _ = FindGoFunc(ef, goWriteFunc)
		}
		if err := os.WriteFile(path, data, 0o755); err != nil {
			t.Fatal(err)
		}
		targets, _ := Inspect(path)
		for _, tg := range targets {
			var panicked *errPanic
			if errors.As(tg.Problem, &panicked) {
				t.Error(tg.Problem)
			}
		}
	})
}

// Functions found through .gopclntab have whatever bounds it says.
func FuzzGosym(f *testing.F) {
	ef, err := elf.NewFile(bytes.NewReader(hostGoFixture(f)))
	if err != nil {
		f.Fatal(err)
	}
	if s := ef.Section(".gopclntab"); s != nil {
		d, _ := s.Data()
		f.Add(d, ef.Section(".text").Addr)
	}
	f.Add([]byte{0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8}, uint64(0))
	f.Fuzz(func(t *testing.T, d []byte, textStart uint64) {
		table, err := goTable(d, textStart)
		if err != nil {
			return
		}
		if fn := table.LookupFunc(goReadFunc); fn != nil {
			_ = fn.End - fn.Entry
		}
		table.PCToFunc(textStart + 0x100)
	})
}
