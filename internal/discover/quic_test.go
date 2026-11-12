package discover

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testSymbol is a dynamic symbol of a file made by makeELF: defined (with
// version, if the file has one) or imported.
type testSymbol struct {
	name    string
	defined bool
}

// makeELF returns a shared library for this machine with only dynamic
// symbols, their version (if version isn't ""), and the libraries it needs.
func makeELF(syms []testSymbol, version string, needed []string) []byte {
	le := binary.LittleEndian
	var dynstr bytes.Buffer
	dynstr.WriteByte(0)
	str := func(s string) uint32 {
		off := uint32(dynstr.Len())
		dynstr.WriteString(s + "\x00")
		return off
	}

	type section struct {
		name       string
		typ        elf.SectionType
		link, info uint32
		entsize    uint64
		data       []byte
	}
	const (
		dynstrIndex = 1
		dynsymIndex = 2
	)
	var dynsym, versym bytes.Buffer
	dynsym.Write(make([]byte, 24)) // the null symbol
	versym.Write(make([]byte, 2))
	for _, s := range syms {
		var e [24]byte
		le.PutUint32(e[0:], str(s.name))
		e[4] = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)
		ver := uint16(1) // global
		if s.defined {
			le.PutUint16(e[6:], dynsymIndex) // any section but SHN_UNDEF
			le.PutUint64(e[8:], 0x1000)
			if version != "" {
				ver = 2
			}
		}
		dynsym.Write(e[:])
		versym.Write(le.AppendUint16(nil, ver))
	}
	sections := []section{{}, {name: ".dynstr", typ: elf.SHT_STRTAB}, {name: ".dynsym", typ: elf.SHT_DYNSYM, link: dynstrIndex, info: 1, entsize: 24, data: dynsym.Bytes()}}
	if version != "" {
		// One version definition, index 2, with one name.
		verdef := make([]byte, 28)
		le.PutUint16(verdef[0:], 1) // vd_version
		le.PutUint16(verdef[4:], 2) // vd_ndx
		le.PutUint16(verdef[6:], 1) // vd_cnt
		le.PutUint32(verdef[12:], 20)
		le.PutUint32(verdef[20:], str(version))
		sections = append(sections,
			section{name: ".gnu.version", typ: elf.SHT_GNU_VERSYM, link: dynsymIndex, entsize: 2, data: versym.Bytes()},
			section{name: ".gnu.version_d", typ: elf.SHT_GNU_VERDEF, link: dynstrIndex, info: 1, data: verdef})
	}
	if len(needed) > 0 {
		var dynamic []byte
		for _, lib := range needed {
			dynamic = le.AppendUint64(le.AppendUint64(dynamic, uint64(elf.DT_NEEDED)), uint64(str(lib)))
		}
		dynamic = append(dynamic, make([]byte, 16)...) // DT_NULL
		sections = append(sections, section{name: ".dynamic", typ: elf.SHT_DYNAMIC, link: dynstrIndex, entsize: 16, data: dynamic})
	}
	sections[dynstrIndex].data = dynstr.Bytes()
	var shstrtab bytes.Buffer
	shstrtab.WriteByte(0)
	sections = append(sections, section{name: ".shstrtab", typ: elf.SHT_STRTAB})
	names := make([]uint32, len(sections))
	for i, s := range sections[1:] {
		names[i+1] = uint32(shstrtab.Len())
		shstrtab.WriteString(s.name + "\x00")
	}
	sections[len(sections)-1].data = shstrtab.Bytes()

	out := make([]byte, 64)
	offsets := make([]uint64, len(sections))
	for i, s := range sections[1:] {
		for len(out)%8 != 0 {
			out = append(out, 0)
		}
		offsets[i+1] = uint64(len(out))
		out = append(out, s.data...)
	}
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	shoff := uint64(len(out))
	for i, s := range sections {
		var h [64]byte
		le.PutUint32(h[0:], names[i])
		le.PutUint32(h[4:], uint32(s.typ))
		le.PutUint64(h[24:], offsets[i])
		le.PutUint64(h[32:], uint64(len(s.data)))
		le.PutUint32(h[40:], s.link)
		le.PutUint32(h[44:], s.info)
		le.PutUint64(h[48:], 8)
		le.PutUint64(h[56:], s.entsize)
		out = append(out, h[:]...)
	}
	copy(out, elf.ELFMAG)
	out[4], out[5], out[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	le.PutUint16(out[16:], uint16(elf.ET_DYN))
	le.PutUint16(out[18:], uint16(hostMachine()))
	le.PutUint32(out[20:], uint32(elf.EV_CURRENT))
	le.PutUint64(out[40:], shoff)
	le.PutUint16(out[52:], 64) // e_ehsize
	le.PutUint16(out[56:], 0)  // no program headers
	le.PutUint16(out[58:], 64)
	le.PutUint16(out[60:], uint16(len(sections)))
	le.PutUint16(out[62:], uint16(len(sections)-1))
	return out
}

// Files made for OpenSSL's QUIC: libcrypto 3.5, curl's libcurl that uses
// OpenSSL's QUIC, and Ruby's OpenSSL extension, which doesn't.
var (
	fakeLibcrypto = makeELF([]testSymbol{{"EVP_CipherInit_ex", true}, {"EVP_CipherUpdate", true}, {"EVP_CipherFinal_ex", true}}, "OPENSSL_3.2.0", nil)
	fakeLibcurl   = makeELF([]testSymbol{{"curl_easy_perform", true}, {"OSSL_QUIC_client_method", false}, {"SSL_CTX_new", false}}, "", []string{"libcrypto.so.3"})
	fakeRubySSL   = makeELF([]testSymbol{{"Init_openssl", true}, {"TLS_client_method", false}, {"SSL_CTX_new", false}}, "", []string{"libcrypto.so.3"})
)

func TestImportsQUICMethod(t *testing.T) {
	dir := t.TempDir()
	for name, c := range map[string]struct {
		data []byte
		want bool
	}{
		"libcurl.so.4":   {fakeLibcurl, true},
		"openssl.so":     {fakeRubySSL, false},
		"libssl.so.3":    {makeELF([]testSymbol{{"OSSL_QUIC_client_method", true}}, "OPENSSL_3.2.0", nil), false}, // defines it
		"thread.so":      {makeELF([]testSymbol{{"OSSL_QUIC_client_thread_method", false}}, "", nil), true},
		"server.so":      {makeELF([]testSymbol{{"OSSL_QUIC_server_method", false}}, "", nil), true},
		"locale-archive": {[]byte("not an ELF file"), false},
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, c.data, 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := importsQUICMethod(path)
		if err != nil || got != c.want {
			t.Errorf("%s: %v, %v; want %v", name, got, err, c.want)
		}
	}
	if _, err := importsQUICMethod(filepath.Join(dir, "gone")); !os.IsNotExist(err) {
		t.Errorf("a missing file: %v", err)
	}
}

// fakeProcess makes /proc/<pid> for a process whose root is root, with
// the files given (paths in the root) mapped, in that order: the first is
// its executable.
func fakeProcess(t *testing.T, proc, pid, comm, root string, files map[string][]byte, order []string) {
	t.Helper()
	dir := filepath.Join(proc, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var maps strings.Builder
	for i, name := range order {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, files[name], 0o755); err != nil {
			t.Fatal(err)
		}
		maps.WriteString(strings.Join([]string{"7f00000" + string(rune('a'+i)) + "0000-7f00000" + string(rune('a'+i)) + "1000", "r-xp", "00000000", "08:01", "1", name}, " ") + "\n")
	}
	maps.WriteString("7ffd3a5f0000-7ffd3a611000 rw-p 00000000 00:00 0 [stack]\n")
	for name, data := range map[string]string{"maps": maps.String(), "comm": comm + "\n", "environ": ""} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"root": root, "exe": order[0]} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
}

// fakeQUICProcs makes two processes, in one root, that map the same
// libcrypto: 7, a Ruby that doesn't use OpenSSL's QUIC, and 8, a curl that
// does, through libcurl.
func fakeQUICProcs(t *testing.T) string {
	proc := t.TempDir()
	root := filepath.Join(t.TempDir(), "rootfs")
	fakeProcess(t, proc, "7", "ruby", root, map[string][]byte{
		"/usr/bin/ruby":           makeELF([]testSymbol{{"main", true}}, "", []string{"openssl.so"}),
		"/usr/lib/openssl.so":     fakeRubySSL,
		"/usr/lib/libcrypto.so.3": fakeLibcrypto,
	}, []string{"/usr/bin/ruby", "/usr/lib/openssl.so", "/usr/lib/libcrypto.so.3"})
	fakeProcess(t, proc, "8", "curl", root, map[string][]byte{
		"/usr/bin/curl":           makeELF([]testSymbol{{"main", true}, {"curl_easy_perform", false}}, "", []string{"libcurl.so.4"}),
		"/usr/lib/libcurl.so.4":   fakeLibcurl,
		"/usr/lib/libcrypto.so.3": fakeLibcrypto,
	}, []string{"/usr/bin/curl", "/usr/lib/libcurl.so.4", "/usr/lib/libcrypto.so.3"})
	return proc
}

func quicPaths(targets []Target) []string {
	var out []string
	for _, t := range targets {
		if t.Library == OpenSSLQUIC {
			out = append(out, t.Path)
		}
	}
	return out
}

// libcrypto is an OpenSSLQUIC target only in a process that uses OpenSSL's
// QUIC: curl's, through libcurl, not Ruby's.
func TestWatcherOpenSSLQUIC(t *testing.T) {
	proc := fakeQUICProcs(t)
	if found, err := Inspect(filepath.Join(proc, "8", "root", "usr/lib/libcrypto.so.3")); err != nil || len(quicPaths(found)) != 1 {
		t.Fatalf("the libcrypto made isn't one for OpenSSL's QUIC: %+v, %v", found, err)
	}
	curlCrypto := filepath.Join(proc, "8", "root", "usr/lib/libcrypto.so.3")
	for _, perProcess := range []bool{false, true} {
		w := newWatcher(proc, perProcess)
		if got := quicPaths(w.Process(7)); len(got) != 0 {
			t.Errorf("perProcess %v: Ruby got %q", perProcess, got)
		}
		if got := quicPaths(w.Process(8)); !slices.Equal(got, []string{curlCrypto}) {
			t.Errorf("perProcess %v: curl got %q", perProcess, got)
		}
		again := quicPaths(w.Process(8))
		if perProcess != (len(again) == 1) {
			t.Errorf("perProcess %v: curl again got %q", perProcess, again)
		}
		if got := quicPaths(w.Root(8)); len(got) != 0 {
			t.Errorf("perProcess %v: Root returned %q", perProcess, got)
		}

		w = newWatcher(proc, perProcess)
		w.SkipOpenSSLQUIC()
		if got := quicPaths(w.Process(8)); len(got) != 0 {
			t.Errorf("perProcess %v: with SkipOpenSSLQUIC, curl got %q", perProcess, got)
		}
	}
}

// A process that has only just started: Needed finds that what it will
// load uses OpenSSL's QUIC.
func TestNeededOpenSSLQUIC(t *testing.T) {
	proc := fakeQUICProcs(t)
	for pid, want := range map[int]int{7: 0, 8: 1} {
		w := newWatcher(proc, true)
		if got := quicPaths(w.Needed(pid)); len(got) != want {
			t.Errorf("pid %d: got %q", pid, got)
		}
	}
}

// Without BTF, --comm's targets come from Find, which may find libcrypto in
// Ruby's process first and curl's after: it's a target, once.
func TestFindOpenSSLQUIC(t *testing.T) {
	proc := fakeQUICProcs(t)
	for _, c := range []struct {
		opts Options
		want int
	}{
		{Options{Comm: "ruby"}, 0},
		{Options{Comm: "curl"}, 1},
		{Options{PID: 8}, 1},
		{Options{PID: 7}, 0},
		{Options{}, 0}, // no process to trace given: not attached to anyway
	} {
		c.opts.ProcRoot = proc
		targets, _, err := Find(c.opts)
		if err != nil {
			t.Fatal(err)
		}
		if got := quicPaths(targets); len(got) != c.want {
			t.Errorf("%+v: got %q", c.opts, got)
		}
	}
	// Both, Ruby first.
	if err := os.WriteFile(filepath.Join(proc, "8", "comm"), []byte("rubycurl\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	targets, _, err := Find(Options{ProcRoot: proc, Comm: "ruby"})
	if err != nil {
		t.Fatal(err)
	}
	if got := quicPaths(targets); len(got) != 1 {
		t.Errorf("Ruby's and curl's: got %q", got)
	}
}
