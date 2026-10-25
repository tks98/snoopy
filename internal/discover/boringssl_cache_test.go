package discover

import (
	"debug/elf"
	"os"
	"testing"
)

// A cache entry is only used for a file with the bytes it recorded: one
// left by a program that copied another's build ID doesn't apply to it.
func TestBoringSSLCacheMatches(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var off uint64
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Filesz > 4096 {
			off = p.Off + 1024
			break
		}
	}
	if off == 0 {
		t.Skip("no executable segment")
	}
	start, ok := bytesAt(f, off, cacheCheckLen)
	if !ok {
		t.Fatal("bytesAt")
	}
	good := boringSSLCache{Offsets: map[string]uint64{"SSL_read": off}, Starts: map[string][]byte{"SSL_read": start}}
	if !good.matches(f) {
		t.Error("an entry with the file's own bytes doesn't match")
	}
	other := append([]byte(nil), start...)
	other[0] ^= 0xff
	poisoned := boringSSLCache{Offsets: good.Offsets, Starts: map[string][]byte{"SSL_read": other}}
	if poisoned.matches(f) {
		t.Error("an entry with other bytes matches")
	}
	if (boringSSLCache{Offsets: good.Offsets}).matches(f) {
		t.Error("an entry without bytes (an older cache's) matches")
	}
}
