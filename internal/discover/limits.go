package discover

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
)

// Files are inspected for every process traced, including those in
// containers an attacker controls, who can make a sparse file of any size
// whose headers say anything. Snoopy reads sections whole, so what it reads
// is bounded, and a file that would make it read more isn't inspected.
const (
	// maxSectionSize is more than any real program's code or data: Chrome's
	// .text, the largest we know of, is about 200 MiB.
	maxSectionSize = 512 << 20
	// maxSymtabSize bounds the symbol tables read, which debug/elf turns
	// into a Symbol of about 100 bytes, with a copy of its name, for each
	// 24 bytes. Programs with more symbols than this (5 million) are read
	// as if stripped.
	maxSymtabSize = 128 << 20
	// maxHeadersSize bounds the program and section headers, which
	// elf.NewFile reads before anything can be checked.
	maxHeadersSize = 64 << 20
	// maxGoFuncSize bounds the size of a Go function read: the largest are
	// a few hundred KiB.
	maxGoFuncSize = 16 << 20
)

var errTooLarge = errors.New("ELF headers or sections implausibly large; not inspected")

// checkHeaders checks what elf.NewFile reads of a 64-bit ELF file, before
// it reads it: its program and section headers, and its section name
// table. Other files aren't checked; NewFile rejects them, or they're for a
// different architecture, which Inspect rejects.
func checkHeaders(r io.ReaderAt) error {
	var hdr [64]byte
	if _, err := r.ReadAt(hdr[:], 0); err != nil || string(hdr[:4]) != elf.ELFMAG || elf.Class(hdr[4]) != elf.ELFCLASS64 {
		return nil
	}
	var bo binary.ByteOrder = binary.LittleEndian
	if elf.Data(hdr[5]) == elf.ELFDATA2MSB {
		bo = binary.BigEndian
	}
	phentsize, phnum := uint64(bo.Uint16(hdr[54:])), uint64(bo.Uint16(hdr[56:]))
	shoff := bo.Uint64(hdr[40:])
	shentsize, shnum, shstrndx := uint64(bo.Uint16(hdr[58:])), uint64(bo.Uint16(hdr[60:])), uint64(bo.Uint16(hdr[62:]))
	if phentsize*phnum > maxHeadersSize {
		return errTooLarge
	}
	if shoff == 0 || shentsize < 64 {
		return nil // NewFile reads no sections, or rejects them
	}
	section := func(i uint64) (flags, size uint64, link uint32, ok bool) {
		var sh [64]byte
		if i > maxHeadersSize/shentsize || shoff+i*shentsize < shoff {
			return 0, 0, 0, false
		}
		if _, err := r.ReadAt(sh[:], int64(shoff+i*shentsize)); err != nil {
			return 0, 0, 0, false
		}
		return bo.Uint64(sh[8:]), bo.Uint64(sh[32:]), bo.Uint32(sh[40:]), true
	}
	if shnum == 0 || shstrndx == uint64(elf.SHN_XINDEX) {
		// More sections than fit in the header: their number is in the
		// first section's size, and the name table's index in its link.
		_, size, link, ok := section(0)
		if !ok {
			return nil
		}
		if shnum == 0 {
			shnum = size
		}
		if shstrndx == uint64(elf.SHN_XINDEX) {
			shstrndx = uint64(link)
		}
	}
	if shnum > maxHeadersSize/shentsize {
		return errTooLarge
	}
	if shstrndx != 0 && shstrndx < shnum {
		if flags, size, _, ok := section(shstrndx); ok && (size > maxSectionSize || flags&uint64(elf.SHF_COMPRESSED) != 0) {
			return errTooLarge
		}
	}
	return nil
}

// checkSections checks the sections of a file that snoopy reads, or
// debug/elf does for it: those loaded into memory, the symbol and string
// tables and the relocations. It leaves out debug information, which isn't
// read, and can be large in real programs.
func checkSections(f *elf.File) error {
	for _, s := range f.Sections {
		switch {
		case s.Type == elf.SHT_NOBITS:
		case s.Flags&elf.SHF_ALLOC != 0 && s.Flags&elf.SHF_COMPRESSED != 0:
			// Not allowed by the ELF specification; debug/elf leaves
			// such a section without a ReaderAt.
			return fmt.Errorf("allocated section %s is compressed", s.Name)
		case s.Flags&elf.SHF_ALLOC != 0, s.Type == elf.SHT_SYMTAB, s.Type == elf.SHT_DYNSYM, s.Type == elf.SHT_STRTAB,
			s.Type == elf.SHT_RELA, s.Type == elf.SHT_REL, s.Type == elf.SHT_DYNAMIC:
			if s.Size > maxSectionSize {
				return fmt.Errorf("section %s: %w", s.Name, errTooLarge)
			}
		}
	}
	return nil
}

// symbols is f.Symbols, but none if the table is too large to read.
func symbols(f *elf.File) ([]elf.Symbol, error) {
	if s := f.SectionByType(elf.SHT_SYMTAB); s != nil && s.Size > maxSymtabSize {
		return nil, fmt.Errorf("symbol table: %w", errTooLarge)
	}
	return f.Symbols()
}

// dynamicSymbols is f.DynamicSymbols, but none if the table is too large to
// read.
func dynamicSymbols(f *elf.File) ([]elf.Symbol, error) {
	if s := f.SectionByType(elf.SHT_DYNSYM); s != nil && s.Size > maxSymtabSize {
		return nil, fmt.Errorf("dynamic symbol table: %w", errTooLarge)
	}
	return f.DynamicSymbols()
}

// errPanic is a panic in a file's analysis, turned into an error.
type errPanic struct {
	value any
	at    string // where it panicked
}

func (e *errPanic) Error() string {
	return fmt.Sprintf("snoopy failed analyzing this file, which is a bug; please report it: %v (at %s)", e.value, e.at)
}

// recovered turns r, what recover returned, into an error: a parser bug
// mustn't take the tracer down, which inspects the files of every process
// it traces. Call it with recover() in a deferred function.
func recovered(r any) error {
	if r == nil {
		return nil
	}
	pcs := make([]uintptr, 32)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs)])
	at := "unknown"
	for {
		fr, more := frames.Next()
		if !strings.HasPrefix(fr.Function, "runtime.") {
			at = fmt.Sprintf("%s, %s:%d", fr.Function, filepath.Base(fr.File), fr.Line)
			break
		}
		if !more {
			break
		}
	}
	return &errPanic{value: r, at: at}
}

// guard runs one analysis of a file, returning a panic in it as an error.
func guard(analyze func()) (err error) {
	defer func() { err = recovered(recover()) }()
	analyze()
	return nil
}
