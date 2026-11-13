package tracer

import (
	"debug/elf"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// uprobe is one probe to attach to a file.
type uprobe struct {
	name    string // the function, for errors and Attach's result
	address uint64 // the function's file offset
	offset  uint64 // the probe's, from the function's start
	prog    *ebpf.Program
	ret     bool // a uretprobe
	// first is set for the probes that catch a call's end (uretprobes, and
	// the uprobes on a Go function's RETs), which are attached before the
	// rest: an entry seen without them would wait for an end never seen.
	first bool
}

// legacyUprobesForTests makes every Tracer attach as with
// Options.LegacyUprobes. The integration tests set it from
// SNOOPY_TEST_LEGACY_UPROBES=1, to run on a new kernel the way older ones
// attach.
var legacyUprobesForTests bool

// HaveUprobeMulti reports whether the kernel can attach uprobes through
// uprobe_multi links (Linux 6.6) and filters them by process correctly.
// The first kernels with them filtered by thread when given a PID, so a
// per-process probe only saw the main thread's calls; that was fixed by
// commit 46ba0e49b642 ("bpf: fix multi-uprobe PID filtering logic"),
// which also made the kernel check a PID before the file. So, as libbpf
// does, a link with an invalid PID on an invalid file tells them apart:
// EINVAL with the fix, EBADF for the file without it.
func HaveUprobeMulti() bool {
	if features.HaveBPFLinkUprobeMulti() != nil {
		return false
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "snoopy_upm_pid",
		Type:         ebpf.Kprobe,
		AttachType:   ebpf.AttachTraceUprobeMulti,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		License:      "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()
	ex, err := link.OpenExecutable("/")
	if err != nil {
		return false
	}
	l, err := ex.UprobeMulti(nil, prog, &link.UprobeMultiOptions{Addresses: []uint64{1}, PID: math.MaxUint32})
	if err == nil {
		_ = l.Close()
		return false
	}
	return errors.Is(err, unix.EINVAL)
}

// useUprobeMulti makes the uprobe programs in spec ones that attach through
// uprobe_multi links, which the kernel then requires of them.
func useUprobeMulti(spec *ebpf.CollectionSpec, multi bool) {
	for _, p := range spec.Programs {
		if p.Type != ebpf.Kprobe {
			continue
		}
		if strings.HasPrefix(p.SectionName, "uprobe") || strings.HasPrefix(p.SectionName, "uretprobe") {
			if multi {
				p.AttachType = ebpf.AttachTraceUprobeMulti
			} else {
				p.AttachType = ebpf.AttachNone
			}
		}
	}
}

// link attaches probes to the file ex is, for process pid only unless it's
// zero, and returns the links and the names of the functions whose probes
// were all attached, in the order they first appear in probes. On an
// error, the links made before it are returned with it.
//
// With uprobe_multi, the probes running the same program the same way are
// one link: the kernel then attaches and detaches them in one go. A
// perf-based link per probe takes it tens of milliseconds each to detach,
// which made snoopy take seconds, or minutes per process, to exit.
func (t *Tracer) link(ex *link.Executable, probes []uprobe, pid int) (links []link.Link, names []string, err error) {
	done := make([]bool, len(probes))
	if t.multi {
		links, err = linkMulti(ex, probes, pid, done)
	} else {
		links, err = linkEach(ex, probes, pid, done)
	}
	return links, attachedNames(probes, done), err
}

// linkEach makes a perf-based link for each probe, in order, and marks
// those it made in done.
func linkEach(ex *link.Executable, probes []uprobe, pid int, done []bool) ([]link.Link, error) {
	var links []link.Link
	for i, p := range probes {
		opts := &link.UprobeOptions{Address: p.address, Offset: p.offset, PID: pid}
		attach := ex.Uprobe
		if p.ret {
			attach = ex.Uretprobe
		}
		l, err := attach("", p.prog, opts)
		if err != nil {
			return links, fmt.Errorf("%s: %w", p.describe(), err)
		}
		links = append(links, l)
		done[i] = true
	}
	return links, nil
}

// linkMulti makes a uprobe_multi link for each group of probes (see
// groupUprobes), and marks those it attached in done.
func linkMulti(ex *link.Executable, probes []uprobe, pid int, done []bool) ([]link.Link, error) {
	var links []link.Link
	for _, group := range groupUprobes(probes) {
		addrs := make([]uint64, len(group))
		for i, j := range group {
			addrs[i] = probes[j].address + probes[j].offset
		}
		p := probes[group[0]]
		attach := ex.UprobeMulti
		if p.ret {
			attach = ex.UretprobeMulti
		}
		l, err := attach(nil, p.prog, &link.UprobeMultiOptions{Addresses: addrs, PID: uint32(pid)})
		if err != nil {
			var where []string
			for _, j := range group {
				if d := probes[j].describe(); !slices.Contains(where, d) {
					where = append(where, d)
				}
			}
			return links, fmt.Errorf("%s: %w", strings.Join(where, ", "), err)
		}
		links = append(links, l)
		for _, j := range group {
			done[j] = true
		}
	}
	return links, nil
}

// groupUprobes returns the indexes of probes grouped by program and kind
// (uprobe or uretprobe), which a uprobe_multi link each can attach: those
// marked first before the others, and otherwise in the order they first
// appear.
func groupUprobes(probes []uprobe) [][]int {
	type key struct {
		prog  *ebpf.Program
		ret   bool
		first bool
	}
	var order []key
	groups := map[key][]int{}
	for i, p := range probes {
		k := key{p.prog, p.ret, p.first}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}
	// Stable, so groups keep their order within each half.
	slices.SortStableFunc(order, func(a, b key) int {
		switch {
		case a.first == b.first:
			return 0
		case a.first:
			return -1
		}
		return 1
	})
	out := make([][]int, len(order))
	for i, k := range order {
		out[i] = groups[k]
	}
	return out
}

// attachedNames returns the names of the functions whose probes are all
// done, in the order they first appear.
func attachedNames(probes []uprobe, done []bool) []string {
	missed := map[string]bool{}
	for i, p := range probes {
		if !done[i] {
			missed[p.name] = true
		}
	}
	var names []string
	for _, p := range probes {
		if !missed[p.name] && !slices.Contains(names, p.name) {
			names = append(names, p.name)
		}
	}
	return names
}

// describe names a probe in an error: its function, and where in it if
// that's not the start.
func (p uprobe) describe() string {
	if p.offset != 0 {
		return fmt.Sprintf("%s+%#x", p.name, p.offset)
	}
	return p.name
}

// symbolOffsets returns the file offsets of the functions an ELF file's
// symbol tables name, as cilium/ebpf finds them for a uprobe on a symbol:
// both tables, the dynamic one taking precedence, and an address in an
// executable segment converted to its offset in the file. Functions
// imported from other files, at address zero, are left out.
func symbolOffsets(path string) (offsets map[string]uint64, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("parse ELF file: %w", err)
	}
	defer f.Close()
	defer func() {
		// debug/elf can panic on a malformed file.
		if r := recover(); r != nil {
			offsets, err = nil, fmt.Errorf("parse ELF file: %v", r)
		}
	}()
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	offsets = map[string]uint64{}
	for _, s := range append(syms, dynsyms...) {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			continue
		}
		if s.Value == 0 {
			delete(offsets, s.Name)
			continue
		}
		addr := s.Value
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Vaddr <= s.Value && s.Value < p.Vaddr+p.Memsz {
				addr = s.Value - p.Vaddr + p.Off
				break
			}
		}
		offsets[s.Name] = addr
	}
	return offsets, nil
}
