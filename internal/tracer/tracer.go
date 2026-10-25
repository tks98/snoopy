// Package tracer loads snoopy's eBPF program, attaches it to TLS libraries
// and turns what it reports into Events.
package tracer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/tks98/snoopy/v2/internal/discover"
	"github.com/tks98/snoopy/v2/internal/procinfo"
)

const (
	// DefaultMaxCapture is the default number of bytes captured per call:
	// one maximum-size TLS record.
	DefaultMaxCapture = 16 << 10
	// MaxCaptureLimit is CHUNK_SIZE * MAX_CHUNKS in bpf/snoopy.c.
	MaxCaptureLimit = 1 << 20

	defaultRingBufferSize = 16 << 20
	maxCommLen            = 15
)

// Options configures a Tracer.
type Options struct {
	// PID traces only this process and those it starts; zero traces every
	// process. With BTF, a process is found to descend from it at its first
	// call; without, only those added with TracePID are traced.
	PID int
	// Comm traces only processes whose name, as shown in /proc/<pid>/comm,
	// starts with this.
	Comm string
	// MaxCapture is the maximum number of bytes captured per call.
	// Zero means DefaultMaxCapture.
	MaxCapture int
	// RingBufferSize is the size of the kernel-to-user buffer in bytes; a
	// power of two. Zero means 16 MiB.
	RingBufferSize int
	// PerProcess attaches probes to the processes the caller attaches for
	// (Attach's pid) rather than to files, with the kernel's PID filter:
	// then other programs using the same library don't trap on them. It's
	// for when only some processes are traced (PID, Comm, or a container
	// the caller filters on). Each new process needs its own, attached to
	// by WatchNewProcesses (forks too), so its first calls can be missed.
	// It needs BTF, to tell forks from threads; without, probes are per
	// file.
	PerProcess bool
	// Java makes the frames of snoopy's Java agent count (see RegisterJava).
	// Without it, the BPF program doesn't look for them in every write.
	Java bool

	// ignoreKernelBTF loads the program as if the kernel had no BTF (tests).
	ignoreKernelBTF bool
}

// Tracer is a loaded eBPF program with its probes.
type Tracer struct {
	opts       Options
	objs       snoopyObjects
	mu         sync.Mutex              // guards links, procs and files: Attach may run while Run does
	links      []link.Link             // the tracepoints'
	procs      map[int]*procLinks      // per process, the links of each
	files      map[procFile]*fileLinks // the files attached to for every process
	perProcess bool
	reader     *ringbuf.Reader
	clock      func(monoNs uint64) time.Time
	haveBTF    bool
	names      map[uint32]string // process names, when the kernel can't tell
	// tracedFull is set once traced_tgids was found full, which is said once.
	tracedFull atomic.Bool
	closing    sync.WaitGroup // closeLater's
	// attaching is held to read while attaching, and by closeLater to
	// write, for each link it closes: the kernel does both one at a time,
	// and attaching to a new process before it's done matters more.
	attaching sync.RWMutex
	closed    atomic.Bool // Close was called
}

// procLinks are the probes attached for one process.
type procLinks struct {
	start uint64                // when it started, so a reused PID isn't taken for it
	files map[procFile][]string // the functions attached to in each
	links []link.Link
}

type procFile struct {
	dev, ino uint64
	lib      discover.Library
}

// fileLinks are the probes attached to a file for every process. They're
// kept until no process can use the file any more (see DetachUnused), but
// not longer: each holds the file, and many programs are run once (a Go
// program that's built, run and deleted, a container's libraries).
type fileLinks struct {
	links []link.Link // nil while it's being attached to
	fd    int         // the file, opened with O_PATH, to tell when it's deleted
	dev   uint64
	ino   uint64
	// The root filesystem it's on, if it's another's than snoopy's (a
	// container's), and it can only be reached through that: no process
	// can map it once none has that root.
	root    fileKey
	hasRoot bool
	user    int // a process that maps it, while it's deleted
}

// fileKey identifies a file or directory.
type fileKey struct{ dev, ino uint64 }

// New loads the eBPF program into the kernel. Call Attach and AttachSyscalls
// to start collecting data, then Run to receive it.
func New(opts Options) (*Tracer, error) {
	if opts.MaxCapture == 0 {
		opts.MaxCapture = DefaultMaxCapture
	}
	if opts.MaxCapture < 1 || opts.MaxCapture > MaxCaptureLimit {
		return nil, fmt.Errorf("max capture must be between 1 and %d bytes", MaxCaptureLimit)
	}
	if len(opts.Comm) > maxCommLen {
		return nil, fmt.Errorf("process name %q is longer than the kernel's %d-character limit", opts.Comm, maxCommLen)
	}
	if opts.RingBufferSize == 0 {
		opts.RingBufferSize = defaultRingBufferSize
	}
	if opts.RingBufferSize < os.Getpagesize() || opts.RingBufferSize&(opts.RingBufferSize-1) != 0 {
		return nil, fmt.Errorf("ring buffer size must be a power of two and at least %d bytes", os.Getpagesize())
	}

	// Kernels before 5.11 charge BPF memory against RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, permissionHint(err)
	}

	spec, err := loadSnoopy()
	if err != nil {
		return nil, fmt.Errorf("parse BPF object: %w", err)
	}

	// Socket addresses and process names are read from kernel structures
	// whose layout is found through the kernel's BTF. Without BTF, give the
	// loader an empty spec instead: the relocations it can't resolve are
	// poisoned, and the verifier drops that code because have_btf is false.
	var loadOpts ebpf.CollectionOptions
	_, btfErr := btf.LoadKernelSpec()
	if opts.ignoreKernelBTF {
		btfErr = errors.New("ignored")
	}
	if btfErr != nil {
		loadOpts.Programs.KernelTypes, err = emptyBTFSpec()
		if err != nil {
			return nil, err
		}
	}

	var comm [16]byte
	copy(comm[:], opts.Comm)
	pidnsDev, pidnsIno := pidNamespace()
	// Per process, the processes attached for are what's traced (Attach
	// adds them to traced_tgids): one that renames itself later stays
	// traced, probes on a file every process uses (--lib) only trace them,
	// and their library loads are told of from their start.
	perProcess := opts.PerProcess && btfErr == nil
	for name, value := range map[string]any{
		"pidns_dev":    pidnsDev,
		"pidns_ino":    pidnsIno,
		"filter_tgids": opts.PID != 0 || perProcess,
		"max_capture":  uint32(opts.MaxCapture),
		// Without BTF the kernel only knows thread names, so the process
		// name is filtered on in user space instead.
		"filter_comm":  opts.Comm != "" && btfErr == nil && !perProcess,
		"targ_comm":    comm,
		"have_btf":     btfErr == nil,
		"java_enabled": opts.Java,
	} {
		if err := spec.Variables[name].Set(value); err != nil {
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}
	spec.Maps["events"].MaxEntries = uint32(opts.RingBufferSize)

	t := &Tracer{opts: opts, clock: monotonicClock(), haveBTF: btfErr == nil, names: map[uint32]string{},
		procs: map[int]*procLinks{}, files: map[procFile]*fileLinks{}}
	t.perProcess = perProcess
	if err := spec.LoadAndAssign(&t.objs, &loadOpts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("the kernel's BPF verifier rejected snoopy's program: %+v", ve)
		}
		return nil, permissionHint(fmt.Errorf("load BPF program: %w", err))
	}

	if opts.PID != 0 || perProcess || opts.Java {
		// Processes traced or registered are forgotten when they exit.
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_exit", Program: t.objs.SchedProcessExit})
		if err != nil {
			t.objs.Close()
			return nil, fmt.Errorf("raw tracepoint sched_process_exit: %w", err)
		}
		t.links = append(t.links, l)
	}
	if opts.PID != 0 {
		if err := t.TracePID(uint32(opts.PID)); err != nil {
			closeLinks(t.links)
			t.objs.Close()
			return nil, err
		}
	}
	t.reader, err = ringbuf.NewReader(t.objs.Events)
	if err != nil {
		closeLinks(t.links)
		t.objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	return t, nil
}

// TracePID adds a process to those traced, with Options.PID set: a process
// that it started, for example. The BPF program forgets it when it exits.
// When too many are traced at once, it says so the first time only.
func (t *Tracer) TracePID(pid uint32) error {
	err := t.objs.TracedTgids.Update(pid, uint8(1), ebpf.UpdateAny)
	if errors.Is(err, unix.E2BIG) {
		if t.tracedFull.Swap(true) {
			return nil
		}
		return fmt.Errorf("trace pid %d: %d processes, the most there can be, are traced already; until some exit, new ones are traced only if they descend from one that is",
			pid, t.objs.TracedTgids.MaxEntries())
	}
	if err != nil {
		return fmt.Errorf("trace pid %d: %w", pid, err)
	}
	// If it exited before it was added, the BPF program didn't see it go.
	if procGone(int(pid)) {
		_ = t.objs.TracedTgids.Delete(pid)
	}
	return nil
}

// procGone reports whether a process has exited: it's gone from /proc, or
// it's a zombie without threads left.
func procGone(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	s, ok := procinfo.ParseStat(stat)
	return !ok || s.Threads == 0 || s.State == 'Z' && s.Threads == 1 || s.State == 'X'
}

// RegisterJava makes the frames of snoopy's Java agent in process pid (as
// snoopy sees it, in its PID namespace) count, those carrying nonce, the session's secret: the agent
// writes them to /dev/null, and they become events like a TLS library's
// calls. Register before loading the agent, so its first calls are seen.
// It needs Options.Java. The session ends when the process exits.
func (t *Tracer) RegisterJava(pid uint32, nonce uint64) error {
	if !t.opts.Java {
		return errors.New("register java session: the tracer was made without Options.Java")
	}
	s := snoopyJavaSession{Nonce: nonce, Fd: -1}
	if err := t.objs.JavaSessions.Update(pid, &s, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("register java session for pid %d: %w", pid, err)
	}
	return nil
}

// JavaReady reports whether process pid's agent has written a frame for its
// session: its first says it's ready.
func (t *Tracer) JavaReady(pid uint32) bool {
	var s snoopyJavaSession
	return t.objs.JavaSessions.Lookup(pid, &s) == nil && s.Fd >= 0
}

// UnregisterJava stops counting process pid's agent frames.
func (t *Tracer) UnregisterJava(pid uint32) {
	_ = t.objs.JavaSessions.Delete(pid)
}

// procPidInitIno is the inode of the kernel's own PID namespace, which is
// fixed (PROC_PID_INIT_INO).
const procPidInitIno = 0xEFFFFFFC

// pidNamespace returns snoopy's PID namespace's device, as the kernel encodes
// it, and inode, for the BPF program to number PIDs as user space does; or
// zeros if it's the kernel's own, where the numbers are the same.
func pidNamespace() (dev, ino uint64) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil || st.Ino == procPidInitIno {
		return 0, 0
	}
	return uint64(unix.Major(st.Dev))<<20 | uint64(unix.Minor(st.Dev)), st.Ino
}

func emptyBTFSpec() (*btf.Spec, error) {
	b, err := btf.NewBuilder([]btf.Type{&btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}, nil)
	if err != nil {
		return nil, err
	}
	raw, err := b.Marshal(nil, nil)
	if err != nil {
		return nil, err
	}
	return btf.LoadSpecFromReader(bytes.NewReader(raw))
}

// PerProcess reports whether probes are attached per process (see
// Options.PerProcess).
func (t *Tracer) PerProcess() bool {
	return t.perProcess
}

// ResolvesAddresses reports whether socket addresses are read in the kernel.
// If not (the kernel has no BTF), events carry no addresses and callers have
// to look them up in /proc, which fails for connections closed by then.
func (t *Tracer) ResolvesAddresses() bool {
	return t.haveBTF
}

// processName returns the name of a process from /proc, for kernels without
// BTF, where the BPF program only sees the name of the calling thread.
func (t *Tracer) processName(pid uint32, fallback string) string {
	if name, ok := t.names[pid]; ok {
		return name
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fallback // the process may have exited; don't cache
	}
	if len(t.names) >= 4096 {
		clear(t.names)
	}
	name := strings.TrimSuffix(string(data), "\n")
	t.names[pid] = name
	return name
}

func permissionHint(err error) error {
	if errors.Is(err, unix.EPERM) || errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w (snoopy needs root, or at least CAP_BPF, CAP_PERFMON, CAP_SYS_RESOURCE and CAP_SYS_PTRACE)", err)
	}
	return err
}

// monotonicClock converts bpf_ktime_get_ns() timestamps (CLOCK_MONOTONIC) to
// wall-clock time.
func monotonicClock() func(uint64) time.Time {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	wall := time.Now()
	mono := ts.Nano()
	return func(ns uint64) time.Time {
		return wall.Add(time.Duration(int64(ns) - mono))
	}
}

type cProbe struct {
	symbol    string
	prog      *ebpf.Program
	entryOnly bool // captures on entry; no return probe
}

// Attach attaches probes to a target and returns the names of the functions
// it attached to. Per process, they're for process pid only, unless it's
// zero; attaching to a target of the process again does nothing and returns
// the names it did the first time. Attaching to a file attached to for every
// process does nothing and returns none.
func (t *Tracer) Attach(target discover.Target, pid int) ([]string, error) {
	if !t.perProcess {
		pid = 0
	}
	var traceErr error
	if pid != 0 {
		// Attached to even if it can't be added: a process descending from
		// one traced still is.
		traceErr = t.TracePID(uint32(pid))
	}
	// The file inspected, held onto: cilium/ebpf opens it again by path to
	// read its symbols, and the kernel looks the path up for each probe, by
	// when something else (a FIFO, which would block) could be there.
	fd, err := discover.OpenPath(target.Path)
	if err != nil {
		return nil, errors.Join(traceErr, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, errors.Join(traceErr, &os.PathError{Op: "stat", Path: target.Path, Err: err})
	}
	key := procFile{dev: uint64(st.Dev), ino: st.Ino, lib: target.Library}

	t.mu.Lock()
	var p *procLinks
	var f *fileLinks
	if pid != 0 {
		p = t.procLocked(pid)
		var funcs []string
		attached := p == nil || t.files[key] != nil // or it's gone
		if !attached {
			funcs, attached = p.files[key]
		}
		if attached {
			t.mu.Unlock()
			unix.Close(fd)
			return funcs, traceErr
		}
	} else {
		if t.files[key] != nil {
			// Already, through another path, or before its mtime changed,
			// which makes it new to the Watcher.
			t.mu.Unlock()
			unix.Close(fd)
			return nil, nil
		}
		f = &fileLinks{fd: fd, dev: key.dev, ino: key.ino}
		f.root, f.hasRoot = otherRoot(target.Path, key.dev)
		t.files[key] = f // taken, while it's attached to
	}
	t.mu.Unlock()

	t.attaching.RLock()
	funcs, links, err := t.attach(target, fd, pid)
	t.attaching.RUnlock()
	var stale []link.Link
	t.mu.Lock()
	switch {
	case len(funcs) == 0:
		stale = links
		if f != nil {
			delete(t.files, key)
		}
	case f != nil:
		f.links = links
	case t.procs[pid] == p:
		p.files[key] = funcs
		p.links = append(p.links, links...)
	default:
		stale = links // it exited meanwhile, and DetachExited closed the rest
	}
	t.mu.Unlock()
	closeLinks(stale)
	if f == nil || len(funcs) == 0 {
		unix.Close(fd)
	}
	return funcs, errors.Join(traceErr, err)
}

// otherRoot returns the root filesystem of the process whose
// /proc/<pid>/root a path is under, if the file there, on device dev, is
// on it, and it's another filesystem than snoopy's root: a container's,
// say, whose files have new device numbers in each container.
func otherRoot(path string, dev uint64) (fileKey, bool) {
	rest, ok := strings.CutPrefix(path, "/proc/")
	if !ok {
		return fileKey{}, false
	}
	pid, _, ok := strings.Cut(rest, "/root/")
	if !ok {
		return fileKey{}, false
	}
	var root, own unix.Stat_t
	if unix.Stat("/proc/"+pid+"/root", &root) != nil || unix.Stat("/", &own) != nil ||
		uint64(root.Dev) != dev || root.Dev == own.Dev {
		return fileKey{}, false
	}
	return fileKey{uint64(root.Dev), root.Ino}, true
}

// procLocked returns the links of a process, new if it has none or the PID
// was another's, or nil if it's gone. t.mu must be held.
func (t *Tracer) procLocked(pid int) *procLinks {
	start, ok := procStart(pid)
	if !ok {
		return nil
	}
	p := t.procs[pid]
	if p != nil && p.start == start {
		return p
	}
	if p != nil {
		closeLinks(p.links)
	}
	p = &procLinks{start: start, files: map[procFile][]string{}}
	t.procs[pid] = p
	return p
}

// procStart returns when a process started, in clock ticks since boot
// (field 22 of /proc/<pid>/stat), and whether it's there.
func procStart(pid int) (uint64, bool) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	s, ok := procinfo.ParseStat(stat)
	return s.Start, ok && s.Complete
}

// DetachExited closes the probes of processes that have exited.
func (t *Tracer) DetachExited() {
	var stale []link.Link
	t.mu.Lock()
	for pid, p := range t.procs {
		if start, ok := procStart(pid); !ok || start != p.start {
			stale = append(stale, p.links...)
			delete(t.procs, pid)
		}
	}
	t.mu.Unlock()
	t.closeLater(stale)
}

// DetachUnused closes the probes attached for every process to files that
// no process can use any more: deleted ones that none maps, and those on a
// container's root filesystem once no process has it as its root (another
// container from the same image has its own, with new device numbers). A
// file that's still there stays attached to: the Watcher returns each file
// once only.
func (t *Tracer) DetachUnused() {
	t.mu.Lock()
	var deleted, rooted []*fileLinks
	for _, f := range t.files {
		if f.links == nil {
			continue // being attached to
		}
		var st unix.Stat_t
		switch {
		case f.hasRoot:
			rooted = append(rooted, f)
		case unix.Fstat(f.fd, &st) == nil && st.Nlink == 0:
			deleted = append(deleted, f)
		}
	}
	t.mu.Unlock()
	if len(deleted) == 0 && len(rooted) == 0 {
		return
	}

	unused := map[*fileLinks]bool{}
	if len(rooted) > 0 {
		roots := liveRoots()
		for _, f := range rooted {
			if !roots[f.root] {
				unused[f] = true
			}
		}
	}
	// For deleted files, the process last seen to map one is looked at
	// first; only if it doesn't any more, every process is.
	want := map[fileKey]bool{}
	for _, f := range deleted {
		key := fileKey{f.dev, f.ino}
		if f.user == 0 || !mapsDeleted(f.user, map[fileKey]bool{key: true}, nil) {
			want[key] = true
		}
	}
	if len(want) > 0 {
		users := map[fileKey]int{}
		dirs, _ := os.ReadDir("/proc")
		for _, d := range dirs {
			if pid, err := strconv.Atoi(d.Name()); err == nil {
				mapsDeleted(pid, want, users)
			}
		}
		t.mu.Lock()
		for _, f := range deleted {
			if key := (fileKey{f.dev, f.ino}); want[key] {
				f.user = users[key]
				if f.user == 0 {
					unused[f] = true
				}
			}
		}
		t.mu.Unlock()
	}
	if len(unused) == 0 {
		return
	}

	var stale []link.Link
	t.mu.Lock()
	for key, f := range t.files {
		if unused[f] {
			stale = append(stale, f.links...)
			unix.Close(f.fd)
			delete(t.files, key)
		}
	}
	t.mu.Unlock()
	t.closeLater(stale)
}

// liveRoots returns the root directories of the processes running.
func liveRoots() map[fileKey]bool {
	roots := map[fileKey]bool{}
	dirs, _ := os.ReadDir("/proc")
	for _, d := range dirs {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		var st unix.Stat_t
		if unix.Stat("/proc/"+d.Name()+"/root", &st) == nil {
			roots[fileKey{uint64(st.Dev), st.Ino}] = true
		}
	}
	return roots
}

// mapsDeleted reports whether process pid maps one of the deleted files in
// want, and if users isn't nil, records it as their user.
func mapsDeleted(pid int, want map[fileKey]bool, users map[fileKey]int) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return false
	}
	defer f.Close()
	found := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// address perms offset dev inode path, and " (deleted)" after the
		// path of a file that's deleted.
		line := sc.Bytes()
		if !bytes.HasSuffix(line, []byte(" (deleted)")) {
			continue
		}
		fields := strings.Fields(string(line))
		if len(fields) < 6 {
			continue
		}
		major, minor, ok := strings.Cut(fields[3], ":")
		maj, err1 := strconv.ParseUint(major, 16, 32)
		mnr, err2 := strconv.ParseUint(minor, 16, 32)
		ino, err3 := strconv.ParseUint(fields[4], 10, 64)
		if !ok || err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		key := fileKey{unix.Mkdev(uint32(maj), uint32(mnr)), ino}
		if want[key] {
			found = true
			if users == nil {
				return true
			}
			users[key] = pid
		}
	}
	return found
}

// closeLater closes links in the background, a few at a time, and not
// while attaching: closing many takes seconds, and the kernel attaches and
// detaches uprobes one at a time, so closing would hold up attaching to new
// processes, and short-lived ones would be missed. Close closes what's left
// at once.
func (t *Tracer) closeLater(links []link.Link) {
	if len(links) == 0 {
		return
	}
	t.closing.Add(1)
	go func() {
		defer t.closing.Done()
		for len(links) > 0 && !t.closed.Load() {
			n := min(len(links), closeBatch)
			t.attaching.Lock()
			closeLinks(links[:n])
			t.attaching.Unlock()
			links = links[n:]
		}
		closeLinks(links)
	}()
}

// closeBatch is how many links closeLater closes at once.
const closeBatch = 8

// maxClosing bounds how many links are closed at once. Closing a uprobe's
// takes the kernel tens of milliseconds, mostly waiting for RCU grace
// periods, which closes at the same time share.
const maxClosing = 1024

// closeLinks closes links, concurrently.
func closeLinks(links []link.Link) {
	if len(links) <= 1 {
		for _, l := range links {
			_ = l.Close()
		}
		return
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxClosing)
	for _, l := range links {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Close()
			<-sem
		}()
	}
	wg.Wait()
}

// attach attaches to a target, the file at fd, and returns the names of the
// functions it attached to and the links, those it made before an error
// too.
func (t *Tracer) attach(target discover.Target, fd, pid int) (attached []string, links []link.Link, err error) {
	ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, nil, err
	}

	var probes []cProbe
	switch target.Library {
	case discover.OpenSSL:
		probes = []cProbe{
			{"SSL_read", t.objs.SslReadEnter, false},
			{"SSL_write", t.objs.SslWriteEnter, false},
			{"SSL_read_ex", t.objs.SslReadExEnter, false},
			{"SSL_write_ex", t.objs.SslWriteExEnter, false},
			// BoringSSL's packet encryption for QUIC (HTTP/3).
			{"EVP_AEAD_CTX_seal", t.objs.QuicSealEnter, true},
			{"EVP_AEAD_CTX_open", t.objs.QuicOpenEnter, false},
		}
	case discover.GnuTLS:
		probes = []cProbe{
			{"gnutls_record_recv", t.objs.GnutlsRecordRecvEnter, false},
			{"gnutls_record_send", t.objs.GnutlsRecordSendEnter, false},
		}
	case discover.NSS:
		if target.Offsets["AES_AEAD"] != 0 { // freebl, for Firefox's QUIC
			probes = []cProbe{
				{"AES_CreateContext", t.objs.AesCreateEnter, false},
				{"AES_AEAD", t.objs.AesAeadEnter, false},
			}
			break
		}
		probes = []cProbe{
			{"PR_Read", t.objs.PR_ReadEnter, false},
			{"PR_Write", t.objs.PR_WriteEnter, false},
			{"PR_Recv", t.objs.PR_RecvEnter, false},
			{"PR_Send", t.objs.PR_SendEnter, false},
		}
	case discover.WolfSSL:
		probes = []cProbe{
			{"wolfSSL_read", t.objs.WolfsslReadEnter, false},
			{"wolfSSL_write", t.objs.WolfsslWriteEnter, false},
		}
	case discover.MbedTLS:
		probes = []cProbe{
			{"mbedtls_ssl_read", t.objs.MbedtlsSslReadEnter, false},
			{"mbedtls_ssl_write", t.objs.MbedtlsSslWriteEnter, false},
		}
	case discover.S2N:
		probes = []cProbe{
			{"s2n_recv", t.objs.S2nRecvEnter, false},
			{"s2n_send", t.objs.S2nSendEnter, false},
		}
	case discover.NGTCP2:
		probes = []cProbe{
			{"ngtcp2_crypto_encrypt", t.objs.Ngtcp2EncryptEnter, true},
			{"ngtcp2_crypto_decrypt", t.objs.Ngtcp2DecryptEnter, false},
		}
	case discover.GoTLS:
		return t.attachGo(ex, target.Go, pid)
	case discover.Rustls:
		return t.attachRustls(ex, target.Rust, pid)
	default:
		return nil, nil, fmt.Errorf("unsupported library %v", target.Library)
	}

	for _, p := range probes {
		// Not limited to Options.PID unless per process, since its
		// descendants are traced too: the BPF program filters on
		// traced_tgids.
		opts := &link.UprobeOptions{PID: pid}
		if target.Offsets != nil { // a stripped copy: functions found by signature
			off, ok := target.Offsets[p.symbol]
			if !ok {
				continue
			}
			opts.Address = off
		}
		// Attach the return probe first so no entry goes unmatched.
		if !p.entryOnly {
			retProg := t.objs.TlsReturn
			if p.symbol == "AES_CreateContext" { // records the new context's direction
				retProg = t.objs.AesCreateReturn
			}
			ret, err := ex.Uretprobe(p.symbol, retProg, opts)
			if errors.Is(err, link.ErrNoSymbol) {
				continue // e.g. SSL_read_ex before OpenSSL 1.1.1
			}
			if err != nil {
				return attached, links, fmt.Errorf("%s: %w", p.symbol, err)
			}
			links = append(links, ret)
		}

		entry, err := ex.Uprobe(p.symbol, p.prog, opts)
		if errors.Is(err, link.ErrNoSymbol) {
			continue
		}
		if err != nil {
			return attached, links, fmt.Errorf("%s: %w", p.symbol, err)
		}
		links = append(links, entry)
		attached = append(attached, p.symbol)
	}
	if len(attached) == 0 {
		return nil, links, errors.New("none of the expected functions were found")
	}
	return attached, links, nil
}

// attachRustls attaches to rustls's Reader::read and Writer::write, found by
// their mangled names, at their file offsets, or to where its crypto
// provider encrypts and decrypts records.
func (t *Tracer) attachRustls(ex *link.Executable, ri *discover.RustInfo, pid int) (attached []string, links []link.Link, err error) {
	if ri == nil {
		return nil, nil, errors.New("missing rustls function information")
	}
	type probe struct {
		name      string
		offsets   []uint64
		prog      *ebpf.Program
		entryOnly bool
	}
	probes := []probe{
		{"rustls::Reader::read", ri.Reads, t.objs.RustlsReadEnter, false},
		{"rustls::Writer::write", ri.Writes, t.objs.RustlsWriteEnter, false},
	}
	if ri.AtRecords() {
		// All of the program's TLS, so not also its Writer, whose data
		// would show twice. Sealing emits at entry.
		probes = []probe{
			{"EVP_AEAD_CTX_seal", ri.Seals, t.objs.AeadSealEnter, true},
			{"EVP_AEAD_CTX_seal_scatter", ri.Scatters, t.objs.AeadSealScatterEnter, true},
			{"EVP_AEAD_CTX_open", ri.Opens, t.objs.AeadOpenEnter, false},
			{"ring::aead seal", ri.RingSeals, t.objs.RingSealEnter, true},
			{"ring::aead open", ri.RingOpens, t.objs.RingOpenEnter, false},
			{"ring::aead open (ring 0.16)", ri.Ring016Opens, t.objs.Ring016OpenEnter, false},
		}
	}
	for _, p := range probes {
		for _, off := range p.offsets {
			opts := &link.UprobeOptions{Address: off, PID: pid}
			if !p.entryOnly {
				ret, err := ex.Uretprobe("", t.objs.TlsReturn, opts)
				if err != nil {
					return attached, links, fmt.Errorf("%s at %#x: %w", p.name, off, err)
				}
				links = append(links, ret)
			}
			entry, err := ex.Uprobe("", p.prog, opts)
			if err != nil {
				return attached, links, fmt.Errorf("%s at %#x: %w", p.name, off, err)
			}
			links = append(links, entry)
		}
		if len(p.offsets) > 0 {
			attached = append(attached, p.name)
		}
	}
	return attached, links, nil
}

func (t *Tracer) attachGo(ex *link.Executable, gi *discover.GoInfo, pid int) (attached []string, links []link.Link, err error) {
	if gi == nil {
		return nil, nil, errors.New("missing Go function information")
	}
	type goProbe struct {
		name    string
		f       discover.GoFunc
		prog    *ebpf.Program
		retProg *ebpf.Program // nil if it emits at entry
	}
	probes := []goProbe{
		{"crypto/tls.(*Conn).Read", gi.Read, t.objs.GoTlsReadEnter, t.objs.GoTlsReturn},
		{"crypto/tls.(*Conn).Write", gi.Write, t.objs.GoTlsWriteEnter, t.objs.GoTlsReturn},
	}
	if gi.Read.Offset == 0 { // a QUIC program without TLS connections
		probes = nil
	}
	for i := range gi.Seals {
		probes = append(probes,
			goProbe{"cipher.AEAD.Seal (QUIC)", gi.Seals[i], t.objs.GoAeadSealEnter, nil},
			goProbe{"cipher.AEAD.Open (QUIC)", gi.Opens[i], t.objs.GoAeadOpenEnter, t.objs.GoAeadOpenReturn})
	}
	for _, fn := range probes {
		// Return probes go on each RET instruction rather than using a
		// uretprobe, which would corrupt the goroutine's stack.
		for _, ret := range fn.f.Returns {
			if fn.retProg == nil {
				break
			}
			l, err := ex.Uprobe("", fn.retProg, &link.UprobeOptions{
				Address: fn.f.Offset, Offset: ret, PID: pid,
			})
			if err != nil {
				return attached, links, fmt.Errorf("%s+%#x: %w", fn.name, ret, err)
			}
			links = append(links, l)
		}
		// The entry probe goes after the stack check: when the stack has to
		// grow, runtime.morestack restarts the function from the top, and a
		// probe on the first instruction would see the call twice.
		l, err := ex.Uprobe("", fn.prog, &link.UprobeOptions{
			Address: fn.f.Offset, Offset: fn.f.Body, PID: pid,
		})
		if err != nil {
			return attached, links, fmt.Errorf("%s+%#x: %w", fn.name, fn.f.Body, err)
		}
		links = append(links, l)
		if !slices.Contains(attached, fn.name) {
			attached = append(attached, fn.name)
		}
	}
	return attached, links, nil
}

// AttachSyscalls attaches the syscall tracepoint that tells snoopy which
// socket each TLS connection of a C library uses. Without it, events from
// those libraries have no file descriptor or addresses.
func (t *Tracer) AttachSyscalls() error {
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: t.objs.SysEnter})
	if err != nil {
		return fmt.Errorf("raw tracepoint sys_enter: %w", err)
	}
	t.addLink(l)
	return nil
}

// rescanDelays are when a new process's files are inspected, counted from
// its exec. Its executable is there right away, which is enough for Go and
// statically linked programs; the dynamic loader maps shared libraries a
// little later, and programs may load more as they go.
var rescanDelays = []time.Duration{0, 50 * time.Millisecond, 500 * time.Millisecond, 3 * time.Second}

// libraryRescanDelays are when a process that loaded a TLS library, and
// isn't held, is looked at again: the BPF program sees the mmap before it's
// done.
var libraryRescanDelays = []time.Duration{20 * time.Millisecond, 300 * time.Millisecond}

// loadedLibrary marks a PID in the execs ring buffer that loaded a library
// (LOADED_LIBRARY in the BPF program).
const loadedLibrary = 0x80000000

// maxHold is how long a new process is held while its files are inspected
// and attached to; inspecting a large program the first time (a browser's
// stripped BoringSSL) can take longer, and it isn't held up for that.
const maxHold = 2 * time.Second

// maxLibraryHold is how long a thread that loaded a TLS library is held: a
// stripped BoringSSL (Conscrypt's) is analyzed the first time snoopy sees
// its build, which takes seconds, and the thread is about to use it.
const maxLibraryHold = 10 * time.Second

// WatchNewProcesses attaches, in the background, to the TLS libraries and
// programs of processes that start from now on, as w finds them, and per
// process (see Options.PerProcess), those forked from a traced one. accept, if
// not nil, decides whether to look at a process at all; attached is called
// with the result of every attempt to attach. TLS calls a process makes
// before its files are inspected are missed, unless hold says to hold it:
// then a process whose executable or root filesystem is new to w is
// stopped (with ptrace, which its parent doesn't see, unlike SIGSTOP) until
// they're attached to, or maxHold; and so is a thread of a process to hold
// that loads a TLS library, until it's attached to. Call stop to stop watching and wait for
// the watcher to finish.
func (t *Tracer) WatchNewProcesses(w *discover.Watcher, accept, hold func(pid int) bool,
	attached func(target discover.Target, funcs []string, err error)) (stop func(), err error) {
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_exec", Program: t.objs.SchedProcessExec})
	if err != nil {
		return nil, fmt.Errorf("raw tracepoint sched_process_exec: %w", err)
	}
	t.addLink(l)
	if t.perProcess {
		// A process forked from a traced one has its parent's probes only
		// until its first call, when the kernel finds they aren't for it.
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_fork", Program: t.objs.SchedProcessFork})
		if err != nil {
			return nil, fmt.Errorf("raw tracepoint sched_process_fork: %w", err)
		}
		t.addLink(l)
	}
	reader, err := ringbuf.NewReader(t.objs.Execs)
	if err != nil {
		return nil, fmt.Errorf("open exec ring buffer: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	pids := make(chan int)
	holds := make(chan heldProcess, 64)
	held := make(chan heldProcess)
	wg.Add(3)
	go func() { // read execs and schedule inspections
		defer wg.Done()
		var rec ringbuf.Record
		for ctx.Err() == nil {
			reader.SetDeadline(time.Now().Add(200 * time.Millisecond))
			err := reader.ReadInto(&rec)
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			if err != nil || len(rec.RawSample) < 4 {
				continue
			}
			pid := int(binary.NativeEndian.Uint32(rec.RawSample))
			if pid&loadedLibrary != 0 && len(rec.RawSample) >= 8 {
				// A process loaded a TLS library: the thread that did is
				// held until it's attached to, if the process is one to
				// hold, as it's about to use it; else it's looked at again
				// once the mapping is done.
				pid &^= loadedLibrary
				tid := int(binary.NativeEndian.Uint32(rec.RawSample[4:]))
				if hold != nil && hold(pid) {
					select {
					case holds <- heldProcess{pid: pid, tid: tid, library: true}:
						continue
					default:
					}
				}
				for _, d := range libraryRescanDelays {
					time.AfterFunc(d, func() {
						select {
						case pids <- pid:
						case <-ctx.Done():
						}
					})
				}
				continue
			}
			if hold != nil && hold(pid) && !w.Known(pid) {
				select {
				case holds <- heldProcess{pid: pid, tid: pid}:
				default: // too many at once; they're looked at as usual
				}
			}
			for _, d := range rescanDelays {
				time.AfterFunc(d, func() {
					select {
					case pids <- pid:
					case <-ctx.Done():
					}
				})
			}
		}
	}()
	go func() { // hold new processes, one at a time
		defer wg.Done()
		// ptrace requests have to come from the thread that seized, which
		// stays locked: when this goroutine ends, so does the thread, and
		// the kernel lets go of whatever it still traces.
		runtime.LockOSThread()
		// Threads seized that didn't stop in time (in an uninterruptible
		// sleep, say), which can't be detached from until they do stop.
		var stray []int
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				stray = slices.DeleteFunc(stray, letGo)
			case p := <-holds:
				// A new process, or a thread that loaded a TLS library.
				sig, ok, attached := seize(p.tid)
				if !ok {
					if attached {
						stray = append(stray, p.tid)
					}
					continue
				}
				// Held until it's attached to, or for maxHold, also when
				// the inspector is still busy with another.
				p.done = make(chan struct{})
				limit := time.After(p.maxHold())
				select {
				case held <- p:
					select {
					case <-p.done:
					case <-limit:
					}
				case <-limit:
				case <-ctx.Done():
				}
				_ = release(p.tid, sig) // stopped, so this works
			}
		}
	}()
	go func() { // inspect and attach, one process at a time
		defer wg.Done()
		// For a held process, what it's about to load too (root), and per
		// process, the libraries it may load later.
		inspect := func(pid int, root bool) {
			if accept != nil && !accept(pid) {
				return
			}
			if t.perProcess {
				// Traced even before anything is attached for it, so that
				// the libraries it loads later are told of.
				if err := t.TracePID(uint32(pid)); err != nil {
					attached(discover.Target{}, nil, err)
				}
			}
			var targets, later []discover.Target
			if root || t.perProcess {
				later = w.Root(pid)
			}
			if root {
				targets = w.Needed(pid)
			}
			if !t.perProcess {
				targets, later = append(later, targets...), nil
			}
			for _, target := range append(targets, w.Process(pid)...) {
				if target.Problem != nil {
					attached(target, nil, target.Problem)
					continue
				}
				funcs, err := t.Attach(target, pid)
				attached(target, funcs, err)
			}
			// Per process, those it may load, after those it has: only
			// failures are worth reporting.
			for _, target := range later {
				if target.Problem == nil {
					if _, err := t.Attach(target, pid); err != nil {
						attached(target, nil, err)
					}
				}
			}
		}
		sweep := time.NewTicker(5 * time.Second)
		defer sweep.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sweep.C:
				if t.perProcess {
					t.DetachExited()
				}
				t.DetachUnused()
			case pid := <-pids:
				inspect(pid, false)
			case p := <-held:
				inspect(p.pid, !p.library)
				close(p.done)
			}
		}
	}()
	return func() {
		cancel()
		wg.Wait()
		reader.Close()
	}, nil
}

type heldProcess struct {
	pid, tid int // the thread held: the process's for a new one
	// library is set for a thread that loaded a TLS library, rather than a
	// new process.
	library bool
	done    chan struct{} // closed once its files are attached to
}

// maxHold is how long the thread is held at most.
func (p heldProcess) maxHold() time.Duration {
	if p.library {
		return maxLibraryHold
	}
	return maxHold
}

// seize stops a process, or one of its threads (pid is a thread ID), with
// ptrace, without its parent seeing it stop, and returns the signal it
// stopped for, if any, which release passes on. If it didn't stop (ok is
// false) but is still traced (attached), it will stop later, when it can,
// and has to be let go of then (letGo): detaching only works from a stop.
func seize(pid int) (sig int, ok, attached bool) {
	if unix.PtraceSeize(pid) != nil {
		return 0, false, false // gone, already traced, or not allowed (Yama)
	}
	if unix.PtraceInterrupt(pid) != nil {
		return 0, false, !letGo(pid)
	}
	// Wait for it to stop, without blocking: another thread waiting for the
	// process (if it's our own child) can take the notification, and then
	// only /proc says it stopped.
	for deadline := time.Now().Add(maxHold); time.Now().Before(deadline); time.Sleep(100 * time.Microsecond) {
		var ws unix.WaitStatus
		n, err := unix.Wait4(pid, &ws, unix.WALL|unix.WNOHANG, nil)
		switch {
		case err == unix.EINTR:
			continue
		case n == pid && ws.Stopped():
			// PTRACE_INTERRUPT's own stop is a PTRACE_EVENT_STOP; any
			// other stop is a signal arriving, to deliver when it goes.
			if ws.TrapCause() == unix.PTRACE_EVENT_STOP {
				return 0, true, true
			}
			return int(ws.StopSignal()), true, true
		case n == pid || err != nil && err != unix.ECHILD:
			return 0, false, false // it exited
		}
		if traceStopped(pid) {
			return 0, true, true
		}
	}
	return 0, false, !letGo(pid)
}

// letGo detaches from a thread seized that didn't stop when asked, if it
// has stopped by now or is gone, and reports whether it's let go of.
func letGo(pid int) bool {
	var ws unix.WaitStatus
	n, err := unix.Wait4(pid, &ws, unix.WALL|unix.WNOHANG, nil)
	sig := 0
	switch {
	case n == pid && ws.Stopped():
		if ws.TrapCause() != unix.PTRACE_EVENT_STOP {
			sig = int(ws.StopSignal())
		}
	case n == pid || err != nil && err != unix.ECHILD && err != unix.EINTR:
		return true // it exited
	case !traceStopped(pid):
		return false // not stopped yet
	default:
		// Stopped since: for a signal, which detaching would lose without
		// it, if the stop's notification came meanwhile.
		if n, _ := unix.Wait4(pid, &ws, unix.WALL|unix.WNOHANG, nil); n == pid && ws.Stopped() &&
			ws.TrapCause() != unix.PTRACE_EVENT_STOP {
			sig = int(ws.StopSignal())
		}
	}
	return release(pid, sig) == nil
}

// traceStopped reports whether a process is in a ptrace stop: state t in
// /proc/<pid>/stat, after the command name, which may contain anything.
func traceStopped(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s, ok := procinfo.ParseStat(stat)
	return ok && s.State == 't'
}

// release detaches from a thread. ESRCH means it's gone, or not in a stop,
// which leaves it traced: the latter is an error.
func release(pid, sig int) error {
	_, _, e := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(pid), 0, uintptr(sig), 0, 0)
	if e == unix.ESRCH {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
			return nil // gone
		}
	}
	if e != 0 {
		return e
	}
	return nil
}

// Run delivers events to handle until ctx is cancelled. handle is called
// from Run's goroutine. A connection's writes that went out before its
// socket was known are held back until it is, briefly.
func (t *Tracer) Run(ctx context.Context, handle func(*Event)) error {
	const (
		pollInterval  = 200 * time.Millisecond
		maxChunkWait  = time.Second
		maxSocketWait = 300 * time.Millisecond
		// The BPF side wakes the reader at most once a millisecond per CPU
		// (WAKEUP_INTERVAL_NS), so records can arrive without a wakeup, the
		// last of a burst especially; they wait at most this long.
		readWait = 20 * time.Millisecond
	)
	asm := newAssembler(t.clock)
	sockets := newSocketWaiter()
	lastExpire := time.Now()
	var rec ringbuf.Record

	release := func(ev *Event) {
		if !t.haveBTF {
			ev.Comm = t.processName(ev.PID, ev.Comm)
			if t.opts.Comm != "" && !strings.HasPrefix(ev.Comm, t.opts.Comm) {
				return
			}
		}
		handle(ev)
	}
	deliver := func(ev *Event, now time.Time) {
		for _, ev := range sockets.add(ev, now) {
			release(ev)
		}
	}

	for {
		if ctx.Err() != nil {
			now := time.Now()
			for _, ev := range asm.expire(now, 0) {
				deliver(ev, now)
			}
			for _, ev := range sockets.expire(now, 0) {
				release(ev)
			}
			return nil
		}

		t.reader.SetDeadline(time.Now().Add(readWait))
		err := t.reader.ReadInto(&rec)
		now := time.Now()
		switch {
		case errors.Is(err, os.ErrDeadlineExceeded):
		case errors.Is(err, ringbuf.ErrClosed):
			return nil
		case err != nil:
			return fmt.Errorf("read ring buffer: %w", err)
		default:
			c, err := parseChunk(rec.RawSample)
			if err != nil {
				return err
			}
			if c.Fn == fnSocketNotice {
				for _, ev := range sockets.notice(c) {
					release(ev)
				}
				break
			}
			if c.Fn == fnQUICPacketSent {
				release(asm.newEvent(c))
				break
			}
			for _, ev := range asm.add(c, now) {
				deliver(ev, now)
			}
		}

		if now.Sub(lastExpire) >= pollInterval {
			for _, ev := range asm.expire(now, maxChunkWait) {
				deliver(ev, now)
			}
			for _, ev := range sockets.expire(now, maxSocketWait) {
				release(ev)
			}
			lastExpire = now
		}
	}
}

// LostEvents returns how many chunks the kernel dropped because the ring
// buffer was full.
func (t *Tracer) LostEvents() (uint64, error) {
	return t.counter(0) // COUNTER_LOST
}

// UntrackedQUIC returns how many QUIC packets were left out because their
// encryption context was created before snoopy started (Firefox's, whose
// direction is only known from its creation).
func (t *Tracer) UntrackedQUIC() (uint64, error) {
	return t.counter(1) // COUNTER_UNTRACKED_QUIC
}

// QUICTraffic is what the BPF program saw of a process's HTTP/3: datagrams
// it sent or received on UDP sockets connected to port 443 (counted up to
// 64), and QUIC packets of its that couldn't be traced because their
// encryption context was created before snoopy started.
type QUICTraffic struct {
	UDP443, Untracked uint32
}

// QUICTraffic returns each traced process's QUICTraffic, by PID. It needs
// BTF to tell UDP sockets and their ports; without it, there's none.
func (t *Tracer) QUICTraffic() (map[uint32]QUICTraffic, error) {
	out := map[uint32]QUICTraffic{}
	var pid uint32
	var qt QUICTraffic
	it := t.objs.QuicTraffic.Iterate()
	for it.Next(&pid, &qt) {
		out[pid] = qt
	}
	return out, it.Err()
}

func (t *Tracer) counter(index uint32) (uint64, error) {
	var perCPU []uint64
	if err := t.objs.Counters.Lookup(index, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, n := range perCPU {
		total += n
	}
	return total, nil
}

// addLink keeps a link until Close.
func (t *Tracer) addLink(l link.Link) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.links = append(t.links, l)
}

// Close detaches all probes and unloads the program.
func (t *Tracer) Close() error {
	t.closed.Store(true)
	t.mu.Lock()
	links := t.links
	for _, p := range t.procs {
		links = append(links, p.links...)
	}
	for _, f := range t.files {
		if f.links != nil { // else Attach has its fd
			links = append(links, f.links...)
			unix.Close(f.fd)
		}
	}
	t.links, t.procs, t.files = nil, map[int]*procLinks{}, map[procFile]*fileLinks{}
	t.mu.Unlock()
	closeLinks(links)
	t.closing.Wait()
	return errors.Join(t.reader.Close(), t.objs.Close())
}
