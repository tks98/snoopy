// Package tracer loads snoopy's eBPF program, attaches it to TLS libraries
// and turns what it reports into Events.
package tracer

import (
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
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/tks98/snoopy/v2/internal/discover"
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
	// PerProcess, with PID or Comm, attaches probes to the processes those
	// select rather than to files, with the kernel's PID filter: then other
	// programs using the same library don't trap on them. Each new process
	// needs its own, attached to by WatchNewProcesses (forks too), so its
	// first calls can be missed. It needs BTF, to tell forks from threads;
	// without, probes are per file.
	PerProcess bool

	// ignoreKernelBTF loads the program as if the kernel had no BTF (tests).
	ignoreKernelBTF bool
}

// Tracer is a loaded eBPF program with its probes.
type Tracer struct {
	opts       Options
	objs       snoopyObjects
	mu         sync.Mutex // guards links and procs: Attach may run while Run does
	links      []link.Link
	procs      map[int]*procLinks // per process, the links of each
	everyone   map[procFile]bool  // per process, files attached to for every process
	perProcess bool
	reader     *ringbuf.Reader
	clock      func(monoNs uint64) time.Time
	haveBTF    bool
	names      map[uint32]string // process names, when the kernel can't tell
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
	for name, value := range map[string]any{
		"filter_tgids": opts.PID != 0,
		"max_capture":  uint32(opts.MaxCapture),
		// Without BTF the kernel only knows thread names, so the process
		// name is filtered on in user space instead.
		"filter_comm": opts.Comm != "" && btfErr == nil,
		"targ_comm":   comm,
		"have_btf":    btfErr == nil,
	} {
		if err := spec.Variables[name].Set(value); err != nil {
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}
	spec.Maps["events"].MaxEntries = uint32(opts.RingBufferSize)

	t := &Tracer{opts: opts, clock: monotonicClock(), haveBTF: btfErr == nil, names: map[uint32]string{},
		procs: map[int]*procLinks{}, everyone: map[procFile]bool{}}
	t.perProcess = opts.PerProcess && t.haveBTF && (opts.PID != 0 || opts.Comm != "")
	if err := spec.LoadAndAssign(&t.objs, &loadOpts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("the kernel's BPF verifier rejected snoopy's program: %+v", ve)
		}
		return nil, permissionHint(fmt.Errorf("load BPF program: %w", err))
	}

	if opts.PID != 0 {
		if err := t.TracePID(uint32(opts.PID)); err != nil {
			t.objs.Close()
			return nil, err
		}
	}
	t.reader, err = ringbuf.NewReader(t.objs.Events)
	if err != nil {
		t.objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	return t, nil
}

// TracePID adds a process to those traced, with Options.PID set: a process
// that it started, for example.
func (t *Tracer) TracePID(pid uint32) error {
	if err := t.objs.TracedTgids.Update(pid, uint8(1), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("trace pid %d: %w", pid, err)
	}
	return nil
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
// the names it did the first time, and to one attached to for every process,
// does nothing and returns none.
func (t *Tracer) Attach(target discover.Target, pid int) ([]string, error) {
	if !t.perProcess {
		pid = 0
	}
	key, err := targetKey(target)
	if err != nil {
		return nil, err
	}
	if pid != 0 {
		t.mu.Lock()
		p := t.procLocked(pid)
		var funcs []string
		attached := p == nil || t.everyone[key] // or it's gone
		if !attached {
			funcs, attached = p.files[key]
		}
		t.mu.Unlock()
		if attached {
			return funcs, nil
		}
	}
	funcs, err := t.attach(target, pid)
	if len(funcs) > 0 {
		t.mu.Lock()
		if pid == 0 {
			t.everyone[key] = true
		} else if p := t.procs[pid]; p != nil {
			p.files[key] = funcs
		}
		t.mu.Unlock()
	}
	return funcs, err
}

func targetKey(target discover.Target) (procFile, error) {
	var st unix.Stat_t
	if err := unix.Stat(target.Path, &st); err != nil {
		return procFile{}, &os.PathError{Op: "stat", Path: target.Path, Err: err}
	}
	return procFile{dev: uint64(st.Dev), ino: st.Ino, lib: target.Library}, nil
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
	i := bytes.LastIndexByte(stat, ')') // the command name may contain anything
	if i < 0 {
		return 0, false
	}
	fields := strings.Fields(string(stat[i+1:]))
	if len(fields) < 20 {
		return 0, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	return start, err == nil
}

// DetachExited closes the probes of processes that have exited.
func (t *Tracer) DetachExited() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for pid, p := range t.procs {
		if start, ok := procStart(pid); !ok || start != p.start {
			closeLinks(p.links)
			delete(t.procs, pid)
		}
	}
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}

func (t *Tracer) attach(target discover.Target, pid int) ([]string, error) {
	ex, err := link.OpenExecutable(target.Path)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("unsupported library %v", target.Library)
	}

	var attached []string
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
				return attached, fmt.Errorf("%s: %w", p.symbol, err)
			}
			t.addLinkFor(pid, ret)
		}

		entry, err := ex.Uprobe(p.symbol, p.prog, opts)
		if errors.Is(err, link.ErrNoSymbol) {
			continue
		}
		if err != nil {
			return attached, fmt.Errorf("%s: %w", p.symbol, err)
		}
		t.addLinkFor(pid, entry)
		attached = append(attached, p.symbol)
	}
	if len(attached) == 0 {
		return nil, errors.New("none of the expected functions were found")
	}
	return attached, nil
}

// attachRustls attaches to rustls's Reader::read and Writer::write, found by
// their mangled names, at their file offsets, or to where its crypto
// provider encrypts and decrypts records.
func (t *Tracer) attachRustls(ex *link.Executable, ri *discover.RustInfo, pid int) ([]string, error) {
	if ri == nil {
		return nil, errors.New("missing rustls function information")
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
	var attached []string
	for _, p := range probes {
		for _, off := range p.offsets {
			opts := &link.UprobeOptions{Address: off, PID: pid}
			if !p.entryOnly {
				ret, err := ex.Uretprobe("", t.objs.TlsReturn, opts)
				if err != nil {
					return attached, fmt.Errorf("%s at %#x: %w", p.name, off, err)
				}
				t.addLinkFor(pid, ret)
			}
			entry, err := ex.Uprobe("", p.prog, opts)
			if err != nil {
				return attached, fmt.Errorf("%s at %#x: %w", p.name, off, err)
			}
			t.addLinkFor(pid, entry)
		}
		if len(p.offsets) > 0 {
			attached = append(attached, p.name)
		}
	}
	return attached, nil
}

func (t *Tracer) attachGo(ex *link.Executable, gi *discover.GoInfo, pid int) ([]string, error) {
	if gi == nil {
		return nil, errors.New("missing Go function information")
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
	var attached []string
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
				return attached, fmt.Errorf("%s+%#x: %w", fn.name, ret, err)
			}
			t.addLinkFor(pid, l)
		}
		// The entry probe goes after the stack check: when the stack has to
		// grow, runtime.morestack restarts the function from the top, and a
		// probe on the first instruction would see the call twice.
		l, err := ex.Uprobe("", fn.prog, &link.UprobeOptions{
			Address: fn.f.Offset, Offset: fn.f.Body, PID: pid,
		})
		if err != nil {
			return attached, fmt.Errorf("%s+%#x: %w", fn.name, fn.f.Body, err)
		}
		t.addLinkFor(pid, l)
		if !slices.Contains(attached, fn.name) {
			attached = append(attached, fn.name)
		}
	}
	return attached, nil
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

// maxHold is how long a new process is held while its files are inspected
// and attached to; inspecting a large program the first time (a browser's
// stripped BoringSSL) can take longer, and it isn't held up for that.
const maxHold = 2 * time.Second

// WatchNewProcesses attaches, in the background, to the TLS libraries and
// programs of processes that start from now on, as w finds them, and per
// process (see Options.PerProcess), those forked from a traced one. accept, if
// not nil, decides whether to look at a process at all; attached is called
// with the result of every attempt to attach. TLS calls a process makes
// before its files are inspected are missed, unless hold says to hold it:
// then a process whose executable or root filesystem is new to w is
// stopped (with ptrace, which its parent doesn't see, unlike SIGSTOP) until
// they're attached to, or maxHold. Call stop to stop watching and wait for
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
	holds := make(chan int, 64)
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
			if hold != nil && hold(pid) && !w.Known(pid) {
				select {
				case holds <- pid:
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
		// ptrace requests have to come from the thread that seized.
		runtime.LockOSThread()
		for {
			select {
			case <-ctx.Done():
				return
			case pid := <-holds:
				sig, ok := seize(pid)
				if !ok {
					continue
				}
				p := heldProcess{pid: pid, done: make(chan struct{})}
				select {
				case held <- p:
					select {
					case <-p.done:
					case <-time.After(maxHold):
					}
				case <-ctx.Done():
				}
				release(pid, sig)
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
			case pid := <-pids:
				inspect(pid, false)
			case p := <-held:
				inspect(p.pid, true)
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
	pid  int
	done chan struct{} // closed once its files are attached to
}

// seize stops a process with ptrace, without its parent seeing it stop, and
// returns the signal it stopped for, if any, which release passes on.
func seize(pid int) (sig int, ok bool) {
	if unix.PtraceSeize(pid) != nil {
		return 0, false // gone, already traced, or not allowed (Yama)
	}
	if unix.PtraceInterrupt(pid) != nil {
		release(pid, 0)
		return 0, false
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
				return 0, true
			}
			return int(ws.StopSignal()), true
		case n == pid || err != nil && err != unix.ECHILD:
			return 0, false // it exited
		}
		if traceStopped(pid) {
			return 0, true
		}
	}
	release(pid, 0)
	return 0, false
}

// traceStopped reports whether a process is in a ptrace stop: state t in
// /proc/<pid>/stat, after the command name, which may contain anything.
func traceStopped(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := bytes.LastIndexByte(stat, ')')
	return i >= 0 && i+2 < len(stat) && stat[i+2] == 't'
}

func release(pid, sig int) {
	_, _, _ = unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(pid), 0, uintptr(sig), 0, 0)
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

// Close detaches all probes and unloads the program.
func (t *Tracer) addLink(l link.Link) {
	t.addLinkFor(0, l)
}

// addLinkFor keeps a link with those of process pid, or if it's zero, with
// those that stay until Close.
func (t *Tracer) addLinkFor(pid int, l link.Link) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if pid != 0 {
		if p := t.procs[pid]; p != nil {
			p.links = append(p.links, l)
			return
		}
	}
	t.links = append(t.links, l)
}

func (t *Tracer) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var errs []error
	for _, l := range t.links {
		errs = append(errs, l.Close())
	}
	for _, p := range t.procs {
		closeLinks(p.links)
	}
	errs = append(errs, t.reader.Close(), t.objs.Close())
	return errors.Join(errs...)
}
