// Package tracer loads snoopy's eBPF program, attaches it to TLS libraries
// and turns what it reports into Events.
package tracer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/tks98/snoopy/internal/discover"
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
	// PID traces only this process; zero traces every process.
	PID int
	// Comm traces only processes with exactly this name, as shown in
	// /proc/<pid>/comm.
	Comm string
	// MaxCapture is the maximum number of bytes captured per call.
	// Zero means DefaultMaxCapture.
	MaxCapture int
	// RingBufferSize is the size of the kernel-to-user buffer in bytes; a
	// power of two. Zero means 16 MiB.
	RingBufferSize int

	// ignoreKernelBTF loads the program as if the kernel had no BTF (tests).
	ignoreKernelBTF bool
}

// Tracer is a loaded eBPF program with its probes.
type Tracer struct {
	opts    Options
	objs    snoopyObjects
	links   []link.Link
	reader  *ringbuf.Reader
	clock   func(monoNs uint64) time.Time
	haveBTF bool
	names   map[uint32]string // process names, when the kernel can't tell
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
		"targ_tgid":   uint32(opts.PID),
		"max_capture": uint32(opts.MaxCapture),
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

	t := &Tracer{opts: opts, clock: monotonicClock(), haveBTF: btfErr == nil, names: map[uint32]string{}}
	if err := spec.LoadAndAssign(&t.objs, &loadOpts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("the kernel's BPF verifier rejected snoopy's program: %+v", ve)
		}
		return nil, permissionHint(fmt.Errorf("load BPF program: %w", err))
	}

	t.reader, err = ringbuf.NewReader(t.objs.Events)
	if err != nil {
		t.objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	return t, nil
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
	symbol string
	prog   *ebpf.Program
}

// Attach attaches probes to a target and returns the names of the functions
// it attached to.
func (t *Tracer) Attach(target discover.Target) ([]string, error) {
	ex, err := link.OpenExecutable(target.Path)
	if err != nil {
		return nil, err
	}

	var probes []cProbe
	switch target.Library {
	case discover.OpenSSL:
		probes = []cProbe{
			{"SSL_read", t.objs.SslReadEnter},
			{"SSL_write", t.objs.SslWriteEnter},
			{"SSL_read_ex", t.objs.SslReadExEnter},
			{"SSL_write_ex", t.objs.SslWriteExEnter},
		}
	case discover.GnuTLS:
		probes = []cProbe{
			{"gnutls_record_recv", t.objs.GnutlsRecordRecvEnter},
			{"gnutls_record_send", t.objs.GnutlsRecordSendEnter},
		}
	case discover.NSS:
		probes = []cProbe{
			{"PR_Read", t.objs.PR_ReadEnter},
			{"PR_Write", t.objs.PR_WriteEnter},
			{"PR_Recv", t.objs.PR_RecvEnter},
			{"PR_Send", t.objs.PR_SendEnter},
		}
	case discover.GoTLS:
		return t.attachGo(ex, target.Go)
	default:
		return nil, fmt.Errorf("unsupported library %v", target.Library)
	}

	opts := &link.UprobeOptions{PID: t.opts.PID}
	var attached []string
	for _, p := range probes {
		// Attach the return probe first so no entry goes unmatched.
		ret, err := ex.Uretprobe(p.symbol, t.objs.TlsReturn, opts)
		if errors.Is(err, link.ErrNoSymbol) {
			continue // e.g. SSL_read_ex before OpenSSL 1.1.1
		}
		if err != nil {
			return attached, fmt.Errorf("%s: %w", p.symbol, err)
		}
		t.links = append(t.links, ret)

		entry, err := ex.Uprobe(p.symbol, p.prog, opts)
		if err != nil {
			return attached, fmt.Errorf("%s: %w", p.symbol, err)
		}
		t.links = append(t.links, entry)
		attached = append(attached, p.symbol)
	}
	if len(attached) == 0 {
		return nil, errors.New("none of the expected functions were found")
	}
	return attached, nil
}

func (t *Tracer) attachGo(ex *link.Executable, gi *discover.GoInfo) ([]string, error) {
	if gi == nil {
		return nil, errors.New("missing Go function information")
	}
	var attached []string
	for _, fn := range []struct {
		name string
		f    discover.GoFunc
		prog *ebpf.Program
	}{
		{"crypto/tls.(*Conn).Read", gi.Read, t.objs.GoTlsReadEnter},
		{"crypto/tls.(*Conn).Write", gi.Write, t.objs.GoTlsWriteEnter},
	} {
		// Return probes go on each RET instruction rather than using a
		// uretprobe, which would corrupt the goroutine's stack.
		for _, ret := range fn.f.Returns {
			l, err := ex.Uprobe("", t.objs.GoTlsReturn, &link.UprobeOptions{
				Address: fn.f.Offset, Offset: ret, PID: t.opts.PID,
			})
			if err != nil {
				return attached, fmt.Errorf("%s+%#x: %w", fn.name, ret, err)
			}
			t.links = append(t.links, l)
		}
		// The entry probe goes after the stack check: when the stack has to
		// grow, runtime.morestack restarts the function from the top, and a
		// probe on the first instruction would see the call twice.
		l, err := ex.Uprobe("", fn.prog, &link.UprobeOptions{
			Address: fn.f.Offset, Offset: fn.f.Body, PID: t.opts.PID,
		})
		if err != nil {
			return attached, fmt.Errorf("%s+%#x: %w", fn.name, fn.f.Body, err)
		}
		t.links = append(t.links, l)
		attached = append(attached, fn.name)
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
	t.links = append(t.links, l)
	return nil
}

// Run delivers events to handle until ctx is cancelled. handle is called
// from Run's goroutine.
func (t *Tracer) Run(ctx context.Context, handle func(*Event)) error {
	const (
		pollInterval = 200 * time.Millisecond
		maxChunkWait = time.Second
	)
	asm := newAssembler(t.clock)
	lastExpire := time.Now()
	var rec ringbuf.Record

	deliver := func(ev *Event) {
		if !t.haveBTF {
			ev.Comm = t.processName(ev.PID, ev.Comm)
			if t.opts.Comm != "" && ev.Comm != t.opts.Comm {
				return
			}
		}
		handle(ev)
	}

	for {
		if ctx.Err() != nil {
			for _, ev := range asm.expire(time.Now(), 0) {
				deliver(ev)
			}
			return nil
		}

		t.reader.SetDeadline(time.Now().Add(pollInterval))
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
			for _, ev := range asm.add(c, now) {
				deliver(ev)
			}
		}

		if now.Sub(lastExpire) >= pollInterval {
			for _, ev := range asm.expire(now, maxChunkWait) {
				deliver(ev)
			}
			lastExpire = now
		}
	}
}

// LostEvents returns how many chunks the kernel dropped because the ring
// buffer was full.
func (t *Tracer) LostEvents() (uint64, error) {
	var perCPU []uint64
	if err := t.objs.LostEvents.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, n := range perCPU {
		total += n
	}
	return total, nil
}

// Close detaches all probes and unloads the program.
func (t *Tracer) Close() error {
	var errs []error
	for _, l := range t.links {
		errs = append(errs, l.Close())
	}
	errs = append(errs, t.reader.Close(), t.objs.Close())
	return errors.Join(errs...)
}
