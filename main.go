// Command snoopy traces the plaintext of TLS connections using eBPF uprobes
// on TLS libraries (OpenSSL, GnuTLS, NSS, wolfSSL, Mbed TLS, s2n-tls) and
// Go's crypto/tls.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"

	"github.com/tks98/snoopy/internal/discover"
	"github.com/tks98/snoopy/internal/output"
	"github.com/tks98/snoopy/internal/procinfo"
	"github.com/tks98/snoopy/internal/tracer"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

type config struct {
	pid       int
	comm      string
	container string
	hosts     stringList
	ports     portList
	libs      stringList
	noScan    bool
	brief     bool
	json      bool
	hex       bool
	maxSize   int
	count     int
	pcap      string
	quiet     bool
	noColor   bool
	verbose   bool
	version   bool
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type portList []uint16

func (p *portList) String() string { return fmt.Sprint([]uint16(*p)) }
func (p *portList) Set(v string) error {
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("not a port: %q", v)
	}
	*p = append(*p, uint16(n))
	return nil
}

const usageHeader = `snoopy traces TLS plaintext using eBPF.

Usage: sudo snoopy [flags]

Flags:
`

const usageExamples = `
Examples:
  sudo snoopy                                 everything, decoded
  sudo snoopy --brief                         one line per call, like tcpdump
  sudo snoopy --comm curl                     only processes named curl
  sudo snoopy --host example.com --port 443   only connections to example.com on port 443
  sudo snoopy --count 20                      stop after 20 calls
  sudo snoopy --json | jq 'select(.direction == "write") | .data'
  sudo snoopy --quiet --pcap - | tcpdump -r - -nn -A
`

func parseFlags(args []string, stderr io.Writer) (config, error) {
	var c config
	fs := flag.NewFlagSet("snoopy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usageHeader)
		fs.PrintDefaults()
		fmt.Fprint(stderr, usageExamples)
	}

	fs.IntVar(&c.pid, "pid", 0, "trace only this process ID")
	fs.StringVar(&c.comm, "comm", "", "trace only processes with this exact name (as in /proc/<pid>/comm)")
	fs.StringVar(&c.container, "container", "", "trace only processes in the container with this ID (or ID prefix)")
	fs.Var(&c.hosts, "host", "show only connections with this IP address, network (CIDR) or host name at either end (repeatable)")
	fs.Var(&c.ports, "port", "show only connections with this port at either end (repeatable)")
	fs.Var(&c.libs, "lib", "also attach to this library or executable, e.g. a binary with OpenSSL linked in statically (repeatable)")
	fs.BoolVar(&c.noScan, "no-scan", false, "don't scan running or newly started processes for TLS libraries and Go binaries; only use system libraries and --lib")
	fs.BoolVar(&c.brief, "brief", false, "print one line per call, like tcpdump")
	fs.BoolVar(&c.json, "json", false, "print events as JSON, one object per line")
	fs.BoolVar(&c.hex, "hex", false, "always print payloads as a hex dump")
	fs.IntVar(&c.maxSize, "max-size", tracer.DefaultMaxCapture, fmt.Sprintf("maximum bytes to capture per call (up to %d)", tracer.MaxCaptureLimit))
	fs.IntVar(&c.count, "count", 0, "stop after this many calls (0: no limit)")
	fs.StringVar(&c.pcap, "pcap", "", "also write plaintext as TCP streams to this pcap file (\"-\" for stdout, e.g. to pipe into wireshark -k -i - or tcpdump -r -)")
	fs.BoolVar(&c.quiet, "quiet", false, "don't print events (useful with --pcap)")
	fs.BoolVar(&c.noColor, "no-color", false, "disable colors")
	fs.BoolVar(&c.verbose, "verbose", false, "show which functions were attached to")
	fs.BoolVar(&c.version, "version", false, "print the version and exit")

	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return c, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if c.pid < 0 {
		return c, errors.New("--pid must be positive")
	}
	if c.count < 0 {
		return c, errors.New("--count must be positive")
	}
	switch {
	case c.json && c.hex:
		return c, errors.New("--json and --hex can't be combined")
	case c.brief && c.json:
		return c, errors.New("--brief and --json can't be combined")
	case c.brief && c.hex:
		return c, errors.New("--brief and --hex can't be combined")
	}
	return c, nil
}

// addrFilter keeps the events of connections with an end among hosts, if
// any are given, and an end on one of ports, if any are given.
type addrFilter struct {
	hosts []netip.Prefix
	ports []uint16
}

func newAddrFilter(cfg config) (addrFilter, error) {
	f := addrFilter{ports: cfg.ports}
	for _, h := range cfg.hosts {
		prefixes, err := hostPrefixes(h)
		if err != nil {
			return f, fmt.Errorf("--host %s: %w", h, err)
		}
		f.hosts = append(f.hosts, prefixes...)
	}
	return f, nil
}

// hostPrefixes parses an IP address or network, or looks up a host name.
func hostPrefixes(h string) ([]netip.Prefix, error) {
	if p, err := netip.ParsePrefix(h); err == nil {
		return []netip.Prefix{p.Masked()}, nil
	}
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.Unmap()
		return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}, nil
	}
	ips, err := net.LookupIP(h)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, nil
}

func (f addrFilter) match(ev *tracer.Event) bool {
	ends := []netip.AddrPort{ev.Local, ev.Remote}
	if len(f.hosts) > 0 && !slices.ContainsFunc(ends, func(a netip.AddrPort) bool {
		return a.IsValid() && !a.Addr().IsUnspecified() && slices.ContainsFunc(f.hosts, func(p netip.Prefix) bool {
			return p.Contains(a.Addr().Unmap())
		})
	}) {
		return false
	}
	return len(f.ports) == 0 || slices.ContainsFunc(ends, func(a netip.AddrPort) bool {
		return a.IsValid() && slices.Contains(f.ports, a.Port())
	})
}

func main() {
	cfg, err := parseFlags(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "snoopy:", err)
		os.Exit(2)
	}
	if cfg.version {
		fmt.Println("snoopy", versionString())
		return
	}
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "snoopy:", err)
		os.Exit(1)
	}
}

func versionString() string {
	if version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			return bi.Main.Version
		}
	}
	return version
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "snoopy: "+format+"\n", a...)
}

func run(cfg config) error {
	if cfg.noColor {
		color.NoColor = true
	}

	filter, err := newAddrFilter(cfg)
	if err != nil {
		return err
	}
	printers, closePrinters, err := openPrinters(cfg)
	if err != nil {
		return err
	}
	defer closePrinters()

	targets, warnings, err := discover.Find(discover.Options{PID: cfg.pid, Extra: cfg.libs, NoScan: cfg.noScan})
	if err != nil {
		return err
	}
	for _, w := range warnings {
		logf("warning: %v", w)
	}
	if len(targets) == 0 {
		return errors.New("no TLS libraries found to attach to; point snoopy at one with --lib")
	}

	t, err := tracer.New(tracer.Options{PID: cfg.pid, Comm: cfg.comm, MaxCapture: cfg.maxSize})
	if err != nil {
		return err
	}
	defer t.Close()

	attached := 0
	for _, target := range targets {
		funcs, err := t.Attach(target)
		if reportAttach(cfg, target, funcs, err) {
			attached++
		}
	}
	if attached == 0 {
		return errors.New("could not attach to any TLS library")
	}
	if err := t.AttachSyscalls(); err != nil {
		logf("warning: socket addresses will be missing for C libraries: %v", err)
	}
	// With --pid, the one process is already running; otherwise also attach
	// to what processes started from now on use.
	if cfg.pid == 0 && !cfg.noScan {
		stopWatching, err := t.WatchNewProcesses(discover.NewWatcher(targets), acceptProcess(cfg),
			func(target discover.Target, funcs []string, err error) { reportAttach(cfg, target, funcs, err) })
		if err != nil {
			logf("warning: programs started from now on are only traced if they use a library already attached to: %v", err)
		} else {
			defer stopWatching()
		}
	}
	if !t.ResolvesAddresses() {
		logf("warning: the kernel has no BTF, so socket addresses are looked up in /proc and may be missing for short-lived connections")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go reportLostEvents(ctx, t)

	resolver := procinfo.NewResolver("/proc")
	calls := 0
	logf("tracing; press Ctrl-C to stop")
	err = t.Run(ctx, func(ev *tracer.Event) {
		ev.ContainerID = resolver.ContainerID(ev.PID)
		if cfg.container != "" && !strings.HasPrefix(ev.ContainerID, cfg.container) {
			return
		}
		if !ev.Remote.IsValid() {
			if local, remote, ok := resolver.Addresses(ev.PID, ev.FD); ok {
				ev.Local, ev.Remote = local, remote
			}
		}
		if !filter.match(ev) || cfg.count > 0 && calls >= cfg.count {
			return
		}
		calls++
		for _, p := range printers {
			if err := p.Print(ev); err != nil {
				logf("error: write output: %v", err)
				stop()
				return
			}
		}
		if cfg.count > 0 && calls >= cfg.count {
			stop()
		}
	})

	logf("captured %d calls", calls)
	if lost, _ := t.LostEvents(); lost > 0 {
		logf("warning: %d chunks were dropped because the ring buffer was full", lost)
	}
	return err
}

// reportAttach logs the result of attaching to a target and reports whether
// any function was attached to.
func reportAttach(cfg config, target discover.Target, funcs []string, err error) bool {
	// A file reached through /proc/<pid> is gone if the process exited in
	// the meantime, which short-lived new processes often do.
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		logf("warning: %s %s: %v", target.Library, target.Path, err)
	}
	if len(funcs) == 0 {
		return false
	}
	desc := fmt.Sprintf("%-7s %s", target.Library, target.Path)
	var notes []string
	if target.Note != "" {
		notes = append(notes, target.Note)
	}
	if target.Go != nil {
		notes = append(notes, target.Go.Version)
	}
	if len(notes) > 0 {
		desc += " (" + strings.Join(notes, ", ") + ")"
	}
	if cfg.verbose {
		desc += ": " + strings.Join(funcs, ", ")
	}
	logf("attached to %s", desc)
	return true
}

// acceptProcess returns which new processes are worth inspecting: those
// that --comm and --container would trace.
func acceptProcess(cfg config) func(pid int) bool {
	if cfg.comm == "" && cfg.container == "" {
		return nil
	}
	resolver := procinfo.NewResolver("/proc") // not shared: Resolver isn't safe for concurrent use
	return func(pid int) bool {
		if cfg.comm != "" {
			comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if err != nil || strings.TrimSuffix(string(comm), "\n") != cfg.comm {
				return false
			}
		}
		return cfg.container == "" || strings.HasPrefix(resolver.ContainerID(uint32(pid)), cfg.container)
	}
}

// openPrinters sets up the requested outputs and returns a function that
// flushes and closes them.
func openPrinters(cfg config) ([]output.Printer, func(), error) {
	var printers []output.Printer
	var closers []func() error
	stdoutUsed := false

	if cfg.pcap != "" {
		w := io.Writer(os.Stdout)
		if cfg.pcap == "-" {
			stdoutUsed = true
		} else {
			f, err := os.Create(cfg.pcap)
			if err != nil {
				return nil, nil, err
			}
			closers = append(closers, f.Close)
			w = f
		}
		p, err := output.NewPcap(w)
		if err != nil {
			return nil, nil, fmt.Errorf("write pcap: %w", err)
		}
		printers = append(printers, p)
		closers = append([]func() error{p.Close}, closers...) // flush before closing the file
	}

	if !cfg.quiet && !stdoutUsed {
		switch {
		case cfg.json:
			printers = append(printers, output.NewJSON(os.Stdout))
		case cfg.brief:
			printers = append(printers, output.NewBrief(os.Stdout))
		default:
			printers = append(printers, output.NewText(os.Stdout, cfg.hex))
		}
	}

	return printers, func() {
		for _, c := range closers {
			if err := c(); err != nil {
				logf("error: %v", err)
			}
		}
	}, nil
}

func reportLostEvents(ctx context.Context, t *tracer.Tracer) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var reported uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lost, err := t.LostEvents()
			if err == nil && lost > reported {
				logf("warning: %d chunks dropped so far because the ring buffer was full", lost)
				reported = lost
			}
		}
	}
}
