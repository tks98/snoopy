// Command snoopy traces the plaintext of TLS connections using eBPF uprobes
// on TLS libraries (OpenSSL, GnuTLS, NSS) and Go's crypto/tls.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
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
	libs      stringList
	noScan    bool
	json      bool
	hex       bool
	maxSize   int
	pcap      string
	quiet     bool
	noColor   bool
	verbose   bool
	version   bool
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

const usageHeader = `snoopy traces TLS plaintext using eBPF.

Usage: sudo snoopy [flags]

Flags:
`

func parseFlags(args []string, stderr io.Writer) (config, error) {
	var c config
	fs := flag.NewFlagSet("snoopy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usageHeader)
		fs.PrintDefaults()
	}

	fs.IntVar(&c.pid, "pid", 0, "trace only this process ID")
	fs.StringVar(&c.comm, "comm", "", "trace only processes with this exact name (as in /proc/<pid>/comm)")
	fs.StringVar(&c.container, "container", "", "trace only processes in the container with this ID (or ID prefix)")
	fs.Var(&c.libs, "lib", "also attach to this library or executable, e.g. a binary with OpenSSL linked in statically (repeatable)")
	fs.BoolVar(&c.noScan, "no-scan", false, "don't scan running processes for TLS libraries and Go binaries; only use system libraries and --lib")
	fs.BoolVar(&c.json, "json", false, "print events as JSON, one object per line")
	fs.BoolVar(&c.hex, "hex", false, "always print payloads as a hex dump")
	fs.IntVar(&c.maxSize, "max-size", tracer.DefaultMaxCapture, fmt.Sprintf("maximum bytes to capture per call (up to %d)", tracer.MaxCaptureLimit))
	fs.StringVar(&c.pcap, "pcap", "", "also write plaintext as TCP streams to this pcap file (\"-\" for stdout, e.g. to pipe into wireshark -k -i -)")
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
	if c.json && c.hex {
		return c, errors.New("--json and --hex can't be combined")
	}
	return c, nil
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
		if err != nil {
			logf("warning: %s %s: %v", target.Library, target.Path, err)
		}
		if len(funcs) == 0 {
			continue
		}
		attached++
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
	}
	if attached == 0 {
		return errors.New("could not attach to any TLS library")
	}
	if err := t.AttachSyscalls(); err != nil {
		logf("warning: socket addresses will be missing for C libraries: %v", err)
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
		calls++
		for _, p := range printers {
			if err := p.Print(ev); err != nil {
				logf("error: write output: %v", err)
				stop()
				return
			}
		}
	})

	logf("captured %d calls", calls)
	if lost, _ := t.LostEvents(); lost > 0 {
		logf("warning: %d chunks were dropped because the ring buffer was full", lost)
	}
	return err
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
		if cfg.json {
			printers = append(printers, output.NewJSON(os.Stdout))
		} else {
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
