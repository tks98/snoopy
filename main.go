// Command snoopy traces the plaintext of TLS connections using eBPF uprobes
// on TLS libraries (OpenSSL, GnuTLS, NSS, wolfSSL, Mbed TLS, s2n-tls,
// rustls), ngtcp2's crypto library and Go's crypto/tls.
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
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"

	"github.com/tks98/snoopy/v2/internal/discover"
	"github.com/tks98/snoopy/v2/internal/output"
	"github.com/tks98/snoopy/v2/internal/procinfo"
	"github.com/tks98/snoopy/v2/internal/tracer"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

type config struct {
	pid        int
	comm       string
	containers containerList
	hosts      stringList
	ports      portList
	libs       stringList
	noScan     bool
	brief      bool
	json       bool
	hex        bool
	full       bool
	maxSize    int
	count      int
	pcap       string
	har        string
	quiet      bool
	redact     bool
	methods    stringList
	paths      stringList
	statuses   stringList
	filter     *output.HTTPFilter // from methods, paths and statuses
	noColor    bool
	verbose    bool
	version    bool
}

// containerList is --container's: IDs or ID prefixes, each optionally with
// a name to show for it (ID=NAME), given repeatedly or comma-separated.
type containerList []containerSpec

type containerSpec struct{ id, name string }

func (c *containerList) String() string {
	var s []string
	for _, spec := range *c {
		s = append(s, spec.id)
	}
	return strings.Join(s, ",")
}

func (c *containerList) Set(v string) error {
	for _, item := range strings.Split(v, ",") {
		id, name, _ := strings.Cut(strings.TrimSpace(item), "=")
		// Runtimes write IDs as <runtime>://<id> (Kubernetes' containerID).
		if _, rest, ok := strings.Cut(id, "://"); ok {
			id = rest
		}
		if id == "" {
			return fmt.Errorf("empty container ID in %q", v)
		}
		*c = append(*c, containerSpec{strings.ToLower(id), name})
	}
	return nil
}

// match reports whether a container ID is one of those given, and the name
// it was given; with none given, every one matches.
func (c containerList) match(id string) (name string, ok bool) {
	if len(c) == 0 {
		return "", true
	}
	for _, spec := range c {
		if id != "" && strings.HasPrefix(id, spec.id) {
			return spec.name, true
		}
	}
	return "", false
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

// usage is the help text. Each flag defined in flags must be in it.
var usage = fmt.Sprintf(`snoopy shows what programs send and receive over TLS, as plaintext, using
eBPF. It needs root.

Usage: sudo snoopy [flags]

Which processes:
  --pid PID          only this process and those it starts
  --comm NAME        only processes whose name, as in /proc/<pid>/comm, or
                     program's file name starts with NAME (curl, firefox, node)
  --container ID     only processes in the container with this ID, or ID
                     prefix; repeatable, or comma-separated. ID=NAME shows
                     NAME for the container's events

Which HTTP exchanges (repeatable, or comma-separated):
  --method METHOD    only requests with this method, and their responses
  --path PREFIX      only requests whose path starts with this, and their
                     responses
  --status STATUS    only responses with this status: 404, 5xx, 400-499;
                     each says which request it answers

Which connections (repeatable):
  --host HOST        only connections with this IP address, network (CIDR)
                     or host name at either end
  --port PORT        only connections with this port at either end

Output:
  --brief            one line per call, like tcpdump
  --json             one JSON object per call
  --full             whole bodies, and binary data as hex dumps (by default,
                     a body's first 2 KiB, and binary data described)
  --hex              payloads as hex dumps
  --redact           mask what's likely secret: credentials in headers,
                     secret query parameters and JSON and form fields, and
                     tokens of well-known kinds, for output to share
  --verbose          also calls that only keep connections going (HTTP/2
                     settings and flow control, QUIC acknowledgments), and
                     every file attached to
  --count N          stop after N calls
  --pcap FILE        also write the plaintext as TCP streams to a pcap file
                     ("-" for stdout, to pipe to wireshark -k -i - or tcpdump -r -)
  --har FILE         also write the HTTP requests and responses to a HAR file
                     when snoopy stops ("-" for stdout), for browsers'
                     developer tools and other HAR viewers
  --quiet            don't print calls (with --pcap or --har)
  --no-color         no colors

Capture:
  --max-size BYTES   bytes to capture per call (default %d, at most %d)
  --lib PATH         also attach to this library or program, e.g. one with
                     OpenSSL linked in statically (repeatable)
  --no-scan          only attach to system libraries and --lib, not to what
                     running and new processes use

  --version          print the version and exit

Examples:
  sudo snoopy                                 everything, decoded
  sudo snoopy --brief                         one line per call
  sudo snoopy --comm curl                     only processes named curl
  sudo snoopy --host example.com --port 443   only connections to example.com:443
  sudo snoopy --count 20                      stop after 20 calls
  sudo snoopy --json | jq 'select(.direction == "write") | .data'
  sudo snoopy --quiet --pcap - | tcpdump -r - -nn -A
`, tracer.DefaultMaxCapture, tracer.MaxCaptureLimit)

// flags returns the command line flags, which set c.
func flags(c *config, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("snoopy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }

	// The usages are in the help text instead.
	fs.IntVar(&c.pid, "pid", 0, "")
	fs.StringVar(&c.comm, "comm", "", "")
	fs.Var(&c.containers, "container", "")
	fs.Var(&c.methods, "method", "")
	fs.Var(&c.paths, "path", "")
	fs.Var(&c.statuses, "status", "")
	fs.Var(&c.hosts, "host", "")
	fs.Var(&c.ports, "port", "")
	fs.Var(&c.libs, "lib", "")
	fs.BoolVar(&c.noScan, "no-scan", false, "")
	fs.BoolVar(&c.brief, "brief", false, "")
	fs.BoolVar(&c.json, "json", false, "")
	fs.BoolVar(&c.full, "full", false, "")
	fs.BoolVar(&c.hex, "hex", false, "")
	fs.IntVar(&c.maxSize, "max-size", tracer.DefaultMaxCapture, "")
	fs.IntVar(&c.count, "count", 0, "")
	fs.StringVar(&c.pcap, "pcap", "", "")
	fs.StringVar(&c.har, "har", "", "")
	fs.BoolVar(&c.quiet, "quiet", false, "")
	fs.BoolVar(&c.redact, "redact", false, "")
	fs.BoolVar(&c.noColor, "no-color", false, "")
	fs.BoolVar(&c.verbose, "verbose", false, "")
	fs.BoolVar(&c.version, "version", false, "")
	return fs
}

func parseFlags(args []string, stderr io.Writer) (config, error) {
	var c config
	fs := flags(&c, stderr)
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() > 0 {
		return c, fmt.Errorf("unexpected argument %q; to trace processes by name, use --comm %[1]s", fs.Arg(0))
	}
	if c.pid < 0 {
		return c, errors.New("--pid must be positive")
	}
	if c.count < 0 {
		return c, errors.New("--count must be positive")
	}
	var output []string
	for name, set := range map[string]bool{"--brief": c.brief, "--json": c.json, "--hex": c.hex, "--full": c.full} {
		if set {
			output = append(output, name)
		}
	}
	if len(output) > 1 {
		slices.Sort(output)
		return c, fmt.Errorf("%s can't be combined", strings.Join(output, " and "))
	}
	// These show data as sent, where HTTP/2's and HTTP/3's headers are
	// compressed: they can't be redacted.
	if f, err := httpFilter(c); err != nil {
		return c, err
	} else {
		c.filter = f
	}
	if c.redact && c.hex {
		return c, errors.New("--redact can't be combined with --hex, which shows data as captured")
	}
	if c.redact && c.pcap != "" {
		return c, errors.New("--redact can't be combined with --pcap, which writes data as captured")
	}
	return c, nil
}

// httpFilter returns the filter --method, --path and --status make, or nil
// if none was given. Each takes several values, comma-separated.
func httpFilter(c config) (*output.HTTPFilter, error) {
	split := func(vs []string) []string {
		var out []string
		for _, v := range vs {
			for _, s := range strings.Split(v, ",") {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	f := &output.HTTPFilter{Methods: split(c.methods), Paths: split(c.paths)}
	for _, s := range split(c.statuses) {
		r, err := output.ParseStatus(s)
		if err != nil {
			return nil, fmt.Errorf("--status: %w", err)
		}
		f.Status = append(f.Status, r)
	}
	for _, p := range f.Paths {
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("--path %s: paths start with /", p)
		}
	}
	if len(f.Methods) == 0 && len(f.Paths) == 0 && len(f.Status) == 0 {
		return nil, nil
	}
	return f, nil
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
	// Loading the BPF program comes first: without root, its error is the
	// one to see.
	// With a process filter, probes go on those processes only, so the
	// rest don't pay for them; that needs the watcher, for new ones.
	perProcess := !cfg.noScan && (cfg.pid != 0 || cfg.comm != "" || len(cfg.containers) > 0)
	t, err := tracer.New(tracer.Options{PID: cfg.pid, Comm: cfg.comm, MaxCapture: cfg.maxSize, PerProcess: perProcess})
	if err != nil {
		return err
	}
	defer t.Close()
	printers, closePrinters, err := openPrinters(cfg)
	if err != nil {
		return err
	}
	defer closePrinters()

	discover.Progress = func(msg string) { logf("%s", msg) }
	targets, warnings, err := discover.Find(discover.Options{PID: cfg.pid, Comm: cfg.comm, Extra: cfg.libs, NoScan: cfg.noScan})
	if err != nil {
		return err
	}
	for _, w := range warnings {
		logf("warning: %v", w)
	}
	if len(targets) == 0 && !t.PerProcess() { // per process, they're found as processes start
		return errors.New("no TLS libraries found to attach to; point snoopy at one with --lib")
	}

	var attached []discover.Target
	watcher := discover.NewWatcher(targets, t.PerProcess())
	if t.PerProcess() {
		for _, target := range targets {
			if slices.Contains(cfg.libs, target.Path) { // asked for: for every process
				funcs, err := t.Attach(target, 0)
				if reportAttach(cfg, target, funcs, err, true) {
					attached = append(attached, target)
				}
			}
		}
		resolver := procinfo.NewResolver("/proc")
		for _, pid := range discover.Selected(cfg.pid, cfg.comm) {
			if _, ok := cfg.containers.match(resolver.ContainerID(uint32(pid))); !ok {
				continue
			}
			// Traced even if nothing is attached for it yet, so that the
			// libraries it loads later are told of.
			if err := t.TracePID(uint32(pid)); err != nil {
				logf("warning: %v", err)
			}
			// What it has, then what it may load.
			for _, target := range append(watcher.Process(pid), watcher.Root(pid)...) {
				funcs, err := t.Attach(target, pid)
				if reportAttach(cfg, target, funcs, err, true) {
					attached = append(attached, target)
				}
			}
		}
	} else {
		for _, target := range targets {
			funcs, err := t.Attach(target, 0)
			if reportAttach(cfg, target, funcs, err, true) {
				attached = append(attached, target)
			}
		}
	}
	switch {
	case len(attached) == 0 && t.PerProcess():
		logf("no process to trace is running yet; attaching to them as they start")
	case len(attached) == 0:
		return errors.New("could not attach to any TLS library")
	case !cfg.verbose:
		logf("attached to %s (--verbose lists every file)", attachSummary(attached))
	}
	if err := t.AttachSyscalls(); err != nil {
		logf("warning: socket addresses will be missing for C libraries: %v", err)
	}
	if cfg.pid != 0 {
		for _, pid := range discover.Descendants(cfg.pid)[1:] {
			if err := t.TracePID(uint32(pid)); err != nil {
				logf("warning: %v", err)
			}
		}
	}
	// Also attach to what processes started from now on use.
	if !cfg.noScan {
		// Per process, every new process attaches to its files: they're
		// reported the first time.
		reported := map[string]bool{}
		for _, target := range attached {
			reported[reportKey(target)] = true
		}
		stopWatching, err := t.WatchNewProcesses(watcher, acceptProcess(cfg, t), holdProcess(cfg),
			func(target discover.Target, funcs []string, err error) {
				key := reportKey(target)
				if t.PerProcess() && err == nil && reported[key] && !cfg.verbose {
					return
				}
				if reportAttach(cfg, target, funcs, err, false) {
					reported[key] = true
				}
			})
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
	quic := &quicSeen{pids: map[uint32]bool{}}
	go watchCounters(ctx, t, quic)
	if cfg.pid != 0 && !t.ResolvesAddresses() {
		// Without BTF, the BPF program can't tell a process's parents, so
		// processes that fork without executing a program are found here.
		go followChildren(ctx, t, cfg.pid)
	}

	resolver := procinfo.NewResolver("/proc")
	calls := 0
	logf("tracing; press Ctrl-C to stop")
	err = t.Run(ctx, func(ev *tracer.Event) {
		if ev.Function.IsQUIC() {
			quic.add(ev.PID) // before any filter, so its HTTP/3 isn't taken for uncaptured
		}
		ev.ContainerID = resolver.ContainerID(ev.PID)
		name, ok := cfg.containers.match(ev.ContainerID)
		if !ok {
			return
		}
		ev.ContainerName = name
		if !ev.Remote.IsValid() {
			if local, remote, ok := resolver.Addresses(ev.PID, ev.FD); ok {
				ev.Local, ev.Remote = local, remote
			}
		}
		if ev.Function == tracer.FuncQUICPacketSent {
			// Not shown or counted, only followed (see its doc).
			for _, p := range printers {
				if err := p.Print(ev); err != nil {
					logf("error: write output: %v", err)
					stop()
					return
				}
			}
			return
		}
		if !filter.match(ev) || cfg.count > 0 && calls >= cfg.count {
			return
		}
		shown := true
		for _, p := range printers {
			before, beforeFiltered := hidden(p), filtered(p)
			if err := p.Print(ev); err != nil {
				logf("error: write output: %v", err)
				stop()
				return
			}
			shown = shown && hidden(p) == before && filtered(p) == beforeFiltered
		}
		if !shown {
			return
		}
		calls++
		if cfg.count > 0 && calls >= cfg.count {
			stop()
		}
	})

	summary := fmt.Sprintf("captured %d calls", calls)
	if n := filteredTotal(printers); n > 0 {
		summary += fmt.Sprintf(", left out %d that --method, --path or --status didn't match", n)
	}
	if n := hiddenTotal(printers); n > 0 {
		summary += fmt.Sprintf(", and hid %d that only kept connections going (--verbose shows them)", n)
	}
	logf("%s", summary)
	if lost, _ := t.LostEvents(); lost > 0 {
		logf("warning: %d chunks were dropped because the ring buffer was full", lost)
	}
	return err
}

// reportKey identifies a target's file however it was reached, by name or
// through a process's /proc directory: by its inode, since resolving
// symlinks in user space goes wrong through /proc/<pid>/root.
func reportKey(target discover.Target) string {
	key := target.Name()
	var st syscall.Stat_t
	if syscall.Stat(target.Path, &st) == nil {
		key = fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}
	return target.Library.String() + " " + key
}

// hidden returns how many events a printer left out so far.
func hidden(p output.Printer) int {
	if h, ok := p.(output.Hider); ok {
		return h.Hidden()
	}
	return 0
}

// filtered returns how many events a printer's filter left out so far.
func filtered(p output.Printer) int {
	if f, ok := p.(output.Filterer); ok {
		return f.Filtered()
	}
	return 0
}

func filteredTotal(printers []output.Printer) int {
	n := 0
	for _, p := range printers {
		n += filtered(p)
	}
	return n
}

func hiddenTotal(printers []output.Printer) int {
	n := 0
	for _, p := range printers {
		n += hidden(p)
	}
	return n
}

// attachSummary says in a few words what was attached to: the TLS libraries
// by name, and the programs (TLS linked in) by file name.
func attachSummary(targets []discover.Target) string {
	var libs, progs []string
	for _, t := range targets {
		name := t.Name()
		if strings.Contains(name, ".so") {
			if l := t.Library.String(); !slices.Contains(libs, l) {
				libs = append(libs, l)
			}
		} else if !slices.Contains(progs, name) {
			progs = append(progs, name)
		}
	}
	var parts []string
	if len(libs) > 0 {
		parts = append(parts, "the "+andList(libs)+" "+plural(len(libs), "library", "libraries"))
	}
	if len(progs) > 0 {
		const maxNamed = 4
		if len(progs) > maxNamed+1 {
			progs = append(progs[:maxNamed:maxNamed], fmt.Sprintf("%d more", len(progs)-maxNamed))
		}
		parts = append(parts, plural(len(progs), "the program ", "the programs ")+andList(progs))
	}
	return strings.Join(parts, ", and to ")
}

func andList(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// reportAttach logs the result of attaching to a target, and reports
// whether any function was attached to. A file attached to at startup, as
// opposed to for a process started since, is only listed with --verbose.
func reportAttach(cfg config, target discover.Target, funcs []string, err error, startup bool) bool {
	// A file reached through /proc/<pid> is gone if the process exited in
	// the meantime, which short-lived new processes often do.
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		logf("warning: %s %s: %v", target.Library, target.Path, err)
	}
	if len(funcs) == 0 {
		return false
	}
	if target.Limits != "" {
		logf("warning: %s: %s", target.Path, target.Limits)
	}
	if startup && !cfg.verbose {
		return true
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
// that --pid, --comm and --container would trace. With --pid, a process
// accepted is also added to those traced.
func acceptProcess(cfg config, t *tracer.Tracer) func(pid int) bool {
	if cfg.pid == 0 && cfg.comm == "" && len(cfg.containers) == 0 {
		return nil
	}
	resolver := procinfo.NewResolver("/proc") // not shared: Resolver isn't safe for concurrent use
	return func(pid int) bool {
		if cfg.comm != "" && !discover.NameMatches(pid, cfg.comm) {
			return false
		}
		if _, ok := cfg.containers.match(resolver.ContainerID(uint32(pid))); !ok {
			return false
		}
		if cfg.pid != 0 {
			if !discover.IsDescendant(pid, cfg.pid) {
				return false
			}
			if err := t.TracePID(uint32(pid)); err != nil {
				logf("warning: %v", err)
			}
		}
		return true
	}
}

// warnOnce returns a func that logs each warning it's given once.
func warnOnce() func(string) {
	var mu sync.Mutex
	said := map[string]bool{}
	return func(msg string) {
		mu.Lock()
		defer mu.Unlock()
		if !said[msg] {
			said[msg] = true
			logf("warning: %s", msg)
		}
	}
}

// holdProcess says which new processes to hold until their files are
// attached to, so that a short-lived one's TLS isn't missed: with --comm,
// --pid or --container, the ones asked for. Without any, every program's
// first run on the machine would be held, which is too much to impose.
func holdProcess(cfg config) func(pid int) bool {
	if cfg.comm == "" && cfg.pid == 0 && len(cfg.containers) == 0 {
		return nil
	}
	resolver := procinfo.NewResolver("/proc") // not shared: Resolver isn't safe for concurrent use
	return func(pid int) bool {
		if cfg.comm != "" && !discover.NameMatches(pid, cfg.comm) {
			return false
		}
		if _, ok := cfg.containers.match(resolver.ContainerID(uint32(pid))); !ok {
			return false
		}
		return cfg.pid == 0 || discover.IsDescendant(pid, cfg.pid)
	}
}

// followChildren adds the processes that pid starts to those traced, as it
// finds them in /proc.
func followChildren(ctx context.Context, t *tracer.Tracer, pid int) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	traced := map[int]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, child := range discover.Descendants(pid) {
				// One that failed, e.g. with the map full, is tried again.
				if !traced[child] && t.TracePID(uint32(child)) == nil {
					traced[child] = true
				}
			}
		}
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

	if cfg.har != "" {
		w := io.Writer(os.Stdout)
		if cfg.har == "-" {
			if stdoutUsed {
				return nil, nil, errors.New("--pcap - and --har - can't both write to stdout")
			}
			stdoutUsed = true
		} else {
			f, err := os.Create(cfg.har)
			if err != nil {
				return nil, nil, err
			}
			closers = append(closers, f.Close)
			w = f
		}
		h := output.NewHAR(w, versionString(), output.Options{Redact: cfg.redact, Filter: cfg.filter})
		printers = append(printers, h)
		closers = append([]func() error{h.Close}, closers...) // written before the file is closed
	}

	if !cfg.quiet && !stdoutUsed {
		warn := warnOnce()
		out := newFlushWriter(os.Stdout)
		closers = append(closers, out.Close)
		switch {
		case cfg.json:
			printers = append(printers, output.NewJSON(out, output.Options{Redact: cfg.redact, Filter: cfg.filter, Warn: warn}))
		case cfg.brief:
			printers = append(printers, output.NewBrief(out, output.Options{Verbose: cfg.verbose, Redact: cfg.redact, Filter: cfg.filter, Warn: warn}))
		default:
			printers = append(printers, output.NewText(out, output.Options{Hex: cfg.hex, Full: cfg.full, Verbose: cfg.verbose, Redact: cfg.redact, Filter: cfg.filter, Warn: warn}))
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

// watchCounters warns about what the BPF program counts going missing: data
// dropped because the ring buffer was full, and QUIC packets of connections
// that started before snoopy and can't be followed (Firefox's).
// quicSeen is the processes snoopy captured QUIC packets from.
type quicSeen struct {
	mu   sync.Mutex
	pids map[uint32]bool
}

func (q *quicSeen) add(pid uint32) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pids[pid] = true
}

func (q *quicSeen) has(pid uint32) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pids[pid]
}

// minUDP443 is how many datagrams on UDP port 443 a process has to send or
// receive, with none of its QUIC packets captured, to be warned about.
const minUDP443 = 32

func watchCounters(ctx context.Context, t *tracer.Tracer, quic *quicSeen) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var reported uint64
	quicWarned := false
	// HTTP/3 traffic of which nothing was captured: a QUIC library snoopy
	// doesn't support, or one that changed. Captured packets are delivered
	// a little behind the traffic, so a process is warned about only once
	// it has had enough traffic and no packets for a whole tick.
	noQUICPending, noQUICWarned := map[uint32]bool{}, map[uint32]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			traffic, _ := t.QUICTraffic()
			for pid, qt := range traffic {
				if qt.UDP443 < minUDP443 || qt.Untracked > 0 || noQUICWarned[pid] || quic.has(pid) {
					continue
				}
				if !noQUICPending[pid] {
					noQUICPending[pid] = true
					continue
				}
				noQUICWarned[pid] = true
				comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
				logf("warning: %s (pid %d) sends or receives on UDP port 443, HTTP/3's, but none of its QUIC packets were captured: its QUIC library isn't supported, or has changed (see docs/maintenance.md)",
					strings.TrimSpace(string(comm)), pid)
			}
			lost, err := t.LostEvents()
			if err == nil && lost > reported {
				logf("warning: %d chunks dropped so far because the ring buffer was full", lost)
				reported = lost
			}
			if n, err := t.UntrackedQUIC(); err == nil && n > 0 && !quicWarned {
				logf("warning: Firefox has HTTP/3 connections that were open before snoopy started, which can't be traced; restart Firefox to trace them")
				quicWarned = true
			}
		}
	}
}
