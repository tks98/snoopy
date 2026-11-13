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
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/fatih/color"
	"golang.org/x/sys/unix"

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
	requests   bool
	json       bool
	hex        bool
	full       bool
	maxSize    int
	bufferSize byteSize
	count      int
	pcap       string
	har        string
	quiet      bool
	redact     bool
	methods    stringList
	paths      stringList
	statuses   stringList
	filter     *output.HTTPFilter // from methods, paths and statuses
	protos     stringList
	grep       string
	grepRe     *regexp.Regexp // from grep
	duration   time.Duration
	schemas    *output.ProtoSchemas // from protos
	noColor    bool
	verbose    bool
	version    bool
	java       bool
	javaAgent  string
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
		if id == "" && v == "" {
			return errors.New("empty container ID")
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
		return errors.New("ports are 1 to 65535")
	}
	*p = append(*p, uint16(n))
	return nil
}

// usage is the help text. Each flag defined in flags must be in it.
var usage = fmt.Sprintf(`snoopy shows what programs send and receive over TLS, as plaintext, using
eBPF. It needs root.

Usage: sudo snoopy [flags]

Which processes:
  --pid PID          only this process and those it starts, until they've
                     all exited
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

Which calls:
  --grep REGEXP      only calls in which REGEXP (Go's syntax) matches
                     something shown: the data, decoded HTTP/2 and HTTP/3
                     headers, decompressed bodies, gRPC fields; not with
                     --requests, whose lines show no bodies

Which connections (repeatable):
  --host HOST        only connections with this IP address, network (CIDR)
                     or host name at either end
  --port PORT        only connections with this port at either end
                     (calls whose peer isn't known are left out, counted)

Output:
  --requests         one line per HTTP request and its response: method,
                     URL, status, type, size and time, once the response ends
  --brief            one line per call, like tcpdump
  --json             one JSON object per call
  --full             whole bodies, and binary data as hex dumps (by default,
                     a body's first 2 KiB, and binary data described)
  --hex              payloads as hex dumps
  --proto FILE       decode gRPC messages with their fields' names, from a
                     descriptor set (protoc --descriptor_set_out=FILE
                     --include_imports, or buf build -o FILE); repeatable
  --redact           mask what's likely secret: credentials in headers,
                     secret query parameters and JSON and form fields, and
                     tokens of well-known kinds, for output to share
  --verbose          also calls that only keep connections going (HTTP/2
                     settings and flow control, QUIC acknowledgments), and
                     every file attached to
  --count N          stop after N calls (0, the default: don't)
  --duration TIME    stop after this long: 30s, 5m, 1h
  --pcap FILE        also write the plaintext as TCP streams to a pcap file
                     ("-" for stdout, to pipe to wireshark -k -i - or tcpdump -r -)
  --har FILE         also write the HTTP requests and responses to a HAR file,
                     for browsers' developer tools and other HAR viewers:
                     every few seconds as it changes ("-": to stdout, when
                     snoopy stops)
  --quiet            don't print calls (with --pcap or --har; without them,
                     snoopy only counts the calls)
  --no-color         no colors

Capture:
  --max-size BYTES   bytes to capture per call (default %d, at most %d)
  --buffer-size SIZE the kernel's buffer for captured data until snoopy
                     reads it, which bursts of calls can fill: a power of
                     two, as bytes or with K, M or G (default %s, at most %s)
  --java             also Java's own TLS (SunJSSE) in the --pid JVM, or the
                     JVMs in the --container containers, by loading
                     snoopy's agent into them (it stays loaded, idle,
                     after snoopy stops)
  --java-agent DIR   the directory with the agent's jars (default: next to
                     snoopy, or java/out in a source tree, else the ones
                     built into snoopy)
  --lib PATH         also attach to this library or program, e.g. one with
                     OpenSSL linked in statically (repeatable)
  --no-scan          only attach to system libraries and --lib, not to what
                     running and new processes use

  --version          print the version and exit

Examples:
  sudo snoopy                                 everything, decoded
  sudo snoopy --requests                      one line per HTTP request
  sudo snoopy --brief                         one line per call
  sudo snoopy --comm curl                     only processes named curl
  sudo snoopy --host example.com --port 443   only connections to example.com:443
  sudo snoopy --count 20                      stop after 20 calls
  sudo snoopy --json | jq 'select(.direction == "write") | .data'
  sudo snoopy --quiet --pcap - | tcpdump -r - -nn -A
`, tracer.DefaultMaxCapture, tracer.MaxCaptureLimit, formatSize(tracer.DefaultRingBufferSize), formatSize(tracer.MaxRingBufferSize))

// flags returns the command line flags, which set c. Their errors are
// returned, not printed, and neither is the help text.
func flags(c *config) *flag.FlagSet {
	fs := flag.NewFlagSet("snoopy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

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
	fs.BoolVar(&c.requests, "requests", false, "")
	fs.BoolVar(&c.json, "json", false, "")
	fs.BoolVar(&c.full, "full", false, "")
	fs.BoolVar(&c.hex, "hex", false, "")
	fs.IntVar(&c.maxSize, "max-size", tracer.DefaultMaxCapture, "")
	c.bufferSize = tracer.DefaultRingBufferSize
	fs.Var(&c.bufferSize, "buffer-size", "")
	fs.IntVar(&c.count, "count", 0, "")
	fs.DurationVar(&c.duration, "duration", 0, "")
	fs.StringVar(&c.grep, "grep", "", "")
	fs.StringVar(&c.pcap, "pcap", "", "")
	fs.StringVar(&c.har, "har", "", "")
	fs.BoolVar(&c.quiet, "quiet", false, "")
	fs.BoolVar(&c.redact, "redact", false, "")
	fs.Var(&c.protos, "proto", "")
	fs.BoolVar(&c.noColor, "no-color", false, "")
	fs.BoolVar(&c.verbose, "verbose", false, "")
	fs.BoolVar(&c.version, "version", false, "")
	fs.BoolVar(&c.java, "java", false, "")
	fs.StringVar(&c.javaAgent, "java-agent", "", "")
	return fs
}

// parseFlags parses the command line; with -h or --help, it writes the
// help text to stderr and returns flag.ErrHelp.
func parseFlags(args []string, stderr io.Writer) (config, error) {
	var c config
	fs := flags(&c)
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stderr, usage)
		return c, err
	} else if err != nil {
		return c, flagError(err, fs)
	}
	if fs.NArg() > 0 {
		return c, fmt.Errorf("unexpected argument %q; to trace processes by name, use --comm %[1]s", fs.Arg(0))
	}
	pidSet := false
	fs.Visit(func(f *flag.Flag) { pidSet = pidSet || f.Name == "pid" })
	if c.pid < 0 || pidSet && c.pid == 0 {
		return c, fmt.Errorf("--pid %d isn't a process ID", c.pid)
	}
	if c.count < 0 {
		return c, errors.New("--count can't be negative")
	}
	if c.duration < 0 {
		return c, errors.New("--duration can't be negative")
	}
	if c.grep != "" {
		re, err := regexp.Compile(c.grep)
		if err != nil {
			return c, fmt.Errorf("--grep: %w", err)
		}
		if c.requests {
			return c, errors.New("--grep can't be combined with --requests, whose lines show no bodies; use --path, --method or --status")
		}
		c.grepRe = re
	}
	if c.pcap == "-" && c.har == "-" {
		return c, errors.New("--pcap - and --har - can't both write to stdout")
	}
	if c.java && c.pid == 0 && len(c.containers) == 0 {
		return c, errors.New("--java needs --pid or --container: snoopy loads its agent only into JVMs it's given")
	}
	if c.java && c.pid != 0 && len(c.containers) > 0 {
		return c, errors.New("--java takes --pid or --container, not both")
	}
	if c.javaAgent != "" && !c.java {
		return c, errors.New("--java-agent is for --java")
	}
	var modes []string
	for name, set := range map[string]bool{"--brief": c.brief, "--json": c.json, "--hex": c.hex, "--full": c.full, "--requests": c.requests} {
		if set {
			modes = append(modes, name)
		}
	}
	if len(modes) > 1 {
		slices.Sort(modes)
		return c, fmt.Errorf("%s can't be combined", strings.Join(modes, " and "))
	}
	if f, err := httpFilter(c); err != nil {
		return c, err
	} else {
		c.filter = f
	}
	if len(c.protos) > 0 {
		s, err := output.LoadProtoSchemas(c.protos)
		if err != nil {
			return c, fmt.Errorf("--proto: %w", err)
		}
		c.schemas = s
	}
	// These show data as sent, where HTTP/2's and HTTP/3's headers are
	// compressed: they can't be redacted.
	if c.redact && c.hex {
		return c, errors.New("--redact can't be combined with --hex, which shows data as captured")
	}
	if c.redact && c.pcap != "" {
		return c, errors.New("--redact can't be combined with --pcap, which writes data as captured")
	}
	return c, nil
}

// flagError puts an error of the flag package's in the help text's terms:
// the package names flags with one dash, the help text with two. For a
// flag that doesn't exist, it suggests the one meant, if one is close.
func flagError(err error, fs *flag.FlagSet) error {
	msg := err.Error()
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: -"); ok {
		if meant := closestFlag(strings.TrimLeft(name, "-"), fs); meant != "" {
			msg += "; did you mean --" + meant + "?"
		}
	}
	for _, s := range []string{"for flag -", "for -", "not defined: -", "needs an argument: -"} {
		msg = strings.Replace(msg, s, s+"-", 1)
	}
	return errors.New(msg)
}

// closestFlag returns the flag whose name is closest to name, if it's at
// most two edits away (a typo, a letter left out or swapped), and the only
// one that close.
func closestFlag(name string, fs *flag.FlagSet) string {
	best, bestDist, ties := "", 3, 0
	fs.VisitAll(func(f *flag.Flag) {
		switch d := editDistance(name, f.Name); {
		case d < bestDist:
			best, bestDist, ties = f.Name, d, 0
		case d == bestDist:
			ties++
		}
	})
	if ties > 0 {
		return ""
	}
	return best
}

// editDistance is the Damerau-Levenshtein distance between a and b (with
// adjacent transpositions), on bytes: flag names are ASCII.
func editDistance(a, b string) int {
	d := make([][]int, len(a)+1)
	for i := range d {
		d[i] = make([]int, len(b)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(a)][len(b)]
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

// active reports whether --host or --port was given.
func (f addrFilter) active() bool {
	return len(f.hosts) > 0 || len(f.ports) > 0
}

// check reports whether an event matches, and, if it doesn't, whether
// that's because its peer's address isn't known: it might have.
func (f addrFilter) check(ev *tracer.Event) (match, unknown bool) {
	if f.match(ev) {
		return true, false
	}
	return false, !ev.Remote.IsValid() || ev.Remote.Addr().IsUnspecified()
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
	// --serve-exec, kubectl snoopy's pods' waiter (see serveExec), is
	// hidden: not in --help, and only on its own.
	if len(os.Args) == 2 && (os.Args[1] == "--serve-exec" || os.Args[1] == "-serve-exec") {
		serveExec()
		return
	}
	cfg, err := parseFlags(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "snoopy: %v (see snoopy --help)\n", err)
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
	// Until tracing starts, Ctrl-C exits at once, as Go's default would.
	// Asked for here, since a program started with SIGINT ignored (a
	// script's background job) keeps ignoring it until it asks, and it used
	// to ask only once tracing started: Ctrl-C while starting was lost.
	tracing := exitOnSignalUntil()

	if cfg.noColor {
		color.NoColor = true
	}

	filter, err := newAddrFilter(cfg)
	if err != nil {
		return err
	}
	if cfg.pid != 0 {
		if _, ok := processKey(cfg.pid); !ok {
			return fmt.Errorf("no process %d", cfg.pid)
		}
	}
	// Loading the BPF program comes first: without root, its error is the
	// one to see.
	// With a process filter, probes go on those processes only, so the
	// rest don't pay for them; that needs the watcher, for new ones.
	perProcess := !cfg.noScan && (cfg.pid != 0 || cfg.comm != "" || len(cfg.containers) > 0)
	t, err := tracer.New(tracer.Options{PID: cfg.pid, Comm: cfg.comm, MaxCapture: cfg.maxSize, RingBufferSize: int(cfg.bufferSize), PerProcess: perProcess, Java: cfg.java})
	if err != nil {
		if errors.Is(err, unix.ENOMEM) && cfg.bufferSize != tracer.DefaultRingBufferSize {
			return fmt.Errorf("%w (with --buffer-size %s; a smaller one may fit)", err, cfg.bufferSize.String())
		}
		return loadError(err, cfg.verbose)
	}
	defer t.Close()
	printers, closePrinters, err := openPrinters(cfg, t.LostEvents)
	if err != nil {
		return err
	}
	closePrinters = sync.OnceFunc(closePrinters)
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
	if !t.ProcessTargets() {
		watcher.SkipOpenSSLQUIC() // not attached to
	}
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
	case len(attached) == 0 && cfg.java:
		// SunJSSE needs no library, which a JVM may not have.
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
	stopWatching := func() {}
	if !cfg.noScan {
		// Per process, every new process attaches to its files: they're
		// reported the first time.
		reported := map[string]bool{}
		for _, target := range attached {
			reported[reportKey(target)] = true
		}
		stop, err := t.WatchNewProcesses(watcher, acceptProcess(cfg, t), holdProcess(cfg),
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
			stopWatching = sync.OnceFunc(stop)
			defer stopWatching()
		}
	}
	if !t.ResolvesAddresses() {
		logf("warning: the kernel has no BTF, so socket addresses are looked up in /proc and may be missing for short-lived connections")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tracing() // after NotifyContext, so that no signal goes unhandled between
	if cfg.duration > 0 {
		timer := time.AfterFunc(cfg.duration, func() {
			logf("--duration %v is up", cfg.duration)
			stop()
		})
		defer timer.Stop()
	}
	stopJava := func() {}
	if cfg.java {
		s, err := startJava(ctx, cfg, t)
		if err != nil {
			return err
		}
		stopJava = sync.OnceFunc(s)
		defer stopJava()
	}
	quic := &quicSeen{pids: map[uint32]bool{}}
	go watchCounters(ctx, t, quic)
	lost := newLostReporter(t.LostEvents, logf, lostHint(cfg))
	go lost.watch(ctx)
	if cfg.pid != 0 {
		go watchExit(ctx, cfg.pid, stop)
		if !t.ResolvesAddresses() {
			// Without BTF, the BPF program can't tell a process's parents, so
			// processes that fork without executing a program are found here.
			go followChildren(ctx, t, cfg.pid)
		}
	}

	resolver := procinfo.NewResolver("/proc")
	events := newPipeline(filter, printers, cfg.count)
	events.filters = filterNames(cfg)
	if cfg.quiet && cfg.pcap == "" && cfg.har == "" {
		// For measuring snoopy's overhead, say, or a smoke test that
		// mustn't show what it captures.
		logf("--quiet without --pcap or --har: calls are counted, not written anywhere")
	}
	if cfg.pid == 0 && cfg.comm == "" && len(cfg.containers) == 0 && !cfg.redact &&
		(!cfg.quiet || cfg.pcap != "" || cfg.har != "") {
		// The default is the widest: said once, since what's captured then
		// includes other programs' secrets, snoopy's own host's included.
		logf("every process on this machine is traced, so their passwords and tokens show too; --comm, --pid or --container narrows it, --redact masks them")
	}
	if w := smallBufferWarning(int(cfg.bufferSize)); w != "" {
		logf("warning: %s", w)
	}
	if cfg.schemas != nil {
		logf("--proto: gRPC messages of %d %s are decoded with their fields' names", cfg.schemas.Methods(), plural(cfg.schemas.Methods(), "method", "methods"))
	}
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
		done, err := events.handle(ev)
		if err != nil {
			logf("error: write output: %v", err)
		}
		if done {
			stop()
		}
	})
	// From here on, a second Ctrl-C exits at once: what's left is
	// reporting, and telling Java agents to stop, which may take a while.
	exitNow := make(chan os.Signal, 1)
	signal.Notify(exitNow, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-exitNow
		os.Exit(130)
	}()
	stop()
	stopWatching() // nothing more to report attaching to

	logf("%s", events.summary(printers))
	lost.final()
	closePrinters()
	stopJava()
	return err
}

// exitOnSignalUntil makes SIGINT and SIGTERM exit at once, with the shell's
// code for them (130 and 143), until the function it returns is called.
func exitOnSignalUntil() (stop func()) {
	sig := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case s := <-sig:
			code := 130
			if s == syscall.SIGTERM {
				code = 143
			}
			os.Exit(code)
		case <-done:
		}
	}()
	return sync.OnceFunc(func() {
		signal.Stop(sig)
		close(done)
	})
}

// writeHARPeriodically rewrites the HAR file every few seconds while it
// changes, less often if writing it takes long (a large log), until stop.
func writeHARPeriodically(h *output.HAR, path string) (stop func()) {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		interval := harInterval
		for {
			select {
			case <-done:
				return
			case <-time.After(interval):
			}
			start := time.Now()
			if err := h.WriteFile(path); err != nil {
				logf("warning: --har: %v", err)
			}
			interval = max(harInterval, 10*time.Since(start))
		}
	}()
	return sync.OnceFunc(func() {
		close(done)
		<-finished
	})
}

// harInterval is how often, at most, the HAR file is rewritten.
const harInterval = 5 * time.Second

// loadError shortens the BPF verifier's rejection of snoopy's program,
// whose log runs to thousands of lines, to what to do about it, unless
// --verbose.
func loadError(err error, verbose bool) error {
	const rejected = "the kernel's BPF verifier rejected snoopy's program"
	var ve *ebpf.VerifierError
	if verbose || !errors.As(err, &ve) && !strings.HasPrefix(err.Error(), rejected) {
		return err
	}
	kernel := ""
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		kernel = " (this is " + unix.ByteSliceToString(u.Release[:]) + ")"
	}
	return fmt.Errorf("%s: it needs Linux 5.10 or later with BTF%s; --verbose shows the verifier's log", rejected, kernel)
}

// pipeline takes the events of the processes asked for to the printers,
// if --host and --port let them through, and counts the calls shown.
type pipeline struct {
	filter addrFilter
	// With --host or --port, a printer whose output is discarded, given QUIC
	// packets first, so that their peers are known before they're filtered:
	// a packet on a socket that isn't connected to one peer (quinn's) has
	// none, and the printers give it the one its connection's packets were
	// sent to.
	peers    output.Printer
	printers []output.Printer
	// requests is --requests' printer, whose lines are what --count counts
	// and the summary reports, rather than calls.
	requests *output.Requests
	count    int // --count
	calls    int
	// filters names the filters printers apply, for the summary: "--grep",
	// "--method, --path or --status", or both.
	filters string
	// noAddr is how many calls --host and --port left out because their
	// peers' addresses weren't known.
	noAddr int
}

func newPipeline(filter addrFilter, printers []output.Printer, count int) *pipeline {
	p := &pipeline{filter: filter, printers: printers, count: count}
	for _, pr := range printers {
		if r, ok := pr.(*output.Requests); ok {
			p.requests = r
		}
	}
	if filter.active() {
		p.peers = output.NewBrief(io.Discard, output.Options{})
	}
	return p
}

// handle passes an event on, and reports whether snoopy is done: with
// --count's calls shown, or on an error writing them.
func (p *pipeline) handle(ev *tracer.Event) (done bool, err error) {
	if p.peers != nil && (ev.Function.IsQUIC() || ev.Function == tracer.FuncQUICPacketSent) {
		_ = p.peers.Print(ev) // writes nowhere
	}
	if ev.Function == tracer.FuncQUICPacketSent {
		// Not shown or counted, only followed (see its doc).
		for _, pr := range p.printers {
			if err := pr.Print(ev); err != nil {
				return true, err
			}
		}
		return false, nil
	}
	if p.count > 0 && p.done() {
		return true, nil
	}
	if match, unknown := p.filter.check(ev); !match {
		if unknown {
			if p.noAddr == 0 {
				logf("warning: --host and --port leave out calls whose peer's address isn't known, such as SSLEngine's (--java); snoopy says how many when it stops")
			}
			p.noAddr++
		}
		return false, nil
	}
	shown := true
	for _, pr := range p.printers {
		before, beforeFiltered, beforeFolded := hidden(pr), filtered(pr), folded(pr)
		if err := pr.Print(ev); err != nil {
			return true, err
		}
		shown = shown && hidden(pr) == before && filtered(pr) == beforeFiltered && folded(pr) == beforeFolded
	}
	if !shown {
		return false, nil
	}
	p.calls++
	return p.count > 0 && p.done(), nil
}

// done reports whether --count's calls, or requests, have been shown.
func (p *pipeline) done() bool {
	if p.requests != nil {
		return p.requests.Shown() >= p.count
	}
	return p.calls >= p.count
}

// filterNames names the filters given that printers apply, for saying how
// many calls they left out.
func filterNames(cfg config) string {
	var names []string
	if cfg.filter != nil {
		names = append(names, "--method, --path or --status")
	}
	if cfg.grepRe != nil {
		names = append(names, "--grep")
	}
	return strings.Join(names, " or ")
}

// summary says what was captured and what was left out.
func (p *pipeline) summary(printers []output.Printer) string {
	summary := fmt.Sprintf("captured %d %s", p.calls, plural(p.calls, "call", "calls"))
	if r := p.requests; r != nil {
		summary += fmt.Sprintf(", shown as %d %s", r.Shown(), plural(r.Shown(), "request", "requests"))
		if n := r.FilteredRequests(); n > 0 {
			summary += fmt.Sprintf(" (%d more that %s didn't match)", n, p.filters)
		}
	}
	if n := p.noAddr; n > 0 {
		summary += fmt.Sprintf(", left out %d whose peer's address --host or --port needed but wasn't known", n)
	}
	if n := filteredTotal(printers); n > 0 {
		summary += fmt.Sprintf(", left out %d that %s didn't match", n, p.filters)
	}
	if n := foldedTotal(printers); n > 0 {
		summary += fmt.Sprintf(", folded %d in the middle of bodies", n)
	}
	if n := hiddenTotal(printers); n > 0 {
		summary += fmt.Sprintf(", and hid %d that only kept connections going", n)
	}
	if foldedTotal(printers) > 0 || hiddenTotal(printers) > 0 {
		summary += " (--verbose shows them)"
	}
	return summary
}

// watchExit calls exited once process pid, and those it started that were
// seen, have exited: there's nothing left to trace.
func watchExit(ctx context.Context, pid int, exited func()) {
	key, ok := processKey(pid)
	if !ok {
		return
	}
	alive := map[procKey]bool{key: true}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if key.alive() {
			for _, child := range discover.Descendants(pid)[1:] {
				if k, ok := processKey(child); ok {
					alive[k] = true
				}
			}
		}
		for k := range alive {
			if !k.alive() {
				delete(alive, k)
			}
		}
		if len(alive) == 0 {
			logf("process %d and those it started have exited", pid)
			exited()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
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

// folded returns how many calls a printer (--brief's) folded into the
// lines that end their bodies.
func folded(p output.Printer) int {
	if f, ok := p.(interface{ Folded() int }); ok {
		return f.Folded()
	}
	return 0
}

func foldedTotal(printers []output.Printer) int {
	n := 0
	for _, p := range printers {
		n += folded(p)
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
	// the meantime, which short-lived new processes often do, and a probe
	// for a process that has gone can't be made (ESRCH).
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ESRCH) {
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
// flushes and closes them. lost is Tracer.LostEvents, which the decoders
// read when they stop, to say that lost calls may be why.
func openPrinters(cfg config, lost func() (uint64, error)) ([]output.Printer, func(), error) {
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

	if cfg.har == "-" {
		stdoutUsed = true
		h := output.NewHAR(os.Stdout, versionString(), output.Options{Redact: cfg.redact, Filter: cfg.filter})
		printers = append(printers, h)
		closers = append([]func() error{h.Close}, closers...) // HAR is one document: written at the end
	} else if cfg.har != "" {
		// Written now, empty, so that a path that can't be written fails at
		// once, then rewritten as it changes, so that a long run, or one
		// that crashes or is killed, doesn't lose it.
		h := output.NewHAR(nil, versionString(), output.Options{Redact: cfg.redact, Filter: cfg.filter})
		if err := h.WriteFile(cfg.har); err != nil {
			return nil, nil, fmt.Errorf("--har: %w", err)
		}
		printers = append(printers, h)
		stop := writeHARPeriodically(h, cfg.har)
		closers = append(closers, func() error {
			stop()
			return h.WriteFile(cfg.har)
		})
	}

	if !cfg.quiet && !stdoutUsed {
		warn := warnOnce()
		out := newFlushWriter(os.Stdout)
		closers = append(closers, out.Close)
		switch {
		case cfg.json:
			printers = append(printers, output.NewJSON(out, output.Options{Redact: cfg.redact, Filter: cfg.filter, Warn: warn, Proto: cfg.schemas, Grep: cfg.grepRe, Lost: lost}))
		case cfg.requests:
			printers = append(printers, output.NewRequests(out, output.Options{Redact: cfg.redact, Filter: cfg.filter}))
		case cfg.brief:
			printers = append(printers, output.NewBrief(out, output.Options{Verbose: cfg.verbose, Redact: cfg.redact, Filter: cfg.filter, Warn: warn, Grep: cfg.grepRe, Lost: lost}))
		default:
			printers = append(printers, output.NewText(out, output.Options{Hex: cfg.hex, Full: cfg.full, Verbose: cfg.verbose, Redact: cfg.redact, Filter: cfg.filter, Warn: warn, Proto: cfg.schemas, Grep: cfg.grepRe, Lost: lost}))
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

// watchCounters warns about the QUIC traffic the BPF program counts that
// snoopy can't show: a process's HTTP/3 of which no packet was captured, and
// packets of connections that started before snoopy and can't be followed
// (Firefox's). Calls lost to a full ring buffer are lostReporter's.
func watchCounters(ctx context.Context, t *tracer.Tracer, quic *quicSeen) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
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
				// OpenSSL's QUIC is only traced in the processes selected.
				hint := ""
				if !t.PerProcess() {
					hint = "; if it uses OpenSSL's own QUIC (as curl does on Debian), select it with --comm or --pid"
				}
				logf("warning: %s (pid %d) sends or receives on UDP port 443, HTTP/3's, but none of its QUIC packets were captured: its QUIC library isn't supported, or has changed (see docs/maintenance.md)%s",
					strings.TrimSpace(string(comm)), pid, hint)
			}
			if n, err := t.UntrackedQUIC(); err == nil && n > 0 && !quicWarned {
				logf("warning: Firefox has HTTP/3 connections that were open before snoopy started, which can't be traced; restart Firefox to trace them")
				quicWarned = true
			}
		}
	}
}
