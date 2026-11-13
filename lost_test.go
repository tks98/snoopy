//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

func TestBufferSizeFlag(t *testing.T) {
	c, err := parseFlags(nil, io.Discard)
	if err != nil || c.bufferSize != tracer.DefaultRingBufferSize {
		t.Errorf("default: %d, %v", c.bufferSize, err)
	}
	page := os.Getpagesize()
	for arg, want := range map[string]int{
		"64M":                  64 << 20,
		"64m":                  64 << 20,
		"64MiB":                64 << 20,
		"64MB":                 64 << 20,
		"1G":                   1 << 30,
		"256k":                 256 << 10,
		"4194304":              4 << 20,
		"4194304B":             4 << 20,
		fmt.Sprint(page):       page,
		formatSize(2 * page):   2 * page,
		formatSize(1 << 30):    1 << 30,
		" 32M ":                32 << 20,
		formatSize(page) + "B": page,
	} {
		c, err := parseFlags([]string{"--buffer-size", arg}, io.Discard)
		if err != nil || int(c.bufferSize) != want {
			t.Errorf("--buffer-size %q: %d, %v; want %d", arg, c.bufferSize, err, want)
		}
	}
	for arg, want := range map[string]string{
		"48M":         "the ring buffer's size is a power of two, such as 32M or 64M",
		"1000000":     "the ring buffer's size is a power of two, such as 512K or 1M",
		"2G":          "the ring buffer is at most 1G",
		"8589934592":  "the ring buffer is at most 1G",
		"0":           "the ring buffer is at least a page, " + formatSize(page),
		"64 M":        "sizes are bytes, or a number with K, M or G: 16M, 64M",
		"64T":         "sizes are bytes, or a number with K, M or G: 16M, 64M",
		"-1M":         "sizes are bytes, or a number with K, M or G: 16M, 64M",
		"16iB":        "sizes are bytes, or a number with K, M or G: 16M, 64M",
		"":            "sizes are bytes, or a number with K, M or G: 16M, 64M",
		"sixteen meg": "sizes are bytes, or a number with K, M or G: 16M, 64M",
	} {
		_, err := parseFlags([]string{"--buffer-size", arg}, io.Discard)
		if want := `invalid value "` + arg + `" for flag --buffer-size: ` + want; err == nil || err.Error() != want {
			t.Errorf("--buffer-size %q: %v; want %s", arg, err, want)
		}
	}
	// A page bigger than the default's machine's, as on some arm64 kernels.
	if err := checkBufferSize(32<<10, 64<<10); err == nil || err.Error() != "the ring buffer is at least a page, 64K" {
		t.Errorf("64K pages: %v", err)
	}
	if got := closestFlag("bufer-size", flags(&config{})); got != "buffer-size" {
		t.Errorf("closestFlag: %q", got)
	}
}

func TestSmallBufferWarning(t *testing.T) {
	if w := smallBufferWarning(16 << 10); w != "--buffer-size 16K can't hold a call of more than 2 KiB, so every one is lost; 32K holds one" {
		t.Errorf("16K: %q", w)
	}
	if w := smallBufferWarning(32 << 10); w != "" {
		t.Errorf("32K: %q", w)
	}
}

func TestFormatSize(t *testing.T) {
	for n, want := range map[int]string{16 << 20: "16M", 4096: "4K", 1 << 30: "1G", 1536: "1536", 3 << 20: "3M", 100: "100", 1<<30 + 1<<20: "1025M"} {
		if got := formatSize(n); got != want {
			t.Errorf("formatSize(%d) = %q, want %q", n, got, want)
		}
	}
}

// fakeLost is a lost-event counter the test sets, standing in for the BPF
// program's.
type fakeLost struct {
	n   uint64
	err error
}

func (f *fakeLost) count() (uint64, error) { return f.n, f.err }

// The first loss is said at the first check that sees it, with what to do;
// more are said at most every lostEvery, with how many since; and the total
// at the end.
func TestLostReporter(t *testing.T) {
	var lines []string
	logf := func(format string, a ...any) { lines = append(lines, fmt.Sprintf(format, a...)) }
	counter := &fakeLost{}
	r := newLostReporter(counter.count, logf, "HINT")
	start := time.Unix(1000, 0)
	at := func(s float64) time.Time { return start.Add(time.Duration(s * float64(time.Second))) }

	r.check(at(1)) // nothing lost
	counter.err = errors.New("no map")
	counter.n = 5
	r.check(at(2)) // can't read it
	counter.err = nil
	r.check(at(3))
	counter.n = 7
	r.check(at(4)) // too soon after
	r.check(at(7.9))
	r.check(at(8))
	r.check(at(9)) // nothing more
	counter.n = 8
	r.check(at(20))
	r.final()

	want := []string{
		"warning: the ring buffer was full, so 5 calls were lost, whole or in part; HINT",
		"warning: the ring buffer was full, so 2 more calls were lost (7 in all)",
		"warning: the ring buffer was full, so 1 more call was lost (8 in all)",
		"warning: 8 calls were lost, whole or in part, because the ring buffer was full",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}

	// Lost only just before snoopy stops: the hint comes with the total.
	lines = nil
	counter.n = 1
	newLostReporter(counter.count, logf, "HINT").final()
	if len(lines) != 1 || lines[0] != "warning: 1 call was lost, whole or in part, because the ring buffer was full; HINT" {
		t.Errorf("got %q", lines)
	}

	// Nothing lost: nothing said.
	lines = nil
	counter.n = 0
	r = newLostReporter(counter.count, logf, "HINT")
	r.check(at(1))
	r.final()
	if len(lines) != 0 {
		t.Errorf("got %q", lines)
	}
}

// The hint suggests what the command line doesn't already do.
func TestLostHint(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "a larger --buffer-size than 16M, such as 64M, rides out longer bursts; --comm, --pid or --container traces fewer calls; --brief, or --quiet with --pcap, keeps up with more"},
		{[]string{"--json", "--comm", "nginx", "--buffer-size", "512M"}, "a larger --buffer-size than 512M, such as 1G, rides out longer bursts; --brief, or --quiet with --pcap, keeps up with more"},
		{[]string{"--brief", "--pid", "1", "--buffer-size", "1G"}, "trace fewer calls at once"},
		{[]string{"--quiet", "--pcap", "x.pcap", "--container", "abc"}, "a larger --buffer-size than 16M, such as 64M, rides out longer bursts"},
		{[]string{"--requests"}, "a larger --buffer-size than 16M, such as 64M, rides out longer bursts; --comm, --pid or --container traces fewer calls"},
	} {
		cfg, err := parseFlags(tc.args, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if got := lostHint(cfg); got != tc.want {
			t.Errorf("%q:\n got %s\nwant %s", tc.args, got, tc.want)
		}
	}
}
