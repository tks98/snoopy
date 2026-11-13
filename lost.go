//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// byteSize is --buffer-size's value: the ring buffer's size in bytes, given
// as bytes or with K, M or G (KiB, MiB, GiB; KB, MB and GB mean the same,
// since the size is a power of two either way).
type byteSize int

func (b *byteSize) String() string { return formatSize(int(*b)) }

func (b *byteSize) Set(v string) error {
	n, err := parseSize(v)
	if err != nil {
		return err
	}
	if err := checkBufferSize(n, os.Getpagesize()); err != nil {
		return err
	}
	*b = byteSize(n)
	return nil
}

// sizePattern is a size as --buffer-size takes it: a number, and a unit
// letter, optionally with B or iB after it, or a B for bytes.
var sizePattern = regexp.MustCompile(`(?i)^([0-9]+)(?:([KMG])(?:i?B)?|B)?$`)

// parseSize parses a size in bytes: 65536, 64K, 64KiB, 16M, 1G.
func parseSize(v string) (int, error) {
	m := sizePattern.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0, errors.New("sizes are bytes, or a number with K, M or G: 16M, 64M")
	}
	n, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("the ring buffer is at most %s", formatSize(tracer.MaxRingBufferSize))
	}
	shift := map[string]int{"": 0, "K": 10, "M": 20, "G": 30}[strings.ToUpper(m[2])]
	return int(n << shift), nil // under 2^62: n has 32 bits
}

// checkBufferSize says what's wrong with a ring buffer size, if anything:
// the kernel takes a power of two that's at least a page.
func checkBufferSize(n, pageSize int) error {
	switch {
	case n < pageSize:
		return fmt.Errorf("the ring buffer is at least a page, %s", formatSize(pageSize))
	case n > tracer.MaxRingBufferSize:
		return fmt.Errorf("the ring buffer is at most %s", formatSize(tracer.MaxRingBufferSize))
	case n&(n-1) != 0:
		below := 1 << (bits.Len(uint(n)) - 1)
		return fmt.Errorf("the ring buffer's size is a power of two, such as %s or %s", formatSize(below), formatSize(2*below))
	}
	return nil
}

// formatSize writes a size as --buffer-size takes it: 16M rather than
// 16777216.
func formatSize(n int) string {
	for _, u := range []struct {
		shift  int
		suffix string
	}{{30, "G"}, {20, "M"}, {10, "K"}} {
		if n >= 1<<u.shift && n%(1<<u.shift) == 0 {
			return strconv.Itoa(n>>u.shift) + u.suffix
		}
	}
	return strconv.Itoa(n)
}

// smallestForChunks is the smallest ring buffer that holds a record of a
// whole 16 KiB chunk (16 KiB, and 168 bytes of headers): in one smaller
// than that, every call of more than 2 KiB is lost.
const smallestForChunks = 32 << 10

// smallBufferWarning warns about a --buffer-size that can't hold a call
// of more than 2 KiB, or returns "".
func smallBufferWarning(size int) string {
	if size >= smallestForChunks {
		return ""
	}
	return fmt.Sprintf("--buffer-size %s can't hold a call of more than 2 KiB, so every one is lost; %s holds one", formatSize(size), formatSize(smallestForChunks))
}

// lostEvery is how often, at most, snoopy says that calls were lost while
// it runs. The first loss is said at the next check, within a second.
const lostEvery = 5 * time.Second

// lostReporter says when the BPF program's count of the records it had no
// room for in the ring buffer goes up: once with what to do about it, then
// at most every lostEvery with how many more, and in all when snoopy stops.
type lostReporter struct {
	lost  func() (uint64, error) // Tracer.LostEvents
	logf  func(format string, a ...any)
	hint  string // what to do about it
	every time.Duration

	mu       sync.Mutex
	reported uint64    // the count as of the last line
	last     time.Time // when the last line was written
}

func newLostReporter(lost func() (uint64, error), logf func(string, ...any), hint string) *lostReporter {
	return &lostReporter{lost: lost, logf: logf, hint: hint, every: lostEvery}
}

// check reads the count and says how many were lost since it was last said,
// unless that was less than r.every ago.
func (r *lostReporter) check(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.lost()
	if err != nil || n <= r.reported || !r.last.IsZero() && now.Sub(r.last) < r.every {
		return
	}
	if r.reported == 0 {
		r.logf("warning: the ring buffer was full, so %d %s lost, whole or in part; %s", n, plural(int(n), "call was", "calls were"), r.hint)
	} else {
		r.logf("warning: the ring buffer was full, so %d more %s lost (%d in all)", n-r.reported, plural(int(n-r.reported), "call was", "calls were"), n)
	}
	r.reported, r.last = n, now
}

// final says how many were lost in all, if any, and what to do about it if
// that wasn't said yet.
func (r *lostReporter) final() {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.lost()
	if err != nil || n == 0 {
		return
	}
	msg := fmt.Sprintf("warning: %d %s lost, whole or in part, because the ring buffer was full", n, plural(int(n), "call was", "calls were"))
	if r.reported == 0 {
		msg += "; " + r.hint
	}
	r.logf("%s", msg)
	r.reported = n
}

// watch checks every second until ctx is done.
func (r *lostReporter) watch(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r.check(now)
		}
	}
}

// lostHint says what would lose fewer calls, of what the command line
// leaves to try: a larger buffer for bursts, tracing fewer processes, and
// output that takes less time per call. Text and JSON take the most;
// writing them to a terminal, or to a program that reads slowly, takes
// longer still.
func lostHint(cfg config) string {
	var hints []string
	if size := int(cfg.bufferSize); size < tracer.MaxRingBufferSize {
		hints = append(hints, fmt.Sprintf("a larger --buffer-size than %s, such as %s, rides out longer bursts",
			formatSize(size), formatSize(min(4*size, tracer.MaxRingBufferSize))))
	}
	if cfg.pid == 0 && cfg.comm == "" && len(cfg.containers) == 0 {
		hints = append(hints, "--comm, --pid or --container traces fewer calls")
	}
	if !cfg.quiet && !cfg.brief && !cfg.requests {
		hints = append(hints, "--brief, or --quiet with --pcap, keeps up with more")
	}
	if len(hints) == 0 {
		return "trace fewer calls at once"
	}
	return strings.Join(hints, "; ")
}
