// Package discover finds the TLS libraries and Go binaries that snoopy can
// attach to: system-wide libraries, libraries mapped by running processes
// (including ones inside containers), and paths given on the command line.
package discover

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Library identifies a TLS implementation.
type Library int

const (
	OpenSSL Library = iota + 1 // also BoringSSL and LibreSSL
	GnuTLS
	NSS
	GoTLS
	WolfSSL
	MbedTLS
	S2N
	Rustls
)

func (l Library) String() string {
	switch l {
	case OpenSSL:
		return "openssl"
	case GnuTLS:
		return "gnutls"
	case NSS:
		return "nss"
	case GoTLS:
		return "go"
	case WolfSSL:
		return "wolfssl"
	case MbedTLS:
		return "mbedtls"
	case S2N:
		return "s2n"
	case Rustls:
		return "rustls"
	}
	return "unknown"
}

// Target is a file snoopy can attach probes to.
type Target struct {
	// Path to the file as seen by snoopy. Files of containerized processes
	// are reached through /proc/<pid>/root, and files that were deleted or
	// replaced while in use through /proc/<pid>/map_files or /proc/<pid>/exe.
	Path string
	// Note says what Path is, if that isn't obvious from it.
	Note    string
	Library Library
	// Go holds the probe locations for GoTLS targets.
	Go *GoInfo
	// Rust holds the probe locations for Rustls targets.
	Rust *RustInfo
}

// libPatterns are the file name globs of shared libraries we know how to probe.
var libPatterns = []string{"libssl.so*", "libgnutls.so*", "libnspr4.so*", "libwolfssl.so*", "libmbedtls.so*", "libs2n.so*"}

// libDirs are searched for system-wide libraries.
var libDirs = []string{
	"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64",
	"/lib/*-linux-gnu", "/usr/lib/*-linux-gnu",
}

// Options controls Find.
type Options struct {
	// PID restricts discovery to the files mapped by one process. Zero means
	// system-wide libraries plus, unless NoScan is set, every running process.
	PID int
	// Extra are additional libraries or executables to attach to.
	Extra []string
	// NoScan skips scanning running processes.
	NoScan bool
	// ProcRoot is the procfs mount point; defaults to /proc.
	ProcRoot string
}

// Find returns the targets to attach to, deduplicated by inode. Problems
// with individual files are returned as warnings rather than failing the
// whole search; an error is returned only if a user-supplied path or PID is
// unusable.
func Find(opts Options) (targets []Target, warnings []error, err error) {
	proc := opts.ProcRoot
	if proc == "" {
		proc = "/proc"
	}

	var candidates []candidate
	for _, p := range opts.Extra {
		if _, err := os.Stat(p); err != nil {
			return nil, nil, fmt.Errorf("--lib %s: %w", p, err)
		}
	}

	if opts.PID > 0 {
		files, err := processFiles(proc, opts.PID)
		if err != nil {
			return nil, nil, fmt.Errorf("pid %d: %w", opts.PID, err)
		}
		candidates = append(candidates, files...)
	} else {
		for _, path := range systemLibraries() {
			candidates = append(candidates, candidate{path: path})
		}
		if !opts.NoScan {
			files, denied := allProcessFiles(proc)
			candidates = append(candidates, files...)
			if denied > 0 {
				msg := fmt.Sprintf("permission denied inspecting %d processes; TLS libraries and Go programs only they use are missed", denied)
				if os.Geteuid() != 0 {
					msg += " (run as root)"
				}
				warnings = append(warnings, errors.New(msg))
			}
		}
	}

	seen := map[fileID]bool{}
	inspect := func(c candidate, explicit bool) {
		id, err := idOf(c.path)
		if err != nil || seen[id] {
			return
		}
		seen[id] = true

		found, err := Inspect(c.path)
		if err != nil {
			if explicit {
				warnings = append(warnings, fmt.Errorf("%s: %w", c.path, err))
			}
			return
		}
		if len(found) == 0 && explicit {
			warnings = append(warnings, fmt.Errorf("%s: no supported TLS functions found", c.path))
		}
		for i := range found {
			found[i].Note = c.note
		}
		targets = append(targets, found...)
	}

	for _, p := range opts.Extra {
		inspect(candidate{path: p}, true)
	}
	for _, c := range candidates {
		inspect(c, false)
	}

	sort.SliceStable(targets, func(i, j int) bool { return targets[i].Library < targets[j].Library })
	return targets, warnings, nil
}

// Watcher finds targets in processes that start after Find ran. Each file is
// inspected once, however many processes use it.
type Watcher struct {
	proc string
	seen map[fileID]bool
}

// NewWatcher returns a Watcher that skips the files of known, which are
// already attached to.
func NewWatcher(known []Target) *Watcher {
	w := &Watcher{proc: "/proc", seen: map[fileID]bool{}}
	for _, t := range known {
		if id, err := idOf(t.Path); err == nil {
			w.seen[id] = true
		}
	}
	return w
}

// Process returns the targets among a process's executable and mapped TLS
// libraries that haven't been seen before. Errors (typically, the process
// has exited) are ignored. It isn't safe for concurrent use.
func (w *Watcher) Process(pid int) []Target {
	files, err := processFiles(w.proc, pid)
	if err != nil {
		return nil
	}
	var targets []Target
	for _, c := range files {
		id, err := idOf(c.path)
		if err != nil || w.seen[id] {
			continue
		}
		found, err := Inspect(c.path)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			continue // gone with the process, or not ours to see; maybe next time
		}
		w.seen[id] = true
		for i := range found {
			found[i].Note = c.note
		}
		targets = append(targets, found...)
	}
	return targets
}

// systemLibraries returns the TLS libraries installed in the usual places.
func systemLibraries() []string {
	var out []string
	for _, dir := range libDirs {
		for _, pat := range libPatterns {
			matches, _ := filepath.Glob(filepath.Join(dir, pat))
			for _, m := range matches {
				// Report libssl.so.3 rather than the libssl.so dev symlink.
				if real, err := filepath.EvalSymlinks(m); err == nil {
					m = real
				}
				out = append(out, m)
			}
		}
	}
	return out
}

type candidate struct {
	path string
	note string
}

const deletedSuffix = " (deleted)"

// processFiles returns the TLS libraries mapped by a process and its
// executable, as paths reachable from snoopy's mount namespace.
//
// A file that was deleted or replaced (e.g. by a package upgrade) while the
// process kept using it is no longer reachable by name. Uprobes attach to
// the file's inode, so it is reached through the process instead.
func processFiles(proc string, pid int) ([]candidate, error) {
	dir := filepath.Join(proc, strconv.Itoa(pid))
	maps, err := os.Open(filepath.Join(dir, "maps"))
	if err != nil {
		return nil, err
	}
	defer maps.Close()

	libs := MappedLibraries(maps)
	out := make([]candidate, 0, len(libs)+1)
	for _, lib := range libs {
		if lib.Deleted {
			out = append(out, candidate{
				path: filepath.Join(dir, "map_files", lib.Range),
				note: "deleted " + lib.Path,
			})
		} else {
			out = append(out, candidate{path: filepath.Join(dir, "root", lib.Path)})
		}
	}

	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	switch {
	case err != nil:
	case strings.HasSuffix(exe, deletedSuffix):
		out = append(out, candidate{
			path: filepath.Join(dir, "exe"),
			note: "deleted " + strings.TrimSuffix(exe, deletedSuffix),
		})
	default:
		out = append(out, candidate{path: filepath.Join(dir, "root", exe)})
	}
	return out, nil
}

// allProcessFiles runs processFiles for every process, ignoring processes
// that exit. It also returns how many processes it wasn't allowed to inspect.
func allProcessFiles(proc string) (files []candidate, denied int) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, 0
	}
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		f, err := processFiles(proc, pid)
		if errors.Is(err, os.ErrPermission) {
			denied++
		}
		files = append(files, f...)
	}
	return files, denied
}

// Mapping is a file mapped into a process.
type Mapping struct {
	Path    string // the file's name, without " (deleted)"
	Range   string // the address range of its first mapping, e.g. "7f3e1d200000-7f3e1d222000"
	Deleted bool   // the file was deleted or replaced since it was mapped
}

// MappedLibraries parses a /proc/<pid>/maps file and returns the distinct
// mapped files whose names look like supported TLS libraries.
func MappedLibraries(maps io.Reader) []Mapping {
	seen := map[string]bool{}
	var out []Mapping
	sc := bufio.NewScanner(maps)
	for sc.Scan() {
		// address perms offset dev inode pathname
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || !strings.HasPrefix(fields[5], "/") {
			continue
		}
		name := strings.Join(fields[5:], " ")
		if seen[name] {
			continue
		}
		path, deleted := strings.CutSuffix(name, deletedSuffix)
		if isTLSLibraryName(filepath.Base(path)) {
			seen[name] = true
			out = append(out, Mapping{Path: path, Range: fields[0], Deleted: deleted})
		}
	}
	return out
}

func isTLSLibraryName(name string) bool {
	for _, pat := range libPatterns {
		if ok, _ := filepath.Match(pat, name); ok {
			return true
		}
	}
	return false
}

type fileID struct {
	dev, ino uint64
}

func idOf(path string) (fileID, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileID{}, err
	}
	if !fi.Mode().IsRegular() {
		return fileID{}, errors.New("not a regular file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, errors.New("no inode information")
	}
	return fileID{dev: uint64(st.Dev), ino: st.Ino}, nil
}
