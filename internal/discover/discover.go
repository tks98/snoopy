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
	}
	return "unknown"
}

// Target is a file snoopy can attach probes to.
type Target struct {
	// Path to the file as seen by snoopy. Files of containerized processes
	// are reached through /proc/<pid>/root.
	Path    string
	Library Library
	// Go holds the probe locations for GoTLS targets.
	Go *GoInfo
}

// libPatterns are the file name globs of shared libraries we know how to probe.
var libPatterns = []string{"libssl.so*", "libgnutls.so*", "libnspr4.so*"}

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

	var candidates []string
	for _, p := range opts.Extra {
		if _, err := os.Stat(p); err != nil {
			return nil, nil, fmt.Errorf("--lib %s: %w", p, err)
		}
	}

	if opts.PID > 0 {
		paths, err := processFiles(proc, opts.PID)
		if err != nil {
			return nil, nil, fmt.Errorf("pid %d: %w", opts.PID, err)
		}
		candidates = append(candidates, paths...)
	} else {
		candidates = append(candidates, systemLibraries()...)
		if !opts.NoScan {
			candidates = append(candidates, allProcessFiles(proc)...)
		}
	}

	seen := map[fileID]bool{}
	inspect := func(path string, explicit bool) {
		id, err := idOf(path)
		if err != nil || seen[id] {
			return
		}
		seen[id] = true

		found, err := Inspect(path)
		if err != nil {
			if explicit {
				warnings = append(warnings, fmt.Errorf("%s: %w", path, err))
			}
			return
		}
		if len(found) == 0 && explicit {
			warnings = append(warnings, fmt.Errorf("%s: no supported TLS functions found", path))
		}
		targets = append(targets, found...)
	}

	for _, p := range opts.Extra {
		inspect(p, true)
	}
	for _, p := range candidates {
		inspect(p, false)
	}

	sort.SliceStable(targets, func(i, j int) bool { return targets[i].Library < targets[j].Library })
	return targets, warnings, nil
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

// processFiles returns the TLS libraries mapped by a process and its
// executable, as paths reachable from snoopy's mount namespace.
func processFiles(proc string, pid int) ([]string, error) {
	root := filepath.Join(proc, strconv.Itoa(pid), "root")
	maps, err := os.Open(filepath.Join(proc, strconv.Itoa(pid), "maps"))
	if err != nil {
		return nil, err
	}
	defer maps.Close()

	libs := MappedLibraries(maps)
	out := make([]string, 0, len(libs)+1)
	for _, lib := range libs {
		out = append(out, filepath.Join(root, lib))
	}
	if exe, err := os.Readlink(filepath.Join(proc, strconv.Itoa(pid), "exe")); err == nil {
		out = append(out, filepath.Join(root, strings.TrimSuffix(exe, " (deleted)")))
	}
	return out, nil
}

// allProcessFiles runs processFiles for every process, ignoring processes
// that exit or can't be read.
func allProcessFiles(proc string) []string {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil
	}
	self := os.Getpid()
	var out []string
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		paths, err := processFiles(proc, pid)
		if err != nil {
			continue
		}
		out = append(out, paths...)
	}
	return out
}

// MappedLibraries parses a /proc/<pid>/maps file and returns the distinct
// mapped files whose names look like supported TLS libraries.
func MappedLibraries(maps io.Reader) []string {
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(maps)
	for sc.Scan() {
		// address perms offset dev inode pathname
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || !strings.HasPrefix(fields[5], "/") {
			continue
		}
		path := strings.Join(fields[5:], " ")
		if strings.HasSuffix(path, " (deleted)") || seen[path] {
			continue
		}
		if isTLSLibraryName(filepath.Base(path)) {
			seen[path] = true
			out = append(out, path)
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
