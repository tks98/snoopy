// Package discover finds the TLS libraries and Go binaries that snoopy can
// attach to: system-wide libraries, libraries mapped by running processes
// (including ones inside containers), and paths given on the command line.
package discover

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	NGTCP2 // its crypto library's packet protection, for QUIC (curl's HTTP/3)
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
	case NGTCP2:
		return "ngtcp2"
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
	Note string
	// Deleted is the name a file that was deleted or replaced while in use
	// had.
	Deleted string
	Library Library
	// Go holds the probe locations for GoTLS targets.
	Go *GoInfo
	// Rust holds the probe locations for Rustls targets.
	Rust *RustInfo
	// Offsets, if set, are the file offsets of a C library's functions,
	// for a stripped copy whose functions were found by signature.
	Offsets map[string]uint64
	// Problem, if set, says why a TLS library found in the file can't be
	// traced, e.g. a stripped BoringSSL whose functions couldn't be told
	// apart. Such a target is reported, not attached to.
	Problem error
	// Limits, if set, says what of a target that is attached to can't be
	// traced, e.g. a BoringSSL build's HTTP/3.
	Limits string
}

// Name returns the file's name, as the processes using it know it.
func (t Target) Name() string {
	if t.Deleted != "" {
		return filepath.Base(t.Deleted)
	}
	return filepath.Base(t.Path)
}

// libPatterns are the file name globs of shared libraries we know how to probe.
var libPatterns = []string{"libssl.so*", "libgnutls.so*", "libnspr4.so*", "libfreeblpriv3.so", "libwolfssl.so*", "libmbedtls.so*", "libs2n.so*",
	"libngtcp2_crypto_*.so*"}

// knownPrograms are where Chromium-based browsers, Electron apps and
// Firefox's own NSS libraries are installed. Inspecting them at startup means
// they are traced from the moment they start: the browsers link BoringSSL
// statically and are found by signature (see findBoringSSL), which takes a
// moment for such large binaries, and Firefox's libraries aren't system ones.
var knownPrograms = []string{
	"/opt/google/chrome/chrome",
	"/opt/google/chrome-beta/chrome",
	"/opt/google/chrome-unstable/chrome",
	"/opt/brave.com/brave/brave",
	"/opt/microsoft/msedge/msedge",
	"/opt/vivaldi/vivaldi-bin",
	"/usr/lib/chromium/chromium",
	"/usr/lib/chromium-browser/chromium-browser",
	"/usr/lib64/chromium-browser/chromium-browser",
	"/snap/chromium/current/usr/lib/chromium-browser/chrome",
	"/usr/share/code/code",
	"/usr/lib/slack/slack",
	"/usr/share/discord/Discord",
	"/opt/Signal/signal-desktop",
	// Firefox's own NSS, whose freebl its QUIC stack uses (see findFreebl).
	"/snap/firefox/current/usr/lib/firefox/libnspr4.so",
	"/snap/firefox/current/usr/lib/firefox/libfreeblpriv3.so",
	"/usr/lib/firefox/libnspr4.so",
	"/usr/lib/firefox/libfreeblpriv3.so",
	"/usr/lib64/firefox/libnspr4.so",
	"/usr/lib64/firefox/libfreeblpriv3.so",
	"/opt/firefox/libnspr4.so",
	"/opt/firefox/libfreeblpriv3.so",
}

// libDirs are searched for system-wide libraries.
var libDirs = []string{
	"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64",
	"/lib/*-linux-gnu", "/usr/lib/*-linux-gnu",
}

// Options controls Find.
type Options struct {
	// PID restricts discovery to system-wide libraries and the files mapped
	// by one process and those it started. Zero means system-wide libraries,
	// known programs and, unless NoScan is set, every running process.
	PID int
	// Comm, if set, leaves out the running processes, and the known
	// programs, whose name doesn't start with it.
	Comm string
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
		for _, child := range descendants(proc, opts.PID)[1:] {
			files, _ := processFiles(proc, child) // it may have exited
			candidates = append(candidates, files...)
		}
		// For the programs it will start.
		for _, path := range systemLibraries() {
			candidates = append(candidates, candidate{path: path})
		}
	} else {
		for _, path := range append(knownFiles(opts.Comm), systemLibraries()...) {
			candidates = append(candidates, candidate{path: path})
		}
		if !opts.NoScan {
			files, denied := allProcessFiles(proc, opts.Comm)
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
		for _, t := range found {
			if t.Problem != nil {
				warnings = append(warnings, fmt.Errorf("%s: %w", c.path, t.Problem))
				continue
			}
			t.Note = joinNotes(t.Note, c.note)
			t.Deleted = c.deleted
			targets = append(targets, t)
		}
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
	proc  string
	mu    sync.Mutex
	seen  map[fileID]bool
	roots map[fileID]bool // root filesystems whose library directories were looked in
}

// NewWatcher returns a Watcher that skips the files of known, which are
// already attached to, and our own root's library directories, whose
// libraries Find returned.
func NewWatcher(known []Target) *Watcher {
	w := &Watcher{proc: "/proc", seen: map[fileID]bool{}, roots: map[fileID]bool{}}
	for _, t := range known {
		if id, err := idOf(t.Path); err == nil {
			w.seen[id] = true
		}
	}
	if id, err := dirID("/"); err == nil {
		w.roots[id] = true
	}
	return w
}

// Known reports whether a process's executable and root filesystem were
// looked at already, and it doesn't set where libraries are loaded from, so
// that its executable and the TLS libraries it's about to load are attached
// to if they can be.
func (w *Watcher) Known(pid int) bool {
	dir := filepath.Join(w.proc, strconv.Itoa(pid))
	exe, errExe := idOf(filepath.Join(dir, "exe"))
	root, errRoot := dirID(filepath.Join(dir, "root"))
	if errExe != nil || errRoot != nil {
		return true // gone, or not ours to see
	}
	if path, preload := loaderEnv(dir); len(path) > 0 || len(preload) > 0 {
		return false // it may load libraries from anywhere
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seen[exe] && w.roots[root]
}

// Root returns the targets among the TLS libraries in the usual library
// directories of a process's root filesystem, the first time it's asked
// about that root: a process in a container or chroot that has only just
// started hasn't mapped its libraries yet, and may be done before the next
// look at its mappings.
func (w *Watcher) Root(pid int) []Target {
	root := filepath.Join(w.proc, strconv.Itoa(pid), "root")
	id, err := dirID(root)
	if err != nil {
		return nil
	}
	w.mu.Lock()
	known := w.roots[id]
	w.roots[id] = true
	w.mu.Unlock()
	if known {
		return nil
	}
	var targets []Target
	for _, dir := range libDirs {
		for _, pat := range libPatterns {
			matches, _ := filepath.Glob(filepath.Join(root, dir, pat))
			for _, path := range matches {
				targets = append(targets, w.inspect(path, "")...)
			}
		}
	}
	return targets
}

// maxNeeded bounds how many libraries Needed reads.
const maxNeeded = 256

// Needed returns the targets among the TLS libraries a process that has
// only just started is about to load: its executable's DT_NEEDED libraries,
// and theirs, found as the dynamic loader finds them, in LD_LIBRARY_PATH,
// each file's RUNPATH or RPATH, and the usual library directories, all in
// the process's root filesystem. Libraries loaded with dlopen aren't among
// them (Root finds those in the usual directories).
func (w *Watcher) Needed(pid int) []Target {
	dir := filepath.Join(w.proc, strconv.Itoa(pid))
	root := filepath.Join(dir, "root")
	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		return nil
	}
	if r, _ := os.Readlink(root); r != "" && r != "/" && strings.HasPrefix(exe, r+"/") {
		exe = strings.TrimPrefix(exe, r) // a chroot's (see processFiles)
	}
	envPath, preload := loaderEnv(dir)

	var targets []Target
	visited := map[string]bool{}
	queue := []string{exe} // paths in the process's root
	for _, lib := range preload {
		if !strings.Contains(lib, "/") {
			lib = findLibrary(root, lib, append(envPath, libDirs...))
		}
		if lib != "" {
			queue = append(queue, lib)
		}
	}
	for len(queue) > 0 && len(visited) < maxNeeded {
		path := queue[0]
		queue = queue[1:]
		if visited[path] {
			continue
		}
		visited[path] = true
		if path != exe && isTLSLibraryName(filepath.Base(path)) {
			targets = append(targets, w.inspect(filepath.Join(root, path), "")...)
		}
		f, err := elf.Open(filepath.Join(root, path))
		if err != nil {
			continue
		}
		needed, _ := f.ImportedLibraries()
		var search []string
		for _, tag := range []elf.DynTag{elf.DT_RUNPATH, elf.DT_RPATH} {
			if paths, _ := f.DynString(tag); len(paths) > 0 {
				for _, p := range filepath.SplitList(paths[0]) {
					search = append(search, strings.ReplaceAll(p, "$ORIGIN", filepath.Dir(path)))
				}
				break // RUNPATH, if present, overrides RPATH
			}
		}
		f.Close()
		search = append(append(envPath, search...), libDirs...)
		for _, name := range needed {
			if lib := findLibrary(root, name, search); lib != "" {
				queue = append(queue, lib)
			}
		}
	}
	return targets
}

// loaderEnv returns the LD_LIBRARY_PATH directories and LD_PRELOAD
// libraries in the environment of the process whose /proc directory is dir.
func loaderEnv(dir string) (path, preload []string) {
	environ, err := os.ReadFile(filepath.Join(dir, "environ"))
	if err != nil {
		return nil, nil
	}
	for _, kv := range strings.Split(string(environ), "\x00") {
		if v, ok := strings.CutPrefix(kv, "LD_LIBRARY_PATH="); ok {
			path = filepath.SplitList(v)
		}
		if v, ok := strings.CutPrefix(kv, "LD_PRELOAD="); ok {
			preload = strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ':' })
		}
	}
	return path, preload
}

// findLibrary returns where the first of dirs (which may be globs) in root
// that has a library named name has it, as a path in root, or "".
func findLibrary(root, name string, dirs []string) string {
	for _, d := range dirs {
		matches, _ := filepath.Glob(filepath.Join(root, d, name))
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.Mode().IsRegular() {
				return strings.TrimPrefix(m, root)
			}
		}
	}
	return ""
}

// inspect returns the targets in a file, unless it was seen before, with
// note added to theirs.
func (w *Watcher) inspect(path, note string) []Target {
	id, err := idOf(path)
	if err != nil {
		return nil
	}
	w.mu.Lock()
	seen := w.seen[id]
	w.mu.Unlock()
	if seen {
		return nil
	}
	found, err := Inspect(path)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return nil // gone with the process, or not ours to see; maybe next time
	}
	w.mu.Lock()
	w.seen[id] = true
	w.mu.Unlock()
	for i := range found {
		found[i].Note = joinNotes(found[i].Note, note)
	}
	return found
}

func dirID(path string) (fileID, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileID{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() {
		return fileID{}, errors.New("not a directory")
	}
	return fileID{dev: uint64(st.Dev), ino: st.Ino}, nil
}

// Process returns the targets among a process's executable and mapped TLS
// libraries that haven't been seen before. Errors (typically, the process
// has exited) are ignored.
func (w *Watcher) Process(pid int) []Target {
	files, err := processFiles(w.proc, pid)
	if err != nil {
		return nil
	}
	var targets []Target
	for _, c := range files {
		targets = append(targets, w.inspect(c.path, c.note)...)
	}
	return targets
}

// knownFiles returns the known programs that are installed, of those whose
// name starts with comm.
func knownFiles(comm string) []string {
	var out []string
	for _, p := range knownPrograms {
		name := filepath.Base(p)
		if strings.Contains(p, "/firefox/") {
			name = "firefox" // its libraries
		}
		if !strings.HasPrefix(name, comm) {
			continue
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			out = append(out, real)
		}
	}
	return out
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
	path    string
	note    string
	deleted string // the name the file had, if it was deleted
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

	// Files are reached through the process's root, but a chrooted
	// process's maps and exe name them by their path from ours.
	root, _ := os.Readlink(filepath.Join(dir, "root"))
	inRoot := func(path string) string {
		if root != "" && root != "/" && strings.HasPrefix(path, root+"/") {
			return strings.TrimPrefix(path, root)
		}
		return path
	}
	libs := MappedLibraries(maps)
	out := make([]candidate, 0, len(libs)+1)
	for _, lib := range libs {
		if lib.Deleted {
			out = append(out, candidate{
				path:    filepath.Join(dir, "map_files", lib.Range),
				note:    "deleted " + lib.Path,
				deleted: lib.Path,
			})
		} else {
			out = append(out, candidate{path: filepath.Join(dir, "root", inRoot(lib.Path))})
		}
	}

	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	switch {
	case err != nil:
	case strings.HasSuffix(exe, deletedSuffix):
		out = append(out, candidate{
			path:    filepath.Join(dir, "exe"),
			note:    "deleted " + strings.TrimSuffix(exe, deletedSuffix),
			deleted: strings.TrimSuffix(exe, deletedSuffix),
		})
	default:
		out = append(out, candidate{path: filepath.Join(dir, "root", inRoot(exe))})
	}
	return out, nil
}

// Descendants returns a process's ID and those of the processes it started,
// and they started, and so on, that are still running.
func Descendants(pid int) []int {
	return descendants("/proc", pid)
}

func descendants(proc string, pid int) []int {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return []int{pid}
	}
	children := map[int][]int{}
	for _, e := range entries {
		child, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if ppid, ok := parentPID(proc, child); ok {
			children[ppid] = append(children[ppid], child)
		}
	}
	out := []int{pid}
	for i := 0; i < len(out); i++ {
		out = append(out, children[out[i]]...)
	}
	return out
}

// parentPID reads a process's parent from /proc/<pid>/stat: "pid (comm)
// state ppid ...", where comm may contain spaces and parentheses.
func parentPID(proc string, pid int) (int, bool) {
	data, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return 0, false
	}
	fields := strings.Fields(string(data[i+1:]))
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	return ppid, err == nil
}

// IsDescendant reports whether pid was started by ancestor, directly or not.
func IsDescendant(pid, ancestor int) bool {
	return isDescendant("/proc", pid, ancestor)
}

func isDescendant(proc string, pid, ancestor int) bool {
	for i := 0; i < 64 && pid > 1; i++ {
		ppid, ok := parentPID(proc, pid)
		if !ok {
			return false
		}
		if ppid == ancestor {
			return true
		}
		pid = ppid
	}
	return false
}

// allProcessFiles runs processFiles for every process whose name starts
// with comm, ignoring processes that exit. It also returns how many
// processes it wasn't allowed to inspect.
func allProcessFiles(proc, comm string) (files []candidate, denied int) {
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
		if comm != "" {
			name, err := os.ReadFile(filepath.Join(proc, e.Name(), "comm"))
			if err != nil || !strings.HasPrefix(string(name), comm) {
				continue
			}
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

func joinNotes(a, b string) string {
	if a == "" || b == "" {
		return a + b
	}
	return a + ", " + b
}
