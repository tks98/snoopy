package discover

import (
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
)

// quicMethods are the functions that make an SSL_CTX for OpenSSL's own
// QUIC, from libssl 3.2 on. A program using OpenSSL's QUIC imports one of
// them, in its executable or in one of its libraries (libcurl, for curl).
var quicMethods = []string{"OSSL_QUIC_client_method", "OSSL_QUIC_client_thread_method", "OSSL_QUIC_server_method"}

// maxMappedFiles bounds how many of a process's mapped files are looked at
// to tell whether it uses OpenSSL's QUIC: real programs map a few hundred
// at most, and a process can map any number.
const maxMappedFiles = 1024

// quicUsers tells which processes use OpenSSL's QUIC, remembering which
// files import it by their identity: a process's files are looked at each
// time it is, and most are shared by many processes.
type quicUsers struct {
	mu    sync.Mutex
	files *lru[fileID, bool]
}

func newQUICUsers() *quicUsers {
	return &quicUsers{files: newLRU[fileID, bool](maxSeen)}
}

// process reports whether a process uses OpenSSL's QUIC: whether one of the
// ELF files it maps, its executable included, imports one of quicMethods.
func (q *quicUsers) process(proc string, pid int) bool {
	dir := filepath.Join(proc, strconv.Itoa(pid))
	maps, err := os.Open(filepath.Join(dir, "maps"))
	if err != nil {
		return false
	}
	mapped := mappedFiles(maps, func(string) bool { return true }, maxMappedFiles)
	maps.Close()
	trimRoot := chrootTrimmer(dir)
	paths := make([]string, 0, len(mapped))
	for _, m := range mapped {
		paths = append(paths, mappedCandidate(dir, pid, m, trimRoot).path)
	}
	return q.anyOf(paths)
}

// anyOf reports whether one of the files at paths imports one of
// quicMethods.
func (q *quicUsers) anyOf(paths []string) bool {
	for _, path := range paths[:min(len(paths), maxMappedFiles)] {
		id, err := idOf(path)
		if err != nil {
			continue
		}
		q.mu.Lock()
		imports, known := q.files.get(id)
		q.mu.Unlock()
		if !known {
			imports, err = importsQUICMethod(path)
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
				continue // gone, or not ours to see; maybe next time
			}
			q.mu.Lock()
			q.files.put(id, imports)
			q.mu.Unlock()
		}
		if imports {
			return true
		}
	}
	return false
}

// importsQUICMethod reports whether the file at path is an ELF file that
// imports one of quicMethods. Files that aren't ELF, or can't be read as
// such, don't. Like Inspect, it turns a panic in reading the file into an
// error.
func importsQUICMethod(path string) (imports bool, err error) {
	defer func() {
		if perr := recovered(recover()); perr != nil {
			imports, err = false, perr
		}
	}()
	f, file, err := openELF(path)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return false, err
	}
	if err != nil {
		return false, nil
	}
	defer file.Close()
	syms, err := dynamicSymbols(f)
	if err != nil {
		return false, nil // none, or too many
	}
	return slices.ContainsFunc(syms, func(s elf.Symbol) bool {
		return s.Section == elf.SHN_UNDEF && slices.Contains(quicMethods, s.Name)
	}), nil
}
