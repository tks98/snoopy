package discover

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"

	"golang.org/x/sys/unix"
)

var errNotRegular = errors.New("not a regular file")

// OpenPath opens a file snoopy reads or attaches to, often in a container,
// with O_PATH, which neither blocks (as opening a FIFO does) nor does
// anything a device might on being opened, and only if it's a regular file.
// /proc/self/fd/<fd> is then that file, whatever its path points to later:
// open it through there.
//
// A path in a process's root filesystem, /proc/<pid>/root/..., is resolved
// as the process would resolve it (see openInRoot).
func OpenPath(path string) (int, error) {
	fd, err := openPath(path)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return -1, &os.PathError{Op: "open", Path: path, Err: errNotRegular}
	}
	return fd, nil
}

// procRootPath matches a path in a process's root filesystem, as snoopy
// reaches it: the process's root, and the path in it.
var procRootPath = regexp.MustCompile(`^(/proc/[0-9]+/root)(/.*)$`)

func openPath(name string) (int, error) {
	if m := procRootPath.FindStringSubmatch(name); m != nil {
		return openInRoot(m[1], m[2])
	}
	return unix.Open(name, unix.O_PATH|unix.O_CLOEXEC, 0)
}

// openInRoot opens name, with O_PATH, in the filesystem whose root is the
// directory root. A process's files are reached through /proc/<pid>/root,
// but a path joined onto that is resolved by snoopy, in its own root: an
// absolute symlink in it (planted by the process, or by whoever made a
// container's image) would point into snoopy's filesystem, which is the
// host's. openat2's RESOLVE_IN_ROOT resolves it relative to a descriptor of
// the process's root, as the process would, with ".." stopping there, and
// without /proc magic links, which could lead out of it.
func openInRoot(root, name string) (int, error) {
	dir, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(dir)
	return unix.Openat2(dir, name, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
}

// inRoot returns the path that a path name in a process's filesystem has
// from root, its /proc/<pid>/root or "" (see filesRoot). name comes from
// the process (its libraries' names and search paths), so it's cleaned as
// an absolute path first: "../.." can't lead out of root.
func inRoot(root, name string) string {
	return root + path.Clean("/"+name)
}

// isRegular reports whether path is a regular file, resolved as OpenPath
// resolves it.
func isRegular(path string) bool {
	fd, err := OpenPath(path)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// openRegular opens a file with OpenPath, to read it.
func openRegular(path string) (*os.File, error) {
	fd, err := OpenPath(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return f, nil
}

// openELF opens an ELF file with openRegular, if what reading it takes is
// of a sane size (see checkHeaders and checkSections). Close the *os.File
// when done.
func openELF(path string) (*elf.File, *os.File, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, nil, err
	}
	if err := checkHeaders(file); err != nil {
		file.Close()
		return nil, nil, err
	}
	f, err := elf.NewFile(file)
	if err == nil {
		err = checkSections(f)
	}
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	return f, file, nil
}
