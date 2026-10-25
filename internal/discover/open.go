package discover

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

var errNotRegular = errors.New("not a regular file")

// OpenPath opens a file snoopy reads or attaches to, often in a container,
// with O_PATH, which neither blocks (as opening a FIFO does) nor does
// anything a device might on being opened, and only if it's a regular file.
// /proc/self/fd/<fd> is then that file, whatever its path points to later:
// open it through there.
func OpenPath(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
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

// openELF opens an ELF file with openRegular. Close the *os.File when done.
func openELF(path string) (*elf.File, *os.File, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, nil, err
	}
	f, err := elf.NewFile(file)
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	return f, file, nil
}
