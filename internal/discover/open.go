package discover

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

var errNotRegular = errors.New("not a regular file")

// openRegular opens a file snoopy reads, often in a container, only if it's
// a regular file. Opening a FIFO blocks, and a device can do things just by
// being opened, so the path is opened with O_PATH first, which does
// neither, and the file reopened through that descriptor once it's known
// to be regular: the same file, whatever the path points to by then.
func openRegular(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, &os.PathError{Op: "open", Path: path, Err: errNotRegular}
	}
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
