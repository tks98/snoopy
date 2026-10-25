package javaagent

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// A process's files are reached through /proc/<pid>/root and /proc/<pid>/cwd,
// but a path joined onto those is resolved by snoopy, as root: an absolute
// symlink in it (planted by the process, or by a container's root, which is
// often root on the host too) points into snoopy's own filesystem. So paths
// in a process's filesystem are opened relative to a descriptor for its
// root, with openat2's RESOLVE_IN_ROOT, which resolves them as the process
// would, and files are made with O_EXCL and O_NOFOLLOW and changed through
// their descriptors, never by path again.

// resolveIn is how paths in a process's filesystem are resolved: symlinks
// within it, and no /proc magic links, which could lead out of it.
const resolveIn = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS

// openRoot returns an O_PATH descriptor for process pid's root directory.
func openRoot(pid int) (int, error) {
	return unix.Open(fmt.Sprintf("/proc/%d/root", pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

// openCwd returns an O_PATH descriptor for process pid's working directory.
func openCwd(pid int) (int, error) {
	return unix.Open(fmt.Sprintf("/proc/%d/cwd", pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

// openIn opens path in the filesystem whose root is root, as the process
// would resolve it.
func openIn(root int, path string, flags int, mode uint32) (int, error) {
	return unix.Openat2(root, path, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Mode: uint64(mode), Resolve: resolveIn})
}

// createIn creates a file named name (one component) in the directory dir,
// which mustn't exist already, not even as a symlink.
func createIn(dir int, name string, mode uint32) (int, error) {
	return unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
}
