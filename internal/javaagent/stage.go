package javaagent

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Jars are the agent's files: AgentJar, the one the JVM loads, and
// HooksJar, which its manifest puts on the boot class path from the same
// directory.
const (
	AgentJar = "snoopy-agent.jar"
	HooksJar = "snoopy-hooks.jar"
)

// IsHotSpot reports whether process pid has HotSpot's libjvm.so mapped:
// java itself, or a program embedding the JVM.
func IsHotSpot(pid int) (bool, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return false, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if strings.HasSuffix(s.Text(), "/libjvm.so") {
			return true, nil
		}
	}
	return false, s.Err()
}

// Stage copies the agent's jars from dir to where process pid can read
// them, a directory in its /tmp named for their contents, and returns the
// agent jar's path as the process sees it. The files stay: the JVM reads
// them for as long as it runs, and a later snoopy uses them again.
func Stage(pid int, dir string) (string, error) {
	var files [][]byte
	for _, name := range []string{AgentJar, HooksJar} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", fmt.Errorf("the Java agent: %w", err)
		}
		files = append(files, data)
	}
	root, err := openRoot(pid)
	if err != nil {
		return "", err
	}
	defer unix.Close(root)
	path, err := stage(root, files[0], files[1])
	if err != nil {
		return "", fmt.Errorf("stage the Java agent in process %d's /tmp: %w", pid, err)
	}
	return path, nil
}

// stage puts the agent's jars in a directory named for their contents in
// /tmp of the filesystem whose root is root, and returns the agent jar's
// path there.
func stage(root int, agent, hooks []byte) (string, error) {
	h := sha256.New()
	h.Write(agent)
	h.Write(hooks)
	name := ".snoopy-java-" + hex.EncodeToString(h.Sum(nil))[:16]
	tmp, err := openIn(root, "tmp", unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(tmp)
	if err := unix.Mkdirat(tmp, name, 0o755); errors.Is(err, unix.EROFS) {
		return "", errors.New("it's read-only (a container with a read-only root?), and the JVM needs it writable to be attached to too: give it a writable /tmp, such as a tmpfs, or start it with -javaagent")
	} else if err != nil && !errors.Is(err, unix.EEXIST) {
		return "", err
	}
	staged, err := unix.Openat(tmp, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	defer unix.Close(staged)
	// Root's own directory, which only root can write in, not something
	// another user left there. Its mode, and the files', is set rather than
	// left to the umask (often 077 for root), since the JVM's user, whoever
	// that is, reads them.
	var st unix.Stat_t
	if err := unix.Fstat(staged, &st); err != nil || st.Uid != 0 || st.Mode&0o022 != 0 {
		return "", fmt.Errorf("%s isn't root's alone; remove it", name)
	}
	if err := unix.Fchmod(staged, 0o755); err != nil {
		return "", err
	}
	for file, data := range map[string][]byte{AgentJar: agent, HooksJar: hooks} {
		if err := stageFile(staged, file, data); err != nil {
			return "", fmt.Errorf("%s: %w", file, err)
		}
	}
	return "/tmp/" + name + "/" + AgentJar, nil
}

// stageFile puts data in a file named name in the directory dir, unless
// it's there already: written to a new file, then renamed over the name,
// which replaces whatever was there (a symlink included) rather than
// writing through it.
func stageFile(dir int, name string, data []byte) error {
	// What's there already, if it's a regular file (O_NONBLOCK: a FIFO
	// planted there would block opening it).
	if fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0); err == nil {
		var st unix.Stat_t
		regular := unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG
		f := os.NewFile(uintptr(fd), name)
		same := false
		if regular {
			old, err := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
			same = err == nil && bytes.Equal(old, data)
		}
		if same {
			err = unix.Fchmod(fd, 0o644)
		}
		f.Close()
		if same {
			return err
		}
	}
	tmp := name + ".tmp"
	if err := unix.Unlinkat(dir, tmp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	// The rename below replaces anything but a directory there.
	fd, err := createIn(dir, tmp, 0o644)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(data)
	if err == nil {
		err = unix.Fchmod(fd, 0o644)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return unix.Renameat(dir, tmp, dir, name)
}
