package javaagent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	h := sha256.New()
	files := map[string][]byte{}
	for _, name := range []string{AgentJar, HooksJar} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", fmt.Errorf("the Java agent: %w", err)
		}
		files[name] = data
		h.Write(data)
	}
	p, err := inspect(pid)
	if err != nil {
		return "", err
	}
	inTarget := "/tmp/.snoopy-java-" + hex.EncodeToString(h.Sum(nil))[:16]
	staged := filepath.Join(p.root, inTarget)
	if err := os.Mkdir(staged, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("stage the Java agent in process %d's /tmp: %w", pid, err)
	}
	// Root's own directory, which only root can write in: not a link or
	// something another user left there, since root writes in it.
	if fi, err := os.Lstat(staged); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("stage the Java agent: %s isn't a directory", staged)
	} else if uid, ok := statOwner(fi); !ok || uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("stage the Java agent: %s isn't root's alone; remove it", staged)
	}
	for name, data := range files {
		path := filepath.Join(staged, name)
		if old, err := os.ReadFile(path); err == nil && string(old) == string(data) {
			continue
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return "", fmt.Errorf("stage the Java agent: %w", err)
		}
		if err := os.Rename(tmp, path); err != nil {
			return "", fmt.Errorf("stage the Java agent: %w", err)
		}
	}
	return filepath.Join(inTarget, AgentJar), nil
}
