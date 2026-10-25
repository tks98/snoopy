package javaagent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A container's root, planting symlinks where snoopy writes, can't get it to
// write or chmod anything outside the container: here, a temporary
// directory stands for the container's root, and another for the host.
func TestStageStaysInRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the staging directory must be root's")
	}
	agent, hooks := []byte("agent jar"), []byte("hooks jar")
	h := sha256.Sum256(append(append([]byte{}, agent...), hooks...))
	name := ".snoopy-java-" + hex.EncodeToString(h[:])[:16]

	host := t.TempDir()
	victim := filepath.Join(host, "victim")
	if err := os.WriteFile(victim, []byte("the host's"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkVictim := func(t *testing.T) {
		t.Helper()
		data, err := os.ReadFile(victim)
		fi, _ := os.Stat(victim)
		if err != nil || string(data) != "the host's" || fi.Mode().Perm() != 0o600 {
			t.Errorf("the host's file was changed: %q, %v", data, fi.Mode())
		}
	}

	t.Run("symlinks in the staging directory", func(t *testing.T) {
		root := t.TempDir()
		staged := filepath.Join(root, "tmp", name)
		if err := os.MkdirAll(staged, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, link := range []string{AgentJar + ".tmp", HooksJar} {
			if err := os.Symlink(victim, filepath.Join(staged, link)); err != nil {
				t.Fatal(err)
			}
		}
		path := stageIn(t, root, agent, hooks)
		checkVictim(t)
		if path != "/tmp/"+name+"/"+AgentJar {
			t.Errorf("path %s", path)
		}
		for file, want := range map[string][]byte{AgentJar: agent, HooksJar: hooks} {
			fi, err := os.Lstat(filepath.Join(staged, file))
			data, _ := os.ReadFile(filepath.Join(staged, file))
			if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 || string(data) != string(want) {
				t.Errorf("%s: %v, %q, %v", file, fi.Mode(), data, err)
			}
		}
	})

	t.Run("a FIFO in the staging directory", func(t *testing.T) {
		root := t.TempDir()
		staged := filepath.Join(root, "tmp", name)
		if err := os.MkdirAll(staged, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(filepath.Join(staged, AgentJar), 0o644); err != nil {
			t.Fatal(err)
		}
		done := make(chan string, 1)
		go func() { done <- stageIn(t, root, agent, hooks) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("staging blocked on a FIFO")
		}
		if fi, err := os.Lstat(filepath.Join(staged, AgentJar)); err != nil || !fi.Mode().IsRegular() {
			t.Errorf("%s: %v, %v", AgentJar, fi.Mode(), err)
		}
	})

	t.Run("/tmp a symlink out", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Symlink(host, filepath.Join(root, "tmp")); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if _, err := stage(fd, agent, hooks); err == nil {
			t.Error("staged, through a /tmp that points at the host")
		}
		if _, err := os.Stat(filepath.Join(host, name)); err == nil {
			t.Errorf("made %s on the host", name)
		}
		checkVictim(t)
	})
}

func stageIn(t *testing.T, root string, agent, hooks []byte) string {
	t.Helper()
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	path, err := stage(fd, agent, hooks)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// The attach file is made, never written through a symlink of that name.
func TestCreateInDoesntFollow(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, ".attach_pid1")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if f, err := createIn(fd, ".attach_pid1", 0o600); !errors.Is(err, unix.EEXIST) {
		if err == nil {
			unix.Close(f)
		}
		t.Errorf("createIn on a symlink: %v", err)
	}
	if data, _ := os.ReadFile(victim); string(data) != "x" {
		t.Errorf("victim: %q", data)
	}
}
