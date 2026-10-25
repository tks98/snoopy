package discover

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A FIFO among a process's files would block snoopy opening it, and with it
// everything waiting for that process to be inspected: it's skipped.
func TestFIFONotOpened(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "libssl.so.3")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	within(t, "openRegular", func() {
		if _, err := openRegular(fifo); !errors.Is(err, errNotRegular) {
			t.Errorf("openRegular: %v", err)
		}
	})
	within(t, "Inspect", func() {
		if _, err := Inspect(fifo); err == nil {
			t.Error("Inspect: no error")
		}
	})

	// A process with it in LD_PRELOAD: the dynamic loader blocks opening it,
	// which keeps the process there to be looked at.
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(sleep, "30")
	cmd.Env = append(os.Environ(), "LD_PRELOAD="+fifo)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	time.Sleep(100 * time.Millisecond)
	within(t, "Needed", func() { NewWatcher(nil, true).Needed(cmd.Process.Pid) })
}

func within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s blocked", what)
	}
}
