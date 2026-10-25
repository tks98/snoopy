package javaagent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// TestMain makes the test binary, run with fakeJVMEnv set, a process that
// handles SIGQUIT, as a JVM does, and says when it gets one, without
// starting an attach listener.
func TestMain(m *testing.M) {
	if os.Getenv(fakeJVMEnv) != "" {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGQUIT)
		fmt.Println("ready")
		for range quit {
			fmt.Println("quit")
		}
		return
	}
	os.Exit(m.Run())
}

const fakeJVMEnv = "SNOOPY_TEST_FAKE_JVM"

func startFakeJVM(t *testing.T) (*exec.Cmd, *bufio.Scanner) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), fakeJVMEnv+"=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	lines := bufio.NewScanner(out)
	if !lines.Scan() || lines.Text() != "ready" {
		t.Fatalf("the fake JVM didn't start: %q", lines.Text())
	}
	return cmd, lines
}

// Loading gives up as soon as it's cancelled: before signalling the JVM, it
// doesn't; while waiting for its listener, it stops. Either way the attach
// file goes.
func TestLoadCancelled(t *testing.T) {
	if _, err := os.Stat("/tmp"); err != nil {
		t.Skip(err)
	}
	cmd, lines := startFakeJVM(t)
	pid := cmd.Process.Pid
	attachFile := fmt.Sprintf("/tmp/.attach_pid%d", pid)
	quits := make(chan string, 8)
	go func() {
		for lines.Scan() {
			quits <- lines.Text()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LoadContext(ctx, pid, "/nonexistent.jar", ""); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled before: %v", err)
	}
	select {
	case s := <-quits:
		t.Errorf("signalled though cancelled before: %q", s)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := os.Lstat(attachFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("attach file left: %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	_, err := LoadContext(ctx, pid, "/nonexistent.jar", "")
	if !errors.Is(err, context.Canceled) || time.Since(start) > 2*time.Second {
		t.Errorf("cancelled while waiting: %v after %v", err, time.Since(start))
	}
	select {
	case <-quits:
	case <-time.After(time.Second):
		t.Error("not signalled")
	}
	if _, err := os.Lstat(attachFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("attach file left: %v", err)
	}

	// A JVM that hasn't taken the signal yet keeps the file, so that it
	// starts its listener when it does, rather than printing a thread dump.
	if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(attachFile) })
	ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := LoadContext(ctx, pid, "/nonexistent.jar", ""); err == nil {
		t.Error("loaded into a stopped process")
	}
	if _, err := os.Lstat(attachFile); err != nil {
		t.Errorf("attach file of a process with SIGQUIT pending: %v", err)
	}
	_ = cmd.Process.Signal(syscall.SIGCONT)
	select {
	case <-quits:
	case <-time.After(time.Second):
		t.Error("not signalled")
	}
}
