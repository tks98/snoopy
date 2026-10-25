package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tks98/snoopy/v2/internal/javaagent"
	"github.com/tks98/snoopy/v2/internal/tracer"
)

// javaReadyTimeout is how long the agent has to say it's ready once loaded.
const javaReadyTimeout = 5 * time.Second

// startJava loads snoopy's Java agent into the --pid JVM, with a session
// registered for its frames first, and returns what stops it: the agent
// is told to stop capturing (it can't be unloaded) and the session goes.
func startJava(cfg config, t *tracer.Tracer) (stop func(), err error) {
	pid := cfg.pid
	if ok, err := javaagent.IsHotSpot(pid); err != nil {
		return nil, fmt.Errorf("--java: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("--java: process %d isn't a HotSpot JVM (it has no libjvm.so)", pid)
	}
	dir, err := javaAgentDir(cfg.javaAgent)
	if err != nil {
		return nil, err
	}
	jar, err := javaagent.Stage(pid, dir)
	if err != nil {
		return nil, fmt.Errorf("--java: %w", err)
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	nonce := binary.LittleEndian.Uint64(b[:])
	if err := t.RegisterJava(uint32(pid), nonce); err != nil {
		return nil, err
	}
	start := time.Now()
	if _, err := javaagent.Load(pid, jar, fmt.Sprintf("nonce=%d,max=%d", nonce, cfg.maxSize), 10*time.Second); err != nil {
		t.UnregisterJava(uint32(pid))
		return nil, fmt.Errorf("--java: loading the agent into process %d: %w", pid, err)
	}
	for !t.JavaReady(uint32(pid)) {
		if time.Since(start) > javaReadyTimeout {
			logf("warning: --java: the agent was loaded into process %d, but nothing it captures is seen; its stderr may say why", pid)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if t.JavaReady(uint32(pid)) {
		logf("Java agent loaded into process %d in %v; tracing its SSLSocket and SSLEngine calls", pid, time.Since(start).Round(time.Millisecond))
	}
	return func() {
		if _, err := javaagent.Load(pid, jar, "disable", 5*time.Second); err != nil && !errors.Is(err, os.ErrNotExist) {
			logf("warning: --java: couldn't tell the agent in process %d to stop capturing: %v", pid, err)
		}
		t.UnregisterJava(uint32(pid))
	}, nil
}

// javaAgentDir finds the agent's jars: in dir if given, else next to
// snoopy's executable, or in java/out beside it (a source tree's build).
func javaAgentDir(dir string) (string, error) {
	if dir != "" {
		return dir, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exeDir := filepath.Dir(exe)
	for _, d := range []string{exeDir, filepath.Join(exeDir, "java", "out"), filepath.Join(exeDir, "..", "share", "snoopy", "java")} {
		if _, err := os.Stat(filepath.Join(d, javaagent.AgentJar)); err == nil {
			return d, nil
		}
	}
	return "", fmt.Errorf("--java: snoopy's Java agent (%s) isn't next to snoopy; build it with java/build.sh and point --java-agent at java/out", javaagent.AgentJar)
}
