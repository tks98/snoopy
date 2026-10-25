package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tks98/snoopy/v2/internal/javaagent"
	"github.com/tks98/snoopy/v2/internal/procinfo"
	"github.com/tks98/snoopy/v2/internal/tracer"
)

const (
	// javaReadyTimeout is how long the agent has to say it's ready once
	// loaded.
	javaReadyTimeout = 5 * time.Second
	// javaScanInterval is how often the --container containers are looked
	// in for JVMs that started since.
	javaScanInterval = 3 * time.Second
	// javaStartupGrace is how long a JVM found that way can't be attached to
	// before snoopy says so: one that just started may not be ready.
	javaStartupGrace = 30 * time.Second
)

// javaLoader loads snoopy's Java agent into the JVMs --java is for: the
// --pid one, or those in the --container containers, now and as they
// start. Each gets a session registered for its frames first.
type javaLoader struct {
	cfg      config
	t        *tracer.Tracer
	dir      string // the agent's jars
	resolver *procinfo.Resolver

	mu       sync.Mutex
	loaded   map[jvmKey]string    // the agent's path as each JVM sees it
	failing  map[jvmKey]time.Time // first failure of JVMs not loaded yet
	reported map[jvmKey]bool
}

// jvmKey is a process, told apart from a later one with its PID.
type jvmKey struct {
	pid   int
	start string
}

// startJava loads the agent into the JVMs --java is for, and returns what
// stops it: each agent is told to stop capturing (it can't be unloaded) and
// its session goes. With --pid, a JVM that can't have the agent is an
// error; with --container, a warning.
func startJava(ctx context.Context, cfg config, t *tracer.Tracer) (stop func(), err error) {
	dir, err := javaAgentDir(cfg.javaAgent)
	if err != nil {
		return nil, err
	}
	l := &javaLoader{cfg: cfg, t: t, dir: dir, resolver: procinfo.NewResolver("/proc"),
		loaded: map[jvmKey]string{}, failing: map[jvmKey]time.Time{}, reported: map[jvmKey]bool{}}
	if cfg.pid != 0 {
		if err := l.load(cfg.pid); err != nil {
			return nil, err
		}
		return l.stop, nil
	}
	if l.scan() == 0 {
		logf("--java: no JVM in the containers yet; loading the agent into them as they start")
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(javaScanInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				l.scan()
			}
		}
	}()
	return func() {
		cancel()
		<-done
		l.stop()
	}, nil
}

// scan loads the agent into the JVMs in the --container containers that
// don't have it, and returns how many JVMs have it.
func (l *javaLoader) scan() int {
	dirs, _ := os.ReadDir("/proc")
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		key, ok := processKey(pid)
		if !ok || l.has(key) {
			continue
		}
		id := l.resolver.ContainerID(uint32(pid))
		if _, ok := l.cfg.containers.match(id); !ok || id == "" {
			continue
		}
		if ok, _ := javaagent.IsHotSpot(pid); !ok {
			continue
		}
		if err := l.load(pid); err != nil {
			l.failed(key, err)
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.loaded)
}

func (l *javaLoader) has(key jvmKey) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.loaded[key]
	return ok
}

// failed notes that a JVM couldn't have the agent, and says so once it's
// been failing for javaStartupGrace: one that just started may not be
// ready to be attached to.
func (l *javaLoader) failed(key jvmKey, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	first, seen := l.failing[key]
	if !seen {
		first = time.Now()
		l.failing[key] = first
	}
	if !l.reported[key] && time.Since(first) >= javaStartupGrace {
		l.reported[key] = true
		logf("warning: %v", err)
	}
}

// load loads the agent into the JVM pid, unless it isn't one.
func (l *javaLoader) load(pid int) error {
	key, ok := processKey(pid)
	if !ok {
		return fmt.Errorf("--java: no process %d", pid)
	}
	if ok, err := javaagent.IsHotSpot(pid); err != nil {
		return fmt.Errorf("--java: %w", err)
	} else if !ok {
		return fmt.Errorf("--java: process %d isn't a HotSpot JVM (it has no libjvm.so)", pid)
	}
	jar, err := javaagent.Stage(pid, l.dir)
	if err != nil {
		return fmt.Errorf("--java: %w", err)
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	nonce := binary.LittleEndian.Uint64(b[:])
	if err := l.t.RegisterJava(uint32(pid), nonce); err != nil {
		return err
	}
	start := time.Now()
	if _, err := javaagent.Load(pid, jar, fmt.Sprintf("nonce=%d,max=%d", nonce, l.cfg.maxSize), 10*time.Second); err != nil {
		l.t.UnregisterJava(uint32(pid))
		return fmt.Errorf("--java: loading the agent into process %d: %w", pid, err)
	}
	for !l.t.JavaReady(uint32(pid)) && time.Since(start) < javaReadyTimeout {
		time.Sleep(20 * time.Millisecond)
	}
	if l.t.JavaReady(uint32(pid)) {
		logf("Java agent loaded into process %d%s in %v; tracing its SSLSocket and SSLEngine calls",
			pid, l.where(pid), time.Since(start).Round(time.Millisecond))
	} else {
		logf("warning: --java: the agent was loaded into process %d, but nothing it captures is seen; its stderr may say why", pid)
	}
	l.mu.Lock()
	l.loaded[key] = jar
	delete(l.failing, key)
	l.mu.Unlock()
	return nil
}

// where names the container a JVM is in, as --container did.
func (l *javaLoader) where(pid int) string {
	id := l.resolver.ContainerID(uint32(pid))
	if id == "" {
		return ""
	}
	if name, _ := l.cfg.containers.match(id); name != "" {
		return " (" + name + ")"
	}
	return " (container " + id[:min(len(id), 12)] + ")"
}

// stop tells each agent to stop capturing, and drops its session.
func (l *javaLoader) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, jar := range l.loaded {
		if k, ok := processKey(key.pid); ok && k == key { // not gone
			if _, err := javaagent.Load(key.pid, jar, "disable", 5*time.Second); err != nil && !errors.Is(err, os.ErrNotExist) {
				logf("warning: --java: couldn't tell the agent in process %d to stop capturing: %v", key.pid, err)
			}
		}
		l.t.UnregisterJava(uint32(key.pid))
	}
}

// processKey returns a process's PID and start time (field 22 of its stat).
func processKey(pid int) (jvmKey, bool) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return jvmKey{}, false
	}
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return jvmKey{}, false
	}
	f := strings.Fields(string(stat[i+1:]))
	if len(f) < 20 {
		return jvmKey{}, false
	}
	return jvmKey{pid, f[19]}, true
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
	return "", fmt.Errorf("--java: snoopy's Java agent (%s and %s) isn't next to snoopy: they're in the release archives and the image, or build them with java/build.sh; then point --java-agent at their directory", javaagent.AgentJar, javaagent.HooksJar)
}
