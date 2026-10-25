//go:build integration

package tracer

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tks98/snoopy/v2/internal/discover"
)

// privateLibSSL copies the system's libssl into a new directory and returns
// the copy's target.
func privateLibSSL(t *testing.T) discover.Target {
	t.Helper()
	for _, target := range systemTargets(t, discover.OpenSSL) {
		if !strings.HasPrefix(filepath.Base(target.Path), "libssl.so") {
			continue
		}
		lib, err := os.ReadFile(target.Path)
		if err != nil {
			t.Fatal(err)
		}
		target.Path = filepath.Join(t.TempDir(), filepath.Base(target.Path))
		if err := os.WriteFile(target.Path, lib, 0o755); err != nil {
			t.Fatal(err)
		}
		return target
	}
	t.Skip("no system libssl")
	return discover.Target{}
}

// renamedTool copies a program to a new directory under a name of its own,
// so that tracing it by name traces nothing else: another curl running at
// the same time on a shared machine, say.
func renamedTool(t *testing.T, name, as string) string {
	t.Helper()
	data, err := os.ReadFile(requireTool(t, name))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), as)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// A library whose mtime changes is new to the Watcher, which tells files
// apart by it, but not attached to again: its calls would show twice.
func TestReattachAfterTouch(t *testing.T) {
	requireRoot(t)
	curl := renamedTool(t, "curl", "fixcurl")
	lib := privateLibSSL(t)
	tr, err := New(Options{Comm: "fixcurl"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.AttachSyscalls(); err != nil {
		t.Fatal(err)
	}
	stop, err := tr.WatchNewProcesses(discover.NewWatcher(nil, false), nil, nil, func(discover.Target, []string, error) {})
	if err != nil {
		t.Fatal(err)
	}
	events := runTracer(t, tr)
	t.Cleanup(stop)
	// Slow to answer, so curl is attached to by then.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		fmt.Fprintf(w, "served %s late", r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	run := func(path string) {
		t.Helper()
		cmd := exec.Command(curl, "-sk", "--http1.1", srv.URL+path)
		cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+filepath.Dir(lib.Path))
		if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "served "+path) {
			t.Fatalf("curl: %v: %s", err, out)
		}
	}
	reads := func(path string) int {
		return events.count(func(ev *Event) bool { return ev.Function == FuncSSLRead && contains("served "+path)(ev) })
	}
	run("/first")
	waitFor(t, events, "the first response", contains("served /first"))
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(lib.Path, later, later); err != nil {
		t.Fatal(err)
	}
	run("/second")
	waitFor(t, events, "the second response", contains("served /second"))
	time.Sleep(time.Second)
	if n := reads("/second"); n != 1 {
		t.Errorf("the second response was seen %d times", n)
	}
}

// openFDs returns how many files the test process has open.
func openFDs(t *testing.T) int {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(fds)
}

// A file attached to for every process is let go of once it's deleted and
// no process maps it, and not before.
func TestDetachUnused(t *testing.T) {
	requireRoot(t)
	python := requireTool(t, "python3")
	lib := privateLibSSL(t)
	tr, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	before := openFDs(t)
	if funcs, err := tr.Attach(lib, 0); err != nil || len(funcs) == 0 {
		t.Fatalf("attach: %v %v", funcs, err)
	}
	attached := func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return len(tr.files) == 1
	}
	if funcs, err := tr.Attach(lib, 0); err != nil || len(funcs) != 0 || !attached() {
		t.Fatalf("attached again: %v %v", funcs, err)
	}
	tr.DetachUnused()
	if !attached() {
		t.Fatal("detached from a file that's there")
	}

	// A process maps it; then it's deleted.
	cmd := exec.Command(python, "-c", `import ctypes, sys; ctypes.CDLL(sys.argv[1]); print("loaded", flush=True); sys.stdin.read()`, lib.Path)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); line != "loaded\n" {
		t.Fatalf("python3: %q", line)
	}
	if err := os.Remove(lib.Path); err != nil {
		t.Fatal(err)
	}
	tr.DetachUnused()
	if !attached() {
		t.Fatal("detached from a deleted file a process maps")
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	tr.DetachUnused()
	if attached() {
		t.Fatal("still attached to a deleted file no process maps")
	}
	tr.closing.Wait()
	if after := openFDs(t); after != before {
		t.Errorf("%d files open before attaching, %d after detaching", before, after)
	}
}

// traced returns whether a process is in traced_tgids.
func traced(tr *Tracer, pid int) bool {
	var v uint8
	return tr.objs.TracedTgids.Lookup(uint32(pid), &v) == nil
}

// A process traced is forgotten when it exits, not when one of its threads
// does.
func TestTracedExit(t *testing.T) {
	requireRoot(t)
	python := requireTool(t, "python3")
	tr, err := New(Options{Comm: "python3", PerProcess: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if !tr.PerProcess() {
		t.Skip("no BTF")
	}
	// It starts a thread, which exits, when told to, and exits itself when
	// its input ends.
	cmd := exec.Command(python, "-c", `
import sys, threading
sys.stdin.readline()
t = threading.Thread(target=lambda: None)
t.start()
t.join()
print("joined", flush=True)
sys.stdin.read()
`)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	pid := cmd.Process.Pid
	if err := tr.TracePID(uint32(pid)); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(stdin)
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); line != "joined\n" {
		t.Fatalf("python3: %q", line)
	}
	if !traced(tr, pid) {
		t.Fatal("forgotten when a thread exited")
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if traced(tr, pid) {
		t.Error("still traced after it exited")
	}

	// One that exited before it was added isn't kept either.
	if err := tr.TracePID(uint32(pid)); err != nil {
		t.Fatal(err)
	}
	if traced(tr, pid) {
		t.Error("traced after it exited")
	}
}

// When traced_tgids is full, Attach still attaches, and says so once.
func TestTracedFull(t *testing.T) {
	requireRoot(t)
	tr, err := New(Options{Comm: "test", PerProcess: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if !tr.PerProcess() {
		t.Skip("no BTF")
	}
	// PIDs no process has: the exit tracepoint never deletes them.
	for i := range tr.objs.TracedTgids.MaxEntries() {
		if err := tr.objs.TracedTgids.Update(uint32(1<<30+i), uint8(1), 0); err != nil {
			t.Fatal(err)
		}
	}
	lib := privateLibSSL(t)
	funcs, err := tr.Attach(lib, os.Getpid())
	if len(funcs) == 0 || err == nil {
		t.Fatalf("attach: %v %v, want functions and an error", funcs, err)
	}
	if err := tr.TracePID(uint32(os.Getppid())); err != nil {
		t.Errorf("said again: %v", err)
	}
}

// Java sessions end when their processes exit.
func TestJavaSessionExit(t *testing.T) {
	requireRoot(t)
	tr, err := New(Options{Java: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	cmd := exec.Command("sleep", "0.5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(cmd.Process.Pid)
	if err := tr.RegisterJava(pid, 1); err != nil {
		t.Fatal(err)
	}
	var s snoopyJavaSession
	if err := tr.objs.JavaSessions.Lookup(pid, &s); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := tr.objs.JavaSessions.Lookup(pid, &s); err == nil {
		t.Error("the session is still there after the process exited")
	}

	// Without Options.Java, there are none.
	plain, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if err := plain.RegisterJava(pid, 1); err == nil {
		t.Error("registered a Java session without Options.Java")
	}
}

// Node.js's OpenSSL reads a file inside SSL_write; that file's descriptor
// isn't taken for the connection's socket, whose number another socket can
// have later. Node.js does its own socket I/O, so its events have no
// socket, or with BTF, the right one. (Without, the addresses are looked up
// in /proc later, which only works for an fd that's the right socket.)
func TestNodeAddresses(t *testing.T) {
	requireRoot(t)
	node := renamedTool(t, "node", "fixnode")
	for _, noBTF := range []bool{false, true} {
		t.Run(fmt.Sprintf("without BTF %v", noBTF), func(t *testing.T) {
			events := startTracer(t, Options{Comm: "fixnode", ignoreKernelBTF: noBTF}, systemTargets(t, discover.OpenSSL))
			srv, _ := newServer(t)
			// Then another connection, whose socket gets the descriptor
			// numbers that came free.
			other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			defer other.Close()
			script := `
const https = require('https');
const get = (url, then) => https.get(url, {rejectUnauthorized: false}, r => { r.resume(); r.on('end', then); })
	.on('error', e => { console.error(e); process.exit(1); });
get(process.argv[1] + '/node', () => get(process.argv[2] + '/other', () => setTimeout(() => process.exit(0), 500)));
`
			if out, err := exec.Command(node, "-e", script, srv.URL, other.URL).CombinedOutput(); err != nil {
				t.Fatalf("node: %v: %s", err, out)
			}
			w := waitFor(t, events, "the request", func(ev *Event) bool { return ev.Function.Direction() == Write && contains("GET /node")(ev) })
			r := waitFor(t, events, "the response", func(ev *Event) bool { return contains("served /node")(ev) })
			for _, ev := range []*Event{w, r} {
				t.Logf("%s fd %d, %s -> %s", ev.Function, ev.FD, ev.Local, ev.Remote)
				switch {
				case noBTF && ev.FD >= 0:
					t.Errorf("%s: fd %d", ev.Function, ev.FD)
				case ev.FD >= 0 || ev.Remote.IsValid():
					checkConnection(t, ev, srv.Listener.Addr().String())
				}
			}
		})
	}
}
