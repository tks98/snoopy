// Package javaagent loads snoopy's Java agent into a running HotSpot JVM,
// through its attach mechanism, without a JDK on the tracing side (spike;
// see docs/plan-java.md).
//
// The attach mechanism, as OpenJDK's Linux client uses it: the JVM listens
// on a Unix socket, /tmp/.java_pid<pid> in its own mount and PID
// namespaces, once it finds a file named .attach_pid<pid> in its working
// directory (or /tmp) on a SIGQUIT. A request is a protocol version, a
// command and three arguments, each NUL-terminated; "load instrument false
// <jar>=<options>" loads a java.lang.instrument agent. The JVM answers with
// a status line and the command's output.
package javaagent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Load loads the agent jar into process pid, passing it options, and
// returns the JVM's answer. jar is a path as the JVM sees it.
func Load(pid int, jar, options string, timeout time.Duration) (string, error) {
	p, err := inspect(pid)
	if err != nil {
		return "", err
	}
	deadline := time.Now().Add(timeout)
	sock := filepath.Join(p.root, "tmp", fmt.Sprintf(".java_pid%d", p.nsPID))
	if !isSocket(sock) {
		if err := p.trigger(sock, deadline); err != nil {
			return "", err
		}
	}
	// The JVM is the same process still, not one that took its PID.
	if q, err := inspect(pid); err != nil || q.start != p.start {
		return "", fmt.Errorf("process %d went away while attaching", pid)
	}
	arg := jar
	if options != "" {
		arg += "=" + options
	}
	return request(p, sock, deadline, "load", "instrument", "false", arg)
}

type process struct {
	pid, nsPID  int
	root, cwd   string
	uid, gid    int
	start       string // field 22 of /proc/<pid>/stat, against PID reuse
	catchesQuit bool
}

func inspect(pid int) (*process, error) {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	p := &process{pid: pid, nsPID: pid, root: fmt.Sprintf("/proc/%d/root", pid), cwd: fmt.Sprintf("/proc/%d/cwd", pid)}
	for _, line := range strings.Split(string(status), "\n") {
		k, v, _ := strings.Cut(line, ":")
		f := strings.Fields(v)
		switch {
		case k == "NSpid" && len(f) > 0:
			// The PID in the process's own namespace, which names the files.
			p.nsPID, _ = strconv.Atoi(f[len(f)-1])
		case k == "Uid" && len(f) > 1:
			p.uid, _ = strconv.Atoi(f[1]) // effective
		case k == "Gid" && len(f) > 1:
			p.gid, _ = strconv.Atoi(f[1])
		case k == "SigCgt" && len(f) > 0:
			mask, _ := strconv.ParseUint(f[0], 16, 64)
			p.catchesQuit = mask&(1<<(syscall.SIGQUIT-1)) != 0
		}
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil, err
	}
	if i := bytes.LastIndexByte(stat, ')'); i >= 0 {
		if f := strings.Fields(string(stat[i+1:])); len(f) > 19 {
			p.start = f[19]
		}
	}
	return p, nil
}

// trigger asks the JVM to start listening on sock: it creates the attach
// file, owned by the JVM's user, and sends SIGQUIT, which a JVM that
// doesn't handle it (-Xrs) would die of.
func (p *process) trigger(sock string, deadline time.Time) error {
	if !p.catchesQuit {
		return fmt.Errorf("process %d doesn't handle SIGQUIT, so it isn't a JVM that can be attached to", p.pid)
	}
	// A JVM that doesn't attach answers SIGQUIT with a thread dump on its
	// stdout: not worth causing to find out.
	if attachDisabled(p.pid) {
		return fmt.Errorf("process %d runs with -XX:+DisableAttachMechanism, so no agent can be loaded into it; start it with -javaagent instead", p.pid)
	}
	name := fmt.Sprintf(".attach_pid%d", p.nsPID)
	var file string
	for _, dir := range []string{p.cwd, filepath.Join(p.root, "tmp")} {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, os.ErrExist) {
			file = filepath.Join(dir, name)
			break
		}
		if err == nil {
			f.Close()
			file = filepath.Join(dir, name)
			_ = os.Chown(file, p.uid, p.gid)
			defer os.Remove(file)
			break
		}
	}
	if file == "" {
		return fmt.Errorf("can't create %s in process %d's working directory or /tmp", name, p.pid)
	}
	if err := syscall.Kill(p.pid, syscall.SIGQUIT); err != nil {
		return err
	}
	for wait := 20 * time.Millisecond; !isSocket(sock); wait = min(2*wait, 500*time.Millisecond) {
		if time.Now().After(deadline) {
			return fmt.Errorf("process %d didn't start its attach listener (is attaching disabled, -XX:+DisableAttachMechanism?)", p.pid)
		}
		time.Sleep(wait)
	}
	return nil
}

func isSocket(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// request sends a command with its arguments, and returns the output of a
// command that succeeded.
func request(p *process, sock string, deadline time.Time, cmd string, args ...string) (string, error) {
	c, err := dialAs(sock, p.uid, p.gid)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(deadline)
	var req bytes.Buffer
	for _, s := range append([]string{"1", cmd}, append(args, "", "", "")[:3]...) {
		req.WriteString(s)
		req.WriteByte(0)
	}
	if _, err := c.Write(req.Bytes()); err != nil {
		return "", err
	}
	r := bufio.NewReader(io.LimitReader(c, 1<<20))
	status, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("attach listener: %w", err)
	}
	out, _ := io.ReadAll(r)
	code, err := strconv.Atoi(strings.TrimSpace(status))
	if err != nil {
		return "", fmt.Errorf("attach listener answered %q", status)
	}
	msg := strings.TrimSpace(string(out))
	if code != 0 {
		return msg, fmt.Errorf("%s failed (%d): %s", cmd, code, msg)
	}
	// load's own result: the agent's, where it failed.
	if rc, ok := strings.CutPrefix(msg, "return code: "); ok && strings.TrimSpace(rc) != "0" {
		return msg, fmt.Errorf("%s failed: %s", cmd, msg)
	}
	return msg, nil
}

func statOwner(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// attachDisabled reports whether a JVM was started with attaching turned
// off, on its command line or in the variables the java launcher and the
// JVM read options from.
func attachDisabled(pid int) bool {
	disabled := false
	scan := func(file, prefix string) {
		data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, file))
		for _, arg := range bytes.Split(data, []byte{0}) {
			s, ok := strings.CutPrefix(string(arg), prefix)
			if !ok {
				continue
			}
			for _, opt := range strings.Fields(s) {
				switch opt {
				case "-XX:+DisableAttachMechanism":
					disabled = true
				case "-XX:-DisableAttachMechanism":
					disabled = false
				}
			}
		}
	}
	// JAVA_TOOL_OPTIONS and JDK_JAVA_OPTIONS come before the command line.
	scan("environ", "JAVA_TOOL_OPTIONS=")
	scan("environ", "JDK_JAVA_OPTIONS=")
	scan("cmdline", "")
	return disabled
}

// dialAs connects to the JVM's attach socket as the JVM's user, uid and gid
// as the host sees them: the listener takes connections from its own user
// (and, in some versions, root), as the kernel shows them in its user
// namespace, where root may be no one (rootless containers).
//
// The socket is opened as root, and connected to through /proc/self/fd on a
// thread whose effective IDs are set to the JVM's: setresuid and setresgid
// as raw syscalls change only the calling thread, unlike Go's own, which
// change every one. The thread isn't given back to the runtime (the
// goroutine exits locked to it), so nothing else runs with its IDs.
func dialAs(sock string, uid, gid int) (net.Conn, error) {
	if uid == 0 {
		return net.Dial("unix", sock)
	}
	fd, err := unix.Open(sock, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	type result struct {
		c   net.Conn
		err error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread() // and never unlocked: the thread goes when this does
		if _, _, e := unix.RawSyscall(unix.SYS_SETRESGID, ^uintptr(0), uintptr(gid), ^uintptr(0)); e != 0 {
			done <- result{nil, fmt.Errorf("setresgid: %w", e)}
			return
		}
		if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, ^uintptr(0), uintptr(uid), ^uintptr(0)); e != 0 {
			done <- result{nil, fmt.Errorf("setresuid: %w", e)}
			return
		}
		c, err := net.Dial("unix", fmt.Sprintf("/proc/self/fd/%d", fd))
		done <- result{c, err}
	}()
	r := <-done
	return r.c, r.err
}
