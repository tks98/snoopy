// Package javaagent loads snoopy's Java agent into a running HotSpot JVM,
// through its attach mechanism, without a JDK on the tracing side.
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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return LoadContext(ctx, pid, jar, options)
}

// LoadContext is Load, until ctx is done: then it stops waiting for the
// JVM and returns ctx's error, and a JVM it hasn't signalled yet isn't.
// Without a deadline in ctx, it waits 10 s at most.
func LoadContext(ctx context.Context, pid int, jar, options string) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	// The process, held onto: a signal goes to it, not to one that took its
	// PID.
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return "", fmt.Errorf("process %d: %w", pid, err)
	}
	defer unix.Close(pidfd)
	p, err := inspect(pid)
	if err != nil {
		return "", err
	}
	root, err := openRoot(pid)
	if err != nil {
		return "", err
	}
	defer unix.Close(root)
	name := fmt.Sprintf("tmp/.java_pid%d", p.nsPID)
	sock, err := openSocket(root, name)
	if err != nil {
		if sock, err = p.trigger(ctx, pidfd, root, name); err != nil {
			return "", err
		}
	}
	defer unix.Close(sock)
	// The JVM is the same process still, not one that took its PID.
	if q, err := inspect(pid); err != nil || q.start != p.start {
		return "", fmt.Errorf("process %d went away while attaching", pid)
	}
	arg := jar
	if options != "" {
		arg += "=" + options
	}
	return request(ctx, p, sock, "load", "instrument", "false", arg)
}

// defaultTimeout bounds LoadContext given a context without a deadline.
const defaultTimeout = 10 * time.Second

type process struct {
	pid, nsPID  int
	uid, gid    int
	start       string // field 22 of /proc/<pid>/stat, against PID reuse
	catchesQuit bool
}

func inspect(pid int) (*process, error) {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	p := &process{pid: pid, nsPID: pid}
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

// trigger asks the JVM to start listening on its attach socket, name in
// its root: it creates the attach file, owned by the JVM's user, and sends
// SIGQUIT, which a JVM that doesn't handle it (-Xrs) would die of. It
// returns the socket, as openSocket does.
func (p *process) trigger(ctx context.Context, pidfd, root int, name string) (int, error) {
	if !p.catchesQuit {
		return -1, fmt.Errorf("process %d doesn't handle SIGQUIT, so it isn't a JVM that can be attached to", p.pid)
	}
	// A JVM that doesn't attach answers SIGQUIT with a thread dump on its
	// stdout: not worth causing to find out.
	if attachDisabled(p.pid) {
		return -1, fmt.Errorf("process %d runs with -XX:+DisableAttachMechanism, so no agent can be loaded into it; start it without that option to trace it with --java", p.pid)
	}
	// In its /tmp, which the JVM looks in after its working directory: made
	// there, not somewhere a symlink points, and given to its user through
	// the file itself. Not in its working directory, which might be one its
	// user can't write in (/etc, say), but root can.
	file := fmt.Sprintf(".attach_pid%d", p.nsPID)
	tmp, err := openIn(root, "tmp", unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, fmt.Errorf("process %d's /tmp: %w", p.pid, err)
	}
	defer unix.Close(tmp)
	signalled := false
	switch fd, err := createIn(tmp, file, 0o600); {
	case errors.Is(err, unix.EEXIST):
		// Someone's, perhaps a JDK tool's: the JVM looks for it all the same.
	case err != nil:
		return -1, fmt.Errorf("can't create %s in process %d's /tmp: %w", file, p.pid, err)
	default:
		_ = unix.Fchown(fd, p.uid, p.gid)
		unix.Close(fd)
		defer func() {
			// Once the JVM has seen it: one signalled that finds it gone
			// prints a thread dump instead. So when this gives up early,
			// the JVM is given a moment, and if it hasn't taken the signal
			// even then (it's stopped, say), the file stays, for it to
			// start its listener when it does.
			if signalled && ctx.Err() != nil {
				time.Sleep(quitGrace)
				if quitPending(p.pid) {
					return
				}
			}
			_ = unix.Unlinkat(tmp, file, 0)
		}()
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	if err := unix.PidfdSendSignal(pidfd, unix.SIGQUIT, nil, 0); err != nil {
		return -1, fmt.Errorf("process %d: %w", p.pid, err)
	}
	signalled = true
	for wait := 20 * time.Millisecond; ; wait = min(2*wait, 500*time.Millisecond) {
		if sock, err := openSocket(root, name); err == nil {
			return sock, nil
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return -1, fmt.Errorf("process %d didn't start its attach listener (is attaching disabled, -XX:+DisableAttachMechanism?)", p.pid)
			}
			return -1, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// quitPending reports whether process pid has a SIGQUIT pending: sent, and
// not yet taken by any of its threads.
func quitPending(pid int) bool {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "ShdPnd:"); ok {
			mask, _ := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return mask&(1<<(syscall.SIGQUIT-1)) != 0
		}
	}
	return false
}

// quitGrace is how long a JVM signalled to attach has to find the attach
// file before it's removed, when attaching is given up on before it
// answered.
const quitGrace = 200 * time.Millisecond

// openSocket returns an O_PATH descriptor for the socket at name in the
// filesystem whose root is root, or an error if there's none.
func openSocket(root int, name string) (int, error) {
	fd, err := openIn(root, name, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		unix.Close(fd)
		return -1, fmt.Errorf("%s isn't a socket", name)
	}
	return fd, nil
}

// request sends a command with its arguments, and returns the output of a
// command that succeeded.
func request(ctx context.Context, p *process, sock int, cmd string, args ...string) (string, error) {
	c, err := dialAs(sock, p.uid, p.gid)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	// Cancelling stops the wait for the answer.
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
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
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", fmt.Errorf("attach listener: %w", err)
	}
	out, _ := io.ReadAll(r)
	code, err := strconv.Atoi(strings.TrimSpace(status))
	if err != nil {
		return "", fmt.Errorf("attach listener answered %s", quote(status))
	}
	msg := strings.TrimSpace(string(out))
	if code != 0 {
		return msg, fmt.Errorf("%s failed (%d): %s", cmd, code, quote(msg))
	}
	// load's own result: the agent's, where it failed.
	if rc, ok := strings.CutPrefix(msg, "return code: "); ok && strings.TrimSpace(rc) != "0" {
		return msg, fmt.Errorf("%s failed: %s", cmd, quote(msg))
	}
	return msg, nil
}

// quote makes what a process said fit to show: quoted, so it can't carry
// terminal escapes, and not too long.
func quote(s string) string {
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return strconv.Quote(s)
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

// dialAs connects to the JVM's attach socket, sock (an O_PATH descriptor),
// as the JVM's user, uid and gid as the host sees them: the listener takes
// connections from its own user (and, in some versions, root), as the
// kernel shows them in its user namespace, where root may be no one
// (rootless containers).
//
// The socket is connected to through /proc/self/fd, for a JVM that isn't
// root's on a thread whose effective IDs are set to the JVM's: setresuid
// and setresgid as raw syscalls change only the calling thread, unlike Go's
// own, which change every one. The thread isn't given back to the runtime
// (the goroutine exits locked to it), so nothing else runs with its IDs.
func dialAs(sock, uid, gid int) (net.Conn, error) {
	path := fmt.Sprintf("/proc/self/fd/%d", sock)
	if uid == 0 {
		return net.Dial("unix", path)
	}
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
		c, err := net.Dial("unix", path)
		done <- result{c, err}
	}()
	r := <-done
	return r.c, r.err
}
