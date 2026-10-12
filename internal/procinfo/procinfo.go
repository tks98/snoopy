// Package procinfo looks up facts about a traced process in /proc: which
// container it runs in and which addresses its sockets are connected to.
package procinfo

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// maxCacheEntries bounds each cache; when full it is simply reset.
const maxCacheEntries = 4096

// Resolver caches /proc lookups. It is not safe for concurrent use.
type Resolver struct {
	proc       string
	containers map[uint32]string
	sockets    map[sockKey]socket
}

type sockKey struct {
	pid uint32
	fd  int32
}

type socket struct {
	inode         uint64
	local, remote netip.AddrPort
}

// NewResolver returns a Resolver reading from procRoot, normally "/proc".
func NewResolver(procRoot string) *Resolver {
	return &Resolver{
		proc:       procRoot,
		containers: map[uint32]string{},
		sockets:    map[sockKey]socket{},
	}
}

// ContainerID returns the ID of the container a process runs in, or "" if
// it isn't in a recognizable container.
func (r *Resolver) ContainerID(pid uint32) string {
	if id, ok := r.containers[pid]; ok {
		return id
	}
	data, err := os.ReadFile(filepath.Join(r.proc, strconv.Itoa(int(pid)), "cgroup"))
	if err != nil {
		return "" // the process may have exited; don't cache
	}
	id := ContainerIDFromCgroup(string(data))
	if len(r.containers) >= maxCacheEntries {
		clear(r.containers)
	}
	r.containers[pid] = id
	return id
}

// Container runtimes put the 64-hex-digit container ID in the cgroup path,
// e.g. /docker/<id>, /system.slice/docker-<id>.scope,
// /kubepods.slice/.../cri-containerd-<id>.scope or .../libpod-<id>.scope.
var containerIDPattern = regexp.MustCompile(`[0-9a-f]{64}`)

// ContainerIDFromCgroup extracts a container ID from the contents of
// /proc/<pid>/cgroup.
func ContainerIDFromCgroup(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		// hierarchy-ID:controller-list:cgroup-path
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if ids := containerIDPattern.FindAllString(parts[2], -1); len(ids) > 0 {
			return ids[len(ids)-1]
		}
	}
	return ""
}

// Addresses returns the local and remote address of a process's TCP socket.
func (r *Resolver) Addresses(pid uint32, fd int32) (local, remote netip.AddrPort, ok bool) {
	if fd < 0 {
		return local, remote, false
	}
	base := filepath.Join(r.proc, strconv.Itoa(int(pid)))
	target, err := os.Readlink(filepath.Join(base, "fd", strconv.Itoa(int(fd))))
	if err != nil {
		return local, remote, false
	}
	inode, ok := socketInode(target)
	if !ok {
		return local, remote, false
	}

	key := sockKey{pid, fd}
	if s, ok := r.sockets[key]; ok && s.inode == inode {
		return s.local, s.remote, true
	}

	// /proc/<pid>/net shows the process's own network namespace.
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(base, "net", name))
		if err != nil {
			continue
		}
		local, remote, err = FindSocket(f, inode)
		f.Close()
		if err == nil {
			if len(r.sockets) >= maxCacheEntries {
				clear(r.sockets)
			}
			r.sockets[key] = socket{inode, local, remote}
			return local, remote, true
		}
	}
	return local, remote, false
}

// socketInode parses a /proc/<pid>/fd link target like "socket:[12345]".
func socketInode(target string) (uint64, bool) {
	s, ok := strings.CutPrefix(target, "socket:[")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64)
	return n, err == nil
}

var errNotFound = errors.New("socket not found")

// FindSocket looks for the socket with the given inode in the contents of
// /proc/net/tcp or /proc/net/tcp6.
func FindSocket(table io.Reader, inode uint64) (local, remote netip.AddrPort, err error) {
	want := strconv.FormatUint(inode, 10)
	sc := bufio.NewScanner(table)
	for sc.Scan() {
		// sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 || fields[9] != want {
			continue
		}
		if local, err = parseAddr(fields[1]); err != nil {
			return local, remote, err
		}
		if remote, err = parseAddr(fields[2]); err != nil {
			return local, remote, err
		}
		return local, remote, nil
	}
	return local, remote, errNotFound
}

// parseAddr parses an address like "0100007F:20FB". The IP is written as
// 32-bit words in host (little-endian) byte order, the port in plain hex.
func parseAddr(s string) (netip.AddrPort, error) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bad port in %q", s)
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}
