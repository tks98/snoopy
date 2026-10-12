package procinfo

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const id = "4b825dc642cb6eb9a060e54bf8d69288fbee49040ae1a7ccd4b9e1a2f1c3d5e7"

func TestContainerIDFromCgroup(t *testing.T) {
	for name, tc := range map[string]struct{ cgroup, want string }{
		"docker cgroup v1": {"12:pids:/docker/" + id + "\n11:memory:/docker/" + id + "\n", id},
		"docker systemd":   {"0::/system.slice/docker-" + id + ".scope\n", id},
		"containerd k8s":   {"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234_5678.slice/cri-containerd-" + id + ".scope\n", id},
		"cri-o":            {"0::/kubepods.slice/kubepods-pod1.slice/crio-" + id + ".scope\n", id},
		"podman":           {"0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + id + ".scope/container\n", id},
		"host process":     {"0::/user.slice/user-1000.slice/session-2.scope\n", ""},
		"empty":            {"", ""},
	} {
		if got := ContainerIDFromCgroup(tc.cgroup); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

const tcp4 = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:20FC 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0
   1: 0200000A:C822 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2222 1 0000000000000000 20 4 30 10 -1
`

const tcp6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: B80D0120000000000000000001000000:9C40 0000000000000000FFFF00000702A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 3333 1 0000000000000000 20 4 0 10 -1
`

func TestFindSocket(t *testing.T) {
	local, remote, err := FindSocket(strings.NewReader(tcp4), 2222)
	if err != nil {
		t.Fatal(err)
	}
	if local != netip.MustParseAddrPort("10.0.0.2:51234") || remote != netip.MustParseAddrPort("93.184.216.34:443") {
		t.Errorf("IPv4: got %s -> %s", local, remote)
	}

	local, remote, err = FindSocket(strings.NewReader(tcp6), 3333)
	if err != nil {
		t.Fatal(err)
	}
	if local != netip.MustParseAddrPort("[2001:db8::1]:40000") || remote != netip.MustParseAddrPort("192.168.2.7:443") {
		t.Errorf("IPv6: got %s -> %s", local, remote)
	}

	if _, _, err := FindSocket(strings.NewReader(tcp4), 9999); err == nil {
		t.Error("found a socket that isn't there")
	}
}

// fakeProc builds a minimal /proc for pid 42 with a socket on fd 5.
func fakeProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	pid := filepath.Join(root, "42")
	for _, dir := range []string{"fd", "net"} {
		if err := os.MkdirAll(filepath.Join(pid, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Symlink("socket:[2222]", filepath.Join(pid, "fd", "5")))
	must(os.Symlink("/dev/null", filepath.Join(pid, "fd", "6")))
	must(os.WriteFile(filepath.Join(pid, "net", "tcp"), []byte(tcp4), 0o644))
	must(os.WriteFile(filepath.Join(pid, "net", "tcp6"), []byte(tcp6), 0o644))
	must(os.WriteFile(filepath.Join(pid, "cgroup"), []byte("0::/system.slice/docker-"+id+".scope\n"), 0o644))
	return root
}

func TestResolver(t *testing.T) {
	r := NewResolver(fakeProc(t))

	local, remote, ok := r.Addresses(42, 5)
	if !ok || local != netip.MustParseAddrPort("10.0.0.2:51234") || remote != netip.MustParseAddrPort("93.184.216.34:443") {
		t.Errorf("got %s -> %s, %v", local, remote, ok)
	}
	for _, tc := range []struct {
		pid uint32
		fd  int32
	}{{42, 6}, {42, 7}, {42, -1}, {43, 5}} {
		if _, _, ok := r.Addresses(tc.pid, tc.fd); ok {
			t.Errorf("pid %d fd %d: resolved", tc.pid, tc.fd)
		}
	}

	if got := r.ContainerID(42); got != id {
		t.Errorf("container ID %q", got)
	}
	if got := r.ContainerID(43); got != "" {
		t.Errorf("container ID for missing process: %q", got)
	}
}
