package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The processes --serve-exec passes SIGTERM on to, and waits for: those in
// its cgroup, but not itself, nor zombies.
func TestCgroupPeers(t *testing.T) {
	proc := t.TempDir()
	const pod, other = "0::/kubepods/pod1/c1\n", "0::/system.slice/x\n"
	for pid, p := range map[string]struct{ cgroup, stat string }{
		"1":    {pod, "1 (snoopy) S 0"},  // itself
		"7":    {pod, "7 (snoopy) S 1"},  // a snoopy run
		"8":    {pod, "8 (snoopy) Z 1"},  // one that ended, unreaped
		"9":    {pod, "9 (a) b) R 1"},    // a name with ") " in it
		"10":   {other, "10 (sshd) S 1"}, // another cgroup's
		"11":   {pod, ""},                // gone meanwhile
		"self": {pod, "1 (snoopy) S 0"},  // not a PID
	} {
		dir := filepath.Join(proc, pid)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "cgroup"), []byte(p.cgroup), 0o644)
		if p.stat != "" {
			os.WriteFile(filepath.Join(dir, "stat"), []byte(p.stat), 0o644)
		}
	}
	got := cgroupPeers(proc, 1)
	slices.Sort(got)
	if !slices.Equal(got, []int{7, 9}) {
		t.Errorf("got %v, want [7 9]", got)
	}
	if got := cgroupPeers(proc, 99); got != nil {
		t.Errorf("without its own cgroup: %v", got)
	}
}
