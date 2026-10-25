package main

import (
	"bytes"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// serveExecGrace bounds how long --serve-exec waits for the snoopy runs in
// its pod to end: kubectl snoopy gives its pods 5 s to stop.
const serveExecGrace = 4 * time.Second

// serveExec is snoopy --serve-exec, a hidden flag (not in --help): what
// kubectl snoopy's pods run as their container's process, the image having
// nothing else to wait with. The plugin runs snoopy in the pod through
// pods/exec, whose streams the kubelet doesn't log. It prints nothing and
// waits for SIGTERM or SIGINT (the pod being deleted); then it passes
// SIGTERM on to the other processes in its cgroup, the snoopy runs, waits
// for them to end, for serveExecGrace at most, and returns.
func serveExec() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	<-sig
	self := os.Getpid()
	for _, pid := range cgroupPeers("/proc", self) {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	deadline := time.Now().Add(serveExecGrace)
	for len(cgroupPeers("/proc", self)) > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
}

// cgroupPeers returns the processes in proc (a /proc) that are in the same
// cgroup as process self, but not self, and not zombies: those have ended,
// and only wait to be reaped by a parent that may never do it.
func cgroupPeers(proc string, self int) []int {
	own, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(self), "cgroup"))
	if err != nil {
		return nil
	}
	var pids []int
	dirs, _ := os.ReadDir(proc)
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid == self {
			continue
		}
		dir := filepath.Join(proc, d.Name())
		if cg, err := os.ReadFile(filepath.Join(dir, "cgroup")); err != nil || !bytes.Equal(cg, own) {
			continue
		}
		if zombie(dir) {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

// zombie reports whether the process whose /proc directory is dir has
// exited, or is gone.
func zombie(dir string) bool {
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return true
	}
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 || i+2 >= len(stat) {
		return true
	}
	return stat[i+2] == 'Z' || stat[i+2] == 'X'
}
