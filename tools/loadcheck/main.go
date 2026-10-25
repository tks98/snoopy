// Command loadcheck loads snoopy's BPF programs as init in a VM, so that
// kernel's verifier checks every one, in the modes that load them
// differently, in the kernel's PID namespace and in a new one, then powers
// the VM off. run.sh runs it under each kernel
// vimto has downloaded; see docs/maintenance.md, "Older kernels".
package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

func main() {
	stage2 := os.Getenv("LOADCHECK_STAGE2") != ""
	for _, m := range []struct{ src, dir, fs string }{
		{"proc", "/proc", "proc"}, {"sysfs", "/sys", "sysfs"}, {"bpf", "/sys/fs/bpf", "bpf"},
	} {
		_ = os.MkdirAll(m.dir, 0o755)
		if err := syscall.Mount(m.src, m.dir, m.fs, 0, ""); err != nil && !stage2 {
			fmt.Printf("LOADCHECK mount %s: %v\n", m.dir, err)
		}
	}
	// cilium/ebpf reads /proc/self/mountinfo once, during package init,
	// before /proc was mounted: start again with it mounted.
	if !stage2 {
		err := syscall.Exec("/init", []string{"/init"}, []string{"LOADCHECK_STAGE2=1"})
		fmt.Printf("LOADCHECK re-exec: %v\n", err)
	}

	var u syscall.Utsname
	_ = syscall.Uname(&u)
	var release []byte
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		release = append(release, byte(c))
	}
	pidns := os.Getenv("LOADCHECK_PIDNS") != ""
	if pidns {
		var st syscall.Stat_t
		_ = syscall.Stat("/proc/self/ns/pid", &st)
		fmt.Printf("LOADCHECK in a PID namespace (inode %#x)\n", st.Ino)
	} else {
		fmt.Printf("LOADCHECK kernel %s\n", release)
	}
	for _, tc := range []struct {
		name string
		opts tracer.Options
	}{
		{"default", tracer.Options{}},
		{"--pid", tracer.Options{PID: 1, PerProcess: true}},
		{"--comm", tracer.Options{Comm: "curl", PerProcess: true}},
		{"--java --pid", tracer.Options{PID: 1, PerProcess: true, Java: true}},
	} {
		t, err := tracer.New(tc.opts)
		if err != nil {
			fmt.Printf("LOADCHECK %s: FAILED: %+v\n", tc.name, err)
			continue
		}
		fmt.Printf("LOADCHECK %s: loaded, BTF %v, per process %v\n", tc.name, t.ResolvesAddresses(), t.PerProcess())
		_ = t.Close()
	}
	if pidns {
		os.Exit(0)
	}
	// Again from a new PID namespace, where the program numbers PIDs as that
	// namespace does: code the verifier otherwise prunes.
	pid, err := syscall.ForkExec("/init", []string{"/init"}, &syscall.ProcAttr{
		Env:   []string{"LOADCHECK_STAGE2=1", "LOADCHECK_PIDNS=1"},
		Files: []uintptr{0, 1, 2},
		Sys:   &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID},
	})
	if err != nil {
		fmt.Printf("LOADCHECK pidns: FAILED: %v\n", err)
	} else {
		var ws syscall.WaitStatus
		_, _ = syscall.Wait4(pid, &ws, 0, nil)
	}
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}
