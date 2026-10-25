package procinfo

import (
	"bytes"
	"strconv"
	"strings"
)

// Stat is what snoopy reads from /proc/<pid>/stat.
type Stat struct {
	State   byte   // field 3: R, S, D, t, Z, X...
	PPID    int    // field 4
	Threads int    // field 20, num_threads
	Start   uint64 // field 22, starttime: with the PID, a process's identity
	// Complete is set if the fields up to Start were there.
	Complete bool
}

// ParseStat parses the contents of /proc/<pid>/stat: "pid (comm) state
// ppid ...", where comm may contain anything, spaces and parentheses
// included, so the fields are counted from its last ")". It reports false if
// there's not even a state.
func ParseStat(data []byte) (Stat, bool) {
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return Stat{}, false
	}
	f := strings.Fields(string(data[i+1:]))
	if len(f) == 0 || len(f[0]) != 1 {
		return Stat{}, false
	}
	s := Stat{State: f[0][0]}
	if len(f) > 1 {
		s.PPID, _ = strconv.Atoi(f[1])
	}
	if len(f) > 17 {
		s.Threads, _ = strconv.Atoi(f[17])
	}
	if len(f) > 19 {
		start, err := strconv.ParseUint(f[19], 10, 64)
		s.Start, s.Complete = start, err == nil
	}
	return s, true
}
