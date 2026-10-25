package procinfo

import "testing"

func TestParseStat(t *testing.T) {
	line := "42 (a) b (c)) S 7 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 3 0 12345 1000 10 18446744073709551615"
	s, ok := ParseStat([]byte(line))
	if !ok || s.State != 'S' || s.PPID != 7 || s.Threads != 3 || s.Start != 12345 || !s.Complete {
		t.Errorf("%+v, %v", s, ok)
	}
	if s, ok := ParseStat([]byte("9 (z) Z")); !ok || s.State != 'Z' || s.Complete {
		t.Errorf("short: %+v, %v", s, ok)
	}
	for _, bad := range []string{"", "9 (no close", "9 (x)", "9 (x) "} {
		if _, ok := ParseStat([]byte(bad)); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}
