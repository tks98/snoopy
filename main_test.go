package main

import (
	"errors"
	"flag"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/tks98/snoopy/v2/internal/discover"
	"github.com/tks98/snoopy/v2/internal/tracer"
)

func TestParseFlags(t *testing.T) {
	c, err := parseFlags([]string{"--json", "--pid", "1337", "--lib", "/a", "--lib", "/b", "-max-size=100"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !c.json || c.pid != 1337 || !reflect.DeepEqual([]string(c.libs), []string{"/a", "/b"}) || c.maxSize != 100 {
		t.Errorf("got %+v", c)
	}

	c, err = parseFlags(nil, io.Discard)
	if err != nil || c.maxSize != tracer.DefaultMaxCapture || c.pid != 0 || c.json {
		t.Errorf("defaults: %+v, %v", c, err)
	}

	if _, err := parseFlags([]string{"-h"}, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: %v", err)
	}
	c, err = parseFlags([]string{"--brief", "--host", "example.com", "--host", "10.0.0.0/8", "--port", "443", "--port", "8443", "--count", "5"}, io.Discard)
	if err != nil || !c.brief || len(c.hosts) != 2 || !reflect.DeepEqual([]uint16(c.ports), []uint16{443, 8443}) || c.count != 5 {
		t.Errorf("got %+v, %v", c, err)
	}

	for _, args := range [][]string{
		{"--pid", "-1"},
		{"--json", "--hex"},
		{"--brief", "--json"},
		{"--brief", "--hex"},
		{"--full", "--json"},
		{"--full", "--brief"},
		{"--full", "--hex"},
		{"--port", "0"},
		{"--port", "https"},
		{"--count", "-1"},
		{"--redact", "--hex"},
		{"--redact", "--pcap", "out.pcap"},
		{"extra"},
		{"--nope"},
	} {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("%q: no error", args)
		}
	}
}

// --container takes IDs and prefixes, named or not, repeated or
// comma-separated, and Kubernetes' runtime://ID form.
func TestContainers(t *testing.T) {
	c, err := parseFlags([]string{"--container", "containerd://3F2A=shop/checkout/app,9b1c", "--container", "77=db"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := containerList{{"3f2a", "shop/checkout/app"}, {"9b1c", ""}, {"77", "db"}}
	if !reflect.DeepEqual(c.containers, want) {
		t.Fatalf("got %+v, want %+v", c.containers, want)
	}
	for id, wantName := range map[string]string{"3f2a00": "shop/checkout/app", "9b1cff": "", "7788": "db"} {
		if name, ok := c.containers.match(id); !ok || name != wantName {
			t.Errorf("%s: %q, %v", id, name, ok)
		}
	}
	for _, id := range []string{"abcd", ""} {
		if _, ok := c.containers.match(id); ok {
			t.Errorf("%q matched", id)
		}
	}
	if _, ok := (containerList{}).match(""); !ok {
		t.Error("with no --container, a process outside containers didn't match")
	}
	if _, err := parseFlags([]string{"--container", "=name"}, io.Discard); err == nil {
		t.Error("an empty ID was accepted")
	}
}

// Each flag is in the help text, which is written by hand.
func TestUsage(t *testing.T) {
	var help strings.Builder
	if _, err := parseFlags([]string{"--help"}, &help); !errors.Is(err, flag.ErrHelp) {
		t.Fatal(err)
	}
	if help.String() != usage {
		t.Error("--help doesn't print the help text")
	}
	n := 0
	flags(&config{}, io.Discard).VisitAll(func(f *flag.Flag) {
		n++
		if !strings.Contains(usage, "\n  --"+f.Name+" ") {
			t.Errorf("--%s isn't in the help text", f.Name)
		}
	})
	if m := strings.Count(usage, "\n  --"); m != n {
		t.Errorf("the help text has %d flags, not %d", m, n)
	}
}

func TestAttachSummary(t *testing.T) {
	target := func(lib discover.Library, path string) discover.Target {
		return discover.Target{Library: lib, Path: path}
	}
	for _, tc := range []struct {
		targets []discover.Target
		want    string
	}{
		{[]discover.Target{target(discover.OpenSSL, "/usr/lib/libssl.so.3")}, "the openssl library"},
		{[]discover.Target{
			target(discover.OpenSSL, "/usr/lib/libssl.so.3"),
			target(discover.OpenSSL, "/proc/7/root/usr/lib/libssl.so.1.1"),
			target(discover.NSS, "/usr/lib/libnspr4.so"),
			target(discover.OpenSSL, "/opt/google/chrome/chrome"),
		}, "the openssl and nss libraries, and to the program chrome"},
		{[]discover.Target{
			target(discover.GoTLS, "/a/one"), target(discover.GoTLS, "/a/two"), target(discover.GoTLS, "/a/three"),
			target(discover.GoTLS, "/a/four"), target(discover.GoTLS, "/a/five"), target(discover.GoTLS, "/a/six"),
		}, "the programs one, two, three, four and 2 more"},
	} {
		if got := attachSummary(tc.targets); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

func TestAddrFilter(t *testing.T) {
	ev := func(local, remote string) *tracer.Event {
		e := &tracer.Event{Function: tracer.FuncSSLWrite}
		if local != "" {
			e.Local = netip.MustParseAddrPort(local)
		}
		if remote != "" {
			e.Remote = netip.MustParseAddrPort(remote)
		}
		return e
	}
	f, err := newAddrFilter(config{hosts: stringList{"93.184.216.34", "10.1.0.0/16"}, ports: portList{443}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		local, remote string
		want          bool
	}{
		{"10.0.0.2:51234", "93.184.216.34:443", true},
		{"10.0.0.2:51234", "93.184.216.34:80", false},                  // wrong port
		{"10.0.0.2:51234", "192.0.2.1:443", false},                     // wrong host
		{"10.1.2.3:443", "192.0.2.1:51234", true},                      // a server in the network
		{"[::ffff:10.0.0.2]:5000", "[::ffff:93.184.216.34]:443", true}, // IPv4 in IPv6
		{"0.0.0.0:443", "0.0.0.0:0", false},                            // an unconnected UDP socket
		{"", "", false},                                                // addresses unknown
	} {
		if got := f.match(ev(tc.local, tc.remote)); got != tc.want {
			t.Errorf("%s > %s: %v", tc.local, tc.remote, got)
		}
	}
	if none, _ := newAddrFilter(config{}); !none.match(ev("", "")) {
		t.Error("no filter dropped an event")
	}
	if _, err := newAddrFilter(config{hosts: stringList{"no such host.invalid"}}); err == nil {
		t.Error("unresolvable host accepted")
	}
}
