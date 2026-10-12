package main

import (
	"errors"
	"flag"
	"io"
	"reflect"
	"testing"

	"github.com/tks98/snoopy/internal/tracer"
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
	for _, args := range [][]string{
		{"--pid", "-1"},
		{"--json", "--hex"},
		{"extra"},
		{"--nope"},
	} {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("%q: no error", args)
		}
	}
}
