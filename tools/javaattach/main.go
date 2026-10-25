// Command javaattach loads a Java agent into a running HotSpot JVM (the
// Java spike's attach prototype; see docs/plan-java.md):
//
//	javaattach PID AGENT_JAR [OPTIONS]
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/tks98/snoopy/v2/internal/javaagent"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: javaattach PID AGENT_JAR [OPTIONS]")
		os.Exit(2)
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "javaattach:", err)
		os.Exit(2)
	}
	opts := ""
	if len(os.Args) > 3 {
		opts = os.Args[3]
	}
	start := time.Now()
	out, err := javaagent.Load(pid, os.Args[2], opts, 10*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "javaattach:", err)
		os.Exit(1)
	}
	fmt.Printf("loaded in %v: %s\n", time.Since(start).Round(time.Millisecond), out)
}
