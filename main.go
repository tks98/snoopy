package main

import (
	"log"
	"os"

	"github.com/tks98/snoopy/internal/util"
	"github.com/tks98/snoopy/pkg/tls_trace"
)

func main() {

	// Check if the user is running with root privileges
	if os.Geteuid() != 0 {
		log.Fatal("snoopy must be run as root!")
	}
	// Parse and command line options
	opts := util.ParseCLIOptions()

	// Read BPF program from source file
	sources, err := util.ReadEbpfProgram("bpf/snoopy.c")
	if err != nil {
		log.Fatal(err)
	}

	// Obtain libssl binary path for Uprobes
	binaryPath, err := util.GetBinaryPath()
	if err != nil {
		log.Fatal(err)
	}

	// Create new TLS tracer with parsed options
	tracer := tls_trace.New(opts.JSONOutput, sources, binaryPath, &opts.PID)

	// Start tracing by obtaining the message channel
	tlsMessages, err := tracer.TraceMessageChannel()
	if err != nil {
		log.Fatalf("Failed to start tls_trace: %s", err)
	}

	// Loop over messages from the TLS tracer
	for message := range tlsMessages {
		// If PID was provided and equals the message Pid, or if no PID was provided
		// and the message has content, print the message.
		if (opts.PID < 0 || opts.PID == int(message.Pid)) && message.HasContent() {
			message.Print(opts.JSONOutput)
		}
	}
}
