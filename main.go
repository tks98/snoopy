package main

import (
	"log"

	"github.com/tks98/snoopy/internal/util"
	"github.com/tks98/snoopy/pkg/tls_trace"
)

func main() {
	opts := util.ParseCLIOptions()

	sources, err := util.ReadEbpfProgram("bpf/snoopy.c")
	if err != nil {
		log.Fatal(err)
	}

	binaryPath, err := util.GetBinaryPath()
	if err != nil {
		log.Fatal(err)
	}

	tracer := tls_trace.New(opts.JSONOutput, sources, binaryPath, &opts.PID)
	tlsMessages, err := tracer.TraceMessageChannel()
	if err != nil {
		log.Fatalf("Failed to start tls_trace: %s", err)
	}

	for message := range tlsMessages {
		if (opts.PID < 0 || opts.PID == int(message.Pid)) && tls_trace.MessageHasContent(message.Message) {
			message.Print(opts.JSONOutput)
		}
	}

}
