package util

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/tks98/snoopy/pkg/tls_trace"
)

type CLIOptions struct {
	JSONOutput bool
	PID        int
}

func ParseCLIOptions() CLIOptions {
	var jsonOutput bool
	flag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	pid := flag.Int("pid", -1, "Specify the PID to trace (optional, if not specified, all processes will be traced)")
	flag.Parse()

	return CLIOptions{
		JSONOutput: jsonOutput,
		PID:        *pid,
	}
}

func ReadEbpfProgram(filePath string) (string, error) {
	b, err := os.ReadFile(filePath)
	return string(b), err
}

func GetBinaryPath() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return tls_trace.LibSSLSoPathAMd64, nil
	case "arm64":
		return tls_trace.LibSSLSoPathArm64, nil
	default:
		return "", fmt.Errorf("unsupported architecture")
	}
}
