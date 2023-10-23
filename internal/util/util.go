package util

import (
	"flag"
	"fmt"
	"os"
	"runtime"
)

const (
	LibSSLSoPathAMd64 = "/lib/x86_64-linux-gnu/libssl.so.3"
	LibSSLSoPathArm64 = "/lib/aarch64-linux-gnu/libssl.so.3"
)

// CLIOptions is a struct for command line options
type CLIOptions struct {
	JSONOutput bool
	PID        int
}

// ParseCLIOptions functions parses the command line arguments to
// create and return an object of CLIOptions
func ParseCLIOptions() CLIOptions {
	// Declare a boolean variable for JSON output option
	var jsonOutput bool
	flag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	// Declare an integer variable for Process ID option
	pid := flag.Int("pid", -1, "Specify the PID to trace (optional, if not specified, all processes will be traced)")
	flag.Parse()

	// Return a new object of CLIOptions with the parsed options
	return CLIOptions{
		JSONOutput: jsonOutput,
		PID:        *pid,
	}
}

// ReadEbpfProgram function reads a file from the given path
func ReadEbpfProgram(filePath string) (string, error) {
	// Read the file from the given path
	b, err := os.ReadFile(filePath)
	return string(b), err
}

// GetLibSSLPath function returns the path of the libssl shared library file based on the architecture
func GetLibSSLPath() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		// Return the path for amd64 architecture
		return LibSSLSoPathAMd64, nil
	case "arm64":
		// Return the path for arm64 architecture
		return LibSSLSoPathArm64, nil
	default:
		// Return error if the architecture is not supported
		return "", fmt.Errorf("unsupported architecture")
	}
}
