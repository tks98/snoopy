package util

import (
	"flag"
	"fmt"
	"os"
	"runtime"
)

const (
	LibSSLSoPathAMd64    = "/lib/x86_64-linux-gnu/libssl.so.3"
	LibSSLSoPathArm64    = "/lib/aarch64-linux-gnu/libssl.so.3"
	LibGnuTLSSoPathAMd64 = "/usr/lib/x86_64-linux-gnu/libgnutls.so.30.31.0"
	LibGnuTLSSoPathArm64 = "/usr/lib/aarch64-linux-gnu/libgnutls.so.30.31.0"
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

// GetLibPaths function returns a map of library names to their paths based on the architecture
func GetLibPaths() (map[string]string, error) {
	libPaths := make(map[string]string)

	switch runtime.GOARCH {
	case "amd64":
		libPaths["OpenSSL"] = LibSSLSoPathAMd64
		libPaths["GnuTLS"] = LibGnuTLSSoPathAMd64 // You should confirm this path
	case "arm64":
		libPaths["OpenSSL"] = LibSSLSoPathArm64
		libPaths["GnuTLS"] = LibGnuTLSSoPathArm64 // This path was confirmed from your system
	default:
		return nil, fmt.Errorf("unsupported architecture")
	}

	return libPaths, nil
}
