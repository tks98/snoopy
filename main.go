package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/tks98/snoopy/pkg/tls_trace"
)

func printTlsMessage(tlsMessage *tls_trace.TlsMessage, jsonOutput bool) {
	endIdx := bytes.IndexByte(tlsMessage.Message[:], 0)
	if endIdx == -1 {
		endIdx = tls_trace.MessageMaxBuffer
	}

	elapsedSeconds := float64(tlsMessage.Elapsed) / 1e6
	funcName := tls_trace.GetFunctionName(tlsMessage.Function)
	procName := string(tlsMessage.ProcessName[:bytes.IndexByte(tlsMessage.ProcessName[:], 0)])

	if jsonOutput {
		msg := struct {
			Function    string  `json:"function"`
			ProcessName string  `json:"process_name"`
			ElapsedTime float64 `json:"elapsed_time"`
			PID         uint32  `json:"pid"`
			TID         uint32  `json:"tid"`
			MessageSize int     `json:"message_size"`
			Result      int32   `json:"result"`
			TLSContent  string  `json:"tls_content"`
		}{
			Function:    funcName,
			ProcessName: procName,
			ElapsedTime: elapsedSeconds,
			PID:         tlsMessage.Pid,
			TID:         tlsMessage.Tid,
			MessageSize: endIdx,
			Result:      tlsMessage.Result,
			TLSContent:  string(tlsMessage.Message[:endIdx]),
		}
		jsonData, err := json.MarshalIndent(msg, "", "    ")
		if err != nil {
			fmt.Printf("Failed to encode message to JSON: %s\n", err)
			return
		}
		fmt.Println(string(jsonData))
	} else {
		currentTime := time.Now()
		timestamp := currentTime.Format("15:04:05.000000")
		fmt.Printf("[%s] Function %s, Process Name %s, PID %d, TID %d: Message Size %d bytes, Result %d\n", timestamp, funcName, procName, tlsMessage.Pid, tlsMessage.Tid, endIdx, tlsMessage.Result)
		fmt.Println("TLS Content:")
		fmt.Println(string(tlsMessage.Message[:endIdx]))
		fmt.Println("========================================")
	}
}

var pidToTrace *int

func main() {
	var jsonOutput bool
	flag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	pid := flag.Int("pid", -1, "Specify the PID to trace (optional, if not specified, all processes will be traced)")
	flag.Parse()
	pidToTrace = pid

	sources, err := ReadEbpfProgram("bpf/snoopy.c")
	if err != nil {
		log.Fatal(fmt.Errorf("Error reading eBPF program: %s", err))
	}

	binaryPath, err := GetBinaryPath()
	if err != nil {
		log.Fatal(fmt.Errorf("Error getting binary path: %s", err))
	}

	// Assuming tls_trace.New has a way to accept optional PID
	tracer := tls_trace.New(jsonOutput, sources, binaryPath, pidToTrace)
	tlsMessages, err := tracer.TraceMessageChannel()
	if err != nil {
		log.Fatal(fmt.Errorf("Failed to start tls_trace: %s", err))
	}

	for message := range tlsMessages {
		// Only process messages from the specified PID, if PID is set
		if pidToTrace == nil || *pidToTrace < 0 || *pidToTrace == int(message.Pid) {
			printTlsMessage(&message, jsonOutput)
		}
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
