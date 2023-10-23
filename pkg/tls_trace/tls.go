package tls_trace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
)

// TlsMessage struct to handle each message data
type TlsMessage struct {
	Elapsed     uint64
	Pid         uint32
	Tid         uint32
	Result      int32
	Function    int32
	ProcessName [16]byte
	Message     [MessageMaxBuffer]byte
	EndIdx      int
}

// getEndIndex returns end index of the message
func (t *TlsMessage) getEndIndex() int {
	endIdx := bytes.IndexByte(t.Message[:], 0)
	if endIdx == -1 {
		endIdx = len(t.Message)
	}
	return endIdx
}

// HasContent checks if the TLS message has content
func (t *TlsMessage) HasContent() bool {
	return bytes.IndexByte(t.Message[:], 0) != 0
}

// GetFunctionName returns function name by function code
func (t *TlsMessage) GetFunctionName() string {
	switch t.Function {
	case SSLRead:
		return "SSL_READ"
	case SSLWrite:
		return "SSL_WRITE"
	default:
		return "UNKNOWN"
	}
}

// createJsonOutput creates and prints JSON representation of the message
func (t *TlsMessage) createJsonOutput(funcName string, procName string, elapsedSeconds float64) {
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
		PID:         t.Pid,
		TID:         t.Tid,
		MessageSize: t.EndIdx,
		Result:      t.Result,
		TLSContent:  string(t.Message[:t.EndIdx]),
	}
	jsonData, err := json.MarshalIndent(msg, "", "    ")
	if err != nil {
		fmt.Printf("Failed to encode message to JSON: %s\n", err)
		return
	}
	fmt.Println(string(jsonData))
}

// printTableOutput prints message info as a table
func (t *TlsMessage) printTableOutput(funcName, procName, timestamp string) {
	// New table writer
	tw := table.NewWriter()
	tw.SetOutputMirror(os.Stdout)
	tw.AppendHeader(table.Row{"DESCRIPTION", "VALUE"})
	tw.AppendRow([]interface{}{"Timestamp", timestamp})
	tw.AppendRow([]interface{}{"Function", funcName})
	tw.AppendRow([]interface{}{"Process Name", procName})
	tw.AppendRow([]interface{}{"PID", t.Pid})
	tw.AppendRow([]interface{}{"TID", t.Tid})
	tw.AppendRow([]interface{}{"Message Size", fmt.Sprintf("%d bytes", t.EndIdx)})

	title := color.New(color.FgHiMagenta, color.Bold).SprintfFunc()
	content := color.New(color.FgHiWhite).SprintfFunc()

	// Outputting data
	fmt.Println(title("[ TLS Message Information ]"))
	tw.Render()
	fmt.Println(title("[ TLS Content ]"))
	fmt.Println(content(string(t.Message[:t.EndIdx])))
	fmt.Println(title("[ End of TLS Message ]"))
}

// Print prints the message info either as a table or JSON based on jsonOutput flag
func (t *TlsMessage) Print(jsonOutput bool) {
	t.EndIdx = t.getEndIndex()

	elapsedSeconds := float64(t.Elapsed) / 1e6
	funcName := t.GetFunctionName()
	procName := string(t.ProcessName[:bytes.IndexByte(t.ProcessName[:], 0)])
	if jsonOutput {
		t.createJsonOutput(funcName, procName, elapsedSeconds)
	} else {
		currentTime := time.Now()
		timestamp := currentTime.Format("15:04:05.000000")
		t.printTableOutput(funcName, procName, timestamp)
	}
}
