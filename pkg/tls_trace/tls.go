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

func MessageHasContent(msg [MessageMaxBuffer]byte) bool {
	endIdx := bytes.IndexByte(msg[:], 0)
	if endIdx == 0 {
		return false
	}
	for _, b := range msg {
		if b != 0 {
			return true
		}
	}
	return false
}

func GetFunctionName(functionCode int32) string {
	switch functionCode {
	case SSLRead:
		return "SSL_READ"
	case SSLWrite:
		return "SSL_WRITE"
	default:
		return "UNKNOWN"
	}
}

func (t *TlsMessage) Print(jsonOutput bool) {
	t.EndIdx = bytes.IndexByte(t.Message[:], 0)
	if t.EndIdx == -1 {
		t.EndIdx = len(t.Message)
	}

	elapsedSeconds := float64(t.Elapsed) / 1e6
	funcName := GetFunctionName(t.Function)
	procName := string(t.ProcessName[:bytes.IndexByte(t.ProcessName[:], 0)])

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
	} else {
		currentTime := time.Now()
		timestamp := currentTime.Format("15:04:05.000000")
		content := color.New(color.FgHiWhite).SprintfFunc()
		title := color.New(color.FgHiMagenta, color.Bold).SprintfFunc()

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

		// Outputting data
		fmt.Println(title("[ TLS Message Information ]"))
		tw.Render()

		fmt.Println(title("[ TLS Content ]"))
		fmt.Println(content(string(t.Message[:t.EndIdx])))

		fmt.Println(title("[ End of TLS Message ]"))
	}
}
