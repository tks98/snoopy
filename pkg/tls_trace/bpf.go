package tls_trace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

// Constants used within the package
const (
	MessageMaxBuffer = 10000

	DefaultUprobeEntry = "entry"
	DefaultUprobeRet   = "return"
	SSLRead            = 0
	SSLWrite           = 1
)

// Tracer struct for TLS tracing
type Tracer struct {
	jsonOutput bool
	bpfModule  *bpf.Module
	sources    string
	binaryPath string
	pid        *int
}

// New returns a new tracer instance
func New(jsonOutput bool, sources string, binaryPath string, pid *int) *Tracer {
	return &Tracer{
		jsonOutput: jsonOutput,
		sources:    sources,
		binaryPath: binaryPath,
		pid:        pid,
	}
}

// attachProbes attaches required uprobe for tracing specific functions
func (t *Tracer) attachProbes(binaryPath string) error {
	t.attachUprobeEntry(binaryPath, "SSL_read")
	t.attachUprobeReturn(binaryPath, "SSL_read")
	t.attachUprobeEntry(binaryPath, "SSL_write")
	t.attachUprobeReturn(binaryPath, "SSL_write")

	return nil
}

// TraceMessageChannel retrieves the trace in a channel from BPF program
func (t *Tracer) TraceMessageChannel() (<-chan TlsMessage, error) {

	t.bpfModule = bpf.NewModule(t.sources, []string{})
	if err := t.attachProbes(t.binaryPath); err != nil {
		return nil, fmt.Errorf("Error attaching probes: %s", err)
	}

	// Map table in bpf module to channel
	tlsData := t.bpfModule.TableId("TLS_DATA_PERF_OUTPUT")
	table := bpf.NewTable(tlsData, t.bpfModule)
	channel := make(chan []byte)
	out := make(chan TlsMessage)

	// Create performance map to relay traced data to channel
	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to init perf map: %s", err)
	}

	// Message decoding routine
	go func() {
		var msg TlsMessage
		for {
			data := <-channel
			buffer := bytes.NewBuffer(data)
			for _, field := range []interface{}{&msg.Elapsed, &msg.Pid, &msg.Tid, &msg.Result, &msg.Function, &msg.ProcessName, &msg.Message} {
				if err := binary.Read(buffer, binary.LittleEndian, field); err != nil {
					log.Printf("Failed to decode data: %s\n", err)
					continue
				}
			}
			// Send the parsed message into output channel
			out <- msg
		}
	}()

	// Capture Interrupt / Kill signals for graceful exit of routines and map
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		<-sig
		perfMap.Stop()
		t.bpfModule.Close()
		close(channel)
		close(out)
	}()

	perfMap.Start()

	return out, nil
}

// UProbe function attachment helpers

func (t *Tracer) attachUprobeEntry(binaryPath, funcName string) {
	t.attachUprobe(binaryPath, funcName, DefaultUprobeEntry)
}

func (t *Tracer) attachUprobeReturn(binaryPath, funcName string) {
	t.attachUprobe(binaryPath, funcName, DefaultUprobeRet)
}

// attachUprobe attaches a uProbe for the function funcName on binaryPath
func (t *Tracer) attachUprobe(binaryPath, funcName, probeType string) {
	probeName := fmt.Sprintf("uprobe_%s_%s", probeType, funcName)
	uProbe, err := t.bpfModule.LoadUprobe(probeName)

	if err != nil {
		log.Fatalf("Failed to load %s: %s\n", probeName, err)
	}

	if probeType == DefaultUprobeEntry {
		err = t.bpfModule.AttachUprobe(binaryPath, funcName, uProbe, -1)
	} else {
		err = t.bpfModule.AttachUretprobe(binaryPath, funcName, uProbe, -1)
	}

	if err != nil {
		log.Fatalf("Failed to attach %s: %s", funcName, err)
	}
}
