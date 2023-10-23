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

const (
	MessageMaxBuffer   = 10000
	LibSSLSoPathAMd64  = "/lib/x86_64-linux-gnu/libssl.so.3"
	LibSSLSoPathArm64  = "/lib/aarch64-linux-gnu/libssl.so.3"
	DefaultUprobeEntry = "entry"
	DefaultUprobeRet   = "return"
	SSLRead            = 0
	SSLWrite           = 1
)

type Tracer struct {
	jsonOutput bool
	bpfModule  *bpf.Module
	sources    string
	binaryPath string
	pid        *int
}

func New(jsonOutput bool, sources string, binaryPath string, pid *int) *Tracer {
	return &Tracer{
		jsonOutput: jsonOutput,
		sources:    sources,
		binaryPath: binaryPath,
		pid:        pid,
	}
}

func (t *Tracer) attachProbes(binaryPath string) error {
	t.attachUprobeEntry(binaryPath, "SSL_read")
	t.attachUprobeReturn(binaryPath, "SSL_read")
	t.attachUprobeEntry(binaryPath, "SSL_write")
	t.attachUprobeReturn(binaryPath, "SSL_write")

	return nil
}

func (t *Tracer) TraceMessageChannel() (<-chan TlsMessage, error) {

	t.bpfModule = bpf.NewModule(t.sources, []string{})
	if err := t.attachProbes(t.binaryPath); err != nil {
		return nil, fmt.Errorf("Error attaching probes: %s", err)
	}

	tlsData := t.bpfModule.TableId("TLS_DATA_PERF_OUTPUT")

	table := bpf.NewTable(tlsData, t.bpfModule)
	channel := make(chan []byte)
	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to init perf map: %s", err)
	}

	out := make(chan TlsMessage)

	go func() {
		var msg TlsMessage
		for {
			data := <-channel
			buffer := bytes.NewBuffer(data)
			if err := binary.Read(buffer, binary.LittleEndian, &msg.Elapsed); err != nil {
				log.Printf("Failed to decode Elapsed: %s\n", err)
				continue
			}
			if err := binary.Read(buffer, binary.LittleEndian, &msg.Pid); err != nil {
				log.Printf("Failed to decode Pid: %s\n", err)
				continue
			}
			if err := binary.Read(buffer, binary.LittleEndian, &msg.Tid); err != nil {
				log.Printf("Failed to decode Tid: %s\n", err)
				continue
			}
			if err := binary.Read(buffer, binary.LittleEndian, &msg.Result); err != nil {
				log.Printf("Failed to decode Result: %s\n", err)
				continue
			}
			if err := binary.Read(buffer, binary.LittleEndian, &msg.Function); err != nil {
				log.Printf("Failed to decode Function: %s\n", err)
				continue
			}
			if err := binary.Read(buffer, binary.LittleEndian, &msg.ProcessName); err != nil {
				log.Printf("Failed to decode ProcessName: %s\n", err)
				continue
			}
			if err := binary.Read(buffer, binary.LittleEndian, &msg.Message); err != nil {
				log.Printf("Failed to decode Message: %s\n", err)
				continue
			}

			// find the first 0 byte
			endIdx := bytes.IndexByte(msg.Message[:], 0)
			if endIdx == -1 {
				endIdx = MessageMaxBuffer
			}

			// send parsed message to output channel
			out <- msg
		}
	}()

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

func (t *Tracer) attachUprobeEntry(binaryPath, funcName string) {
	t.attachUprobe(binaryPath, funcName, DefaultUprobeEntry)
}

func (t *Tracer) attachUprobeReturn(binaryPath, funcName string) {
	t.attachUprobe(binaryPath, funcName, DefaultUprobeRet)
}

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
