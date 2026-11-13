package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// LLM APIs' streams, shaped as their documentation shows them. Anthropic's
// is the Messages API's example at
// https://platform.claude.com/docs/en/build-with-claude/streaming, with the
// error event that page says can come mid-stream. OpenAI's Chat Completions
// chunks are data-only, ended by "data: [DONE]"; its Responses API names
// each event, with no [DONE]; Gemini's streamGenerateContent with alt=sse
// sends data-only events ended by CRLF CRLF, with no terminator. The IDs,
// model names and numbers are made up.
var llmStreams = []struct {
	name, path, host, contentType string
	body                          string
	eventTypes                    []string // the events' types, "message" for none
}{
	{
		name: "Anthropic Messages", path: "/v1/messages", host: "api.anthropic.com",
		contentType: "text/event-stream; charset=utf-8",
		body: `event: message_start
data: {"type": "message_start", "message": {"id": "msg_test", "type": "message", "role": "assistant", "content": [], "model": "claude-test", "stop_reason": null, "stop_sequence": null, "usage": {"input_tokens": 25, "output_tokens": 1}}}

event: content_block_start
data: {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}

event: ping
data: {"type": "ping"}

event: content_block_delta
data: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello"}}

event: content_block_delta
data: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "!"}}

event: content_block_stop
data: {"type": "content_block_stop", "index": 0}

event: message_delta
data: {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence":null}, "usage": {"output_tokens": 15}}

event: message_stop
data: {"type": "message_stop"}

`,
		eventTypes: []string{"message_start", "content_block_start", "ping", "content_block_delta", "content_block_delta",
			"content_block_stop", "message_delta", "message_stop"},
	},
	{
		name: "Anthropic Messages, overloaded", path: "/v1/messages", host: "api.anthropic.com",
		contentType: "text/event-stream; charset=utf-8",
		body: `event: message_start
data: {"type":"message_start","message":{"id":"msg_test","type":"message","role":"assistant","content":[],"model":"claude-test","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":1}}}

event: error
data: {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}

`,
		eventTypes: []string{"message_start", "error"},
	},
	{
		name: "OpenAI Chat Completions", path: "/v1/chat/completions", host: "api.openai.com",
		contentType: "text/event-stream; charset=utf-8",
		body: `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","created":1694268190,"model":"gpt-test","system_fingerprint":"fp_test","choices":[{"index":0,"delta":{"role":"assistant","content":"","refusal":null},"logprobs":null,"finish_reason":null}],"usage":null,"obfuscation":"r4N7"}

data: {"id":"chatcmpl-test","object":"chat.completion.chunk","created":1694268190,"model":"gpt-test","system_fingerprint":"fp_test","choices":[{"index":0,"delta":{"content":"Hello"},"logprobs":null,"finish_reason":null}],"usage":null,"obfuscation":"Q2"}

data: {"id":"chatcmpl-test","object":"chat.completion.chunk","created":1694268190,"model":"gpt-test","system_fingerprint":"fp_test","choices":[{"index":0,"delta":{"content":"!"},"logprobs":null,"finish_reason":null}],"usage":null,"obfuscation":"aB3dE"}

data: {"id":"chatcmpl-test","object":"chat.completion.chunk","created":1694268190,"model":"gpt-test","system_fingerprint":"fp_test","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"stop"}],"usage":null}

data: {"id":"chatcmpl-test","object":"chat.completion.chunk","created":1694268190,"model":"gpt-test","system_fingerprint":"fp_test","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}

data: [DONE]

`,
		eventTypes: []string{"message", "message", "message", "message", "message", "message"},
	},
	{
		name: "OpenAI Responses", path: "/v1/responses", host: "api.openai.com",
		contentType: "text/event-stream; charset=utf-8",
		body: `event: response.created
data: {"type":"response.created","sequence_number":0,"response":{"id":"resp_test","object":"response","created_at":1741290958,"status":"in_progress","model":"gpt-test","output":[],"usage":null}}

event: response.in_progress
data: {"type":"response.in_progress","sequence_number":1,"response":{"id":"resp_test","object":"response","created_at":1741290958,"status":"in_progress","model":"gpt-test","output":[],"usage":null}}

event: response.output_item.added
data: {"type":"response.output_item.added","sequence_number":2,"output_index":0,"item":{"id":"msg_test","type":"message","status":"in_progress","role":"assistant","content":[]}}

event: response.content_part.added
data: {"type":"response.content_part.added","sequence_number":3,"item_id":"msg_test","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","sequence_number":4,"item_id":"msg_test","output_index":0,"content_index":0,"delta":"Hi","logprobs":[]}

event: response.output_text.delta
data: {"type":"response.output_text.delta","sequence_number":5,"item_id":"msg_test","output_index":0,"content_index":0,"delta":" there","logprobs":[]}

event: response.output_text.done
data: {"type":"response.output_text.done","sequence_number":6,"item_id":"msg_test","output_index":0,"content_index":0,"text":"Hi there","logprobs":[]}

event: response.content_part.done
data: {"type":"response.content_part.done","sequence_number":7,"item_id":"msg_test","output_index":0,"content_index":0,"part":{"type":"output_text","text":"Hi there","annotations":[]}}

event: response.output_item.done
data: {"type":"response.output_item.done","sequence_number":8,"output_index":0,"item":{"id":"msg_test","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Hi there","annotations":[]}]}}

event: response.completed
data: {"type":"response.completed","sequence_number":9,"response":{"id":"resp_test","object":"response","created_at":1741290958,"status":"completed","model":"gpt-test","output":[{"id":"msg_test","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Hi there","annotations":[]}]}],"usage":{"input_tokens":8,"output_tokens":3,"total_tokens":11}}}

`,
		eventTypes: []string{"response.created", "response.in_progress", "response.output_item.added", "response.content_part.added",
			"response.output_text.delta", "response.output_text.delta", "response.output_text.done", "response.content_part.done",
			"response.output_item.done", "response.completed"},
	},
	{
		name: "Gemini streamGenerateContent", path: "/v1beta/models/gemini-test:streamGenerateContent?alt=sse",
		host: "generativelanguage.googleapis.com", contentType: "text/event-stream",
		body: strings.ReplaceAll(`data: {"candidates": [{"content": {"parts": [{"text": "Hello"}],"role": "model"},"index": 0}],"usageMetadata": {"promptTokenCount": 4,"candidatesTokenCount": 1,"totalTokenCount": 5},"modelVersion": "gemini-test","responseId": "resp-test"}

data: {"candidates": [{"content": {"parts": [{"text": " there!\n"}],"role": "model"},"index": 0}],"usageMetadata": {"promptTokenCount": 4,"candidatesTokenCount": 3,"totalTokenCount": 7},"modelVersion": "gemini-test","responseId": "resp-test"}

data: {"candidates": [{"content": {"parts": [{"text": ""}],"role": "model"},"finishReason": "STOP","index": 0}],"usageMetadata": {"promptTokenCount": 4,"candidatesTokenCount": 3,"totalTokenCount": 7},"modelVersion": "gemini-test","responseId": "resp-test"}

`, "\n", "\r\n"),
		eventTypes: []string{"message", "message", "message"},
	},
}

// llmEvents reads a well-formed stream's events as a client would: blocks
// split by blank lines, each a list of "field: value" lines.
func llmEvents(body string) (types, data []string) {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	for _, block := range strings.Split(strings.TrimSpace(body), "\n\n") {
		typ := "message"
		var lines []string
		for _, line := range strings.Split(block, "\n") {
			name, value, _ := strings.Cut(line, ": ")
			switch name {
			case "event":
				typ = value
			case "data":
				lines = append(lines, value)
			}
		}
		types, data = append(types, typ), append(data, strings.Join(lines, "\n"))
	}
	return types, data
}

// chunkedResponse returns an HTTP/1.1 response streaming body chunked, in
// pieces: its headers, then each chunk, then the last chunk. The chunks hold
// an event each or, with chunk set, that many bytes, which split events and
// lines anywhere.
func chunkedResponse(contentType, body string, chunk int) []string {
	out := []string{"HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"}
	var pieces []string
	if chunk == 0 {
		sep := "\n\n"
		if strings.Contains(body, "\r\n") {
			sep = "\r\n\r\n"
		}
		for _, p := range strings.SplitAfter(body, sep) {
			if p != "" {
				pieces = append(pieces, p)
			}
		}
	} else {
		for s := body; s != ""; {
			n := min(chunk, len(s))
			pieces, s = append(pieces, s[:n]), s[n:]
		}
	}
	for _, p := range pieces {
		out = append(out, fmt.Sprintf("%x\r\n%s\r\n", len(p), p))
	}
	return append(out, "0\r\n\r\n")
}

// llmCalls returns an SDK's calls for a stream: its POST, and the response
// read a piece a call or, with size set, in calls of that many bytes, a
// millisecond apart.
func llmCalls(path, host string, response []string, size int) []*tracer.Event {
	req := "POST " + path + " HTTP/1.1\r\nHost: " + host + "\r\nAccept: text/event-stream\r\nContent-Type: application/json\r\n" +
		"Content-Length: 2\r\n\r\n{}"
	evs := []*tracer.Event{event(tracer.FuncSSLWrite, req)}
	if size > 0 {
		all := strings.Join(response, "")
		response = nil
		for all != "" {
			n := min(size, len(all))
			response, all = append(response, all[:n]), all[n:]
		}
	}
	for _, p := range response {
		evs = append(evs, event(tracer.FuncSSLRead, p))
	}
	for i, ev := range evs {
		ev.Comm = "python3"
		ev.Time = ev.Time.Add(time.Duration(i) * time.Millisecond)
	}
	return evs
}

// Each API's stream is read as its documentation says a client reads it,
// however it's split into chunks and calls, and --requests counts its
// events.
func TestSSELLMStreams(t *testing.T) {
	for _, tc := range llmStreams {
		wantTypes, wantData := llmEvents(tc.body)
		if !reflect.DeepEqual(wantTypes, tc.eventTypes) {
			t.Fatalf("%s: the test's stream has events %q", tc.name, wantTypes)
		}
		for _, split := range []struct{ chunk, size int }{{0, 0}, {0, 1 << 16}, {0, 1}, {37, 50}, {1, 7}, {500, 3}} {
			var out bytes.Buffer
			jp := NewJSON(&out, Options{})
			var types, data []string
			for _, line := range printAll(t, jp, &out, llmCalls(tc.path, tc.host, chunkedResponse(tc.contentType, tc.body, split.chunk), split.size)...) {
				if line == "" {
					continue
				}
				var ev struct{ HTTP1 []jsonHTTP1 }
				if err := json.Unmarshal([]byte(line), &ev); err != nil {
					t.Fatal(err)
				}
				for _, p := range ev.HTTP1 {
					for _, e := range p.SSE {
						if e.Incomplete || e.Truncated || e.Data == nil {
							t.Errorf("%s %+v: event %+v", tc.name, split, e)
							continue
						}
						types, data = append(types, cmpOr(e.Event, "message")), append(data, *e.Data)
					}
				}
			}
			if !reflect.DeepEqual(types, wantTypes) || !reflect.DeepEqual(data, wantData) {
				t.Errorf("%s %+v:\ngot  %q\nwant %q\ndata %q", tc.name, split, types, wantTypes, data)
			}
		}

		// --requests: the early line, then one with the count.
		after := requestLines(t, Options{}, llmCalls(tc.path, tc.host, chunkedResponse(tc.contentType, tc.body, 0), 0)...)
		lines := strings.Split(strings.TrimSpace(after[len(after)-1]), "\n")
		want := fmt.Sprintf("POST https://%s%s HTTP/1.1 → 200, %s, ", tc.host, tc.path, tc.contentType)
		if len(lines) != 2 || !strings.Contains(lines[0], want+"streaming") ||
			!strings.Contains(lines[1], fmt.Sprintf("%s%d bytes, %d events", want, len(tc.body), len(wantTypes))) {
			t.Errorf("%s: --requests:\n%s", tc.name, after[len(after)-1])
		}
	}
}

// What the text output shows of each, one chunk per event as the APIs
// flush them: each event under its type, its JSON compact, as it arrives.
func TestTextSSELLM(t *testing.T) {
	want := map[string][]string{
		"Anthropic Messages": {
			"SSE event content_block_delta\n" + `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}` + "\n",
			"SSE event ping\n" + `{"type":"ping"}` + "\n",
			"SSE event message_stop\n" + `{"type":"message_stop"}` + "\n",
		},
		"Anthropic Messages, overloaded": {
			"SSE event error\n" + `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}` + "\n",
		},
		"OpenAI Chat Completions": {
			"SSE event message\n" + `{"id":"chatcmpl-test","object":"chat.completion.chunk",`,
			`"choices":[{"index":0,"delta":{"content":"Hello"},`,
			"SSE event message\n[DONE]\n",
		},
		"OpenAI Responses": {
			"SSE event response.output_text.delta\n" + `{"type":"response.output_text.delta","sequence_number":5,"item_id":"msg_test","output_index":0,"content_index":0,"delta":" there","logprobs":[]}` + "\n",
		},
		"Gemini streamGenerateContent": {
			"SSE event message\n" + `{"candidates":[{"content":{"parts":[{"text":" there!\n"}],"role":"model"},"index":0}],`,
			`"finishReason":"STOP"`,
		},
	}
	for _, tc := range llmStreams {
		var out bytes.Buffer
		after := printAll(t, NewText(&out, Options{}), &out, llmCalls(tc.path, tc.host, chunkedResponse(tc.contentType, tc.body, 0), 0)...)
		all := strings.Join(after, "")
		for _, w := range want[tc.name] {
			if !strings.Contains(all, w) {
				t.Errorf("%s lacks %q:\n%s", tc.name, w, all)
			}
		}
		// The response's headers, alone in their call, start the stream;
		// each call after carries one event and shows it.
		for i, a := range after[2 : len(after)-1] {
			if strings.Count(a, "SSE event ") != 1 {
				t.Errorf("%s: call %d shows %d events:\n%s", tc.name, i+2, strings.Count(a, "SSE event "), a)
			}
		}
		if strings.Contains(all, "not decoded") || strings.Contains(all, "shown when it ends") {
			t.Errorf("%s:\n%s", tc.name, all)
		}
	}
}

// OpenAI's Python SDK stops reading at "data: [DONE]" and closes the
// connection, so the chunked body's last chunk is never read: --requests
// ends the response at [DONE], over HTTP/1.1 and HTTP/2 alike, and a stream
// that only looks like it, its [DONE] in an event of another type, doesn't
// end.
func TestRequestsSSEDone(t *testing.T) {
	body := "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\ndata: [DONE]\n\n"
	response := chunkedResponse("text/event-stream; charset=utf-8", body, 0)
	evs := llmCalls("/v1/chat/completions", "api.openai.com", response[:len(response)-1], 0) // no last chunk
	after := requestLines(t, Options{}, evs...)
	if got := after[len(after)-1]; strings.Count(got, "\n") != 2 || !strings.Contains(got, ", 2 events, ") {
		t.Errorf("HTTP/1.1:\n%s", got)
	}

	other := strings.Replace(body, "data: [DONE]", "event: delta\ndata: [DONE]", 1)
	after = requestLines(t, Options{}, llmCalls("/v1/x", "api.example.com", chunkedResponse("text/event-stream", other, 0)[:3], 0)...)
	if got := after[len(after)-1]; strings.Count(got, "\n") != 1 || !strings.Contains(got, "streaming") {
		t.Errorf("another event's [DONE]:\n%s", got)
	}

	// HTTP/2: the [DONE] frame without END_STREAM, the stream left open.
	client := newHTTP2Writer(true)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "POST", ":scheme", "https", ":authority", "api.openai.com", ":path", "/v1/chat/completions")})
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true,
		BlockFragment: server.block(":status", "200", "content-type", "text/event-stream")})
	server.fr.WriteData(1, false, []byte(body))
	h2 := append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, server.buf.Bytes(), 1<<20)...)
	for _, ev := range h2 {
		ev.Comm = "python3"
	}
	after = requestLines(t, Options{}, h2...)
	if got := after[len(after)-1]; strings.Count(got, "\n") != 1 || !strings.Contains(got, fmt.Sprintf("HTTP/2 → 200, text/event-stream, %d bytes, 2 events, ", len(body))) {
		t.Errorf("HTTP/2:\n%s", got)
	}
}
