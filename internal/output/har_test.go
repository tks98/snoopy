package output

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

type harLog struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name string `json:"name"`
		} `json:"creator"`
		Entries []struct {
			Started string  `json:"startedDateTime"`
			Time    float64 `json:"time"`
			Request struct {
				Method      string `json:"method"`
				URL         string `json:"url"`
				HTTPVersion string `json:"httpVersion"`
				Headers     []struct{ Name, Value string }
				QueryString []struct{ Name, Value string } `json:"queryString"`
				Cookies     []struct{ Name, Value string }
				PostData    *struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
				} `json:"postData"`
			} `json:"request"`
			Response struct {
				Status  int    `json:"status"`
				Text    string `json:"statusText"`
				Content struct {
					Size     int    `json:"size"`
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
				} `json:"content"`
				BodySize int `json:"bodySize"`
			} `json:"response"`
			ServerIP string `json:"serverIPAddress"`
			Process  string `json:"_process"`
			Comment  string `json:"comment"`
		} `json:"entries"`
	} `json:"log"`
}

func readHAR(t *testing.T, b []byte) harLog {
	t.Helper()
	var l harLog
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatalf("%v:\n%s", err, b)
	}
	return l
}

// HTTP/1.1: two requests on a connection, and their responses in order, the
// second gzipped and split over calls.
func TestHARHTTP1(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(`{"ok":true}`))
	zw.Close()
	at := func(ev *tracer.Event, ms int) *tracer.Event {
		ev.Time = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Add(time.Duration(ms) * time.Millisecond)
		return ev
	}
	resp2 := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: " +
		itoa(gz.Len()) + "\r\n\r\n" + gz.String()
	evs := []*tracer.Event{
		at(event(tracer.FuncSSLWrite, "GET /a?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\nCookie: s=1; t=2\r\n\r\n"), 0),
		at(event(tracer.FuncSSLWrite, "POST /b HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"), 1),
		at(event(tracer.FuncSSLRead, "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope"), 10),
		at(event(tracer.FuncSSLRead, resp2[:len(resp2)-5]), 20),
		at(event(tracer.FuncSSLRead, resp2[len(resp2)-5:]), 25),
	}
	var out bytes.Buffer
	h := NewHAR(&out, "test", Options{})
	for _, ev := range evs {
		if err := h.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	l := readHAR(t, out.Bytes())
	if l.Log.Version != "1.2" || l.Log.Creator.Name != "snoopy" || len(l.Log.Entries) != 2 {
		t.Fatalf("log: %+v", l.Log)
	}
	a, b := l.Log.Entries[0], l.Log.Entries[1]
	switch {
	case a.Request.Method != "GET" || a.Request.URL != "https://example.com/a?x=1&y=2" || a.Request.HTTPVersion != "HTTP/1.1":
		t.Errorf("first request: %+v", a.Request)
	case len(a.Request.QueryString) != 2 || len(a.Request.Cookies) != 2:
		t.Errorf("query %v, cookies %v", a.Request.QueryString, a.Request.Cookies)
	case a.Response.Status != 404 || a.Response.Text != "Not Found" || a.Response.Content.Text != "nope":
		t.Errorf("first response: %+v", a.Response)
	case a.Time != 10 || a.ServerIP != "93.184.216.34" || a.Process != "curl":
		t.Errorf("first entry: time %v, server %q, process %q", a.Time, a.ServerIP, a.Process)
	case b.Request.Method != "POST" || b.Request.PostData == nil || b.Request.PostData.Text != "hello":
		t.Errorf("second request: %+v", b.Request)
	case b.Response.Status != 200 || b.Response.Content.Text != `{"ok":true}` || b.Response.Content.MimeType != "application/json":
		t.Errorf("second response, decompressed: %+v", b.Response)
	case b.Response.BodySize != gz.Len() || b.Time != 24:
		t.Errorf("second: body size %d (want %d), time %v", b.Response.BodySize, gz.Len(), b.Time)
	}
}

// HTTP/2: exchanges by stream, a response's body after its headers.
func TestHARHTTP2(t *testing.T) {
	client := newHTTP2Writer(true)
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/one")})
	client.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, EndStream: true, EndHeaders: true,
		BlockFragment: client.block(":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/two")})
	server := newHTTP2Writer(false)
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, EndHeaders: true,
		BlockFragment: server.block(":status", "200", "content-type", "text/plain")})
	server.fr.WriteData(3, true, []byte("two"))
	server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: true,
		BlockFragment: server.block(":status", "204")})

	var out bytes.Buffer
	h := NewHAR(&out, "test", Options{})
	for _, ev := range append(events(tracer.FuncSSLWrite, client.buf.Bytes(), 1<<20), events(tracer.FuncSSLRead, server.buf.Bytes(), 1<<20)...) {
		if err := h.Print(ev); err != nil {
			t.Fatal(err)
		}
	}
	h.Close()
	l := readHAR(t, out.Bytes())
	if len(l.Log.Entries) != 2 {
		t.Fatalf("%d entries:\n%s", len(l.Log.Entries), out.String())
	}
	one, two := l.Log.Entries[0], l.Log.Entries[1]
	if one.Request.URL != "https://example.com/one" || one.Response.Status != 204 || one.Request.HTTPVersion != "HTTP/2" {
		t.Errorf("stream 1: %+v", one)
	}
	if two.Request.URL != "https://example.com/two" || two.Response.Status != 200 || two.Response.Content.Text != "two" {
		t.Errorf("stream 3: %+v", two)
	}
}

// A request with no response, and none at all, still make valid logs.
func TestHAREmptyAndUnanswered(t *testing.T) {
	var out bytes.Buffer
	h := NewHAR(&out, "test", Options{})
	h.Close()
	if l := readHAR(t, out.Bytes()); l.Log.Entries == nil || len(l.Log.Entries) != 0 {
		t.Errorf("empty log: %s", out.String())
	}
	out.Reset()
	h = NewHAR(&out, "test", Options{})
	h.Print(event(tracer.FuncSSLWrite, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	h.Close()
	if l := readHAR(t, out.Bytes()); len(l.Log.Entries) != 1 || l.Log.Entries[0].Comment != "no response was seen" {
		t.Errorf("unanswered: %s", out.String())
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// With Redact, the log's secrets are masked as in the other outputs.
func TestHARRedact(t *testing.T) {
	var out bytes.Buffer
	h := NewHAR(&out, "test", Options{Redact: true})
	h.Print(event(tracer.FuncSSLWrite, "GET /?token=s3cr3t HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer abcdefghij\r\n\r\n"))
	h.Close()
	for _, s := range []string{"s3cr3t", "abcdefghij"} {
		if bytes.Contains(out.Bytes(), []byte(s)) {
			t.Errorf("%q in the log:\n%s", s, out.String())
		}
	}
}
