package output

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

func TestRedactHeader(t *testing.T) {
	for _, c := range []struct{ name, value, want string }{
		{"Authorization", "Bearer abc.def.ghi", "Bearer [redacted]"},
		{"authorization", "opaque", "[redacted]"},
		{"Cookie", "session=abc; theme=dark", "session=[redacted]; theme=[redacted]"},
		{"Set-Cookie", "sid=xyz; Path=/; HttpOnly", "sid=[redacted]; Path=/; HttpOnly"},
		{"X-Api-Key", "k123", "[redacted]"},
		{"X-My-Secret-Thing", "s", "[redacted]"},
		{"Github-Token", "t", "[redacted]"},
		{":path", "/login?user=bob&password=hunter2&next=%2F", "/login?user=bob&password=[redacted]&next=%2F"},
		{":path", "/maps?key=AIzaXYZ&q=x", "/maps?key=[redacted]&q=x"},
		{":authority", "example.com", "example.com"},
		{"Content-Type", "application/json", "application/json"},
		{"User-Agent", "curl/8.18", "curl/8.18"},
		{"X-Forwarded", "token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "token [redacted]"},
	} {
		if got := redactHeader(c.name, c.value); got != c.want {
			t.Errorf("%s: %q, got %q, want %q", c.name, c.value, got, c.want)
		}
	}
}

func TestRedactText(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`{"user":"bob","password":"hunter2","api_key":"k","n":1}`, `{"user":"bob","password":"[redacted]","api_key":"[redacted]","n":1}`},
		{`{"accessToken": "a\"b", "refresh_token":"r"}`, `{"accessToken": "[redacted]", "refresh_token":"[redacted]"}`},
		{`grant_type=password&username=bob&password=hunter2&client_secret=s`, `grant_type=password&username=bob&password=[redacted]&client_secret=[redacted]`},
		{"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abcdefghij\r\n\r\n", "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer [redacted]\r\n\r\n"},
		{"id eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl done", "id [redacted] done"},
		{"aws AKIAIOSFODNN7EXAMPLE x", "aws [redacted] x"},
		{"key sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "key [redacted]"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----", "[redacted]"},
		{"nothing secret here, a=b and {\"name\":\"x\"}", "nothing secret here, a=b and {\"name\":\"x\"}"},
	} {
		if got := string(redactText([]byte(c.in))); got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// The decoders keep what they decoded: redaction works on copies.
func TestRedactCopies(t *testing.T) {
	fields := []hpack.HeaderField{{Name: "authorization", Value: "Bearer abcdefghij"}}
	m := &httpMessage{startLine: "GET /?token=t HTTP/1.1", headers: [][2]string{{"Cookie", "a=b"}}, body: []byte(`{"password":"p"}`)}
	dc := decoded{data: []byte("x"), http1: []http1Segment{{msg: m}}, http2: []http2Frame{{Headers: fields}}}.redact()
	if dc.http2[0].Headers[0].Value != "Bearer [redacted]" || dc.http1[0].msg.headers[0][1] != "a=[redacted]" {
		t.Errorf("not redacted: %+v", dc)
	}
	if fields[0].Value != "Bearer abcdefghij" || m.headers[0][1] != "a=b" || m.startLine != "GET /?token=t HTTP/1.1" || string(m.body) != `{"password":"p"}` {
		t.Error("the originals were changed")
	}
}

// Through each printer, no secret of a request and its response shows.
func TestRedactPrinters(t *testing.T) {
	secrets := []string{"hunter2", "s3cr3t", "abcdefghijklmnop", "sessionvalue", "AKIAIOSFODNN7EXAMPLE"}
	req := event(tracer.FuncSSLWrite, "POST /login?api_key=s3cr3t HTTP/1.1\r\nHost: example.com\r\n"+
		"Authorization: Bearer abcdefghijklmnop\r\nCookie: sid=sessionvalue\r\nContent-Type: application/json\r\n"+
		"Content-Length: 46\r\n\r\n"+`{"user":"bob","password":"hunter2","n":"x"}   `)
	other := event(tracer.FuncSSLWrite, "not HTTP: AKIAIOSFODNN7EXAMPLE\n")
	other.ConnID = 0xfeed
	for name, p := range map[string]func(*bytes.Buffer) Printer{
		"text":  func(b *bytes.Buffer) Printer { return NewText(b, Options{Redact: true, Full: true}) },
		"brief": func(b *bytes.Buffer) Printer { return NewBrief(b, Options{Redact: true}) },
		"json":  func(b *bytes.Buffer) Printer { return NewJSON(b, Options{Redact: true}) },
	} {
		var buf bytes.Buffer
		pr := p(&buf)
		for _, ev := range []*tracer.Event{req, other} {
			if err := pr.Print(ev); err != nil {
				t.Fatal(err)
			}
		}
		out := buf.String()
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("%s shows %q:\n%s", name, s, out)
			}
		}
		if !strings.Contains(out, "[redacted]") {
			t.Errorf("%s: nothing redacted:\n%s", name, out)
		}
	}
	// Without it, they show.
	var buf bytes.Buffer
	_ = NewText(&buf, Options{Full: true}).Print(req)
	if !strings.Contains(buf.String(), "hunter2") {
		t.Errorf("without Redact, the body was changed:\n%s", buf.String())
	}
}
