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
	dc := decoded{data: []byte("x"), http1: []http1Segment{{msg: m}}, http2: []http2Frame{{Headers: fields}}}.redact(nil, harConnKey{}, tracer.Write)
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

// What's masked beyond the obvious names, and what isn't.
func TestRedactCoverage(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		// OAuth: secretParams in form bodies and in a redirect's URL.
		{`grant_type=authorization_code&code=AUTHCODE123&code_verifier=VERIFIER456&redirect_uri=x`,
			`grant_type=authorization_code&code=[redacted]&code_verifier=[redacted]&redirect_uri=x`},
		{"Location: https://app/cb?code=LOCCODE&state=s\r\n", "Location: https://app/cb?code=[redacted]&state=s\r\n"},
		{`{"auth": "authval1", "pwd": "p", "pin": "1"}`, `{"auth": "[redacted]", "pwd": "[redacted]", "pin": "[redacted]"}`},
		// Numbers, and JSON in a JSON string.
		{`{"password": 12345, "pin": 9999}`, `{"password": [redacted], "pin": [redacted]}`},
		{`{"data":"{\"password\":\"hunter2\",\"user\":\"bob\"}"}`, `{"data":"{\"password\":\"[redacted]\",\"user\":\"bob\"}"}`},
		{`{"variables":"{\"token\":\"t0k\"}"}`, `{"variables":"{\"token\":\"[redacted]\"}"}`},
		// Headers.
		{"X-Auth-Key: cfkey123456\r\n", "X-Auth-Key: [redacted]\r\n"},
		{"Ocp-Apim-Subscription-Key: azkey123456\r\n", "Ocp-Apim-Subscription-Key: [redacted]\r\n"},
		{"X-Auth: plainauth\r\n", "X-Auth: [redacted]\r\n"},
		// Passwords in URLs.
		{"db postgres://admin:dbpass99@db.internal/x", "db postgres://admin:[redacted]@db.internal/x"},
		{"https://u:p@h/", "https://u:[redacted]@h/"},
		// Tokens, in pieces so that this file doesn't look like it has any.
		{"npm_" + "abcdefghijklmnopqrstuvwxyz0123456789 x", "[redacted] x"},
		{"hf_" + "abcdefghijklmnopqrstuvwxyzABCDEF x", "[redacted] x"},
		{"whsec_" + "abcdefghijklmnopqrstuvwx x", "[redacted] x"},
		{"SG." + "abcdefghijklmnopqrstuv." + "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG x", "[redacted] x"},
		{"post to https://hooks.slack.com/" + "services/T000/B000/XXXXXXXXXXXXXXXX now", "post to [redacted] now"},
		{"glsa_" + "abcdefghijklmnopqrstuvwxyz012345_abcdef01 x", "[redacted] x"},
	} {
		if got := string(redactText([]byte(c.in))); got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	for _, c := range []struct{ name, value, want string }{
		{"Location", "https://app/cb?code=LOCCODE&state=s", "https://app/cb?code=[redacted]&state=s"},
		{"X-Auth-Key", "cf", "[redacted]"},
		{"Ocp-Apim-Subscription-Key", "az", "[redacted]"},
		{"X-Auth", "a", "[redacted]"},
		{"Referer", "https://x/?access_token=REFTOK", "https://x/?access_token=[redacted]"},
	} {
		if got := redactHeader(c.name, c.value); got != c.want {
			t.Errorf("%s: %q, got %q, want %q", c.name, c.value, got, c.want)
		}
	}
	// Ordinary values stay.
	for _, s := range []string{
		`{"keyboard":"qwerty","key":"settings","key_count":3,"id":"abc123","count":5,"code":404,"status":"NOT_FOUND"}`,
		`{"max_tokens":1024,"prompt_tokens":12,"session_count":2,"auth_required":true,"author":"bob"}`,
		`{"code":"invalid_request","authors":["a"],"monkey":"x","pinned":true,"spinner":"y"}`,
		"the code=200 and key=value pairs in prose, monkey=1",
		"see https://example.com/path?q=1&page=2 and mailto:bob@example.com",
		"Content-Type: application/json\r\nX-Request-Id: abc\r\nAuthor: me\r\n",
		"npm_short hf_x SG.a.b whsec_x glsa_x",
		"keyboard=us&monkey=1&codec=h264&signal=1",
	} {
		if got := string(redactText([]byte(s))); got != s {
			t.Errorf("changed:\n%q\n%q", s, got)
		}
	}
}

// A secret split across calls doesn't show, wherever the split is, in what
// streams (text, JSON) nor in HAR; but a token's start does, in the
// streams, if it's too short to be recognized.
func TestRedactSplit(t *testing.T) {
	const secret = "SPLITSECRET"
	for _, body := range []string{
		`{"user":"bob","password":"SPLITSECRET","n":1}`,
		`user=bob&password=SPLITSECRET&next=%2F`,
		`{"query":"q","variables":"{\"token\":\"SPLITSECRET\"}"}`,
		`{"pin": 9876, "x": "Bearer SPLITSECRET", "y": 1}`,
	} {
		head := "POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n"
		next := "GET /next HTTP/1.1\r\nHost: x\r\n\r\n"
		for i := 1; i < len(body); i++ {
			a := event(tracer.FuncSSLWrite, head+body[:i])
			b := event(tracer.FuncSSLWrite, body[i:])
			c := event(tracer.FuncSSLWrite, next)
			for name, mk := range map[string]func(*bytes.Buffer) Printer{
				"text": func(w *bytes.Buffer) Printer { return NewText(w, Options{Redact: true, Full: true}) },
				"json": func(w *bytes.Buffer) Printer { return NewJSON(w, Options{Redact: true}) },
				"har":  func(w *bytes.Buffer) Printer { return NewHAR(w, "t", Options{Redact: true}) },
			} {
				var w bytes.Buffer
				p := mk(&w)
				for _, ev := range []*tracer.Event{a, b, c} {
					_ = p.Print(ev)
				}
				if c, ok := p.(interface{ Close() error }); ok {
					_ = c.Close()
				}
				out := w.String()
				at := strings.Index(body, secret)
				for j := 0; j+4 <= len(secret); j++ {
					shown := strings.Contains(body, "Bearer") && name != "har" && at+j+4 <= i
					if !shown && strings.Contains(out, secret[j:j+4]) {
						t.Fatalf("%s, %q split at %d: %q shows:\n%s", name, body, i, secret[j:j+4], out)
					}
				}
				if strings.Contains(body, "9876") && strings.Contains(out, "9876") || strings.Contains(out, "[redacted]T /next") ||
					name != "har" && !strings.Contains(out, "GET /next") {
					t.Fatalf("%s, %q split at %d:\n%s", name, body, i, out)
				}
			}
		}
	}
}

// A value that ends a call isn't taken to go on in the next one.
func TestRedactStreamsNoCarry(t *testing.T) {
	r := newRedactStreams()
	k := redactKey{}
	if got := string(r.text(k, []byte(`a=1&password=x`))); got != `a=1&password=[redacted]` {
		t.Errorf("first: %q", got)
	}
	if got := string(r.text(k, []byte(`"done":"yes"}`))); got != `"done":"yes"}` {
		t.Errorf("after a cut-off value: %q", got)
	}
	r = newRedactStreams()
	_ = r.text(k, []byte(`{"password":"x"}`))
	if got := string(r.text(k, []byte(`more`))); got != `more` {
		t.Errorf("after a whole value: %q", got)
	}
	// A long value that spans many calls.
	r = newRedactStreams()
	_ = r.text(k, []byte(`{"token":"`))
	for i := 0; i < 5; i++ {
		if got := string(r.text(k, bytes.Repeat([]byte("A"), 1000))); got != "[redacted]" {
			t.Fatalf("call %d: %q", i, got)
		}
	}
	if got := string(r.text(k, []byte(`AAA","n":1}`))); got != `[redacted]","n":1}` {
		t.Errorf("end: %q", got)
	}
}

// With a status filter, which request a response answers is shown with its
// secrets masked.
func TestRedactAnswers(t *testing.T) {
	req := event(tracer.FuncSSLWrite, "GET /cb?token=ANSWERTOKEN&x=1 HTTP/1.1\r\nHost: x\r\n\r\n")
	resp := event(tracer.FuncSSLRead, "HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n")
	opts := Options{Redact: true, Filter: &HTTPFilter{Status: []StatusRange{{500, 599}}}}
	for name, mk := range map[string]func(*bytes.Buffer) Printer{
		"text":  func(b *bytes.Buffer) Printer { return NewText(b, opts) },
		"brief": func(b *bytes.Buffer) Printer { return NewBrief(b, opts) },
		"json":  func(b *bytes.Buffer) Printer { return NewJSON(b, opts) },
	} {
		var b bytes.Buffer
		p := mk(&b)
		_ = p.Print(req)
		_ = p.Print(resp)
		if strings.Contains(b.String(), "ANSWERTOKEN") || !strings.Contains(b.String(), "GET /cb?token=[redacted]&x=1") {
			t.Errorf("%s:\n%s", name, b.String())
		}
	}
}
