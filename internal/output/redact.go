package output

import (
	"bytes"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// Redaction (Options.Redact) masks what's likely secret in what snoopy
// decodes, so that output can be shared: the values of headers that carry
// credentials (keeping an Authorization header's scheme, and cookies'
// names), of query parameters and of JSON and form fields with names that
// say they're secret, and anything that looks like a token of a well-known
// kind, wherever text is shown. It works on decoded headers, since HTTP/2's
// and HTTP/3's are compressed in the data as sent; output that shows the
// data as sent (--hex, --pcap) can't be redacted.

// redacted replaces what's masked.
const redacted = "[redacted]"

// secretHeaders are the headers whose values are credentials, besides those
// whose names contain one of secretWords.
var secretHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "api-key": true, "x-auth-token": true, "x-access-token": true,
	"x-csrf-token": true, "x-xsrf-token": true, "x-amz-security-token": true,
	"x-goog-api-key": true, "private-token": true, "x-vault-token": true, "x-consul-token": true,
	"x-registry-auth": true,
}

// secretWords mark a header, query parameter or JSON or form field as
// secret when its name contains one, ignoring case and separators.
var secretWords = []string{"token", "secret", "password", "passwd", "apikey", "privatekey",
	"credential", "signature", "session", "cookie", "authorization", "clientsecret"}

// secretParams are query parameters that are secret though their names
// don't say so.
var secretParams = map[string]bool{"key": true, "sig": true, "code": true, "auth": true, "pwd": true}

func secretName(name string) bool {
	n := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(name))
	for _, w := range secretWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

func secretHeader(name string) bool {
	name = strings.ToLower(name)
	return secretHeaders[name] || !strings.HasPrefix(name, ":") && secretName(name)
}

// redactHeader returns a header's value with what's secret masked.
func redactHeader(name, value string) string {
	name = strings.ToLower(name)
	switch {
	case name == ":path":
		return redactTarget(value)
	case name == "authorization" || name == "proxy-authorization":
		// The scheme says what kind of credential it is.
		if scheme, _, ok := strings.Cut(strings.TrimSpace(value), " "); ok {
			return scheme + " " + redacted
		}
		return redacted
	case name == "cookie":
		var out []string
		for _, c := range strings.Split(value, ";") {
			n, _, _ := strings.Cut(strings.TrimSpace(c), "=")
			out = append(out, n+"="+redacted)
		}
		return strings.Join(out, "; ")
	case name == "set-cookie":
		// The cookie's value, not its attributes.
		first, attrs, _ := strings.Cut(value, ";")
		n, _, _ := strings.Cut(first, "=")
		if attrs != "" {
			return n + "=" + redacted + ";" + attrs
		}
		return n + "=" + redacted
	case secretHeader(name):
		return redacted
	}
	return string(redactText([]byte(value)))
}

func redactFields(fields []hpack.HeaderField) []hpack.HeaderField {
	if fields == nil {
		return nil
	}
	out := make([]hpack.HeaderField, len(fields))
	for i, f := range fields {
		f.Value = redactHeader(f.Name, f.Value)
		out[i] = f
	}
	return out
}

// redactTarget masks a request target's secret query parameters.
func redactTarget(target string) string {
	path, query, ok := strings.Cut(target, "?")
	if !ok {
		return string(redactText([]byte(target)))
	}
	parts := strings.Split(query, "&")
	for i, p := range parts {
		name, _, hasValue := strings.Cut(p, "=")
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			decoded = name
		}
		if hasValue && (secretParams[strings.ToLower(decoded)] || secretName(decoded)) {
			parts[i] = name + "=" + redacted
		}
	}
	return string(redactText([]byte(path + "?" + strings.Join(parts, "&"))))
}

// redactStartLine masks an HTTP/1.x request line's target.
func redactStartLine(line string) string {
	method, rest, ok := strings.Cut(line, " ")
	if !ok || strings.HasPrefix(method, "HTTP/") {
		return line
	}
	target, version, _ := strings.Cut(rest, " ")
	return method + " " + redactTarget(target) + " " + version
}

func redactMessage(m *httpMessage) *httpMessage {
	if m == nil {
		return nil
	}
	out := *m
	out.startLine = redactStartLine(m.startLine)
	out.headers = make([][2]string, len(m.headers))
	for i, h := range m.headers {
		out.headers[i] = [2]string{h[0], redactHeader(h[0], h[1])}
	}
	out.body = redactText(m.body)
	return &out
}

var (
	// "name": "value" in JSON, and name=value in forms, with secret names;
	// the names are checked with secretName.
	jsonField = regexp.MustCompile(`"([^"\\]{1,64})"(\s*:\s*)"((?:[^"\\]|\\.)*)"`)
	formField = regexp.MustCompile(`(^|[&?\s])([A-Za-z0-9_.\-\[\]]{1,64})=([^&\s"]*)`)
	// HTTP/1.x header lines, in data that wasn't decoded as such.
	headerLine = regexp.MustCompile(`(?m)^([A-Za-z0-9-]{1,64})(:[ \t]*)([^\r\n]*)`)
	// Tokens of well-known kinds, wherever they appear.
	tokenPatterns = regexp.MustCompile(strings.Join([]string{
		`(?i:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}`,
		`eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}`, // JWT
		`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,                                 // AWS access key ID
		`\bgh[pousr]_[A-Za-z0-9]{30,}\b`,                                // GitHub
		`\bgithub_pat_[A-Za-z0-9_]{40,}\b`,
		`\bglpat-[A-Za-z0-9_-]{20,}\b`,             // GitLab
		`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`,        // Slack
		`\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b`, // Stripe
		`\bAIza[0-9A-Za-z_-]{35}\b`,                // Google API key
		`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b`, // OpenAI, Anthropic
		`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`,
	}, "|"))
)

// redactText masks secrets in text: JSON and form fields with secret names,
// header lines of secret headers, and tokens of well-known kinds. Data that
// isn't text only gets the tokens masked. It returns a copy.
func redactText(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	out := jsonField.ReplaceAllFunc(data, func(m []byte) []byte {
		sub := jsonField.FindSubmatch(m)
		if !secretName(string(sub[1])) {
			return m
		}
		return []byte(`"` + string(sub[1]) + `"` + string(sub[2]) + `"` + redacted + `"`)
	})
	out = formField.ReplaceAllFunc(out, func(m []byte) []byte {
		sub := formField.FindSubmatch(m)
		if !secretName(string(sub[2])) {
			return m
		}
		return []byte(string(sub[1]) + string(sub[2]) + "=" + redacted)
	})
	out = headerLine.ReplaceAllFunc(out, func(m []byte) []byte {
		sub := headerLine.FindSubmatch(m)
		if !secretHeader(string(sub[1])) {
			return m
		}
		return []byte(string(sub[1]) + string(sub[2]) + redactHeader(string(sub[1]), string(bytes.TrimRight(sub[3], " \t"))))
	})
	return tokenPatterns.ReplaceAllFunc(out, func(m []byte) []byte {
		// Keep a scheme's name: "Bearer [redacted]".
		if i := bytes.IndexAny(m, " \t"); i > 0 && i < 7 {
			return append(m[:i+1:i+1], redacted...)
		}
		return []byte(redacted)
	})
}

func redactLines(lines []string) []string {
	if lines == nil {
		return nil
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = string(redactText([]byte(l)))
	}
	return out
}

func redactPart(p bodyPart) bodyPart {
	p.Decoded = redactText(p.Decoded)
	return p
}

// redact returns what an event was decoded to, with secrets masked, as
// copies: the decoders keep using what they decoded.
func (dc decoded) redact() decoded {
	dc.data = redactText(dc.data)
	segs := make([]http1Segment, len(dc.http1))
	for i, s := range dc.http1 {
		s.msg = redactMessage(s.msg)
		s.raw = redactText(s.raw)
		s.body = redactPart(s.body)
		segs[i] = s
	}
	if dc.http1 != nil {
		dc.http1 = segs
	}
	frames := make([]http2Frame, len(dc.http2))
	for i, f := range dc.http2 {
		f.Headers = redactFields(f.Headers)
		f.Data = redactText(f.Data)
		f.Body = redactPart(f.Body)
		msgs := make([]grpcMessage, len(f.GRPC))
		for j, m := range f.GRPC {
			m.Fields = redactLines(m.Fields)
			msgs[j] = m
		}
		if f.GRPC != nil {
			f.GRPC = msgs
		}
		frames[i] = f
	}
	if dc.http2 != nil {
		dc.http2 = frames
	}
	items := make([]quicItem, len(dc.quic))
	for i, it := range dc.quic {
		it.Headers = redactFields(it.Headers)
		it.Data = redactText(it.Data)
		it.Body = redactPart(it.Body)
		items[i] = it
	}
	if dc.quic != nil {
		dc.quic = items
	}
	return dc
}
