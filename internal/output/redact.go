package output

import (
	"bytes"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/http2/hpack"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// Redaction (Options.Redact) masks what's likely secret in what snoopy
// decodes, so that output can be shared: the values of headers that carry
// credentials (keeping an Authorization header's scheme, and cookies'
// names), of query parameters and of JSON and form fields with names that
// say they're secret, passwords in URLs, and anything that looks like a
// token of a well-known kind, wherever text is shown. It works on decoded
// headers, since HTTP/2's and HTTP/3's are compressed in the data as sent;
// output that shows the data as sent (--hex, --pcap) can't be redacted.
//
// What's masked is found as spans of the text, so that a secret split
// across calls can be found in the end of the earlier call and the start of
// the later one, and the later one's part masked (see redactStreams).

// redacted replaces what's masked.
const redacted = "[redacted]"

// secretHeaders are the headers whose values are credentials, besides those
// whose names contain one of secretWords.
var secretHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "api-key": true, "x-auth-token": true, "x-access-token": true,
	"x-csrf-token": true, "x-xsrf-token": true, "x-amz-security-token": true,
	"x-goog-api-key": true, "private-token": true, "x-vault-token": true, "x-consul-token": true,
	"x-registry-auth": true, "x-auth": true, "x-auth-key": true, "ocp-apim-subscription-key": true,
}

// secretWords mark a header, query parameter or JSON or form field as
// secret when its name contains one, ignoring case and separators.
var secretWords = []string{"token", "secret", "password", "passwd", "apikey", "privatekey",
	"credential", "signature", "session", "cookie", "authorization", "clientsecret",
	"authkey", "subscriptionkey", "codeverifier"}

// secretParams are query parameters and form fields that are secret though
// their names don't say so. Some are ordinary JSON names ("code": 404), so
// in JSON only jsonParams are.
var (
	secretParams = map[string]bool{"key": true, "sig": true, "code": true, "auth": true, "pwd": true}
	jsonParams   = map[string]bool{"auth": true, "pwd": true, "pin": true}
)

func secretName(name string) bool {
	n := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(name))
	for _, w := range secretWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// secretNumber reports whether a JSON field whose value is a number is
// secret: a password, not one of the many counts named after tokens
// ("max_tokens": 1024) or sessions.
func secretNumber(name string) bool {
	n := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(name))
	return strings.Contains(n, "password") || strings.Contains(n, "passwd") ||
		strings.Contains(n, "passcode") || jsonParams[n]
}

func secretHeader(name string) bool {
	name = strings.ToLower(name)
	return secretHeaders[name] || !strings.HasPrefix(name, ":") && secretName(name)
}

// span is a range of bytes to mask. For a field's value (field), name is
// where the field's name starts; see redactStreams.
type span struct {
	start, end int
	field      bool
	name       int
}

// mask returns data with the spans replaced by redacted. Overlapping and
// adjacent spans are masked as one. It doesn't change data.
func mask(data []byte, spans []span) []byte {
	if len(spans) == 0 {
		return data
	}
	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })
	out := make([]byte, 0, len(data))
	pos, masked := 0, false
	for _, s := range spans {
		switch {
		case s.end <= s.start:
		case masked && s.start <= pos: // overlaps or touches the last one
			pos = max(pos, s.end)
		default:
			out = append(out, data[pos:s.start]...)
			out = append(out, redacted...)
			pos, masked = s.end, true
		}
	}
	return append(out, data[pos:]...)
}

func maskString(s string, spans []span) string {
	if len(spans) == 0 {
		return s
	}
	return string(mask([]byte(s), spans))
}

// headerSpans returns what's secret in a header's value, besides what
// textSpans finds in it.
func headerSpans(name, value string) []span {
	name = strings.ToLower(name)
	trimmed := strings.TrimSpace(value)
	lead := strings.Index(value, trimmed)
	switch {
	case name == ":path":
		return targetSpans(value)
	case name == "authorization" || name == "proxy-authorization":
		// The scheme says what kind of credential it is.
		if scheme, _, ok := strings.Cut(trimmed, " "); ok {
			return []span{{start: lead + len(scheme) + 1, end: lead + len(trimmed)}}
		}
		return []span{{start: lead, end: lead + len(trimmed)}}
	case name == "cookie" || name == "set-cookie":
		var out []span
		at := 0
		for _, c := range strings.Split(value, ";") {
			if n := strings.TrimSpace(c); n != "" {
				if i := strings.IndexByte(c, '='); i >= 0 {
					out = append(out, span{start: at + i + 1, end: at + len(strings.TrimRight(c, " \t"))})
				} else {
					l := strings.Index(c, n)
					out = append(out, span{start: at + l, end: at + l + len(n)})
				}
			}
			if name == "set-cookie" {
				break // the cookie's value, not its attributes
			}
			at += len(c) + 1
		}
		return out
	case secretHeader(name):
		return []span{{start: lead, end: lead + len(trimmed)}}
	}
	return nil
}

// redactHeader returns a header's value with what's secret masked.
func redactHeader(name, value string) string {
	spans := headerSpans(name, value)
	if !secretHeader(name) {
		spans = append(spans, textSpans([]byte(value))...)
	}
	return maskString(value, spans)
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

// targetSpans returns the values of a request target's secret query
// parameters.
func targetSpans(target string) []span {
	path, query, ok := strings.Cut(target, "?")
	if !ok {
		return nil
	}
	var out []span
	at := len(path) + 1
	for _, p := range strings.Split(query, "&") {
		name, _, hasValue := strings.Cut(p, "=")
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			decoded = name
		}
		if hasValue && (secretParams[strings.ToLower(decoded)] || secretName(decoded)) {
			out = append(out, span{start: at + len(name) + 1, end: at + len(p)})
		}
		at += len(p) + 1
	}
	return out
}

// redactTarget masks a request target's secret query parameters.
func redactTarget(target string) string {
	return maskString(target, append(targetSpans(target), textSpans([]byte(target))...))
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
	// "name": "value" (or a number) in JSON, also escaped as in a JSON
	// string that holds JSON, and name=value in forms and queries; the names
	// are checked with secretName. A string value may run to the end of
	// the text, cut off there.
	jsonField = regexp.MustCompile(`"([^"\\]{1,64})"\s*:\s*(?:"((?:[^"\\]|\\.)*\\?)(?:"|$)|(-?[0-9][0-9.eE+-]*)\b)`)
	escField  = regexp.MustCompile(`\\"([^"\\]{1,64})\\"\s*:\s*(?:\\"((?:[^"\\]|\\[^"])*\\?)(?:\\"|$)|(-?[0-9][0-9.eE+-]*)\b)`)
	formField = regexp.MustCompile(`(^|[&?\s])([A-Za-z0-9_.\-\[\]]{1,64})=([^&;\s"]*)`)
	// HTTP/1.x header lines, in data that wasn't decoded as such.
	headerLine = regexp.MustCompile(`(?m)^([A-Za-z0-9-]{1,64}):[ \t]*([^\r\n]*)`)
	// The password in a URL's userinfo: postgres://user:password@host.
	userinfo = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]{0,20}://[^\s/?#@:"']*:([^\s/?#@"']+)@`)
	// Tokens of well-known kinds, wherever they appear.
	tokenPatterns = regexp.MustCompile(strings.Join([]string{
		`(?i:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}`,
		`eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}`, // JWT
		`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,                                 // AWS access key ID
		`\bgh[pousr]_[A-Za-z0-9]{30,}\b`,                                // GitHub
		`\bgithub_pat_[A-Za-z0-9_]{40,}\b`,
		`\bglpat-[A-Za-z0-9_-]{20,}\b`,            // GitLab
		`\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b`, // Grafana service account
		`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`,       // Slack
		`https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]+`,
		`\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b`,     // Stripe
		`\bwhsec_[A-Za-z0-9+/=]{20,}`,                  // webhook signing secrets
		`\bAIza[0-9A-Za-z_-]{35}\b`,                    // Google API key
		`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b`,     // OpenAI, Anthropic
		`\bnpm_[A-Za-z0-9]{36}\b`,                      // npm
		`\bhf_[A-Za-z0-9]{30,}\b`,                      // Hugging Face
		`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`, // SendGrid
		`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`,
	}, "|"))
)

// textSpans returns what's secret in text: JSON and form fields with secret
// names, header lines of secret headers, passwords in URLs, and tokens of
// well-known kinds. Data that isn't text is searched the same way, which
// in practice only finds tokens.
func textSpans(data []byte) []span {
	var out []span
	fields := func(re *regexp.Regexp) {
		for _, m := range re.FindAllSubmatchIndex(data, -1) {
			name := string(data[m[2]:m[3]])
			switch {
			case m[4] >= 0 && (secretName(name) || jsonParams[strings.ToLower(name)]):
				out = append(out, span{start: m[4], end: m[5], field: true, name: m[0]})
			case m[6] >= 0 && secretNumber(name):
				out = append(out, span{start: m[6], end: m[7], field: true, name: m[0]})
			}
		}
	}
	fields(jsonField)
	fields(escField)
	for _, m := range formField.FindAllSubmatchIndex(data, -1) {
		name := string(data[m[4]:m[5]])
		// Names that only say so as query parameters, not in prose.
		param := m[2] == m[3] || data[m[2]] == '&' || data[m[2]] == '?'
		if secretName(name) || param && secretParams[strings.ToLower(name)] {
			out = append(out, span{start: m[6], end: m[7], field: true, name: m[4]})
		}
	}
	for _, m := range headerLine.FindAllSubmatchIndex(data, -1) {
		name := string(data[m[2]:m[3]])
		if !secretHeader(name) {
			continue
		}
		value := string(bytes.TrimRight(data[m[4]:m[5]], " \t"))
		for _, s := range headerSpans(name, value) {
			out = append(out, span{start: m[4] + s.start, end: m[4] + s.end})
		}
	}
	for _, m := range userinfo.FindAllSubmatchIndex(data, -1) {
		out = append(out, span{start: m[2], end: m[3]})
	}
	for _, m := range tokenPatterns.FindAllIndex(data, -1) {
		// Keep a scheme's name: "Bearer [redacted]".
		start := m[0]
		if i := bytes.IndexAny(data[m[0]:m[1]], " \t"); i > 0 && i < 7 {
			start += i + 1
		}
		out = append(out, span{start: start, end: m[1]})
	}
	return out
}

// redactText masks secrets in text (see textSpans). It doesn't change data.
func redactText(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	return mask(data, textSpans(data))
}

// splitTail is how much of the end of a stream's earlier bytes is kept to
// find secrets split across calls, and maxRedactStreams how many streams'
// ends are kept.
const (
	splitTail        = 256
	maxRedactStreams = 16384
)

// redactStreams redacts each call's bytes together with the end of the
// earlier bytes of the same stream: a direction of a connection, and on
// HTTP/2 and HTTP/3 a stream of it, apart from bodies as decoded. A secret
// whose name is split across calls is then masked in the later one, as is
// the rest of a field's value that ended the earlier one (and was masked
// there), and the rest of a token or a header line. A token's start in the
// earlier call is shown if it isn't recognizable there on its own.
type redactStreams struct {
	tails map[redactKey]*redactTail
}

type redactKey struct {
	conn   harConnKey
	dir    tracer.Direction
	part   redactPart
	stream uint64
}

// redactPart is which of an event's views of its stream's bytes a tail is
// of.
type redactPart uint8

const (
	partData         redactPart = iota // the event's data
	partRaw                            // HTTP/1.x bytes besides a message's head
	partDecoded                        // an HTTP/1.x body as decoded
	partFrame                          // HTTP/2's or HTTP/3's DATA, by stream
	partFrameDecoded                   // and as decoded
)

type redactTail struct {
	b    []byte
	open bool // b ends in a secret field's value
}

func newRedactStreams() *redactStreams {
	return &redactStreams{tails: map[redactKey]*redactTail{}}
}

// text redacts data, the next bytes of a stream. Without r, it's
// redactText.
func (r *redactStreams) text(key redactKey, data []byte) []byte {
	if r == nil {
		return redactText(data)
	}
	if len(data) == 0 {
		return data
	}
	t := r.tails[key]
	if t == nil {
		if len(r.tails) >= maxRedactStreams {
			clear(r.tails)
		}
		t = &redactTail{}
		r.tails[key] = t
	}
	prev := len(t.b)
	all := append(t.b, data...)
	var mine []span
	open, name := false, 0
	for _, s := range textSpans(all) {
		// A field's value that ended the earlier bytes was likely all of it,
		// and what follows something else; it carries on only if it was
		// cut off there, as far as can be told.
		if s.end > prev && (s.start >= prev || !s.field || t.open) {
			mine = append(mine, span{start: max(s.start-prev, 0), end: s.end - prev})
		}
		if s.field && s.end == len(all) && (!open || s.name < name) {
			open, name = true, s.name
		}
	}
	if !open {
		name = len(all)
	}
	t.b, t.open = keepTail(all, name), open
	return mask(data, mine)
}

// keepTail returns the end of all to keep for the next call: its last
// splitTail bytes, after all[name:] cut to its first 128 bytes (a field's
// name) if they don't include it.
func keepTail(all []byte, name int) []byte {
	from := max(len(all)-splitTail, 0)
	if name >= from {
		return slices.Clone(all[from:])
	}
	return append(slices.Clone(all[name:min(name+128, from)]), all[from:]...)
}

// reset forgets the end of a stream's bytes, at the start of a message.
func (r *redactStreams) reset(key redactKey) {
	if r != nil {
		delete(r.tails, key)
	}
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

// redact returns what an event was decoded to, with secrets masked, as
// copies: the decoders keep using what they decoded. With r, secrets split
// between the event and earlier ones of its connection (conn, the event
// sent in direction dir) are found too.
func (dc decoded) redact(r *redactStreams, conn harConnKey, dir tracer.Direction) decoded {
	key := func(part redactPart, stream uint64) redactKey {
		return redactKey{conn: conn, dir: dir, part: part, stream: stream}
	}
	if len(dc.http1) > 0 && dc.http1[0].msg != nil {
		r.reset(key(partData, 0)) // a new message
	}
	dc.data = r.text(key(partData, 0), dc.data)
	segs := make([]http1Segment, len(dc.http1))
	for i, s := range dc.http1 {
		if s.msg != nil {
			r.reset(key(partRaw, 0))
			r.reset(key(partDecoded, 0))
		}
		s.msg = redactMessage(s.msg)
		s.raw = r.text(key(partRaw, 0), s.raw)
		s.body.Decoded = r.text(key(partDecoded, 0), s.body.Decoded)
		segs[i] = s
	}
	if dc.http1 != nil {
		dc.http1 = segs
	}
	frames := make([]http2Frame, len(dc.http2))
	for i, f := range dc.http2 {
		f.Headers = redactFields(f.Headers)
		f.Data = r.text(key(partFrame, uint64(f.Stream)), f.Data)
		f.Body.Decoded = r.text(key(partFrameDecoded, uint64(f.Stream)), f.Body.Decoded)
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
		if strings.HasPrefix(it.HTTP3, "DATA") {
			it.Data = r.text(key(partFrame, it.Stream), it.Data)
		} else {
			it.Data = redactText(it.Data) // a summary's details
		}
		it.Body.Decoded = r.text(key(partFrameDecoded, it.Stream), it.Body.Decoded)
		items[i] = it
	}
	if dc.quic != nil {
		dc.quic = items
	}
	return dc
}
