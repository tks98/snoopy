package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// Requests prints one line per HTTP exchange, a request and its response,
// once the response has ended: what an API's caller or server wants to
// see, where the other printers show each TLS call, of which an exchange
// takes several. It pairs them as HAR does (on an HTTP/1.x connection in
// order, on HTTP/2 and HTTP/3 by stream), keeping no bodies, only their
// sizes. A response whose body ends with its connection, or that hasn't
// ended when snoopy stops, isn't shown, unless it was streaming: a
// streaming response (see progress) also gets a line before its end.
type Requests struct {
	w        io.Writer
	opts     Options
	har      *HAR
	err      error
	shown    int
	filtered int

	dim, title, ok, bad, warn func(a ...any) string
}

func NewRequests(w io.Writer, opts Options) *Requests {
	s := func(attrs ...color.Attribute) func(a ...any) string {
		return color.New(attrs...).SprintFunc()
	}
	r := &Requests{w: w, opts: opts,
		dim: s(color.Faint), title: s(color.Bold), ok: s(color.FgGreen), bad: s(color.FgRed), warn: s(color.FgYellow)}
	// The filter and redaction apply to whole exchanges, here.
	r.har = NewHAR(nil, "", Options{})
	r.har.maxKept = 0
	r.har.done = r.print
	r.har.progress = r.progress
	return r
}

func (r *Requests) Print(ev *tracer.Event) error {
	if err := r.har.Print(ev); err != nil {
		return err
	}
	err := r.err
	r.err = nil
	return err
}

// Shown returns how many exchanges were printed.
func (r *Requests) Shown() int { return r.shown }

// FilteredRequests returns how many exchanges Options.Filter left out.
func (r *Requests) FilteredRequests() int { return r.filtered }

// print is HAR's done: it prints an exchange whose response ended.
func (r *Requests) print(e *harEntry) {
	if !r.matches(e) {
		r.filtered++
		return
	}
	r.shown++
	r.write(r.line(e, false))
}

// streamingAfter is how long after its headers a response that hasn't
// ended is shown as streaming, when more of it arrives: one sent a piece
// at a time, as JSON lines or a long download.
const streamingAfter = time.Second

// progress is HAR's progress: it prints a line for a response that's
// streaming, before its end: an event stream once its headers arrive,
// another response once it's still going streamingAfter after them. Its
// line when it ends is printed as well.
func (r *Requests) progress(e *harEntry, now time.Time) {
	if e.announced || !e.resp.seen || e.resp.status < 200 {
		return
	}
	if !isEventStream(headerValue(e.resp.headers, "content-type")) && now.Sub(e.respAt) < streamingAfter {
		return
	}
	e.announced = true
	if r.matches(e) {
		r.write(r.line(e, true))
	}
}

// matches reports whether Options.Filter keeps an exchange.
func (r *Requests) matches(e *harEntry) bool {
	f := r.opts.Filter
	return f == nil || f.match(&exchange{method: e.req.method, path: e.req.target, status: e.resp.status})
}

func (r *Requests) write(line string) {
	if _, err := fmt.Fprintln(r.w, line); err != nil && r.err == nil {
		r.err = err
	}
}

// line describes an exchange: as it ended, or, if streaming is set, as a
// response that's still arriving, with the time its headers took.
func (r *Requests) line(e *harEntry, streaming bool) string {
	req, resp := &e.req, &e.resp
	if r.opts.Redact {
		req = req.redacted()
	}
	process := fmt.Sprintf("%s[%d]", e.process, e.pid)
	if e.container != "" {
		process = e.container + " " + process
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s ", r.dim(e.start.Format("15:04:05.000000")), r.title(process))
	if e.reqDir == tracer.Read {
		b.WriteString(r.dim("served "))
	}
	if req.seen {
		u := e.url(req)
		fmt.Fprintf(&b, "%s %s %s", req.method, u.String(), e.version)
	} else {
		fmt.Fprintf(&b, "%s %s", r.warn("(a request from before snoopy)"), e.version)
	}
	b.WriteString(" → ")
	status := fmt.Sprint(resp.status)
	switch {
	case e.reset && !resp.seen:
		status = r.warn("reset before a response")
	case !resp.seen: // its stream ended or was given up on
		status = r.warn("no response seen")
	case resp.status >= 400:
		status = r.bad(status)
	default:
		status = r.ok(status)
	}
	b.WriteString(status)
	ct := headerValue(resp.headers, "content-type")
	if resp.seen && ct != "" {
		b.WriteString(", " + ct)
	}
	if streaming {
		b.WriteString(", " + r.title("streaming") + ", " + r.dim(formatLatency(e.respAt.Sub(e.start))))
		return b.String()
	}
	if resp.seen {
		b.WriteString(", " + cmpOr(e.tunnel, sizeOf(resp)))
		if isEventStream(ct) || resp.events > 0 {
			b.WriteString(", " + fmt.Sprint(resp.events) + " " + plural(resp.events, "event", "events"))
		}
		// A gRPC call's outcome is in its trailers, its HTTP status 200.
		if gs := headerValue(resp.headers, "grpc-status"); gs != "" {
			outcome := strings.TrimSpace("grpc-status " + gs + " " + grpcStatusName(gs))
			if gs != "0" {
				outcome = r.bad(outcome)
			}
			b.WriteString(", " + outcome)
		}
		if e.reset {
			b.WriteString(", " + r.warn("reset"))
		}
	}
	b.WriteString(", " + r.dim(formatLatency(e.end.Sub(e.start))))
	return b.String()
}

// sizeOf describes a response's body as brief does: its length (without
// chunked framing), and decoded if it has a Content-Encoding.
func sizeOf(m *harMessage) string {
	switch {
	case m.status == 101: // no body, but another protocol: what it switched to
		return cmpOr(headerValue(m.headers, "upgrade"), "no body")
	case m.length == 0:
		return "no body"
	case m.encoding != "":
		return fmt.Sprintf("%d bytes (%s, %d decoded)", m.length, m.encoding, m.decoded)
	}
	return fmt.Sprintf("%d bytes", m.length)
}

// headerValue returns the first value of a header, by its name in any case.
func headerValue(headers [][2]string, name string) string {
	for _, hd := range headers {
		if strings.EqualFold(hd[0], name) {
			return hd[1]
		}
	}
	return ""
}
