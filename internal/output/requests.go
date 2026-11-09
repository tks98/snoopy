package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/tks98/snoopy/v2/internal/tracer"
)

// Requests prints one line per HTTP exchange, a request and its response,
// once the response has ended: what an API's caller or server wants to
// see, where the other printers show each TLS call, of which an exchange
// takes several. It pairs them as HAR does (on an HTTP/1.x connection in
// order, on HTTP/2 and HTTP/3 by stream), keeping no bodies, only their
// sizes. A response whose body ends with its connection, or that hasn't
// ended when snoopy stops, isn't shown.
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

func (r *Requests) print(e *harEntry) {
	req, resp := &e.req, &e.resp
	if f := r.opts.Filter; f != nil && !f.match(&exchange{method: req.method, path: req.target, status: resp.status}) {
		r.filtered++
		return
	}
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
	case resp.status >= 400:
		status = r.bad(status)
	default:
		status = r.ok(status)
	}
	b.WriteString(status)
	if resp.seen {
		if ct := headerValue(resp.headers, "content-type"); ct != "" {
			b.WriteString(", " + ct)
		}
		b.WriteString(", " + sizeOf(resp))
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
	r.shown++
	if _, err := fmt.Fprintln(r.w, b.String()); err != nil && r.err == nil {
		r.err = err
	}
}

// sizeOf describes a response's body as brief does: its length (without
// chunked framing), and decoded if it has a Content-Encoding.
func sizeOf(m *harMessage) string {
	switch {
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
