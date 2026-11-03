// Package nginx parses Nginx access logs (NCSA combined, combined with
// timing extensions, JSON access logs) and Nginx error logs into ECS per
// docs/SCHEMA.md §8. The Apache parser reuses the combined-format routines.
package nginx

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
	"github.com/lumidren/argus/internal/syslog"
)

// Parser implements parsers.Parser for Nginx.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string    { return "nginx" }
func (*Parser) Version() string { return "1.0.0" }
func (*Parser) Datasets() []string {
	return []string{"nginx.access", "nginx.error"}
}

// combinedRe matches the NCSA combined format with optional trailing
// request_time / upstream_response_time (nginx "main_ext") and an optional
// leading "vhost:port " prefix (Apache vhost_combined).
var combinedRe = regexp.MustCompile(
	`^(?:(?P<vhost>[^\s:]+):(?P<vport>\d+)\s+)?` +
		`(?P<remote>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+` +
		`"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)` +
		`(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)")?` +
		`(?:\s+"(?P<xff>[^"]*)")?` +
		`(?:\s+(?P<rt>\d+\.\d+))?(?:\s+(?P<urt>[\d.,\s-]+))?\s*$`)

var errorRe = regexp.MustCompile(
	`^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<cid>\d+) )?(?P<msg>.*)$`)

// Detect accepts combined access lines, nginx error lines and nginx JSON
// access logs (identified by the "remote_addr"/"request" keys).
func (p *Parser) Detect(raw []byte, hints map[string]string) bool {
	if hints != nil && (hints["kind"] == "nginx" || strings.Contains(hints["path"], "nginx")) {
		return true
	}
	s := strings.TrimSpace(string(raw))
	if len(s) == 0 {
		return false
	}
	if parsers.LooksLikeJSONObject(raw) {
		return strings.Contains(s, `"remote_addr"`) && (strings.Contains(s, `"request"`) || strings.Contains(s, `"request_uri"`))
	}
	if errorRe.MatchString(s) {
		return true
	}
	return looksLikeCombined(s)
}

func looksLikeCombined(s string) bool {
	// quick structural check: has " [dd/Mon/yyyy:" and a quoted request
	i := strings.Index(s, " [")
	if i < 0 {
		return false
	}
	j := strings.Index(s[i:], "] \"")
	if j < 0 {
		return false
	}
	ts := s[i+2 : i+j]
	return len(ts) >= 20 && ts[2] == '/' && ts[6] == '/' && ts[11] == ':'
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	raw := strings.TrimRight(string(in.Raw), "\r\n")
	body := raw
	var hdr syslog.Header
	hasHdr := false
	if h, err := syslog.Parse([]byte(raw), in.ReceivedAt); err == nil && h.Format != "bare" {
		hdr, hasHdr = h, true
		body = h.Message
	}
	var e *schema.Event
	var err error
	switch {
	case parsers.LooksLikeJSONObject([]byte(body)):
		e, err = parseJSONAccess(in, body)
	case errorRe.MatchString(body):
		e, err = parseError(in, body)
	default:
		e, err = ParseCombined(in, body, "nginx", "nginx.access")
	}
	if e == nil {
		return nil, err
	}
	if hasHdr {
		applyHeader(e, hdr)
	}
	return []*schema.Event{e}, err
}

func applyHeader(e *schema.Event, h syslog.Header) {
	// The access line carries its own timestamp; keep it and only take
	// host/process from the syslog header.
	ts := e.String(schema.FieldTimestamp)
	syslog.Apply(e, h)
	if ts != "" {
		e.Set(schema.FieldTimestamp, ts)
	}
	// syslog Apply sets process.name to the app name (nginx), which is correct.
}

// ErrNotAccessLine is returned when a line does not match the combined format.
var ErrNotAccessLine = errors.New("nginx: line does not match combined log format")

// ParseCombined parses an NCSA combined line into an event with the given
// module/dataset. It is exported for the Apache parser.
func ParseCombined(in *parsers.Input, line, module, dataset string) (*schema.Event, error) {
	m := combinedRe.FindStringSubmatch(line)
	if m == nil {
		return nil, ErrNotAccessLine
	}
	get := func(name string) string {
		i := combinedRe.SubexpIndex(name)
		if i < 0 || i >= len(m) {
			return ""
		}
		return m[i]
	}
	e := parsers.Base(in, module, dataset)
	e.SetCategory(schema.CategoryWeb)
	e.SetTypes(schema.TypeAccess)
	if !parsers.SetTime(e, schema.FieldTimestamp, get("time")) {
		return nil, errors.New("nginx: unparsable timestamp " + get("time"))
	}
	setRemote(e, get("remote"))
	if u := get("user"); u != "-" && u != "" {
		e.Set("user.name", u)
	}
	if v := get("vhost"); v != "" {
		e.Set("url.domain", strings.ToLower(v))
		parsers.SetPort(e, "destination.port", get("vport"))
	}
	setRequest(e, get("request"))
	status, _ := strconv.Atoi(get("status"))
	e.Set("http.response.status_code", int64(status))
	e.Set(schema.FieldEventOutcome, parsers.OutcomeFromBool(status < 400))
	if b := get("bytes"); b != "-" && b != "" {
		parsers.SetInt(e, "http.response.body.bytes", b)
	} else {
		e.Set("http.response.body.bytes", int64(0))
	}
	if r := get("referrer"); r != "-" && r != "" {
		e.Set("http.request.referrer", r)
	}
	if ua := get("agent"); ua != "-" && ua != "" {
		e.Set("user_agent.original", ua)
	}
	if xff := get("xff"); xff != "" && xff != "-" {
		setForwarded(e, xff)
	}
	if rt := get("rt"); rt != "" {
		if f, err := strconv.ParseFloat(rt, 64); err == nil {
			e.Set("event.duration", schema.SecondsToNanos(f))
		}
	}
	if urt := strings.TrimSpace(get("urt")); urt != "" && urt != "-" {
		e.Set(module+".access.upstream_response_time", urt)
	}
	e.Set(schema.FieldEventAction, "http-request")
	e.Set(schema.FieldMessage, line)
	return e, nil
}

func setRemote(e *schema.Event, remote string) {
	if remote == "" || remote == "-" {
		return
	}
	e.Set("source.address", remote)
	parsers.SetIP(e, "source.ip", remote)
}

// setRequest splits `METHOD /path?query HTTP/1.1`. Malformed request lines
// (scanner probes, raw TLS bytes) are stored verbatim in url.original.
func setRequest(e *schema.Event, req string) {
	if req == "" || req == "-" {
		return
	}
	parts := strings.Fields(req)
	switch len(parts) {
	case 3:
		e.Set("http.request.method", strings.ToUpper(parts[0]))
		parsers.SetURL(e, parts[1])
		if strings.HasPrefix(strings.ToUpper(parts[2]), "HTTP/") {
			e.Set("http.version", parts[2][5:])
		}
	case 2:
		e.Set("http.request.method", strings.ToUpper(parts[0]))
		parsers.SetURL(e, parts[1])
	default:
		e.Set("url.original", req)
		e.AddTag("malformed_request_line")
	}
}

// setForwarded records the X-Forwarded-For chain; the first public hop
// becomes client.ip.
func setForwarded(e *schema.Event, xff string) {
	var chain []string
	for _, hop := range strings.Split(xff, ",") {
		if ip := parsers.NormalizeIP(hop); ip != "" {
			chain = append(chain, ip)
		}
	}
	if len(chain) == 0 {
		return
	}
	e.Set("network.forwarded_ip", chain)
	for _, ip := range chain {
		if parsers.IsPublicIP(ip) {
			e.Set("client.ip", ip)
			return
		}
	}
	e.Set("client.ip", chain[0])
}

func parseJSONAccess(in *parsers.Input, body string) (*schema.Event, error) {
	obj, err := parsers.DecodeJSON([]byte(body))
	if err != nil {
		return nil, err
	}
	e := parsers.Base(in, "nginx", "nginx.access")
	e.SetCategory(schema.CategoryWeb)
	e.SetTypes(schema.TypeAccess)
	for _, k := range []string{"time_iso8601", "time_local", "@timestamp", "timestamp", "time", "msec"} {
		if parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(obj, k)) {
			break
		}
	}
	setRemote(e, parsers.GetString(obj, "remote_addr"))
	if u := parsers.GetString(obj, "remote_user"); u != "" && u != "-" {
		e.Set("user.name", u)
	}
	if req := parsers.GetString(obj, "request"); req != "" {
		setRequest(e, req)
	} else {
		e.Set("http.request.method", strings.ToUpper(parsers.GetString(obj, "request_method")))
		parsers.SetURL(e, parsers.GetString(obj, "request_uri"))
		if proto := parsers.GetString(obj, "server_protocol"); strings.HasPrefix(proto, "HTTP/") {
			e.Set("http.version", proto[5:])
		}
	}
	if st, ok := parsers.GetInt(obj, "status"); ok {
		e.Set("http.response.status_code", st)
		e.Set(schema.FieldEventOutcome, parsers.OutcomeFromBool(st < 400))
	}
	if b, ok := parsers.GetInt(obj, "body_bytes_sent"); ok {
		e.Set("http.response.body.bytes", b)
	} else if b, ok := parsers.GetInt(obj, "bytes_sent"); ok {
		e.Set("http.response.body.bytes", b)
	}
	if b, ok := parsers.GetInt(obj, "request_length"); ok {
		e.Set("http.request.bytes", b)
	}
	if r := parsers.GetString(obj, "http_referer"); r != "" && r != "-" {
		e.Set("http.request.referrer", r)
	}
	if ua := parsers.GetString(obj, "http_user_agent"); ua != "" && ua != "-" {
		e.Set("user_agent.original", ua)
	}
	if xff := parsers.GetString(obj, "http_x_forwarded_for"); xff != "" && xff != "-" {
		setForwarded(e, xff)
	}
	if h := parsers.GetString(obj, "host"); h != "" {
		e.Set("url.domain", strings.ToLower(h))
	}
	if sn := parsers.GetString(obj, "server_name"); sn != "" {
		e.Set("nginx.access.server_name", sn)
	}
	if rt := parsers.GetString(obj, "request_time"); rt != "" {
		if f, err := strconv.ParseFloat(rt, 64); err == nil {
			e.Set("event.duration", schema.SecondsToNanos(f))
		}
	}
	for _, k := range []string{"upstream_response_time", "upstream_addr", "upstream_status", "request_id", "ssl_protocol", "ssl_cipher", "scheme", "server_port", "connection", "connection_requests", "gzip_ratio", "sent_http_content_type"} {
		if v := parsers.GetString(obj, k); v != "" && v != "-" {
			e.Set("nginx.access."+k, v)
		}
	}
	if sp := parsers.GetString(obj, "server_port"); sp != "" {
		parsers.SetPort(e, "destination.port", sp)
	}
	if sch := parsers.GetString(obj, "scheme"); sch != "" {
		e.Set("url.scheme", sch)
	}
	if ct := parsers.GetString(obj, "sent_http_content_type"); ct != "" {
		e.Set("http.response.mime_type", strings.SplitN(ct, ";", 2)[0])
	}
	e.Set(schema.FieldEventAction, "http-request")
	e.Set(schema.FieldMessage, body)
	return e, nil
}

func parseError(in *parsers.Input, body string) (*schema.Event, error) {
	m := errorRe.FindStringSubmatch(body)
	if m == nil {
		return nil, errors.New("nginx: not an error line")
	}
	get := func(name string) string { return m[errorRe.SubexpIndex(name)] }
	e := parsers.Base(in, "nginx", "nginx.error")
	e.SetCategory(schema.CategoryWeb)
	e.SetTypes(schema.TypeError)
	parsers.SetTime(e, schema.FieldTimestamp, get("time"))
	e.Set("log.level", strings.ToLower(get("level")))
	parsers.SetInt(e, "process.pid", get("pid"))
	parsers.SetInt(e, "process.thread.id", get("tid"))
	parsers.SetInt(e, "nginx.error.connection_id", get("cid"))
	e.Set("process.name", "nginx")
	msg := get("msg")
	e.Set(schema.FieldMessage, msg)
	// Trailing context: ", client: 1.2.3.4, server: example.com, request: "GET / HTTP/1.1", upstream: "...", host: "example.com", referrer: "..."
	main, ctx, _ := strings.Cut(msg, ", client: ")
	e.Set("nginx.error.message", main)
	if ctx != "" {
		ctx = "client: " + ctx
		for _, part := range splitErrorContext(ctx) {
			k, v, ok := strings.Cut(part, ": ")
			if !ok {
				continue
			}
			v = strings.Trim(strings.TrimSpace(v), `"`)
			switch k {
			case "client":
				parsers.SetIP(e, "source.ip", v)
			case "server":
				e.Set("destination.domain", strings.ToLower(v))
			case "request":
				setRequest(e, v)
			case "host":
				e.Set("url.domain", strings.ToLower(strings.SplitN(v, ":", 2)[0]))
			case "referrer":
				e.Set("http.request.referrer", v)
			case "upstream":
				e.Set("nginx.error.upstream", v)
			}
		}
	}
	e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	e.Set(schema.FieldEventAction, "error")
	return e, nil
}

// splitErrorContext splits `k: v, k2: "quoted, with comma", ...` on commas
// outside quotes.
func splitErrorContext(s string) []string {
	var out []string
	var b strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQ = !inQ
			b.WriteByte(c)
		case c == ',' && !inQ:
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	if b.Len() > 0 {
		out = append(out, strings.TrimSpace(b.String()))
	}
	return out
}
