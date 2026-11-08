// Package apache parses Apache httpd access logs (combined, vhost_combined,
// common, combined with %D) and error logs (2.2 and 2.4 formats) into ECS per
// docs/SCHEMA.md §8.
//
// Plain combined access lines are format-identical to Nginx; the registry
// sniffs nginx first, so this parser only claims a combined line by sniffing
// when a hint (kind/path) or an Apache-only feature (vhost:port prefix,
// trailing %D integer, error-log syntax) says it is Apache.
package apache

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/parsers/nginx"
	"github.com/lumidren/argus/internal/schema"
	"github.com/lumidren/argus/internal/syslog"
)

// Parser implements parsers.Parser.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string       { return "apache" }
func (*Parser) Version() string    { return "1.0.0" }
func (*Parser) Datasets() []string { return []string{"apache.access", "apache.error"} }

var (
	// 2.4: [Sat Jun 01 09:15:32.123456 2024] [core:error] [pid 1234:tid 140000] [client 1.2.3.4:5678] AH00128: msg
	// 2.2: [Sat Jun 01 09:15:32 2024] [error] [client 1.2.3.4] msg
	errorRe  = regexp.MustCompile(`^\[(?P<time>[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] \[(?:(?P<module>[\w-]+):)?(?P<level>\w+)\](?: \[pid (?P<pid>\d+)(?::tid (?P<tid>\d+))?\])?(?: \[client (?P<client>[^\]]+)\])? (?:(?P<code>AH\d{5}): )?(?P<msg>.*)$`)
	commonRe = regexp.MustCompile(`^(?P<remote>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)\s*$`)
	vhostRe  = regexp.MustCompile(`^[^\s:]+:\d+ \S+ \S+ \S+ \[`)
	trailDRe = regexp.MustCompile(`^(.*") (\d+)\s*$`)
	fileRe   = regexp.MustCompile(`(?:File does not exist|script '?|client denied by server configuration): ([^,']+)`)
)

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, hints map[string]string) bool {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return false
	}
	if errorRe.MatchString(s) {
		return true
	}
	if hints != nil {
		if hints["kind"] == "apache" || strings.Contains(hints["path"], "apache") || strings.Contains(hints["path"], "httpd") {
			return true
		}
	}
	return vhostRe.MatchString(s) || (strings.Contains(s, `] "`) && trailDRe.MatchString(s) && strings.Contains(s, " ["))
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	raw := strings.TrimRight(string(in.Raw), "\r\n")
	body := raw
	h, herr := syslog.Parse([]byte(raw), in.ReceivedAt)
	hasHdr := herr == nil && h.Format != "bare" && !strings.HasPrefix(strings.TrimSpace(raw), "[")
	if hasHdr {
		body = h.Message
	}
	var e *schema.Event
	var err error
	if errorRe.MatchString(body) {
		e, err = parseError(in, body)
	} else {
		e, err = parseAccess(in, body)
	}
	if e == nil {
		return nil, err
	}
	if hasHdr {
		ts := e.String(schema.FieldTimestamp)
		syslog.Apply(e, h)
		e.Set(schema.FieldTimestamp, ts)
	}
	return []*schema.Event{e}, nil
}

func parseAccess(in *parsers.Input, line string) (*schema.Event, error) {
	if m := trailDRe.FindStringSubmatch(line); m != nil {
		if e, err := nginx.ParseCombined(in, m[1], "apache", "apache.access"); err == nil {
			if us, err := strconv.ParseInt(m[2], 10, 64); err == nil {
				e.Set("event.duration", us*1000)
			}
			e.Set(schema.FieldMessage, line)
			return e, nil
		}
	}
	if e, err := nginx.ParseCombined(in, line, "apache", "apache.access"); err == nil {
		return e, nil
	}
	m := commonRe.FindStringSubmatch(line)
	if m == nil {
		return nil, errors.New("apache: line matches no access log format")
	}
	// Re-use the combined parser by appending empty referrer/agent fields.
	e, err := nginx.ParseCombined(in, line+` "-" "-"`, "apache", "apache.access")
	if err != nil {
		return nil, err
	}
	e.Set(schema.FieldMessage, line)
	return e, nil
}

func parseError(in *parsers.Input, line string) (*schema.Event, error) {
	m := errorRe.FindStringSubmatch(line)
	if m == nil {
		return nil, errors.New("apache: not an error line")
	}
	get := func(n string) string { return m[errorRe.SubexpIndex(n)] }
	e := parsers.Base(in, "apache", "apache.error")
	e.SetCategory(schema.CategoryWeb)
	e.SetTypes(schema.TypeError)
	e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	e.Set(schema.FieldEventAction, "error")
	e.Set("process.name", "httpd")
	ts := get("time")
	// "Sat Jun 01 09:15:32.123456 2024" -> drop weekday for parsing
	if i := strings.IndexByte(ts, ' '); i > 0 {
		parsers.SetTime(e, schema.FieldTimestamp, "Mon"+ts[i:])
		if !e.Has(schema.FieldTimestamp) {
			parsers.SetTime(e, schema.FieldTimestamp, ts)
		}
	}
	e.Set("log.level", strings.ToLower(get("level")))
	e.Set("apache.error.module", get("module"))
	parsers.SetInt(e, "process.pid", get("pid"))
	parsers.SetInt(e, "process.thread.id", get("tid"))
	if c := get("client"); c != "" {
		host, port := c, ""
		if i := strings.LastIndexByte(c, ':'); i > 0 && strings.Count(c, ":") == 1 {
			host, port = c[:i], c[i+1:]
		}
		parsers.SetIP(e, "source.ip", host)
		parsers.SetPort(e, "source.port", port)
	}
	e.Set("apache.error.error_code", get("code"))
	msg := get("msg")
	if i := strings.Index(msg, ", referer: "); i >= 0 {
		e.Set("http.request.referrer", strings.TrimSpace(msg[i+len(", referer: "):]))
		msg = msg[:i]
	}
	if fm := fileRe.FindStringSubmatch(msg); fm != nil {
		e.Set("file.path", strings.TrimSpace(fm[1]))
	}
	e.Set(schema.FieldMessage, msg)
	return e, nil
}
