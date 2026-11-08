// Package generic is the catch-all parser (docs/SCHEMA.md §19). It is tried
// last by the registry and accepts any non-empty record: an optional syslog
// header is stripped, then the body is classified as CEF, LEEF, JSON, syslog
// text or plain text.
package generic

import (
	"bytes"
	"errors"
	"regexp"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
	"github.com/lumidren/argus/internal/syslog"
)

// Parser implements parsers.Parser.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string    { return "generic" }
func (*Parser) Version() string { return "1.0.0" }
func (*Parser) Datasets() []string {
	return []string{"generic.json", "generic.cef", "generic.leef", "generic.syslog", "generic.text"}
}

// ErrEmpty is returned for blank input.
var ErrEmpty = errors.New("generic: empty record")

// Detect accepts any non-empty record.
func (*Parser) Detect(raw []byte, _ map[string]string) bool {
	return len(bytes.TrimSpace(raw)) > 0
}

// ciscoRe matches "%ASA-6-302013: text" style prefixes, optionally preceded by
// a sequence number, '*' and a device timestamp ending in ':'.
var ciscoRe = regexp.MustCompile(`^(?:\d+:\s*)?(?:\*?[A-Za-z]{3}\s+\d+\s+[\d:.]+(?:\s+[A-Z]{2,5})?:\s*)?%([A-Za-z0-9_]+)-(\d)-([A-Za-z0-9_]+):\s*(.*)$`)

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	raw := strings.TrimRight(string(in.Raw), "\r\n")
	if strings.TrimSpace(raw) == "" {
		return nil, ErrEmpty
	}
	hdr, herr := syslog.Parse([]byte(raw), in.ReceivedAt)
	hasHdr := herr == nil && hdr.Format != "bare"
	body := raw
	if hasHdr {
		body = hdr.Message
	}
	trimmed := strings.TrimLeft(body, " \t")
	var e *schema.Event
	var err error
	switch {
	case strings.HasPrefix(trimmed, "CEF:"):
		e, err = parseCEF(in, trimmed)
	case strings.HasPrefix(trimmed, "LEEF:"):
		e, err = parseLEEF(in, trimmed)
	case parsers.LooksLikeJSONObject([]byte(trimmed)):
		e, err = parseJSON(in, trimmed)
	case hasHdr:
		e = parseSyslogText(in, trimmed)
	default:
		e = parsers.Base(in, "generic", "generic.text")
		e.Set(schema.FieldMessage, trimmed)
	}
	if e == nil {
		return nil, err
	}
	if hasHdr {
		// The payload's own timestamp wins over the relay's header.
		ts := e.String(schema.FieldTimestamp)
		host := e.String(schema.FieldHostName)
		level := e.String("log.level")
		syslog.Apply(e, hdr)
		if level != "" {
			e.Set("log.level", level)
		}
		if ts != "" {
			e.Set(schema.FieldTimestamp, ts)
		}
		if host != "" {
			e.Set(schema.FieldHostName, host)
		}
	}
	return []*schema.Event{e}, err
}

func parseSyslogText(in *parsers.Input, body string) *schema.Event {
	e := parsers.Base(in, "generic", "generic.syslog")
	e.Set(schema.FieldMessage, body)
	if m := ciscoRe.FindStringSubmatch(body); m != nil {
		sev, _ := parsers.ParseInt(m[2])
		e.Set("generic.syslog.cisco.facility", m[1])
		e.Set("generic.syslog.cisco.severity", sev)
		e.Set("generic.syslog.cisco.mnemonic", m[3])
		e.Set(schema.FieldEventCode, m[3])
		e.Set(schema.FieldMessage, m[4])
		e.Set("log.level", syslog.LogLevel(int(sev)))
	}
	return e
}

// severityFromNumber maps a 0–10 vendor severity to the ECS 0–100 scale.
func severityFromNumber(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if n, ok := parsers.ParseInt(s); ok && n >= 0 && n <= 10 {
		return n * 10, true
	}
	switch strings.ToLower(s) {
	case "unknown":
		return 0, false
	case "low":
		return 25, true
	case "medium":
		return 50, true
	case "high":
		return 75, true
	case "very-high", "very high", "critical":
		return 100, true
	}
	return 0, false
}
