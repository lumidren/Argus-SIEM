// Package syslog parses RFC 5424 and RFC 3164 syslog headers and frames
// TCP syslog streams (octet counting and newline delimited). It is used by
// the agent's syslog listener and by every parser that receives
// syslog-wrapped payloads.
package syslog

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/lumidren/argus/internal/schema"
)

// Header is the parsed syslog envelope.
type Header struct {
	Priority  int // -1 when absent
	Facility  int
	Severity  int
	Version   int // 1 for RFC 5424, 0 for RFC 3164
	Timestamp time.Time
	Hostname  string
	AppName   string
	ProcID    string
	MsgID     string
	// StructuredData holds RFC 5424 SD-ELEMENTs: id -> param -> value.
	StructuredData map[string]map[string]string
	// Message is the MSG part, with leading BOM/space removed.
	Message string
	// Format is "rfc5424", "rfc3164" or "bare" when no header was found.
	Format string
}

var facilityNames = []string{
	"kernel", "user-level", "mail", "system", "security/authorization", "syslogd", "line printer",
	"network news", "UUCP", "clock", "security/authorization", "FTP", "NTP", "log audit", "log alert",
	"clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

var severityNames = []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}

var logLevels = []string{"emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"}

// FacilityName returns the RFC 5424 facility name.
func FacilityName(f int) string {
	if f >= 0 && f < len(facilityNames) {
		return facilityNames[f]
	}
	return strconv.Itoa(f)
}

// SeverityName returns the RFC 5424 severity name.
func SeverityName(s int) string {
	if s >= 0 && s < len(severityNames) {
		return severityNames[s]
	}
	return strconv.Itoa(s)
}

// LogLevel returns the ECS log.level value for a severity.
func LogLevel(s int) string {
	if s >= 0 && s < len(logLevels) {
		return logLevels[s]
	}
	return ""
}

// ErrNoHeader is returned by Parse when the input has no recognizable syslog
// header; Header.Message then holds the entire input.
var ErrNoHeader = errors.New("syslog: no header")

// Parse parses one syslog message. reference supplies the year for RFC 3164
// timestamps and defaults to time.Now when zero.
func Parse(raw []byte, reference time.Time) (Header, error) {
	h := Header{Priority: -1, Format: "bare"}
	s := strings.TrimRight(string(raw), "\r\n")
	s = strings.TrimLeft(s, " ")
	// Optional leading octet count ("123 <34>1 ...") left by a framer that
	// did not strip it.
	if i := strings.IndexByte(s, ' '); i > 0 && i < 7 && s[0] >= '1' && s[0] <= '9' && isDigits(s[:i]) && i+1 < len(s) && s[i+1] == '<' {
		s = s[i+1:]
	}
	if strings.HasPrefix(s, "<") {
		end := strings.IndexByte(s, '>')
		if end > 1 && end <= 4 {
			if pri, err := strconv.Atoi(s[1:end]); err == nil && pri >= 0 && pri <= 191 {
				h.Priority = pri
				h.Facility = pri / 8
				h.Severity = pri % 8
				s = s[end+1:]
			}
		}
	}
	if len(s) >= 2 && s[0] == '1' && s[1] == ' ' {
		if err := parse5424(&h, s[2:]); err == nil {
			h.Format = "rfc5424"
			return h, nil
		}
	}
	if parse3164(&h, s, reference) {
		h.Format = "rfc3164"
		return h, nil
	}
	h.Message = s
	if h.Priority >= 0 {
		// PRI only (e.g. Cisco/firewall "<134>message") is still a header.
		h.Format = "rfc3164"
		return h, nil
	}
	return h, ErrNoHeader
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parse5424 parses "TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG".
func parse5424(h *Header, s string) error {
	fields := make([]string, 0, 5)
	rest := s
	for len(fields) < 5 {
		rest = strings.TrimLeft(rest, " ")
		if rest == "" {
			return errors.New("syslog: truncated 5424 header")
		}
		i := strings.IndexByte(rest, ' ')
		if i < 0 {
			fields = append(fields, rest)
			rest = ""
			break
		}
		fields = append(fields, rest[:i])
		rest = rest[i+1:]
	}
	if len(fields) < 5 {
		// Allow missing MSGID/SD only if STRUCTURED-DATA starts right away.
		return errors.New("syslog: incomplete 5424 header")
	}
	h.Version = 1
	if fields[0] != "-" {
		t, ok := schema.ParseTime(fields[0])
		if !ok {
			return errors.New("syslog: bad 5424 timestamp")
		}
		h.Timestamp = t
	}
	h.Hostname = nilval(fields[1])
	h.AppName = nilval(fields[2])
	h.ProcID = nilval(fields[3])
	h.MsgID = nilval(fields[4])
	rest = strings.TrimLeft(rest, " ")
	if strings.HasPrefix(rest, "-") {
		rest = strings.TrimLeft(rest[1:], " ")
	} else if strings.HasPrefix(rest, "[") {
		sd, remaining, err := parseSD(rest)
		if err != nil {
			return err
		}
		h.StructuredData = sd
		rest = strings.TrimLeft(remaining, " ")
	}
	h.Message = strings.TrimPrefix(rest, "\xef\xbb\xbf")
	return nil
}

func nilval(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// parseSD parses one or more [id k="v" ...] elements.
func parseSD(s string) (map[string]map[string]string, string, error) {
	out := make(map[string]map[string]string)
	for strings.HasPrefix(s, "[") {
		s = s[1:]
		end := strings.IndexAny(s, " ]")
		if end < 0 {
			return nil, "", errors.New("syslog: bad structured data")
		}
		id := s[:end]
		params := make(map[string]string)
		s = s[end:]
		for {
			s = strings.TrimLeft(s, " ")
			if s == "" {
				return nil, "", errors.New("syslog: unterminated structured data")
			}
			if s[0] == ']' {
				s = s[1:]
				break
			}
			eq := strings.IndexByte(s, '=')
			if eq < 0 || eq+1 >= len(s) || s[eq+1] != '"' {
				return nil, "", errors.New("syslog: bad sd-param")
			}
			name := s[:eq]
			s = s[eq+2:]
			var b strings.Builder
			closed := false
			for i := 0; i < len(s); i++ {
				c := s[i]
				if c == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i++
					continue
				}
				if c == '"' {
					s = s[i+1:]
					closed = true
					break
				}
				b.WriteByte(c)
			}
			if !closed {
				return nil, "", errors.New("syslog: unterminated sd-param value")
			}
			params[name] = b.String()
		}
		out[id] = params
	}
	return out, s, nil
}

// parse3164 handles the BSD format and its common dialects:
//
//	Mmm dd hh:mm:ss host app[pid]: msg
//	Mmm dd hh:mm:ss host app: msg
//	Mmm dd hh:mm:ss host msg                 (no app)
//	Mmm dd hh:mm:ss msg                      (no host, e.g. local logger)
//	2024-01-02T03:04:05.000Z host app[pid]: msg   (ISO timestamp, rsyslog default)
//	Mmm dd yyyy hh:mm:ss host app: msg       (with year)
func parse3164(h *Header, s string, reference time.Time) bool {
	var ts time.Time
	rest := s
	ok := false
	// ISO timestamp first token
	if i := strings.IndexByte(rest, ' '); i > 0 {
		if t, good := schema.ParseTime(rest[:i]); good && len(rest[:i]) >= 19 && (rest[4] == '-' || rest[4] == '/') {
			ts, ok = t, true
			rest = rest[i+1:]
		}
	}
	if !ok && len(rest) >= 15 && isMonth(rest[:3]) {
		// Tokenize: Mmm dd [yyyy] hh:mm:ss[.frac]
		toks := strings.Fields(rest)
		if len(toks) >= 3 && isDigits(toks[1]) && len(toks[1]) <= 2 {
			if len(toks) >= 4 && len(toks[2]) == 4 && isDigits(toks[2]) && strings.Contains(toks[3], ":") {
				if t, err := time.Parse("Jan _2 2006 15:04:05", strings.Join(toks[:4], " ")); err == nil {
					ts, ok = t.UTC(), true
					rest = afterTokens(rest, 4)
				}
			} else if strings.Contains(toks[2], ":") {
				timeTok := toks[2]
				if i := strings.IndexByte(timeTok, '.'); i > 0 {
					timeTok = timeTok[:i]
				}
				if t, good := schema.ParseSyslogTime(toks[0]+" "+toks[1]+" "+timeTok, reference); good {
					ts, ok = t, true
					rest = afterTokens(rest, 3)
				}
			}
		}
	}
	if !ok {
		return false
	}
	h.Timestamp = ts
	// Hostname: next token unless it looks like "app[pid]:" / "app:" (no host).
	host, after := nextToken(rest)
	if host == "" {
		h.Message = ""
		return true
	}
	if !strings.HasSuffix(host, ":") && !strings.Contains(host, "[") {
		h.Hostname = host
		rest = after
	}
	// Tag: "app[pid]:" or "app:" — must end with ':' within the first token.
	tag, after := nextToken(rest)
	if strings.HasSuffix(tag, ":") {
		tag = strings.TrimSuffix(tag, ":")
		if lb := strings.IndexByte(tag, '['); lb > 0 && strings.HasSuffix(tag, "]") {
			h.AppName = tag[:lb]
			h.ProcID = tag[lb+1 : len(tag)-1]
		} else {
			h.AppName = tag
		}
		rest = after
	} else if lb := strings.IndexByte(tag, '['); lb > 0 && strings.HasSuffix(tag, "]:") {
		h.AppName = tag[:lb]
		h.ProcID = tag[lb+1 : len(tag)-2]
		rest = after
	}
	h.Message = strings.TrimLeft(rest, " ")
	return true
}

// afterTokens returns s with the first n whitespace-separated tokens removed.
func afterTokens(s string, n int) string {
	s = strings.TrimLeft(s, " ")
	for ; n > 0; n-- {
		i := strings.IndexByte(s, ' ')
		if i < 0 {
			return ""
		}
		s = strings.TrimLeft(s[i+1:], " ")
	}
	return s
}

func nextToken(s string) (tok, rest string) {
	s = strings.TrimLeft(s, " ")
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

func isMonth(s string) bool {
	switch s {
	case "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec":
		return true
	}
	return false
}

// ---- framing ----

// ErrFrameTooLarge is returned when an octet count exceeds MaxFrame.
var ErrFrameTooLarge = errors.New("syslog: frame exceeds maximum size")

// MaxFrame bounds a single TCP syslog frame.
const MaxFrame = 1 << 20

// Frame extracts the next complete message from buf, supporting RFC 6587
// octet counting ("123 <34>...") and non-transparent framing (newline).
// It returns the message, the number of bytes consumed, and ok=false when
// more data is needed.
func Frame(buf []byte) (msg []byte, consumed int, ok bool, err error) {
	if len(buf) == 0 {
		return nil, 0, false, nil
	}
	if buf[0] >= '1' && buf[0] <= '9' {
		// possible octet count
		i := 0
		for i < len(buf) && i < 8 && buf[i] >= '0' && buf[i] <= '9' {
			i++
		}
		if i < len(buf) && buf[i] == ' ' {
			n, _ := strconv.Atoi(string(buf[:i]))
			if n > MaxFrame {
				return nil, 0, false, ErrFrameTooLarge
			}
			start := i + 1
			if len(buf) < start+n {
				return nil, 0, false, nil
			}
			return buf[start : start+n], start + n, true, nil
		}
	}
	nl := bytes.IndexByte(buf, '\n')
	if nl < 0 {
		if len(buf) > MaxFrame {
			return nil, 0, false, ErrFrameTooLarge
		}
		return nil, 0, false, nil
	}
	line := bytes.TrimRight(buf[:nl], "\r")
	return line, nl + 1, true, nil
}

// Apply writes the header's fields onto an event using ECS log.syslog.*,
// host.name, process.name and process.pid.
func Apply(e *schema.Event, h Header) {
	if h.Priority >= 0 {
		e.Set("log.syslog.priority", int64(h.Priority))
		e.Set("log.syslog.facility.code", int64(h.Facility))
		e.Set("log.syslog.facility.name", FacilityName(h.Facility))
		e.Set("log.syslog.severity.code", int64(h.Severity))
		e.Set("log.syslog.severity.name", SeverityName(h.Severity))
		e.Set("log.level", LogLevel(h.Severity))
	}
	if h.Version > 0 {
		e.Set("log.syslog.version", int64(h.Version))
	}
	if h.Hostname != "" {
		e.Set("log.syslog.hostname", h.Hostname)
		e.Set(schema.FieldHostName, strings.ToLower(h.Hostname))
	}
	if h.AppName != "" {
		e.Set("log.syslog.appname", h.AppName)
		e.Set("process.name", h.AppName)
	}
	if h.ProcID != "" {
		e.Set("log.syslog.procid", h.ProcID)
		if n, err := strconv.ParseInt(h.ProcID, 10, 64); err == nil {
			e.Set("process.pid", n)
		}
	}
	if h.MsgID != "" {
		e.Set("log.syslog.msgid", h.MsgID)
	}
	for id, params := range h.StructuredData {
		for k, v := range params {
			e.Set("log.syslog.structured_data."+sanitizeKey(id)+"."+sanitizeKey(k), v)
		}
	}
	if !h.Timestamp.IsZero() {
		e.SetTimestamp(h.Timestamp)
	}
}

func sanitizeKey(k string) string {
	return strings.NewReplacer(".", "_", "@", "_", " ", "_").Replace(k)
}
