// Package linux parses Linux authentication syslog (sshd, sudo, su, PAM,
// logind, account management), auditd records and journald JSON exports into
// ECS per docs/SCHEMA.md §5.
package linux

import (
	"bytes"
	"errors"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
	"github.com/lumidren/argus/internal/syslog"
)

// Parser implements parsers.Parser.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string    { return "linux" }
func (*Parser) Version() string { return "1.0.0" }
func (*Parser) Datasets() []string {
	return []string{"linux.auth", "linux.auditd", "linux.journald"}
}

// authPrograms are the syslog app-names routed through the auth matcher.
var authPrograms = map[string]bool{
	"sshd": true, "sudo": true, "su": true, "login": true, "systemd-logind": true, "useradd": true,
	"usermod": true, "userdel": true, "groupadd": true, "groupdel": true, "passwd": true, "chage": true,
	"gdm-password": true, "CRON": true, "cron": true, "polkitd": true, "unix_chkpwd": true, "chpasswd": true,
	"gpasswd": true, "groupmod": true, "doas": true,
}

var authMessagePrefixes = []string{
	"Accepted ", "Failed password", "Failed publickey", "Invalid user", "pam_unix(", "Connection closed by",
	"Disconnected from", "FAILED SU", "new user:", "new group:", "session opened for user", "session closed for user",
}

// ErrUnmatchedAuth marks an auth-program line that matched no known pattern;
// the event is still emitted (partial parse).
var ErrUnmatchedAuth = errors.New("linux: auth message matched no known pattern")

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, hints map[string]string) bool {
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 {
		return false
	}
	if bytes.HasPrefix(b, []byte("type=")) && bytes.Contains(b, []byte("msg=audit(")) {
		return true
	}
	if b[0] == '{' {
		if bytes.Contains(b, []byte(`"__REALTIME_TIMESTAMP"`)) || bytes.Contains(b, []byte(`"_SYSTEMD_UNIT"`)) || bytes.Contains(b, []byte(`"SYSLOG_IDENTIFIER"`)) {
			return true
		}
		return bytes.Contains(b, []byte(`"messages"`)) && bytes.Contains(b, []byte(`"sequence"`))
	}
	if hints != nil && authPrograms[hints["syslog_app"]] {
		return true
	}
	h, err := syslog.Parse(b, parsers.Now())
	if err != nil && h.Format == "bare" {
		return false
	}
	if authPrograms[h.AppName] {
		return true
	}
	for _, pre := range authMessagePrefixes {
		if strings.HasPrefix(h.Message, pre) {
			return true
		}
	}
	return false
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	b := bytes.TrimLeft(in.Raw, " \t\r\n")
	if len(b) == 0 {
		return nil, errors.New("linux: empty record")
	}
	switch {
	case bytes.HasPrefix(b, []byte("type=")):
		return parseAuditText(in, string(b))
	case b[0] == '{' && bytes.Contains(b, []byte(`"messages"`)) && bytes.Contains(b, []byte(`"sequence"`)):
		return parseGoAudit(in, b)
	case b[0] == '{':
		e, err := parseJournald(in, b)
		if e == nil {
			return nil, err
		}
		return e, err
	}
	return parseAuthLine(in, strings.TrimRight(string(b), "\r\n"))
}

func parseAuthLine(in *parsers.Input, raw string) ([]*schema.Event, error) {
	e := parsers.Base(in, "linux", "linux.auth")
	msg := raw
	app := in.Hint("syslog_app")
	h, err := syslog.Parse([]byte(raw), in.ReceivedAt)
	if err == nil || h.Format != "bare" {
		syslog.Apply(e, h)
		msg = h.Message
		if h.AppName != "" {
			app = h.AppName
		}
	} else if app != "" {
		e.Set("process.name", app)
	}
	e.Set(schema.FieldMessage, msg)
	if !matchAuth(e, app, msg) {
		return []*schema.Event{e}, ErrUnmatchedAuth
	}
	return []*schema.Event{e}, nil
}
