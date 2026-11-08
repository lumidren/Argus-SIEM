package linux

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
	"github.com/lumidren/argus/internal/syslog"
)

var errNoJournalMessage = errors.New("linux: journald record has no MESSAGE")

func timeOf(secs, millis int64) time.Time {
	return time.Unix(secs, millis*int64(time.Millisecond)).UTC()
}

func parseJournald(in *parsers.Input, b []byte) ([]*schema.Event, error) {
	obj, err := parsers.DecodeJSON(b)
	if err != nil {
		return nil, err
	}
	msg := parsers.GetString(obj, "MESSAGE")
	if msg == "" {
		// MESSAGE may be a byte array for binary messages.
		if arr := parsers.GetSlice(obj, "MESSAGE"); arr != nil {
			var sb strings.Builder
			for _, x := range arr {
				if n, ok := toInt(x); ok && n >= 0 && n < 256 {
					sb.WriteByte(byte(n))
				}
			}
			msg = sb.String()
		}
	}
	if msg == "" {
		return nil, errNoJournalMessage
	}
	// Audit records captured by journald go through the auditd parser.
	if parsers.GetString(obj, "_AUDIT_TYPE") != "" || parsers.GetString(obj, "_TRANSPORT") == "audit" {
		if strings.HasPrefix(msg, "type=") {
			return parseAuditText(in, msg)
		}
	}
	e := parsers.Base(in, "linux", "linux.journald")
	if us := parsers.GetString(obj, "__REALTIME_TIMESTAMP"); us != "" {
		if n, err := strconv.ParseInt(us, 10, 64); err == nil {
			e.SetTimestamp(time.UnixMicro(n))
		}
	}
	e.Set(schema.FieldMessage, msg)
	comm := parsers.GetString(obj, "_COMM")
	ident := parsers.GetString(obj, "SYSLOG_IDENTIFIER")
	e.Set("process.name", comm)
	e.Set("process.executable", parsers.GetString(obj, "_EXE"))
	e.Set("process.command_line", parsers.GetString(obj, "_CMDLINE"))
	parsers.SetInt(e, "process.pid", parsers.GetString(obj, "_PID"))
	e.Set("user.id", parsers.GetString(obj, "_UID"))
	e.Set(schema.FieldHostName, parsers.GetString(obj, "_HOSTNAME"))
	e.Set("log.syslog.identifier", ident)
	parsers.SetInt(e, "log.syslog.facility.code", parsers.GetString(obj, "SYSLOG_FACILITY"))
	if pr := parsers.GetString(obj, "PRIORITY"); pr != "" {
		if n, err := strconv.Atoi(pr); err == nil {
			e.Set("log.level", syslog.LogLevel(n))
		}
	}
	e.Set("journald.unit", parsers.GetString(obj, "_SYSTEMD_UNIT"))
	e.Set("journald.boot_id", parsers.GetString(obj, "_BOOT_ID"))
	e.Set("journald.machine_id", parsers.GetString(obj, "_MACHINE_ID"))
	e.Set("journald.cap_effective", parsers.GetString(obj, "_CAP_EFFECTIVE"))
	e.Set("journald.transport", parsers.GetString(obj, "_TRANSPORT"))
	e.Set("journald.code.file", parsers.GetString(obj, "CODE_FILE"))
	parsers.SetInt(e, "journald.code.line", parsers.GetString(obj, "CODE_LINE"))
	e.Set("journald.code.func", parsers.GetString(obj, "CODE_FUNC"))
	app := ident
	if app == "" {
		app = comm
	}
	if authPrograms[app] {
		if matchAuth(e, app, msg) {
			return []*schema.Event{e}, nil
		}
	}
	e.SetCategory(schema.CategoryHost)
	e.SetTypes(schema.TypeInfo)
	return []*schema.Event{e}, nil
}

func toInt(v any) (int64, bool) {
	e := schema.New()
	e.Set("v", v)
	return e.Int64("v")
}
