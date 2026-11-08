// Package windows parses Windows Event Log records (Security, Sysmon,
// PowerShell, System and other channels) delivered either as the XML rendered
// by wevtapi EvtRender or as Winlogbeat/NXLog-style JSON, into ECS per
// docs/SCHEMA.md §4.
package windows

import (
	"bytes"
	"errors"
	"strconv"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// Parser implements parsers.Parser for Windows event logs.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string    { return "windows" }
func (*Parser) Version() string { return "1.0.0" }

// Datasets lists the datasets the parser can emit.
func (*Parser) Datasets() []string {
	return []string{
		"windows.security", "windows.system", "windows.application", "windows.sysmon_operational",
		"windows.powershell", "windows.powershell_operational", "windows.defender",
		"windows.taskscheduler", "windows.wmi_activity", "windows.bits_client",
		"windows.terminalservices", "windows.ntlm", "windows.ldap_debug", "windows.dns_server",
		"windows.firewall", "windows.other",
	}
}

// ErrNotWindows is returned when the record is neither Windows XML nor a
// recognized JSON form.
var ErrNotWindows = errors.New("windows: not a windows event record")

// Detect recognizes Event XML and the two JSON forms.
func (p *Parser) Detect(raw []byte, hints map[string]string) bool {
	if hints != nil && hints["kind"] == "windows" {
		return true
	}
	b := bytes.TrimLeft(raw, " \t\r\n\xef\xbb\xbf")
	if len(b) == 0 {
		return false
	}
	if b[0] == '<' {
		if !bytes.Contains(b[:min(len(b), 64)], []byte("<Event")) {
			return false
		}
		return bytes.Contains(b, []byte("schemas.microsoft.com/win/2004/08/events/event")) || bytes.Contains(b, []byte("<System>"))
	}
	if b[0] == '{' {
		if bytes.Contains(b, []byte(`"winlog"`)) {
			return true
		}
		return bytes.Contains(b, []byte(`"EventID"`)) && (bytes.Contains(b, []byte(`"Channel"`)) || bytes.Contains(b, []byte(`"SourceName"`)))
	}
	return false
}

// record is the format-independent view of one event.
type record struct {
	Provider     string
	ProviderGUID string
	EventID      int64
	Qualifiers   string
	Version      string
	Level        string
	Task         string
	Opcode       string
	Keywords     []string
	TimeCreated  string
	RecordID     string
	ActivityID   string
	ProcessID    string
	ThreadID     string
	Channel      string
	Computer     string
	UserID       string
	Message      string
	// RenderingInfo (optional)
	LevelName  string
	TaskName   string
	OpcodeName string
	// EventData in document order.
	DataOrder []string
	Data      map[string]string
	// UserData flattened with dotted keys.
	UserData map[string]string
}

func (r *record) get(name string) string {
	v := r.Data[name]
	if v == "-" {
		return ""
	}
	return v
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	b := bytes.TrimLeft(in.Raw, " \t\r\n\xef\xbb\xbf")
	if len(b) == 0 {
		return nil, ErrNotWindows
	}
	var rec *record
	var err error
	switch b[0] {
	case '<':
		rec, err = parseXML(b)
	case '{':
		rec, err = parseJSON(b)
	default:
		return nil, ErrNotWindows
	}
	if err != nil {
		return nil, err
	}
	if rec.Channel == "" && in.Hint("channel") != "" {
		rec.Channel = in.Hint("channel")
	}
	e := build(in, rec)
	return []*schema.Event{e}, nil
}

// datasetFor maps a channel name to the dataset.
func datasetFor(channel string) string {
	switch channel {
	case "Security":
		return "windows.security"
	case "System":
		return "windows.system"
	case "Application":
		return "windows.application"
	case "Microsoft-Windows-Sysmon/Operational":
		return "windows.sysmon_operational"
	case "Microsoft-Windows-PowerShell/Operational":
		return "windows.powershell_operational"
	case "Windows PowerShell":
		return "windows.powershell"
	case "Microsoft-Windows-Windows Defender/Operational":
		return "windows.defender"
	case "Microsoft-Windows-TaskScheduler/Operational":
		return "windows.taskscheduler"
	case "Microsoft-Windows-WMI-Activity/Operational":
		return "windows.wmi_activity"
	case "Microsoft-Windows-Bits-Client/Operational":
		return "windows.bits_client"
	case "Microsoft-Windows-NTLM/Operational":
		return "windows.ntlm"
	case "Microsoft-Windows-LDAP-Client/Debug":
		return "windows.ldap_debug"
	case "Microsoft-Windows-DNS-Server/Audit", "DNS Server", "Microsoft-Windows-DNSServer/Audit":
		return "windows.dns_server"
	case "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall":
		return "windows.firewall"
	}
	if strings.HasPrefix(channel, "Microsoft-Windows-TerminalServices-") || strings.HasPrefix(channel, "Microsoft-Windows-RemoteDesktopServices-") {
		return "windows.terminalservices"
	}
	return "windows.other"
}

var levelNames = map[string]string{
	"0": "information", "1": "critical", "2": "error", "3": "warning", "4": "information", "5": "verbose",
}

// keywordNames decodes the well-known Security auditing keyword bits.
func keywordNames(hex string) []string {
	v, ok := parsers.ParseInt(hex)
	if !ok {
		return nil
	}
	var out []string
	if uint64(v)&0x8020000000000000 == 0x8020000000000000 {
		out = append(out, "Audit Success")
	}
	if uint64(v)&0x8010000000000000 == 0x8010000000000000 {
		out = append(out, "Audit Failure")
	}
	return out
}

// build converts a record to an ECS event.
func build(in *parsers.Input, r *record) *schema.Event {
	dataset := datasetFor(r.Channel)
	e := parsers.Base(in, "windows", dataset)
	parsers.SetTime(e, schema.FieldTimestamp, r.TimeCreated)
	e.Set(schema.FieldEventCode, strconv.FormatInt(r.EventID, 10))
	e.Set(schema.FieldEventProvider, r.Provider)
	e.Set(schema.FieldHostName, r.Computer)
	e.Set("winlog.channel", r.Channel)
	e.Set("winlog.event_id", r.EventID)
	e.Set("winlog.provider_name", r.Provider)
	e.Set("winlog.provider_guid", r.ProviderGUID)
	e.Set("winlog.computer_name", r.Computer)
	e.Set("winlog.version", r.Version)
	e.Set("winlog.qualifiers", r.Qualifiers)
	if r.RecordID != "" {
		if n, ok := parsers.ParseInt(r.RecordID); ok {
			e.Set("winlog.record_id", n)
		} else {
			e.Set("winlog.record_id", r.RecordID)
		}
	}
	e.Set("winlog.activity_id", r.ActivityID)
	parsers.SetInt(e, "winlog.process.pid", r.ProcessID)
	parsers.SetInt(e, "winlog.process.thread.id", r.ThreadID)
	e.Set("winlog.user.identifier", r.UserID)
	if r.TaskName != "" {
		e.Set("winlog.task", r.TaskName)
	} else {
		e.Set("winlog.task", r.Task)
	}
	if r.OpcodeName != "" {
		e.Set("winlog.opcode", r.OpcodeName)
	} else {
		e.Set("winlog.opcode", r.Opcode)
	}
	if r.LevelName != "" {
		e.Set("winlog.level", strings.ToLower(r.LevelName))
	} else if name, ok := levelNames[r.Level]; ok {
		e.Set("winlog.level", name)
	}
	if lvl := e.String("winlog.level"); lvl != "" {
		e.Set("log.level", lvl)
	}
	if len(r.Keywords) > 0 {
		e.Set("winlog.keywords", r.Keywords)
	}
	for _, k := range r.DataOrder {
		e.Set("winlog.event_data."+k, r.Data[k])
	}
	for k, v := range r.UserData {
		e.Set("winlog.user_data."+k, v)
	}
	// Default outcome from auditing keywords (Security channel).
	for _, kw := range r.Keywords {
		switch kw {
		case "Audit Success":
			e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
		case "Audit Failure":
			e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		}
	}
	// Dispatch to the channel-specific mapping.
	switch {
	case r.Channel == "Microsoft-Windows-Sysmon/Operational":
		applySysmon(e, r)
	case r.Channel == "Security":
		applySecurity(e, r)
	default:
		applyOtherChannel(e, r, dataset)
	}
	if !e.Has(schema.FieldEventAction) {
		if r.TaskName != "" {
			e.Set(schema.FieldEventAction, r.TaskName)
		} else {
			e.Set(schema.FieldEventAction, "event-"+strconv.FormatInt(r.EventID, 10))
		}
	}
	if r.Message != "" {
		e.Set(schema.FieldMessage, r.Message)
	} else {
		e.Set(schema.FieldMessage, r.Provider+": EventID "+strconv.FormatInt(r.EventID, 10))
	}
	return e
}

// ---- shared field helpers ----

// setSubject maps Subject* to user.*.
func setSubject(e *schema.Event, r *record) {
	if u := r.get("SubjectUserName"); u != "" {
		e.Set("user.name", u)
	}
	if d := r.get("SubjectDomainName"); d != "" {
		e.Set("user.domain", d)
	}
	if s := r.get("SubjectUserSid"); s != "" {
		e.Set("user.id", s)
	}
	if l := r.get("SubjectLogonId"); l != "" && !e.Has("winlog.logon.id") {
		e.Set("winlog.logon.id", l)
	}
}

// setTargetUser maps Target* to user.* (used when the target is the acting
// identity, e.g. logons).
func setTargetUser(e *schema.Event, r *record) {
	if u := r.get("TargetUserName"); u != "" {
		name, dom := splitUPN(u)
		e.Set("user.name", name)
		if dom != "" {
			e.Set("user.domain", dom)
		}
	}
	if d := r.get("TargetDomainName"); d != "" {
		e.Set("user.domain", d)
	}
	if s := r.get("TargetUserSid"); s != "" {
		e.Set("user.id", s)
	} else if s := r.get("TargetSid"); s != "" {
		e.Set("user.id", s)
	}
	if l := r.get("TargetLogonId"); l != "" {
		e.Set("winlog.logon.id", l)
	}
}

// setTargetAsTarget maps Target* to user.target.* (account management).
func setTargetAsTarget(e *schema.Event, r *record) {
	if u := r.get("TargetUserName"); u != "" {
		e.Set("user.target.name", u)
	}
	if d := r.get("TargetDomainName"); d != "" {
		e.Set("user.target.domain", d)
	}
	if s := r.get("TargetSid"); s != "" {
		e.Set("user.target.id", s)
	} else if s := r.get("TargetUserSid"); s != "" {
		e.Set("user.target.id", s)
	}
}

func splitUPN(s string) (string, string) {
	if i := strings.IndexByte(s, '@'); i > 0 && !strings.ContainsAny(s, `\`) {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// setSourceIP stores IpAddress-style values, dropping placeholders and
// loopback addresses.
func setSourceIP(e *schema.Event, key, v string) {
	ip := parsers.NormalizeIP(v)
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return
	}
	e.Set(key, ip)
}

// setProcess maps an executable path and a (possibly hex) pid.
func setProcess(e *schema.Event, prefix, exe, pid string) {
	parsers.SetProcessExecutable(e, prefix, exe)
	parsers.SetInt(e, prefix+".pid", pid)
}

// cnFromDN extracts the first CN= component of a distinguished name, or
// returns the input when it is not a DN.
func cnFromDN(s string) string {
	if !strings.Contains(s, "=") {
		return s
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if len(part) > 3 && strings.EqualFold(part[:3], "CN=") {
			return part[3:]
		}
	}
	return s
}

func kerberosOutcome(status string) string {
	st := strings.ToLower(strings.TrimSpace(status))
	if st == "" {
		return ""
	}
	if st == "0x0" || st == "0" || st == "0x00000000" {
		return schema.OutcomeSuccess
	}
	return schema.OutcomeFailure
}

func trimQuotes(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"`)
}
