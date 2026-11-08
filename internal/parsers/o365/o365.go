// Package o365 parses Office 365 Management Activity API audit records into
// ECS per docs/SCHEMA.md §13.
package o365

import (
	"bytes"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// Parser implements parsers.Parser.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string       { return "o365" }
func (*Parser) Version() string    { return "1.0.0" }
func (*Parser) Datasets() []string { return []string{"o365.audit"} }

var errNotO365 = errors.New("o365: not a Management Activity record")

// recordTypes maps the common RecordType values to their names; unknown
// values leave record_type_name unset.
var recordTypes = map[int64]string{
	1: "ExchangeAdmin", 2: "ExchangeItem", 3: "ExchangeItemGroup", 4: "SharePoint", 6: "SharePointFileOperation",
	7: "OneDrive", 8: "AzureActiveDirectory", 9: "AzureActiveDirectoryAccountLogon", 10: "DataCenterSecurityCmdlet",
	11: "ComplianceDLPSharePoint", 13: "ComplianceDLPExchange", 14: "SharePointSharingOperation",
	15: "AzureActiveDirectoryStsLogon", 18: "SecurityComplianceCenterEOPCmdlet", 20: "PowerBIAudit", 22: "Yammer",
	23: "SkypeForBusinessCmdlets", 24: "Discovery", 25: "MicrosoftTeams", 28: "ThreatIntelligence", 29: "MailSubmission",
	32: "MicrosoftFlow", 35: "MicrosoftStream", 36: "ComplianceDLPSharePointClassification", 40: "SecurityComplianceAlerts",
	41: "ThreatIntelligenceUrl", 42: "SecurityComplianceInsights", 47: "ThreatIntelligenceAtpContent",
	50: "MicrosoftTeamsAdmin", 52: "MicrosoftTeamsDevice", 54: "InformationWorkerProtection", 55: "Campaign",
	56: "DLPEndpoint", 57: "AirInvestigation", 58: "Quarantine", 59: "MicrosoftForms", 61: "Project",
	62: "SharePointListOperation", 64: "DataGovernance", 66: "SecurityComplianceUserChange", 73: "Search",
	75: "WDATPAlerts", 82: "HygieneEvent", 90: "MCASAlerts", 93: "ExchangeSearch", 94: "SharePointSearch",
	102: "MSDEGeneralSettings", 104: "MS365DCustomDetection", 113: "MipAutoLabelProgressFeedback",
	117: "Microsoft365Group", 157: "Alert", 158: "AlertStatus", 159: "AlertIncident", 160: "IncidentStatus",
	181: "PlannerTask", 196: "SharePointAppPermissionOperation", 209: "AttackSimAdmin", 226: "MicrosoftDefenderForIdentityAudit",
}

var userTypes = map[int64]string{0: "Regular", 1: "Reserved", 2: "Admin", 3: "DcAdmin", 4: "System", 5: "Application", 6: "ServicePrincipal", 7: "CustomPolicy", 8: "SystemPolicy"}

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, _ map[string]string) bool {
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 || (b[0] != '{' && b[0] != '[') {
		return false
	}
	return bytes.Contains(b, []byte(`"RecordType"`)) && bytes.Contains(b, []byte(`"CreationTime"`)) && bytes.Contains(b, []byte(`"Operation"`))
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	v, err := parsers.DecodeJSONAny(in.Raw)
	if err != nil {
		return nil, err
	}
	var recs []map[string]any
	collect := func(arr []any) {
		for _, x := range arr {
			if m, ok := x.(map[string]any); ok {
				recs = append(recs, m)
			}
		}
	}
	switch t := v.(type) {
	case []any:
		collect(t)
	case map[string]any:
		if c := parsers.GetSlice(t, "content"); c != nil {
			collect(c)
		} else {
			recs = append(recs, t)
		}
	}
	out := make([]*schema.Event, 0, len(recs))
	for _, r := range recs {
		if parsers.GetString(r, "Operation") == "" || parsers.GetString(r, "CreationTime") == "" {
			continue
		}
		out = append(out, build(in, r))
	}
	if len(out) == 0 {
		return nil, errNotO365
	}
	return out, nil
}

var consumed = map[string]bool{
	"CreationTime": true, "Id": true, "Operation": true, "Workload": true, "RecordType": true, "ResultStatus": true,
	"UserId": true, "UserKey": true, "UserType": true, "ClientIP": true, "ClientIPAddress": true, "ActorIpAddress": true,
	"UserAgent": true, "OrganizationId": true, "ExtendedProperties": true, "ModifiedProperties": true, "Parameters": true,
	"Actor": true, "Target": true, "DeviceProperties": true, "SourceFileName": true, "SourceFileExtension": true,
	"SourceRelativeUrl": true, "ObjectId": true,
}

func build(in *parsers.Input, r map[string]any) *schema.Event {
	e := parsers.Base(in, "o365", "o365.audit")
	op := parsers.GetString(r, "Operation")
	parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(r, "CreationTime"))
	e.Set(schema.FieldEventID, parsers.GetString(r, "Id"))
	e.Set(schema.FieldEventAction, op)
	workload := parsers.GetString(r, "Workload")
	e.Set(schema.FieldEventProvider, workload)
	e.Set("o365.audit.workload", workload)
	if rt, ok := parsers.GetInt(r, "RecordType"); ok {
		e.Set(schema.FieldEventCode, strconv.FormatInt(rt, 10))
		e.Set("o365.audit.record_type", rt)
		e.Set("o365.audit.record_type_name", recordTypes[rt])
	}
	status := parsers.GetString(r, "ResultStatus")
	e.Set("o365.audit.result_status", status)
	switch strings.ToLower(status) {
	case "succeeded", "success", "true", "partiallysucceeded":
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	case "failed", "failure", "false":
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	}
	if op == "UserLoginFailed" {
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	}
	uid := parsers.GetString(r, "UserId")
	if i := strings.IndexByte(uid, '@'); i > 0 {
		e.Set("user.email", uid)
		e.Set("user.name", uid[:i])
	} else {
		e.Set("user.name", uid)
	}
	e.Set("user.id", parsers.GetString(r, "UserKey"))
	if ut, ok := parsers.GetInt(r, "UserType"); ok {
		e.Set("o365.audit.user_type", ut)
		e.Set("o365.audit.user_type_name", userTypes[ut])
	}
	for _, k := range []string{"ClientIP", "ClientIPAddress", "ActorIpAddress"} {
		if parsers.SetIP(e, "source.ip", stripPort(parsers.GetString(r, k))) {
			break
		}
	}
	org := parsers.GetString(r, "OrganizationId")
	e.Set("cloud.provider", "azure")
	e.Set("cloud.account.id", org)
	e.Set("organization.id", org)
	// ExtendedProperties / DeviceProperties: [{Name, Value}]
	ext := nameValues(parsers.GetSlice(r, "ExtendedProperties"))
	for k, v := range ext {
		e.Set("o365.audit.extended_properties."+sanitize(k), v)
	}
	for k, v := range nameValues(parsers.GetSlice(r, "DeviceProperties")) {
		e.Set("o365.audit.device_properties."+sanitize(k), v)
	}
	ua := parsers.GetString(r, "UserAgent")
	if ua == "" {
		ua = ext["UserAgent"]
	}
	if ua == "" {
		ua = parsers.GetString(r, "ClientInfoString")
	}
	e.Set("user_agent.original", ua)
	for _, x := range parsers.GetSlice(r, "ModifiedProperties") {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		name := sanitize(parsers.GetString(m, "Name"))
		if name == "" {
			continue
		}
		e.Set("o365.audit.modified_properties."+name+".new_value", parsers.GetString(m, "NewValue"))
		e.Set("o365.audit.modified_properties."+name+".old_value", parsers.GetString(m, "OldValue"))
	}
	if params := parsers.GetSlice(r, "Parameters"); len(params) > 0 {
		for k, v := range nameValues(params) {
			e.Set("o365.audit.parameters."+sanitize(k), v)
		}
		e.Set("o365.audit.parameters_text", parsers.CompactJSON(params, 32*1024))
	}
	for _, k := range []string{"Actor", "Target"} {
		var arr []any
		for _, x := range parsers.GetSlice(r, k) {
			if m, ok := x.(map[string]any); ok {
				arr = append(arr, map[string]any{"id": parsers.GetString(m, "ID"), "type": parsers.GetString(m, "Type")})
			}
		}
		if len(arr) > 0 {
			e.Set("o365.audit."+strings.ToLower(k), arr)
		}
	}
	// SharePoint / OneDrive file fields.
	if fn := parsers.GetString(r, "SourceFileName"); fn != "" {
		e.Set("file.name", fn)
		e.Set("file.extension", strings.ToLower(parsers.GetString(r, "SourceFileExtension")))
		if rel := parsers.GetString(r, "SourceRelativeUrl"); rel != "" {
			e.Set("file.path", strings.TrimRight(rel, "/")+"/"+fn)
		}
	}
	if obj := parsers.GetString(r, "ObjectId"); obj != "" {
		e.Set("o365.audit.object_id", obj)
		if strings.HasPrefix(obj, "http://") || strings.HasPrefix(obj, "https://") {
			parsers.SetURL(e, obj)
		}
	}
	keys := make([]string, 0, len(r))
	for k := range r {
		if !consumed[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := r[k]
		if m, ok := v.(map[string]any); ok {
			parsers.FlattenInto(e, "o365.audit."+parsers.Snake(k), m, true)
			continue
		}
		flat := map[string]any{}
		schema.Flatten("", map[string]any{"x": v}, flat)
		e.Set("o365.audit."+parsers.Snake(k), flat["x"])
	}
	classify(e, op)
	e.Set(schema.FieldMessage, op+" by "+uid)
	return e
}

func nameValues(arr []any) map[string]string {
	out := map[string]string{}
	for _, x := range arr {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		if n := parsers.GetString(m, "Name"); n != "" {
			out[n] = parsers.GetString(m, "Value")
		}
	}
	return out
}

func sanitize(k string) string {
	return strings.NewReplacer(" ", "_", ".", "_", "/", "_").Replace(strings.TrimSpace(k))
}

// stripPort removes "[v6]:port" brackets and "v4:port" suffixes.
func stripPort(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i > 0 {
			return s[1:i]
		}
	}
	if strings.Count(s, ":") == 1 {
		return s[:strings.IndexByte(s, ':')]
	}
	return s
}

var opClass = map[string][2]string{
	"UserLoggedIn": {schema.CategoryAuthentication, schema.TypeStart}, "UserLoginFailed": {schema.CategoryAuthentication, schema.TypeStart},
	"Add user.": {schema.CategoryIAM, schema.TypeCreation}, "Update user.": {schema.CategoryIAM, schema.TypeChange},
	"Delete user.": {schema.CategoryIAM, schema.TypeDeletion}, "Add member to role.": {schema.CategoryIAM, schema.TypeChange},
	"Remove member from role.": {schema.CategoryIAM, schema.TypeChange}, "Add member to group.": {schema.CategoryIAM, schema.TypeChange},
	"Remove member from group.": {schema.CategoryIAM, schema.TypeChange}, "Reset user password.": {schema.CategoryIAM, schema.TypeChange},
	"Change user password.": {schema.CategoryIAM, schema.TypeChange}, "Consent to application.": {schema.CategoryIAM, schema.TypeChange},
	"Add service principal.": {schema.CategoryIAM, schema.TypeCreation}, "Add service principal credentials.": {schema.CategoryIAM, schema.TypeChange},
	"Add-MailboxPermission": {schema.CategoryIAM, schema.TypeChange}, "Add-RecipientPermission": {schema.CategoryIAM, schema.TypeChange},
	"New-InboxRule": {schema.CategoryConfiguration, schema.TypeCreation}, "Set-InboxRule": {schema.CategoryConfiguration, schema.TypeChange},
	"New-TransportRule": {schema.CategoryConfiguration, schema.TypeCreation}, "Set-TransportRule": {schema.CategoryConfiguration, schema.TypeChange},
	"Set-Mailbox": {schema.CategoryConfiguration, schema.TypeChange}, "Set-OrganizationConfig": {schema.CategoryConfiguration, schema.TypeChange},
	"Set-CASMailbox": {schema.CategoryConfiguration, schema.TypeChange}, "UpdateInboxRules": {schema.CategoryConfiguration, schema.TypeChange},
	"FileAccessed": {schema.CategoryFile, schema.TypeAccess}, "FileDownloaded": {schema.CategoryFile, schema.TypeAccess},
	"FilePreviewed": {schema.CategoryFile, schema.TypeAccess}, "FileUploaded": {schema.CategoryFile, schema.TypeCreation},
	"FileDeleted": {schema.CategoryFile, schema.TypeDeletion}, "FileModified": {schema.CategoryFile, schema.TypeChange},
	"FileSyncDownloadedFull": {schema.CategoryFile, schema.TypeAccess}, "SharingSet": {schema.CategoryFile, schema.TypeChange},
	"AnonymousLinkCreated": {schema.CategoryFile, schema.TypeCreation}, "SharingInvitationCreated": {schema.CategoryFile, schema.TypeCreation},
	"MailItemsAccessed": {schema.CategoryEmail, schema.TypeAccess}, "Send": {schema.CategoryEmail, schema.TypeInfo},
	"SendAs": {schema.CategoryEmail, schema.TypeInfo}, "SendOnBehalf": {schema.CategoryEmail, schema.TypeInfo},
	"MoveToDeletedItems": {schema.CategoryEmail, schema.TypeDeletion}, "SoftDelete": {schema.CategoryEmail, schema.TypeDeletion},
	"HardDelete": {schema.CategoryEmail, schema.TypeDeletion}, "TeamsSessionStarted": {schema.CategorySession, schema.TypeStart},
	"MemberAdded": {schema.CategoryIAM, schema.TypeChange}, "MemberRemoved": {schema.CategoryIAM, schema.TypeChange},
}

func classify(e *schema.Event, op string) {
	if c, ok := opClass[op]; ok {
		e.SetCategory(c[0])
		e.SetTypes(c[1])
		return
	}
	switch {
	case strings.HasPrefix(op, "New-") || strings.HasPrefix(op, "Add-") || strings.HasPrefix(op, "Enable-"):
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeCreation)
	case strings.HasPrefix(op, "Set-") || strings.HasPrefix(op, "Update-") || strings.HasPrefix(op, "Disable-"):
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
	case strings.HasPrefix(op, "Remove-"):
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeDeletion)
	default:
		e.SetTypes(schema.TypeInfo)
	}
}
