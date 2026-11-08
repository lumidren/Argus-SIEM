// Package gcp parses Google Cloud Logging entries (Cloud Audit Logs and
// generic entries) delivered as LogEntry JSON, Pub/Sub push envelopes or
// {"entries":[...]} exports, into ECS per docs/SCHEMA.md §11.
package gcp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// Parser implements parsers.Parser.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string       { return "gcp" }
func (*Parser) Version() string    { return "1.0.0" }
func (*Parser) Datasets() []string { return []string{"gcp.audit", "gcp.log"} }

var errNotGCP = errors.New("gcp: not a Cloud Logging entry")

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, _ map[string]string) bool {
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 || b[0] != '{' {
		return false
	}
	if bytes.Contains(b, []byte(`"protoPayload"`)) && bytes.Contains(b, []byte(`google.cloud.audit.AuditLog`)) {
		return true
	}
	if bytes.Contains(b, []byte(`"logName"`)) && bytes.Contains(b, []byte(`"insertId"`)) {
		return true
	}
	return bytes.Contains(b, []byte(`"message"`)) && bytes.Contains(b, []byte(`"messageId"`)) && bytes.Contains(b, []byte(`"data"`))
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	obj, err := parsers.DecodeJSON(in.Raw)
	if err != nil {
		return nil, err
	}
	var entries []map[string]any
	switch {
	case parsers.GetMap(obj, "message") != nil && parsers.GetString(obj, "message.data") != "":
		data, err := base64.StdEncoding.DecodeString(parsers.GetString(obj, "message.data"))
		if err != nil {
			return nil, err
		}
		inner, err := parsers.DecodeJSON(data)
		if err != nil {
			return nil, err
		}
		entries = append(entries, inner)
	case parsers.GetSlice(obj, "entries") != nil:
		for _, x := range parsers.GetSlice(obj, "entries") {
			if m, ok := x.(map[string]any); ok {
				entries = append(entries, m)
			}
		}
	default:
		entries = append(entries, obj)
	}
	out := make([]*schema.Event, 0, len(entries))
	for _, entry := range entries {
		if parsers.GetString(entry, "logName") == "" && parsers.GetMap(entry, "protoPayload") == nil {
			continue
		}
		out = append(out, build(in, entry))
	}
	if len(out) == 0 {
		return nil, errNotGCP
	}
	return out, nil
}

func build(in *parsers.Input, entry map[string]any) *schema.Event {
	pp := parsers.GetMap(entry, "protoPayload")
	isAudit := pp != nil && strings.Contains(parsers.GetString(pp, "@type"), "google.cloud.audit.AuditLog")
	dataset := "gcp.log"
	if isAudit {
		dataset = "gcp.audit"
	}
	e := parsers.Base(in, "gcp", dataset)
	parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(entry, "timestamp"))
	e.Set(schema.FieldEventID, parsers.GetString(entry, "insertId"))
	e.Set("cloud.provider", "gcp")
	labels := parsers.GetMap(entry, "resource.labels")
	e.Set("cloud.project.id", parsers.GetString(labels, "project_id"))
	region := parsers.GetString(labels, "region")
	if region == "" {
		region = parsers.GetString(labels, "location")
	}
	e.Set("cloud.region", region)
	e.Set("cloud.availability_zone", parsers.GetString(labels, "zone"))
	e.Set("cloud.instance.id", parsers.GetString(labels, "instance_id"))
	sev := parsers.GetString(entry, "severity")
	logName := parsers.GetString(entry, "logName")
	prefix := "gcp.audit"
	if !isAudit {
		prefix = "gcp.log"
	}
	e.Set(prefix+".log_name", logName)
	e.Set(prefix+".severity", sev)
	if sev != "" {
		e.Set("log.level", strings.ToLower(sev))
	}
	e.Set("gcp.resource.type", parsers.GetString(entry, "resource.type"))
	for k, v := range labels {
		e.Set("gcp.resource.labels."+k, str(v))
	}
	if op := parsers.GetMap(entry, "operation"); op != nil {
		e.Set(prefix+".operation.id", parsers.GetString(op, "id"))
		e.Set(prefix+".operation.producer", parsers.GetString(op, "producer"))
		if b, ok := parsers.GetBool(op, "first"); ok {
			e.Set(prefix+".operation.first", b)
		}
		if b, ok := parsers.GetBool(op, "last"); ok {
			e.Set(prefix+".operation.last", b)
		}
	}
	e.Set(prefix+".receive_timestamp", parsers.GetString(entry, "receiveTimestamp"))
	if !isAudit {
		e.SetCategory(schema.CategoryHost)
		e.SetTypes(schema.TypeInfo)
		if jp := parsers.GetMap(entry, "jsonPayload"); jp != nil {
			parsers.FlattenInto(e, "gcp.log.json_payload", jp, true)
			if m := parsers.GetString(jp, "message"); m != "" {
				e.Set(schema.FieldMessage, m)
			}
		}
		if tp := parsers.GetString(entry, "textPayload"); tp != "" {
			e.Set("gcp.log.text_payload", tp)
			e.Set(schema.FieldMessage, tp)
		}
		return e
	}
	audit(e, pp, logName)
	return e
}

func audit(e *schema.Event, pp map[string]any, logName string) {
	method := parsers.GetString(pp, "methodName")
	service := parsers.GetString(pp, "serviceName")
	e.Set(schema.FieldEventAction, method)
	e.Set(schema.FieldEventProvider, service)
	e.Set("gcp.audit.type", parsers.GetString(pp, "@type"))
	e.Set("gcp.audit.method_name", method)
	e.Set("gcp.audit.service_name", service)
	e.Set("gcp.audit.resource_name", parsers.GetString(pp, "resourceName"))
	if locs := parsers.GetStrings(pp, "resourceLocation.currentLocations"); len(locs) > 0 {
		e.Set("gcp.audit.resource_location.current_locations", locs)
	}
	parsers.SetInt(e, "gcp.audit.num_response_items", parsers.GetString(pp, "numResponseItems"))
	code, hasCode := parsers.GetInt(pp, "status.code")
	if hasCode {
		e.Set("gcp.audit.status.code", code)
	}
	e.Set("gcp.audit.status.message", parsers.GetString(pp, "status.message"))
	success := !hasCode || code == 0
	e.Set(schema.FieldEventOutcome, parsers.OutcomeFromBool(success))
	ai := parsers.GetMap(pp, "authenticationInfo")
	email := parsers.GetString(ai, "principalEmail")
	e.Set("user.email", email)
	if i := strings.IndexByte(email, '@'); i > 0 {
		e.Set("user.name", email[:i])
	} else {
		e.Set("user.name", email)
	}
	e.Set("user.id", parsers.GetString(ai, "principalSubject"))
	if ai != nil {
		parsers.FlattenInto(e, "gcp.audit.authentication_info", ai, true)
	}
	rm := parsers.GetMap(pp, "requestMetadata")
	caller := parsers.GetString(rm, "callerIp")
	if !parsers.SetIP(e, "source.ip", caller) {
		e.Set("source.address", caller)
	}
	e.Set("user_agent.original", parsers.GetString(rm, "callerSuppliedUserAgent"))
	if rm != nil {
		parsers.FlattenInto(e, "gcp.audit.request_metadata", rm, true)
	}
	if az := parsers.GetSlice(pp, "authorizationInfo"); len(az) > 0 {
		arr := make([]any, 0, len(az))
		for _, x := range az {
			if m, ok := x.(map[string]any); ok {
				item := map[string]any{"permission": parsers.GetString(m, "permission"), "resource": parsers.GetString(m, "resource")}
				if b, ok := parsers.GetBool(m, "granted"); ok {
					item["granted"] = b
				}
				if ra := parsers.GetMap(m, "resourceAttributes"); ra != nil {
					item["resource_attributes"] = ra
				}
				arr = append(arr, item)
			}
		}
		e.Set("gcp.audit.authorization_info", arr)
	}
	for _, k := range []struct{ from, to string }{{"request", "request"}, {"response", "response"}, {"metadata", "metadata"}, {"serviceData", "service_data"}} {
		if m := parsers.GetMap(pp, k.from); m != nil {
			parsers.FlattenInto(e, "gcp.audit."+k.to, m, false)
		}
	}
	classify(e, service, method, logName, success)
	msg := method
	if email != "" {
		msg = email + " called " + method
	}
	e.Set(schema.FieldMessage, msg)
}

func classify(e *schema.Event, service, method, logName string, success bool) {
	lm := strings.ToLower(method)
	switch {
	case strings.HasPrefix(method, "google.login.LoginService."):
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeStart)
		if strings.HasSuffix(method, "loginFailure") {
			e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		}
		return
	case service == "iam.googleapis.com" || strings.Contains(method, "SetIamPolicy") || strings.Contains(lm, "serviceaccounts") || strings.Contains(lm, ".roles."):
		e.SetCategory(schema.CategoryIAM)
	default:
		e.SetCategory(schema.CategoryConfiguration)
	}
	switch {
	case strings.HasSuffix(logName, "/data_access") || strings.HasSuffix(logName, "%2Fdata_access"):
		e.SetTypes(schema.TypeAccess)
		return
	case strings.HasSuffix(logName, "/system_event") || strings.HasSuffix(logName, "%2Fsystem_event"):
		e.SetTypes(schema.TypeInfo)
		return
	}
	verb := lm
	if i := strings.LastIndexByte(lm, '.'); i >= 0 {
		verb = lm[i+1:]
	}
	switch {
	case strings.HasPrefix(verb, "create") || strings.HasPrefix(verb, "insert"):
		e.SetTypes(schema.TypeCreation)
	case strings.HasPrefix(verb, "delete") || strings.HasPrefix(verb, "remove"):
		e.SetTypes(schema.TypeDeletion)
	case strings.HasPrefix(verb, "update") || strings.HasPrefix(verb, "patch") || strings.HasPrefix(verb, "set") || strings.HasPrefix(verb, "enable") || strings.HasPrefix(verb, "disable"):
		e.SetTypes(schema.TypeChange)
	case strings.HasPrefix(verb, "get") || strings.HasPrefix(verb, "list"):
		e.SetTypes(schema.TypeAccess)
	default:
		e.SetTypes(schema.TypeInfo)
	}
	_ = success
}

func str(v any) string {
	e := schema.New()
	e.Set("v", v)
	return e.String("v")
}
