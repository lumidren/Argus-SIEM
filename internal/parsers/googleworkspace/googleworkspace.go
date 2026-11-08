// Package googleworkspace parses Google Workspace Reports API activities into
// ECS per docs/SCHEMA.md §14. Each entry of an activity's events[] becomes
// one Argus event.
package googleworkspace

import (
	"bytes"
	"errors"
	"strconv"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// Parser implements parsers.Parser.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string    { return "google_workspace" }
func (*Parser) Version() string { return "1.0.0" }
func (*Parser) Datasets() []string {
	apps := []string{"admin", "login", "drive", "token", "groups", "calendar", "mobile", "saml", "user_accounts",
		"access_transparency", "chat", "meet", "rules", "context_aware_access", "data_studio", "gcp", "chrome", "keep", "vault", "jamboard"}
	out := make([]string, len(apps))
	for i, a := range apps {
		out[i] = "google_workspace." + a
	}
	return out
}

var errNotGWS = errors.New("google_workspace: not a Reports API activity")

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, _ map[string]string) bool {
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 || b[0] != '{' {
		return false
	}
	if bytes.Contains(b, []byte(`"admin#reports#activity"`)) {
		return true
	}
	return bytes.Contains(b, []byte(`"applicationName"`)) && bytes.Contains(b, []byte(`"uniqueQualifier"`))
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	obj, err := parsers.DecodeJSON(in.Raw)
	if err != nil {
		return nil, err
	}
	var acts []map[string]any
	if items := parsers.GetSlice(obj, "items"); items != nil {
		for _, x := range items {
			if m, ok := x.(map[string]any); ok {
				acts = append(acts, m)
			}
		}
	} else {
		acts = append(acts, obj)
	}
	var out []*schema.Event
	for _, a := range acts {
		app := parsers.GetString(a, "id.applicationName")
		if app == "" {
			continue
		}
		for i, ev := range parsers.GetSlice(a, "events") {
			m, ok := ev.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, build(in, a, m, app, i))
		}
	}
	if len(out) == 0 {
		return nil, errNotGWS
	}
	return out, nil
}

func build(in *parsers.Input, a, ev map[string]any, app string, idx int) *schema.Event {
	e := parsers.Base(in, "google_workspace", "google_workspace."+app)
	name := parsers.GetString(ev, "name")
	parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(a, "id.time"))
	e.Set(schema.FieldEventID, parsers.GetString(a, "id.uniqueQualifier")+"-"+strconv.Itoa(idx))
	e.Set(schema.FieldEventProvider, app)
	e.Set(schema.FieldEventAction, name)
	e.Set("google_workspace.event.type", parsers.GetString(ev, "type"))
	email := parsers.GetString(a, "actor.email")
	e.Set("user.email", email)
	if i := strings.IndexByte(email, '@'); i > 0 {
		e.Set("user.name", email[:i])
		e.Set("user.domain", email[i+1:])
	}
	e.Set("user.id", parsers.GetString(a, "actor.profileId"))
	e.Set("google_workspace.actor.type", parsers.GetString(a, "actor.callerType"))
	e.Set("google_workspace.actor.key", parsers.GetString(a, "actor.key"))
	parsers.SetIP(e, "source.ip", parsers.GetString(a, "ipAddress"))
	e.Set("organization.id", parsers.GetString(a, "id.customerId"))
	e.Set("google_workspace.organization.domain", parsers.GetString(a, "ownerDomain"))
	params := map[string]any{}
	for _, x := range parsers.GetSlice(ev, "parameters") {
		pm, ok := x.(map[string]any)
		if !ok {
			continue
		}
		pname := parsers.GetString(pm, "name")
		if pname == "" {
			continue
		}
		v := paramValue(pm)
		if v == nil {
			continue
		}
		params[pname] = v
		key := "google_workspace." + app + "." + parsers.Snake(strings.ToLower(pname))
		if mv, ok := v.(map[string]any); ok {
			for k, sub := range mv {
				e.Set(key+"."+parsers.Snake(k), sub)
			}
			continue
		}
		e.Set(key, v)
	}
	promote(e, app, params)
	classify(e, app, name)
	e.Set(schema.FieldMessage, app+" "+name)
	return e
}

func paramValue(pm map[string]any) any {
	if _, ok := pm["value"]; ok {
		return parsers.GetString(pm, "value")
	}
	if _, ok := pm["intValue"]; ok {
		if n, ok := parsers.GetInt(pm, "intValue"); ok {
			return n
		}
	}
	if b, ok := parsers.GetBool(pm, "boolValue"); ok {
		return b
	}
	if mv := parsers.GetStrings(pm, "multiValue"); len(mv) > 0 {
		return mv
	}
	if arr := parsers.GetSlice(pm, "multiIntValue"); len(arr) > 0 {
		out := make([]any, 0, len(arr))
		for _, x := range arr {
			ev := schema.New()
			ev.Set("v", x)
			if n, ok := ev.Int64("v"); ok {
				out = append(out, n)
			}
		}
		return out
	}
	if inner := parsers.GetSlice(pm, "messageValue.parameter"); len(inner) > 0 {
		m := map[string]any{}
		for _, x := range inner {
			if sub, ok := x.(map[string]any); ok {
				if n := parsers.GetString(sub, "name"); n != "" {
					if v := paramValue(sub); v != nil {
						m[n] = v
					}
				}
			}
		}
		return m
	}
	return nil
}

func s(params map[string]any, k string) string {
	v, ok := params[k]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case []string:
		if len(t) > 0 {
			return t[0]
		}
	}
	return ""
}

func setTargetEmail(e *schema.Event, email string) {
	if email == "" {
		return
	}
	e.Set("user.target.email", email)
	if i := strings.IndexByte(email, '@'); i > 0 {
		e.Set("user.target.name", email[:i])
	}
}

func promote(e *schema.Event, app string, p map[string]any) {
	switch app {
	case "login":
		e.Set("google_workspace.login.type", s(p, "login_type"))
		if b, ok := p["is_suspicious"].(bool); ok {
			e.Set("google_workspace.login.is_suspicious", b)
		}
		if b, ok := p["is_second_factor"].(bool); ok {
			e.Set("google_workspace.login.is_second_factor", b)
		}
		if v, ok := p["login_challenge_method"].([]string); ok {
			e.Set("google_workspace.login.challenge_method", v)
		}
		e.Set("google_workspace.login.failure_type", s(p, "login_failure_type"))
		setTargetEmail(e, s(p, "affected_email_address"))
	case "admin":
		setTargetEmail(e, s(p, "USER_EMAIL"))
		e.Set("group.name", s(p, "GROUP_EMAIL"))
		e.Set("google_workspace.admin.role.name", s(p, "ROLE_NAME"))
		e.Set("google_workspace.admin.privilege.name", s(p, "PRIVILEGE_NAME"))
		e.Set("google_workspace.admin.setting.name", s(p, "SETTING_NAME"))
		e.Set("google_workspace.admin.setting.new_value", s(p, "NEW_VALUE"))
		e.Set("google_workspace.admin.setting.old_value", s(p, "OLD_VALUE"))
		e.Set("google_workspace.admin.domain.name", s(p, "DOMAIN_NAME"))
		e.Set("google_workspace.admin.application.name", s(p, "APPLICATION_NAME"))
		e.Set("google_workspace.admin.api_client.name", s(p, "API_CLIENT_NAME"))
		e.Set("google_workspace.admin.oauth2.service.name", s(p, "OAUTH2_SERVICE_NAME"))
	case "drive":
		e.Set("google_workspace.drive.file.id", s(p, "doc_id"))
		e.Set("file.name", s(p, "doc_title"))
		e.Set("google_workspace.drive.file.type", s(p, "doc_type"))
		e.Set("google_workspace.drive.owner", s(p, "owner"))
		e.Set("google_workspace.drive.visibility", s(p, "visibility"))
		setTargetEmail(e, s(p, "target_user"))
	case "token":
		e.Set("google_workspace.token.client.id", s(p, "client_id"))
		e.Set("google_workspace.token.app_name", s(p, "app_name"))
		if v, ok := p["scope"].([]string); ok {
			e.Set("google_workspace.token.scope.data", v)
		}
	case "groups":
		e.Set("group.name", s(p, "group_email"))
		setTargetEmail(e, s(p, "member_email"))
	case "saml":
		e.Set("google_workspace.saml.application_name", s(p, "application_name"))
		e.Set("google_workspace.saml.failure_type", s(p, "failure_type"))
	}
}

func classify(e *schema.Event, app, name string) {
	ln := strings.ToLower(name)
	switch app {
	case "login":
		e.SetCategory(schema.CategoryAuthentication)
		switch ln {
		case "login_success":
			e.SetTypes(schema.TypeStart)
			e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
		case "login_failure":
			e.SetTypes(schema.TypeStart)
			e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		case "logout":
			e.SetTypes(schema.TypeEnd)
		case "password_edit":
			e.SetCategory(schema.CategoryIAM)
			e.SetTypes(schema.TypeUser, schema.TypeChange)
		default:
			e.SetTypes(schema.TypeInfo)
			if strings.HasPrefix(ln, "suspicious_login") || strings.HasPrefix(ln, "account_disabled") {
				e.Set(schema.FieldEventOutcome, schema.OutcomeUnknown)
			}
		}
	case "saml":
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventOutcome, parsers.OutcomeFromBool(ln == "login_success"))
	case "admin":
		up := strings.ToUpper(name)
		switch {
		case strings.Contains(up, "SETTING") || strings.Contains(up, "DOMAIN") || strings.Contains(up, "APPLICATION") || strings.Contains(up, "API_CLIENT") || strings.Contains(up, "SSO") || strings.Contains(up, "DATA_TRANSFER"):
			e.SetCategory(schema.CategoryConfiguration)
		default:
			e.SetCategory(schema.CategoryIAM)
		}
		switch {
		case strings.HasPrefix(up, "CREATE_"):
			e.SetTypes(schema.TypeCreation)
		case strings.HasPrefix(up, "DELETE_") || strings.HasPrefix(up, "REMOVE_") || strings.HasPrefix(up, "REVOKE_"):
			e.SetTypes(schema.TypeDeletion)
		case strings.HasPrefix(up, "CHANGE_") || strings.HasPrefix(up, "UPDATE_") || strings.HasPrefix(up, "ASSIGN_") || strings.HasPrefix(up, "GRANT_") ||
			strings.HasPrefix(up, "ADD_") || strings.HasPrefix(up, "SUSPEND_") || strings.HasPrefix(up, "UNSUSPEND_") || strings.HasPrefix(up, "TOGGLE_") || strings.HasPrefix(up, "RENAME_"):
			e.SetTypes(schema.TypeChange)
		default:
			e.SetTypes(schema.TypeInfo)
		}
	case "drive":
		e.SetCategory(schema.CategoryFile)
		switch {
		case ln == "view" || ln == "download" || ln == "preview" || ln == "print":
			e.SetTypes(schema.TypeAccess)
		case ln == "create" || ln == "upload" || ln == "add_to_folder" || ln == "copy":
			e.SetTypes(schema.TypeCreation)
		case ln == "delete" || ln == "trash" || ln == "remove_from_folder":
			e.SetTypes(schema.TypeDeletion)
		default:
			e.SetTypes(schema.TypeChange)
		}
	case "token":
		e.SetCategory(schema.CategoryIAM)
		switch ln {
		case "authorize":
			e.SetTypes(schema.TypeCreation)
		case "revoke":
			e.SetTypes(schema.TypeDeletion)
		default:
			e.SetTypes(schema.TypeInfo)
		}
	case "groups", "groups_enterprise":
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeGroup, schema.TypeChange)
	default:
		e.SetTypes(schema.TypeInfo)
	}
}
