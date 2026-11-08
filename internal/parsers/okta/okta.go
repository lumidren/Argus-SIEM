// Package okta parses Okta System Log events into ECS per docs/SCHEMA.md §12.
package okta

import (
	"bytes"
	"errors"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// Parser implements parsers.Parser.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string       { return "okta" }
func (*Parser) Version() string    { return "1.0.0" }
func (*Parser) Datasets() []string { return []string{"okta.system"} }

var errNotOkta = errors.New("okta: not a System Log event")

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, _ map[string]string) bool {
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 || (b[0] != '{' && b[0] != '[') {
		return false
	}
	return bytes.Contains(b, []byte(`"eventType"`)) && bytes.Contains(b, []byte(`"published"`)) &&
		(bytes.Contains(b, []byte(`"actor"`)) || bytes.Contains(b, []byte(`"uuid"`)))
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	v, err := parsers.DecodeJSONAny(in.Raw)
	if err != nil {
		return nil, err
	}
	var items []map[string]any
	switch t := v.(type) {
	case map[string]any:
		items = append(items, t)
	case []any:
		for _, x := range t {
			if m, ok := x.(map[string]any); ok {
				items = append(items, m)
			}
		}
	}
	out := make([]*schema.Event, 0, len(items))
	for _, it := range items {
		if parsers.GetString(it, "eventType") == "" {
			continue
		}
		out = append(out, build(in, it))
	}
	if len(out) == 0 {
		return nil, errNotOkta
	}
	return out, nil
}

func build(in *parsers.Input, o map[string]any) *schema.Event {
	e := parsers.Base(in, "okta", "okta.system")
	et := parsers.GetString(o, "eventType")
	parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(o, "published"))
	e.Set(schema.FieldEventID, parsers.GetString(o, "uuid"))
	e.Set(schema.FieldEventAction, et)
	e.Set("okta.event_type", et)
	e.Set("okta.display_message", parsers.GetString(o, "displayMessage"))
	e.Set("okta.legacy_event_type", parsers.GetString(o, "legacyEventType"))
	e.Set("okta.version", parsers.GetString(o, "version"))
	sev := parsers.GetString(o, "severity")
	e.Set("okta.severity", sev)
	switch strings.ToUpper(sev) {
	case "DEBUG", "INFO":
		e.Set(schema.FieldEventSeverity, int64(10))
	case "WARN":
		e.Set(schema.FieldEventSeverity, int64(50))
	case "ERROR":
		e.Set(schema.FieldEventSeverity, int64(75))
	}
	result := parsers.GetString(o, "outcome.result")
	e.Set("okta.outcome.result", result)
	e.Set("okta.outcome.reason", parsers.GetString(o, "outcome.reason"))
	switch strings.ToUpper(result) {
	case "SUCCESS", "ALLOW":
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	case "FAILURE", "DENY":
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	case "":
	default:
		e.Set(schema.FieldEventOutcome, schema.OutcomeUnknown)
	}
	classify(e, et)
	if a := parsers.GetMap(o, "actor"); a != nil {
		alt := parsers.GetString(a, "alternateId")
		e.Set("okta.actor.id", parsers.GetString(a, "id"))
		e.Set("okta.actor.type", parsers.GetString(a, "type"))
		e.Set("okta.actor.alternate_id", alt)
		e.Set("okta.actor.display_name", parsers.GetString(a, "displayName"))
		e.Set("user.id", parsers.GetString(a, "id"))
		e.Set("user.full_name", parsers.GetString(a, "displayName"))
		if i := strings.IndexByte(alt, '@'); i > 0 {
			e.Set("user.email", alt)
			e.Set("user.name", alt[:i])
		} else {
			e.Set("user.name", alt)
		}
	}
	if c := parsers.GetMap(o, "client"); c != nil {
		parsers.SetIP(e, "source.ip", parsers.GetString(c, "ipAddress"))
		e.Set("okta.client.zone", parsers.GetString(c, "zone"))
		e.Set("okta.client.device", parsers.GetString(c, "device"))
		e.Set("okta.client.id", parsers.GetString(c, "id"))
		e.Set("user_agent.original", parsers.GetString(c, "userAgent.rawUserAgent"))
		e.Set("user_agent.os.full", parsers.GetString(c, "userAgent.os"))
		e.Set("user_agent.name", parsers.GetString(c, "userAgent.browser"))
		if g := parsers.GetMap(c, "geographicalContext"); g != nil {
			e.Set("source.geo.city_name", parsers.GetString(g, "city"))
			e.Set("source.geo.region_name", parsers.GetString(g, "state"))
			e.Set("source.geo.country_name", parsers.GetString(g, "country"))
			e.Set("source.geo.postal_code", parsers.GetString(g, "postalCode"))
			lat, okLat := parsers.GetPath(g, "geolocation.lat")
			lon, okLon := parsers.GetPath(g, "geolocation.lon")
			if okLat && okLon {
				e.Set("source.geo.location", map[string]any{"lat": num(lat), "lon": num(lon)})
			}
		}
	}
	if sc := parsers.GetMap(o, "securityContext"); sc != nil {
		if n, ok := parsers.GetInt(sc, "asNumber"); ok {
			e.Set("source.as.number", n)
		}
		e.Set("source.as.organization.name", parsers.GetString(sc, "asOrg"))
		e.Set("okta.security_context.isp", parsers.GetString(sc, "isp"))
		e.Set("okta.security_context.domain", parsers.GetString(sc, "domain"))
		if b, ok := parsers.GetBool(sc, "isProxy"); ok {
			e.Set("okta.security_context.is_proxy", b)
		}
	}
	if ac := parsers.GetMap(o, "authenticationContext"); ac != nil {
		parsers.FlattenInto(e, "okta.authentication_context", ac, true)
	}
	if tx := parsers.GetMap(o, "transaction"); tx != nil {
		parsers.FlattenInto(e, "okta.transaction", tx, true)
	}
	if dd := parsers.GetMap(o, "debugContext.debugData"); dd != nil {
		parsers.FlattenInto(e, "okta.debug_context.debug_data", dd, true)
	}
	if chain := parsers.GetSlice(o, "request.ipChain"); len(chain) > 0 {
		arr := make([]any, 0, len(chain))
		for _, x := range chain {
			if m, ok := x.(map[string]any); ok {
				arr = append(arr, snake(m))
			}
		}
		e.Set("okta.request.ip_chain", arr)
	}
	if targets := parsers.GetSlice(o, "target"); len(targets) > 0 {
		arr := make([]any, 0, len(targets))
		userDone, appDone := false, false
		for _, x := range targets {
			m, ok := x.(map[string]any)
			if !ok {
				continue
			}
			arr = append(arr, snake(m))
			typ := parsers.GetString(m, "type")
			if typ == "User" && !userDone {
				userDone = true
				alt := parsers.GetString(m, "alternateId")
				e.Set("user.target.id", parsers.GetString(m, "id"))
				e.Set("user.target.full_name", parsers.GetString(m, "displayName"))
				if i := strings.IndexByte(alt, '@'); i > 0 {
					e.Set("user.target.email", alt)
					e.Set("user.target.name", alt[:i])
				} else {
					e.Set("user.target.name", alt)
				}
			}
			if typ == "UserGroup" {
				e.Set("group.name", parsers.GetString(m, "displayName"))
				e.Set("group.id", parsers.GetString(m, "id"))
			}
			if typ == "AppInstance" && !appDone {
				appDone = true
				e.Set("okta.target.app.display_name", parsers.GetString(m, "displayName"))
				e.Set("okta.target.app.id", parsers.GetString(m, "id"))
			}
		}
		e.Set("okta.target", arr)
	}
	msg := parsers.GetString(o, "displayMessage")
	if msg == "" {
		msg = et
	}
	e.Set(schema.FieldMessage, msg)
	return e
}

func verbType(et string) string {
	last := et[strings.LastIndexByte(et, '.')+1:]
	switch {
	case strings.HasPrefix(last, "create") || strings.HasPrefix(last, "activate") || strings.HasPrefix(last, "add") || strings.HasPrefix(last, "enroll"):
		return schema.TypeCreation
	case strings.HasPrefix(last, "deactivate") || strings.HasPrefix(last, "delete") || strings.HasPrefix(last, "suspend") || strings.HasPrefix(last, "remove") || strings.HasPrefix(last, "revoke"):
		return schema.TypeDeletion
	case strings.HasPrefix(last, "update") || strings.HasPrefix(last, "reset") || strings.HasPrefix(last, "unlock") || strings.HasPrefix(last, "unsuspend") || strings.HasPrefix(last, "change") || strings.HasPrefix(last, "grant"):
		return schema.TypeChange
	}
	return schema.TypeInfo
}

func classify(e *schema.Event, et string) {
	switch {
	case et == "user.session.end":
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeEnd)
	case strings.HasPrefix(et, "user.mfa.factor."):
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(verbType(et))
	case et == "user.session.start" || strings.HasPrefix(et, "user.authentication.") || strings.HasPrefix(et, "user.mfa."):
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeStart)
	case et == "policy.evaluate_sign_on":
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeInfo)
	case strings.HasPrefix(et, "user.lifecycle.") || strings.HasPrefix(et, "user.account.") || strings.HasPrefix(et, "group.user_membership.") ||
		strings.HasPrefix(et, "group.lifecycle.") || strings.HasPrefix(et, "application.user_membership.") ||
		strings.HasPrefix(et, "application.lifecycle.") || strings.HasPrefix(et, "system.api_token."):
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(verbType(et))
	case strings.HasPrefix(et, "policy.") || strings.HasPrefix(et, "system.") || strings.HasPrefix(et, "security.") || strings.HasPrefix(et, "app."):
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(verbType(et))
	default:
		e.SetTypes(schema.TypeInfo)
	}
}

func num(v any) any {
	e := schema.New()
	e.Set("v", v)
	if f, ok := e.Float64("v"); ok {
		return f
	}
	return e.String("v")
}

func snake(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			out[parsers.Snake(k)] = snake(sub)
			continue
		}
		out[parsers.Snake(k)] = num2(v)
	}
	return out
}

func num2(v any) any {
	e := schema.New()
	e.Set("v", v)
	got, _ := e.Get("v")
	return got
}
