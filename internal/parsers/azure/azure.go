// Package azure parses Azure Monitor / Entra ID records (sign-in logs,
// directory audit logs, ARM activity logs) delivered through Event Hub
// envelopes or Microsoft Graph, into ECS per docs/SCHEMA.md §10.
package azure

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

func (*Parser) Name() string    { return "azure" }
func (*Parser) Version() string { return "1.0.0" }
func (*Parser) Datasets() []string {
	return []string{"azure.signinlogs", "azure.auditlogs", "azure.activitylogs"}
}

var errNotAzure = errors.New("azure: not an Azure record")

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, _ map[string]string) bool {
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 || b[0] != '{' {
		return false
	}
	if bytes.Contains(b, []byte(`"eventSource"`)) || bytes.Contains(b, []byte(`"RecordType"`)) {
		return false
	}
	if bytes.Contains(b, []byte(`"userPrincipalName"`)) && bytes.Contains(b, []byte(`"appDisplayName"`)) {
		return true
	}
	if !bytes.Contains(b, []byte(`"operationName"`)) {
		return false
	}
	return bytes.Contains(b, []byte(`"resourceId"`)) || bytes.Contains(b, []byte(`"tenantId"`)) || bytes.Contains(b, []byte(`"callerIpAddress"`)) || bytes.Contains(b, []byte(`"category"`))
}

var signinCategories = map[string]bool{
	"SignInLogs": true, "NonInteractiveUserSignInLogs": true, "ServicePrincipalSignInLogs": true, "ManagedIdentitySignInLogs": true,
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	obj, err := parsers.DecodeJSON(in.Raw)
	if err != nil {
		return nil, err
	}
	var records []map[string]any
	if recs := parsers.GetSlice(obj, "records"); recs != nil {
		for _, r := range recs {
			if m, ok := r.(map[string]any); ok {
				records = append(records, m)
			}
		}
	} else if vals := parsers.GetSlice(obj, "value"); vals != nil {
		for _, r := range vals {
			if m, ok := r.(map[string]any); ok {
				records = append(records, m)
			}
		}
	} else {
		records = append(records, obj)
	}
	out := make([]*schema.Event, 0, len(records))
	for _, r := range records {
		var e *schema.Event
		cat := parsers.GetString(r, "category")
		switch {
		case parsers.GetString(r, "userPrincipalName") != "" && parsers.GetString(r, "createdDateTime") != "":
			e = graphSignIn(in, r)
		case signinCategories[cat] || parsers.GetString(r, "operationName") == "Sign-in activity":
			e = signIn(in, r)
		case cat == "AuditLogs" || parsers.GetString(r, "properties.activityDisplayName") != "":
			e = auditLog(in, r)
		case parsers.GetString(r, "operationName") != "":
			e = activityLog(in, r)
		}
		if e != nil {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, errNotAzure
	}
	return out, nil
}

func commonFields(e *schema.Event, r map[string]any) {
	e.Set("cloud.provider", "azure")
	tenant := parsers.GetString(r, "tenantId")
	e.Set("azure.tenant_id", tenant)
	e.Set("cloud.account.id", tenant)
	e.Set("azure.correlation_id", parsers.GetString(r, "correlationId"))
	if rid := parsers.GetString(r, "resourceId"); rid != "" {
		e.Set("azure.resource.id", rid)
		parseResourceID(e, rid)
	}
	parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(r, "time"))
}

// parseResourceID splits /SUBSCRIPTIONS/<id>/RESOURCEGROUPS/<rg>/PROVIDERS/<ns>/<type>/<name>.
func parseResourceID(e *schema.Event, rid string) {
	parts := strings.Split(strings.Trim(rid, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		switch strings.ToUpper(parts[i]) {
		case "SUBSCRIPTIONS":
			e.Set("azure.subscription_id", parts[i+1])
		case "RESOURCEGROUPS":
			e.Set("azure.resource.group", parts[i+1])
		case "PROVIDERS":
			if i+2 < len(parts) {
				e.Set("azure.resource.provider", parts[i+1]+"/"+parts[i+2])
				if i+3 < len(parts) {
					e.Set("azure.resource.name", parts[len(parts)-1])
				}
			} else {
				e.Set("azure.resource.provider", parts[i+1])
			}
			return
		}
	}
}

func signIn(in *parsers.Input, r map[string]any) *schema.Event {
	e := parsers.Base(in, "azure", "azure.signinlogs")
	commonFields(e, r)
	props := parsers.GetMap(r, "properties")
	if props == nil {
		props = map[string]any{}
	}
	e.Set(schema.FieldEventID, parsers.GetString(props, "id"))
	e.Set(schema.FieldEventAction, parsers.GetString(r, "operationName"))
	cat := parsers.GetString(r, "category")
	e.Set("azure.signinlogs.category", cat)
	resultType := parsers.GetString(r, "resultType")
	e.Set("azure.signinlogs.result_type", resultType)
	e.Set("azure.signinlogs.result_signature", parsers.GetString(r, "resultSignature"))
	e.Set("azure.signinlogs.result_description", parsers.GetString(r, "resultDescription"))
	if resultType == "" {
		resultType = parsers.GetString(props, "status.errorCode")
	}
	signInCommon(e, props, resultType == "0")
	if ip := parsers.GetString(r, "callerIpAddress"); ip != "" && !e.Has("source.ip") {
		parsers.SetIP(e, "source.ip", ip)
	}
	return e
}

func graphSignIn(in *parsers.Input, r map[string]any) *schema.Event {
	e := parsers.Base(in, "azure", "azure.signinlogs")
	e.Set("cloud.provider", "azure")
	parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(r, "createdDateTime"))
	e.Set(schema.FieldEventID, parsers.GetString(r, "id"))
	e.Set(schema.FieldEventAction, "Sign-in activity")
	code, _ := parsers.GetInt(r, "status.errorCode")
	signInCommon(e, r, code == 0)
	return e
}

// signInCommon maps the sign-in property bag (Event Hub "properties" or a
// Graph signIn object; both use the same camelCase names).
func signInCommon(e *schema.Event, p map[string]any, success bool) {
	e.SetCategory(schema.CategoryAuthentication)
	if b, ok := parsers.GetBool(p, "isInteractive"); ok && !b {
		e.SetTypes(schema.TypeInfo)
	} else {
		e.SetTypes(schema.TypeStart)
	}
	e.Set(schema.FieldEventOutcome, parsers.OutcomeFromBool(success))
	upn := parsers.GetString(p, "userPrincipalName")
	e.Set("user.name", upn)
	if strings.Contains(upn, "@") {
		e.Set("user.email", upn)
	}
	e.Set("user.id", parsers.GetString(p, "userId"))
	e.Set("user.full_name", parsers.GetString(p, "userDisplayName"))
	parsers.SetIP(e, "source.ip", parsers.GetString(p, "ipAddress"))
	e.Set("user_agent.original", parsers.GetString(p, "userAgent"))
	if loc := parsers.GetMap(p, "location"); loc != nil {
		e.Set("source.geo.city_name", parsers.GetString(loc, "city"))
		e.Set("source.geo.region_name", parsers.GetString(loc, "state"))
		e.Set("source.geo.country_iso_code", parsers.GetString(loc, "countryOrRegion"))
		lat, okLat := parsers.GetPath(loc, "geoCoordinates.latitude")
		lon, okLon := parsers.GetPath(loc, "geoCoordinates.longitude")
		if okLat && okLon {
			e.Set("source.geo.location", map[string]any{"lat": num(lat), "lon": num(lon)})
		}
	}
	scalars := []string{
		"appId", "appDisplayName", "clientAppUsed", "conditionalAccessStatus", "riskDetail", "riskLevelAggregated",
		"riskLevelDuringSignIn", "riskState", "resourceDisplayName", "resourceId", "authenticationRequirement",
		"authenticationProtocol", "tokenIssuerType", "userType", "servicePrincipalId", "servicePrincipalName",
		"crossTenantAccessType", "homeTenantId", "incomingTokenType", "originalRequestId", "sessionId", "correlationId",
		"status.errorCode", "status.failureReason", "status.additionalDetails", "deviceDetail.deviceId",
		"deviceDetail.displayName", "deviceDetail.operatingSystem", "deviceDetail.browser", "deviceDetail.trustType",
		"mfaDetail.authMethod", "mfaDetail.authDetail",
	}
	for _, k := range scalars {
		v, ok := parsers.GetPath(p, k)
		if !ok || v == nil {
			continue
		}
		e.Set("azure.signinlogs.properties."+parsers.SnakePath(k), num(v))
	}
	for _, k := range []string{"isInteractive", "deviceDetail.isCompliant", "deviceDetail.isManaged"} {
		if b, ok := parsers.GetBool(p, k); ok {
			e.Set("azure.signinlogs.properties."+parsers.SnakePath(k), b)
		}
	}
	if rt := parsers.GetStrings(p, "riskEventTypes"); len(rt) > 0 {
		e.Set("azure.signinlogs.properties.risk_event_types", rt)
	}
	for _, k := range []string{"appliedConditionalAccessPolicies", "authenticationDetails", "networkLocationDetails", "authenticationProcessingDetails"} {
		if arr := parsers.GetSlice(p, k); len(arr) > 0 {
			e.Set("azure.signinlogs.properties."+parsers.Snake(k), snakeArray(arr))
		}
	}
	msg := "sign-in"
	if app := parsers.GetString(p, "appDisplayName"); app != "" {
		msg += " to " + app
	}
	if upn != "" {
		msg = upn + " " + msg
	}
	e.Set(schema.FieldMessage, msg)
}

func auditLog(in *parsers.Input, r map[string]any) *schema.Event {
	e := parsers.Base(in, "azure", "azure.auditlogs")
	commonFields(e, r)
	p := parsers.GetMap(r, "properties")
	if p == nil {
		p = r
	}
	activity := parsers.GetString(p, "activityDisplayName")
	e.Set(schema.FieldEventID, parsers.GetString(p, "id"))
	e.Set(schema.FieldEventAction, activity)
	result := strings.ToLower(parsers.GetString(p, "result"))
	switch result {
	case "success":
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	case "failure":
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	}
	e.Set("azure.auditlogs.category", parsers.GetString(r, "category"))
	e.Set("azure.auditlogs.operation_name", parsers.GetString(r, "operationName"))
	e.Set("azure.auditlogs.operation_version", parsers.GetString(r, "operationVersion"))
	e.Set("azure.auditlogs.result_signature", parsers.GetString(r, "resultSignature"))
	for _, k := range []string{"activityDateTime", "activityDisplayName", "category", "loggedByService", "operationType", "result", "resultReason"} {
		e.Set("azure.auditlogs.properties."+parsers.Snake(k), parsers.GetString(p, k))
	}
	if u := parsers.GetMap(p, "initiatedBy.user"); u != nil {
		upn := parsers.GetString(u, "userPrincipalName")
		e.Set("user.name", upn)
		if strings.Contains(upn, "@") {
			e.Set("user.email", upn)
		}
		e.Set("user.id", parsers.GetString(u, "id"))
		parsers.SetIP(e, "source.ip", parsers.GetString(u, "ipAddress"))
		parsers.FlattenInto(e, "azure.auditlogs.properties.initiated_by.user", u, true)
	} else if a := parsers.GetMap(p, "initiatedBy.app"); a != nil {
		e.Set("user.name", parsers.GetString(a, "displayName"))
		e.Set("user.id", parsers.GetString(a, "servicePrincipalId"))
		parsers.FlattenInto(e, "azure.auditlogs.properties.initiated_by.app", a, true)
	}
	if trs := parsers.GetSlice(p, "targetResources"); len(trs) > 0 {
		e.Set("azure.auditlogs.properties.target_resources", snakeArray(trs))
		if first, ok := trs[0].(map[string]any); ok {
			if upn := parsers.GetString(first, "userPrincipalName"); upn != "" {
				e.Set("user.target.name", upn)
				if strings.Contains(upn, "@") {
					e.Set("user.target.email", upn)
				}
			}
			e.Set("user.target.id", parsers.GetString(first, "id"))
		}
	}
	if ad := parsers.GetSlice(p, "additionalDetails"); len(ad) > 0 {
		e.Set("azure.auditlogs.properties.additional_details", snakeArray(ad))
	}
	cat := parsers.GetString(p, "category")
	switch cat {
	case "UserManagement", "GroupManagement", "ApplicationManagement", "RoleManagement", "Policy", "DirectoryManagement":
		e.SetCategory(schema.CategoryIAM)
	default:
		e.SetCategory(schema.CategoryConfiguration)
	}
	e.SetTypes(activityType(activity))
	e.Set(schema.FieldMessage, activity)
	return e
}

func activityType(activity string) string {
	a := strings.ToLower(activity)
	switch {
	case strings.HasPrefix(a, "add") || strings.HasPrefix(a, "create") || strings.HasPrefix(a, "register"):
		return schema.TypeCreation
	case strings.HasPrefix(a, "delete") || strings.HasPrefix(a, "remove") || strings.HasPrefix(a, "hard delete"):
		return schema.TypeDeletion
	case strings.HasPrefix(a, "update") || strings.HasPrefix(a, "change") || strings.HasPrefix(a, "set") || strings.HasPrefix(a, "reset") || strings.HasPrefix(a, "enable") || strings.HasPrefix(a, "disable") || strings.HasPrefix(a, "restore") || strings.HasPrefix(a, "consent"):
		return schema.TypeChange
	}
	return schema.TypeInfo
}

const claimsName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
const claimsUPN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
const claimsOID = "http://schemas.microsoft.com/identity/claims/objectidentifier"

func activityLog(in *parsers.Input, r map[string]any) *schema.Event {
	e := parsers.Base(in, "azure", "azure.activitylogs")
	commonFields(e, r)
	op := parsers.GetString(r, "operationName")
	e.Set(schema.FieldEventAction, op)
	e.Set(schema.FieldEventID, parsers.GetString(r, "correlationId")+":"+op)
	e.Set("azure.activitylogs.operation_name", op)
	e.Set("azure.activitylogs.category", parsers.GetString(r, "category"))
	rt := parsers.GetString(r, "resultType")
	e.Set("azure.activitylogs.result_type", rt)
	e.Set("azure.activitylogs.result_signature", parsers.GetString(r, "resultSignature"))
	e.Set("azure.activitylogs.event_category", parsers.GetString(r, "properties.eventCategory"))
	e.Set("azure.activitylogs.level", parsers.GetString(r, "level"))
	switch strings.ToLower(rt) {
	case "success", "succeeded":
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	case "failure", "failed":
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	default:
		e.Set(schema.FieldEventOutcome, schema.OutcomeUnknown)
	}
	parsers.SetIP(e, "source.ip", parsers.GetString(r, "callerIpAddress"))
	if claims := parsers.GetMap(r, "identity.claims"); claims != nil {
		name := str(claims[claimsName])
		if name == "" {
			name = str(claims[claimsUPN])
		}
		if name == "" {
			name = str(claims["appid"])
		}
		e.Set("user.name", name)
		if strings.Contains(name, "@") {
			e.Set("user.email", name)
		}
		e.Set("user.id", str(claims[claimsOID]))
		for k, v := range claims {
			key := strings.NewReplacer("/", "_", ":", "_", ".", "_").Replace(k)
			e.Set("azure.activitylogs.identity.claims."+key, str(v))
		}
	}
	if auth := parsers.GetMap(r, "identity.authorization"); auth != nil {
		e.Set("azure.activitylogs.identity.authorization.scope", parsers.GetString(auth, "scope"))
		e.Set("azure.activitylogs.identity.authorization.action", parsers.GetString(auth, "action"))
		if ev := parsers.GetMap(auth, "evidence"); ev != nil {
			parsers.FlattenInto(e, "azure.activitylogs.identity.authorization.evidence", ev, true)
		}
	}
	if props := parsers.GetMap(r, "properties"); props != nil {
		parsers.FlattenInto(e, "azure.activitylogs.properties", props, true)
	}
	upper := strings.ToUpper(op)
	if strings.HasPrefix(upper, "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/") || strings.HasPrefix(upper, "MICROSOFT.AUTHORIZATION/ROLEDEFINITIONS/") {
		e.SetCategory(schema.CategoryIAM)
	} else {
		e.SetCategory(schema.CategoryConfiguration)
	}
	last := upper[strings.LastIndexByte(upper, '/')+1:]
	switch last {
	case "WRITE":
		e.SetTypes(schema.TypeChange)
	case "DELETE":
		e.SetTypes(schema.TypeDeletion)
	case "READ":
		e.SetTypes(schema.TypeAccess)
	default:
		e.SetTypes(schema.TypeInfo)
	}
	e.Set(schema.FieldMessage, op)
	return e
}

func str(v any) string {
	e := schema.New()
	e.Set("v", v)
	return e.String("v")
}

func num(v any) any {
	e := schema.New()
	e.Set("v", v)
	if n, ok := e.Int64("v"); ok {
		if f, ok := e.Float64("v"); ok && f != float64(n) {
			return f
		}
		return n
	}
	if f, ok := e.Float64("v"); ok {
		return f
	}
	return e.String("v")
}

// snakeArray converts an array of objects to snake_case keys.
func snakeArray(arr []any) []any {
	out := make([]any, 0, len(arr))
	for _, x := range arr {
		out = append(out, snakeValue(x))
	}
	return out
}

func snakeValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[parsers.Snake(k)] = snakeValue(x)
		}
		return m
	case []any:
		return snakeArray(t)
	}
	return num(v)
}
