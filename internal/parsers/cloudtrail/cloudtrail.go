// Package cloudtrail parses AWS CloudTrail records (single record, the
// {"Records":[...]} S3 envelope, or an EventBridge envelope) into ECS per
// docs/SCHEMA.md §9.
package cloudtrail

import (
	"bytes"
	"errors"
	"sort"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// Parser implements parsers.Parser.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string       { return "aws" }
func (*Parser) Version() string    { return "1.0.0" }
func (*Parser) Datasets() []string { return []string{"aws.cloudtrail"} }

var errNotCloudTrail = errors.New("cloudtrail: not a CloudTrail record")

// textLimit bounds the compact JSON copies used for substring search.
const textLimit = 32 * 1024

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, _ map[string]string) bool {
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 || b[0] != '{' {
		return false
	}
	if bytes.Contains(b, []byte(`"AWS API Call via CloudTrail"`)) {
		return true
	}
	return bytes.Contains(b, []byte(`"eventVersion"`)) && bytes.Contains(b, []byte(`"eventSource"`)) && bytes.Contains(b, []byte(`"eventName"`))
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	obj, err := parsers.DecodeJSON(in.Raw)
	if err != nil {
		return nil, err
	}
	var records []map[string]any
	switch {
	case parsers.GetSlice(obj, "Records") != nil:
		for _, r := range parsers.GetSlice(obj, "Records") {
			if m, ok := r.(map[string]any); ok {
				records = append(records, m)
			}
		}
	case parsers.GetString(obj, "detail-type") == "AWS API Call via CloudTrail":
		if d := parsers.GetMap(obj, "detail"); d != nil {
			records = append(records, d)
		}
	default:
		records = append(records, obj)
	}
	out := make([]*schema.Event, 0, len(records))
	for _, r := range records {
		if parsers.GetString(r, "eventName") == "" || parsers.GetString(r, "eventSource") == "" {
			continue
		}
		out = append(out, build(in, r))
	}
	if len(out) == 0 {
		return nil, errNotCloudTrail
	}
	return out, nil
}

func build(in *parsers.Input, r map[string]any) *schema.Event {
	e := parsers.Base(in, "aws", "aws.cloudtrail")
	name := parsers.GetString(r, "eventName")
	source := parsers.GetString(r, "eventSource")
	parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(r, "eventTime"))
	e.Set(schema.FieldEventID, parsers.GetString(r, "eventID"))
	e.Set(schema.FieldEventAction, name)
	e.Set(schema.FieldEventProvider, source)
	e.Set("cloud.provider", "aws")
	e.Set("cloud.region", parsers.GetString(r, "awsRegion"))
	e.Set("cloud.account.id", parsers.GetString(r, "recipientAccountId"))
	e.Set("cloud.service.name", strings.TrimSuffix(source, ".amazonaws.com"))
	errCode := parsers.GetString(r, "errorCode")
	errMsg := parsers.GetString(r, "errorMessage")
	e.Set("aws.cloudtrail.error_code", errCode)
	e.Set("aws.cloudtrail.error_message", errMsg)
	readOnly, hasRO := parsers.GetBool(r, "readOnly")
	if hasRO {
		e.Set("aws.cloudtrail.read_only", readOnly)
	}
	classify(e, source, name, readOnly && hasRO)
	outcome := schema.OutcomeSuccess
	if errCode != "" || errMsg != "" {
		outcome = schema.OutcomeFailure
	}
	if name == "ConsoleLogin" {
		if res := parsers.GetString(r, "responseElements.ConsoleLogin"); res == "Failure" {
			outcome = schema.OutcomeFailure
		}
	}
	e.Set(schema.FieldEventOutcome, outcome)
	src := parsers.GetString(r, "sourceIPAddress")
	if !parsers.SetIP(e, "source.ip", src) {
		e.Set("source.address", src)
	}
	e.Set("user_agent.original", parsers.GetString(r, "userAgent"))
	userIdentity(e, parsers.GetMap(r, "userIdentity"))
	for _, k := range []struct{ from, to string }{
		{"requestParameters", "request_parameters"}, {"responseElements", "response_elements"},
		{"additionalEventData", "additional_eventdata"}, {"serviceEventDetails", "service_event_details"},
	} {
		v, ok := r[k.from]
		if !ok || v == nil {
			continue
		}
		if m, ok := v.(map[string]any); ok {
			parsers.FlattenInto(e, "aws.cloudtrail.flattened."+k.to, m, false)
		}
		if k.to == "request_parameters" || k.to == "response_elements" {
			e.Set("aws.cloudtrail."+k.to, parsers.CompactJSON(v, textLimit))
		}
	}
	if name == "ConsoleLogin" {
		if mfa := parsers.GetString(r, "additionalEventData.MFAUsed"); mfa != "" {
			e.Set("aws.cloudtrail.console_login.additional_eventdata.mfa_used", strings.EqualFold(mfa, "Yes"))
		}
		e.Set("aws.cloudtrail.console_login.additional_eventdata.mobile_version", parsers.GetString(r, "additionalEventData.MobileVersion"))
		e.Set("aws.cloudtrail.console_login.additional_eventdata.login_to", parsers.GetString(r, "additionalEventData.LoginTo"))
	}
	for _, k := range []struct{ from, to string }{
		{"eventType", "event_type"}, {"eventVersion", "event_version"}, {"eventCategory", "event_category"},
		{"apiVersion", "api_version"}, {"sharedEventID", "shared_event_id"}, {"vpcEndpointId", "vpc_endpoint_id"},
		{"recipientAccountId", "recipient_account_id"}, {"requestID", "request_id"},
	} {
		e.Set("aws.cloudtrail."+k.to, parsers.GetString(r, k.from))
	}
	if b, ok := parsers.GetBool(r, "managementEvent"); ok {
		e.Set("aws.cloudtrail.management_event", b)
	}
	var resources []any
	for _, x := range parsers.GetSlice(r, "resources") {
		if m, ok := x.(map[string]any); ok {
			resources = append(resources, map[string]any{
				"arn": parsers.GetString(m, "ARN"), "account_id": parsers.GetString(m, "accountId"), "type": parsers.GetString(m, "type"),
			})
		}
	}
	if len(resources) > 0 {
		e.Set("aws.cloudtrail.resources", resources)
	}
	if td := parsers.GetMap(r, "tlsDetails"); td != nil {
		e.Set("aws.cloudtrail.tls_details.tls_version", parsers.GetString(td, "tlsVersion"))
		e.Set("aws.cloudtrail.tls_details.cipher_suite", parsers.GetString(td, "cipherSuite"))
		e.Set("aws.cloudtrail.tls_details.client_provided_host_header", parsers.GetString(td, "clientProvidedHostHeader"))
	}
	if id := parsers.GetMap(r, "insightDetails"); id != nil {
		parsers.FlattenInto(e, "aws.cloudtrail.insight_details", id, true)
	}
	msg := name + " on " + source
	if u := e.String("user.name"); u != "" {
		msg = u + " called " + msg
	}
	e.Set(schema.FieldMessage, msg)
	return e
}

func userIdentity(e *schema.Event, ui map[string]any) {
	if ui == nil {
		return
	}
	typ := parsers.GetString(ui, "type")
	arn := parsers.GetString(ui, "arn")
	e.Set("aws.cloudtrail.user_identity.type", typ)
	e.Set("aws.cloudtrail.user_identity.arn", arn)
	e.Set("aws.cloudtrail.user_identity.account_id", parsers.GetString(ui, "accountId"))
	e.Set("aws.cloudtrail.user_identity.access_key_id", parsers.GetString(ui, "accessKeyId"))
	e.Set("aws.cloudtrail.user_identity.invoked_by", parsers.GetString(ui, "invokedBy"))
	e.Set("aws.cloudtrail.user_identity.identity_provider", parsers.GetString(ui, "identityProvider"))
	e.Set("user.id", parsers.GetString(ui, "principalId"))
	sc := parsers.GetMap(ui, "sessionContext")
	if sc != nil {
		if mfa := parsers.GetString(sc, "attributes.mfaAuthenticated"); mfa != "" {
			e.Set("aws.cloudtrail.user_identity.session_context.mfa_authenticated", strings.EqualFold(mfa, "true"))
		}
		e.Set("aws.cloudtrail.user_identity.session_context.creation_date", parsers.GetString(sc, "attributes.creationDate"))
		if si := parsers.GetMap(sc, "sessionIssuer"); si != nil {
			for _, k := range []struct{ from, to string }{{"type", "type"}, {"principalId", "principal_id"}, {"arn", "arn"}, {"accountId", "account_id"}, {"userName", "user_name"}} {
				e.Set("aws.cloudtrail.user_identity.session_context.session_issuer."+k.to, parsers.GetString(si, k.from))
			}
		}
		if wf := parsers.GetMap(sc, "webIdFederationData"); wf != nil {
			parsers.FlattenInto(e, "aws.cloudtrail.user_identity.session_context.web_id_federation_data", wf, true)
		}
	}
	name := parsers.GetString(ui, "userName")
	switch {
	case name != "":
	case typ == "Root":
		name = "Root"
	case arn != "":
		name = arn[strings.LastIndexByte(arn, '/')+1:]
		if !strings.Contains(arn, "/") {
			name = ""
		}
	}
	if name == "" && sc != nil {
		name = parsers.GetString(sc, "sessionIssuer.userName")
	}
	if name == "" && typ == "AWSService" {
		name = parsers.GetString(ui, "invokedBy")
	}
	e.Set("user.name", name)
}

// verbType maps an API name's verb prefix to an ECS event.type.
func verbType(name string) string {
	prefixes := []struct{ p, t string }{
		{"Create", schema.TypeCreation}, {"Run", schema.TypeCreation}, {"Import", schema.TypeCreation}, {"Copy", schema.TypeCreation},
		{"Delete", schema.TypeDeletion}, {"Remove", schema.TypeDeletion}, {"Terminate", schema.TypeDeletion}, {"Deregister", schema.TypeDeletion},
		{"Put", schema.TypeChange}, {"Update", schema.TypeChange}, {"Modify", schema.TypeChange}, {"Attach", schema.TypeChange},
		{"Detach", schema.TypeChange}, {"Add", schema.TypeChange}, {"Set", schema.TypeChange}, {"Enable", schema.TypeChange},
		{"Disable", schema.TypeChange}, {"Authorize", schema.TypeChange}, {"Revoke", schema.TypeChange}, {"Stop", schema.TypeChange},
		{"Start", schema.TypeChange}, {"Reset", schema.TypeChange}, {"Associate", schema.TypeChange}, {"Disassociate", schema.TypeChange},
		{"Tag", schema.TypeChange}, {"Untag", schema.TypeChange}, {"Change", schema.TypeChange}, {"Upload", schema.TypeChange},
		{"Get", schema.TypeAccess}, {"List", schema.TypeAccess}, {"Describe", schema.TypeAccess}, {"Head", schema.TypeAccess},
		{"Lookup", schema.TypeAccess}, {"Search", schema.TypeAccess},
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p.p) {
			return p.t
		}
	}
	return schema.TypeInfo
}

var configServices = map[string]bool{
	"ec2.amazonaws.com": true, "s3.amazonaws.com": true, "kms.amazonaws.com": true, "cloudtrail.amazonaws.com": true,
	"config.amazonaws.com": true, "guardduty.amazonaws.com": true, "securityhub.amazonaws.com": true,
	"lambda.amazonaws.com": true, "logs.amazonaws.com": true,
}

func classify(e *schema.Event, source, name string, readOnly bool) {
	switch {
	case name == "ConsoleLogin" || strings.HasPrefix(name, "AssumeRole") || name == "GetSessionToken" || name == "GetFederationToken" || name == "SwitchRole":
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeStart)
		return
	case source == "iam.amazonaws.com" || source == "sts.amazonaws.com" || source == "sso.amazonaws.com" || source == "identitystore.amazonaws.com":
		e.SetCategory(schema.CategoryIAM)
	case name == "GetObject" || name == "PutObject" || name == "DeleteObject" || name == "CopyObject" || name == "DeleteObjects":
		e.SetCategory(schema.CategoryFile)
	case configServices[source]:
		e.SetCategory(schema.CategoryConfiguration)
	default:
		e.SetCategory(schema.CategoryConfiguration)
	}
	t := verbType(name)
	if readOnly {
		t = schema.TypeAccess
	}
	e.SetTypes(t)
}

// sortedKeys is used by tests to assert deterministic flattening.
func sortedKeys(m map[string]any) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
