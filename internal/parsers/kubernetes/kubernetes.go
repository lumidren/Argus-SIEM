// Package kubernetes parses Kubernetes API server audit events (audit.k8s.io/v1
// Event or EventList) into ECS per docs/SCHEMA.md §18.
package kubernetes

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

func (*Parser) Name() string       { return "kubernetes" }
func (*Parser) Version() string    { return "1.0.0" }
func (*Parser) Datasets() []string { return []string{"kubernetes.audit"} }

var errNotAudit = errors.New("kubernetes: not an audit event")

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, _ map[string]string) bool {
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 || b[0] != '{' {
		return false
	}
	if bytes.Contains(b, []byte(`audit.k8s.io/v1`)) && (bytes.Contains(b, []byte(`"Event"`)) || bytes.Contains(b, []byte(`"EventList"`))) {
		return true
	}
	return bytes.Contains(b, []byte(`"auditID"`)) && bytes.Contains(b, []byte(`"verb"`)) && bytes.Contains(b, []byte(`"requestURI"`))
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	obj, err := parsers.DecodeJSON(in.Raw)
	if err != nil {
		return nil, err
	}
	var items []map[string]any
	if parsers.GetString(obj, "kind") == "EventList" {
		for _, x := range parsers.GetSlice(obj, "items") {
			if m, ok := x.(map[string]any); ok {
				items = append(items, m)
			}
		}
	} else {
		items = append(items, obj)
	}
	keepAll := in.Hint("keep_all_stages") == "true"
	var out []*schema.Event
	valid := 0
	for _, it := range items {
		if parsers.GetString(it, "auditID") == "" || parsers.GetString(it, "verb") == "" {
			continue
		}
		valid++
		stage := parsers.GetString(it, "stage")
		if !keepAll && stage != "" && stage != "ResponseComplete" && stage != "Panic" {
			continue
		}
		out = append(out, build(in, it))
	}
	if valid == 0 {
		return nil, errNotAudit
	}
	return out, nil
}

var iamResources = map[string]bool{
	"roles": true, "rolebindings": true, "clusterroles": true, "clusterrolebindings": true, "serviceaccounts": true,
	"tokenreviews": true, "subjectaccessreviews": true, "certificatesigningrequests": true,
}

func build(in *parsers.Input, a map[string]any) *schema.Event {
	e := parsers.Base(in, "kubernetes", "kubernetes.audit")
	stage := parsers.GetString(a, "stage")
	verb := parsers.GetString(a, "verb")
	if stage == "Panic" {
		parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(a, "stageTimestamp"))
	} else {
		parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(a, "requestReceivedTimestamp"))
	}
	auditID := parsers.GetString(a, "auditID")
	e.Set(schema.FieldEventID, auditID+"-"+stage)
	e.Set(schema.FieldEventAction, verb)
	for _, k := range []struct{ from, to string }{{"level", "level"}, {"stage", "stage"}, {"verb", "verb"}, {"requestURI", "request_uri"}, {"auditID", "audit_id"}, {"kind", "kind"}, {"apiVersion", "api_version"}} {
		e.Set("kubernetes.audit."+k.to, parsers.GetString(a, k.from))
	}
	uri := parsers.GetString(a, "requestURI")
	parsers.SetURL(e, uri)
	e.Set("user.name", parsers.GetString(a, "user.username"))
	e.Set("user.id", parsers.GetString(a, "user.uid"))
	if g := parsers.GetStrings(a, "user.groups"); len(g) > 0 {
		e.Set("user.group.name", g)
	}
	if ex := parsers.GetMap(a, "user.extra"); ex != nil {
		for k, v := range ex {
			e.Set("kubernetes.audit.user.extra."+sanitize(k), toStrings(v))
		}
	}
	if iu := parsers.GetMap(a, "impersonatedUser"); iu != nil {
		e.Set("kubernetes.audit.impersonated_user.username", parsers.GetString(iu, "username"))
		e.Set("kubernetes.audit.impersonated_user.uid", parsers.GetString(iu, "uid"))
		if g := parsers.GetStrings(iu, "groups"); len(g) > 0 {
			e.Set("kubernetes.audit.impersonated_user.groups", g)
		}
		e.Set("user.effective.name", parsers.GetString(iu, "username"))
	}
	ips := parsers.GetStrings(a, "sourceIPs")
	if len(ips) > 0 {
		if !parsers.SetIP(e, "source.ip", ips[0]) {
			e.Set("source.address", ips[0])
		}
		for _, ip := range ips {
			if n := parsers.NormalizeIP(ip); n != "" {
				e.Append("related.ip", n)
			}
		}
	}
	e.Set("user_agent.original", parsers.GetString(a, "userAgent"))
	ref := parsers.GetMap(a, "objectRef")
	resource := parsers.GetString(ref, "resource")
	sub := parsers.GetString(ref, "subresource")
	for _, k := range []struct{ from, to string }{{"resource", "resource"}, {"namespace", "namespace"}, {"name", "name"}, {"uid", "uid"}, {"apiGroup", "api_group"}, {"apiVersion", "api_version"}, {"resourceVersion", "resource_version"}, {"subresource", "subresource"}} {
		e.Set("kubernetes.audit.object_ref."+k.to, parsers.GetString(ref, k.from))
	}
	e.Set("orchestrator.type", "kubernetes")
	e.Set("orchestrator.namespace", parsers.GetString(ref, "namespace"))
	e.Set("orchestrator.resource.type", resource)
	e.Set("orchestrator.resource.name", parsers.GetString(ref, "name"))
	e.Set("orchestrator.api_version", parsers.GetString(ref, "apiVersion"))
	cluster := in.Hint("cluster")
	ann := parsers.GetMap(a, "annotations")
	if cluster == "" {
		cluster = parsers.GetString(ann, "cluster")
	}
	e.Set("orchestrator.cluster.name", cluster)
	code, hasCode := parsers.GetInt(a, "responseStatus.code")
	if hasCode {
		e.Set("kubernetes.audit.response_status.code", code)
	}
	for _, k := range []string{"status", "reason", "message"} {
		e.Set("kubernetes.audit.response_status."+k, parsers.GetString(a, "responseStatus."+k))
	}
	decision := ""
	for k, v := range ann {
		val := str(v)
		e.Set("kubernetes.audit.annotations."+sanitize(k), val)
		if k == "authorization.k8s.io/decision" {
			decision = val
			e.Set("kubernetes.audit.annotations.authorization_k8s_io/decision", val)
		}
		if k == "authorization.k8s.io/reason" {
			e.Set("kubernetes.audit.annotations.authorization_k8s_io/reason", val)
		}
	}
	switch {
	case decision == "forbid":
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	case hasCode && code >= 400:
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	case hasCode || stage == "ResponseComplete":
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	}
	for _, k := range []struct{ from, to string }{{"requestObject", "request_object"}, {"responseObject", "response_object"}} {
		if m := parsers.GetMap(a, k.from); m != nil {
			parsers.FlattenInto(e, "kubernetes.audit."+k.to, m, false)
			if k.to == "request_object" {
				e.Set("kubernetes.audit.request_object_text", parsers.CompactJSON(m, 32*1024))
				if resource == "pods" && verb == "create" {
					podSpec(e, m)
				}
			}
		}
	}
	classify(e, resource, sub, verb)
	msg := e.String("user.name") + " " + verb + " " + resource
	if n := parsers.GetString(ref, "name"); n != "" {
		msg += "/" + n
	}
	e.Set(schema.FieldMessage, strings.TrimSpace(msg))
	return e
}

func podSpec(e *schema.Event, obj map[string]any) {
	spec := parsers.GetMap(obj, "spec")
	if spec == nil {
		return
	}
	var images []string
	privileged := false
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for _, x := range parsers.GetSlice(spec, key) {
			c, ok := x.(map[string]any)
			if !ok {
				continue
			}
			if img := parsers.GetString(c, "image"); img != "" {
				images = append(images, img)
			}
			if b, ok := parsers.GetBool(c, "securityContext.privileged"); ok && b {
				privileged = true
			}
		}
	}
	if len(images) > 0 {
		e.Set("container.image.name", images[0])
		e.Set("kubernetes.audit.pod.image", images[0])
		e.Set("kubernetes.audit.pod.images", images)
	}
	e.Set("kubernetes.audit.pod.privileged", privileged)
	for _, f := range []struct{ from, to string }{{"hostPID", "host_pid"}, {"hostNetwork", "host_network"}, {"hostIPC", "host_ipc"}} {
		if b, ok := parsers.GetBool(spec, f.from); ok {
			e.Set("kubernetes.audit.pod."+f.to, b)
		}
	}
	var hostPaths []string
	for _, x := range parsers.GetSlice(spec, "volumes") {
		if v, ok := x.(map[string]any); ok {
			if p := parsers.GetString(v, "hostPath.path"); p != "" {
				hostPaths = append(hostPaths, p)
			}
		}
	}
	if len(hostPaths) > 0 {
		e.Set("kubernetes.audit.pod.host_path", hostPaths)
	}
}

func classify(e *schema.Event, resource, sub, verb string) {
	switch {
	case iamResources[resource]:
		e.SetCategory(schema.CategoryIAM)
	case resource == "pods" && (sub == "exec" || sub == "attach" || sub == "portforward"):
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeStart)
		return
	default:
		e.SetCategory(schema.CategoryConfiguration)
	}
	switch verb {
	case "create":
		e.SetTypes(schema.TypeCreation)
	case "delete", "deletecollection":
		e.SetTypes(schema.TypeDeletion)
	case "update", "patch":
		e.SetTypes(schema.TypeChange)
	case "get", "list", "watch", "proxy":
		e.SetTypes(schema.TypeAccess)
	default:
		e.SetTypes(schema.TypeInfo)
	}
}

func sanitize(k string) string {
	return strings.NewReplacer(".", "_", "/", "_").Replace(k)
}

func str(v any) string {
	e := schema.New()
	e.Set("v", v)
	return e.String("v")
}

func toStrings(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			out = append(out, str(x))
		}
		return out
	default:
		return []string{str(v)}
	}
}
