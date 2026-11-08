// Package paloalto parses Palo Alto Networks PAN-OS syslog (CSV bodies) into
// ECS per docs/SCHEMA.md §15.
package paloalto

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
	"github.com/lumidren/argus/internal/syslog"
)

// Parser implements parsers.Parser.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string       { return "panw" }
func (*Parser) Version() string    { return "1.0.0" }
func (*Parser) Datasets() []string { return []string{"panw.panos"} }

var errNotPANOS = errors.New("panw: not a PAN-OS CSV log")

var serialRe = regexp.MustCompile(`^[A-Za-z0-9]{6,}$`)
var threatIDRe = regexp.MustCompile(`^(.*)\((\d+)\)$`)

func body(raw []byte) string {
	s := strings.TrimRight(string(raw), "\r\n")
	if h, err := syslog.Parse([]byte(s), parsers.Now()); err == nil && h.Format != "bare" {
		return h.Message
	}
	return s
}

func columns(b string) []string {
	cols := parsers.SplitCSVLine(b)
	if len(cols) < 8 {
		return nil
	}
	if !knownTypes[cols[3]] || !serialRe.MatchString(cols[2]) {
		return nil
	}
	return cols
}

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, _ map[string]string) bool {
	return columns(body(raw)) != nil
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	s := strings.TrimRight(string(in.Raw), "\r\n")
	var hdr syslog.Header
	hasHdr := false
	if h, err := syslog.Parse([]byte(s), in.ReceivedAt); err == nil && h.Format != "bare" {
		hdr, hasHdr = h, true
		s = h.Message
	}
	cols := columns(s)
	if cols == nil {
		return nil, errNotPANOS
	}
	typ := cols[3]
	e := parsers.Base(in, "panw", "panw.panos")
	if hasHdr {
		syslog.Apply(e, hdr)
		e.Set("observer.hostname", hdr.Hostname)
		e.Delete(schema.FieldHostName)
	}
	e.Set("observer.vendor", "Palo Alto Networks")
	e.Set("observer.product", "PAN-OS")
	e.Set("observer.type", "firewall")
	f := map[string]string{}
	if tbl, ok := tables[typ]; ok {
		for i, c := range cols {
			if i < len(tbl) {
				if !strings.HasPrefix(tbl[i], "_") {
					f[tbl[i]] = c
				}
			} else if c != "" {
				e.Append("panw.panos.extra", c)
			}
		}
	} else {
		for i, c := range cols {
			if i < len(prefix) {
				if !strings.HasPrefix(prefix[i], "_") {
					f[prefix[i]] = c
				}
				continue
			}
			if c != "" {
				e.Set("panw.panos."+strings.ToLower(typ)+".col_"+strconv.Itoa(i), c)
			}
		}
	}
	get := func(k string) string {
		v := strings.TrimSpace(f[k])
		if v == "" {
			return ""
		}
		return v
	}
	e.Set("panw.panos.type", typ)
	e.Set("panw.panos.sub_type", get("subtype"))
	e.Set("observer.serial_number", get("serial"))
	if !parsers.SetTime(e, schema.FieldTimestamp, get("high_res_timestamp")) {
		parsers.SetTime(e, schema.FieldTimestamp, get("generated_time"))
	}
	parsers.SetTime(e, "panw.panos.receive_time", get("receive_time"))
	for _, k := range []string{"seqno", "actionflags", "vsys", "vsys_name", "device_name", "action_source", "rule_uuid", "session_end_reason", "logset"} {
		e.Set("panw.panos."+k, get(k))
	}
	for i := 1; i <= 4; i++ {
		e.Set("panw.panos.device_group_hierarchy.level_"+strconv.Itoa(i), get("dg_hier_level_"+strconv.Itoa(i)))
	}
	e.Set("observer.name", get("device_name"))
	switch typ {
	case "TRAFFIC", "THREAT":
		network(e, get, typ)
	case "SYSTEM":
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeInfo)
		e.Set("panw.panos.event_id", get("eventid"))
		e.Set("panw.panos.object", get("object"))
		e.Set("panw.panos.module", get("module"))
		e.Set("log.level", get("severity"))
		e.Set(schema.FieldMessage, get("opaque"))
		e.Set(schema.FieldEventAction, get("eventid"))
	case "CONFIG":
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		parsers.SetIP(e, "source.ip", get("host"))
		e.Set("user.name", get("admin"))
		e.Set("panw.panos.cmd", get("cmd"))
		e.Set("panw.panos.client", get("client"))
		e.Set("panw.panos.result", get("result"))
		e.Set("panw.panos.config_path", get("path"))
		e.Set("panw.panos.before_change_detail", get("before_change_detail"))
		e.Set("panw.panos.after_change_detail", get("after_change_detail"))
		e.Set(schema.FieldEventAction, get("cmd"))
		switch strings.ToLower(get("result")) {
		case "succeeded", "success":
			e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
		case "failed", "failure":
			e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		}
		e.Set(schema.FieldMessage, get("admin")+" "+get("cmd")+" "+get("path"))
	case "AUTHENTICATION":
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeStart)
		parsers.SetIP(e, "source.ip", get("ip"))
		parsers.SetUser(e, "user", get("user"))
		e.Set("rule.name", get("authpolicy"))
		ev := get("event")
		e.Set(schema.FieldEventAction, ev)
		for _, k := range []string{"serverprofile", "desc", "clienttype", "factorno", "authproto", "vendor", "object", "normalize_user"} {
			e.Set("panw.panos.auth."+k, get(k))
		}
		e.Set("panw.panos.auth.event", ev)
		switch {
		case strings.Contains(strings.ToLower(ev), "success"):
			e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
		case strings.Contains(strings.ToLower(ev), "fail"):
			e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		}
		e.Set(schema.FieldMessage, get("desc"))
	case "GLOBALPROTECT":
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeInfo)
		parsers.SetUser(e, "user", get("srcuser"))
		parsers.SetIP(e, "source.ip", get("public_ip"))
		e.Set(schema.FieldEventAction, get("eventid"))
		for _, k := range []string{"stage", "auth_method", "tunnel_type", "srcregion", "machinename", "private_ip", "hostid", "client_ver", "client_os", "client_os_ver", "status", "error", "error_code", "portal", "gateway", "connect_method", "login_duration", "selection_type", "priority", "attempted_gateways", "reason"} {
			e.Set("panw.panos.gp."+k, get(k))
		}
		switch strings.ToLower(get("status")) {
		case "success":
			e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
		case "failure":
			e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		}
		e.Set(schema.FieldMessage, get("opaque"))
	default:
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeInfo)
	}
	if !e.Has(schema.FieldMessage) {
		e.Set(schema.FieldMessage, typ+" "+get("subtype"))
	}
	return []*schema.Event{e}, nil
}

func network(e *schema.Event, get func(string) string, typ string) {
	parsers.SetIP(e, "source.ip", get("src"))
	parsers.SetIP(e, "destination.ip", get("dst"))
	if n := get("natsrc"); n != "0.0.0.0" {
		parsers.SetIP(e, "source.nat.ip", n)
	}
	if n := get("natdst"); n != "0.0.0.0" {
		parsers.SetIP(e, "destination.nat.ip", n)
	}
	parsers.SetPort(e, "source.port", get("sport"))
	parsers.SetPort(e, "destination.port", get("dport"))
	if v := get("natsport"); v != "0" {
		parsers.SetPort(e, "source.nat.port", v)
	}
	if v := get("natdport"); v != "0" {
		parsers.SetPort(e, "destination.nat.port", v)
	}
	e.Set("rule.name", get("rule"))
	e.Set("rule.uuid", get("rule_uuid"))
	parsers.SetUser(e, "source.user", get("srcuser"))
	parsers.SetUser(e, "destination.user", get("dstuser"))
	e.Set("user.name", e.String("source.user.name"))
	e.Set("network.application", get("app"))
	e.Set("observer.ingress.zone", get("from"))
	e.Set("observer.egress.zone", get("to"))
	e.Set("observer.ingress.interface.name", get("inbound_if"))
	e.Set("observer.egress.interface.name", get("outbound_if"))
	e.Set("panw.panos.flow_id", get("sessionid"))
	parsers.SetInt(e, "panw.panos.repeat_count", get("repeatcnt"))
	parsers.SetTransport(e, get("proto"))
	action := get("action")
	e.Set(schema.FieldEventAction, action)
	e.Set("panw.panos.action", action)
	e.Set("panw.panos.url.category", get("category"))
	for _, loc := range []struct{ key, dst string }{{"srcloc", "source"}, {"dstloc", "destination"}} {
		v := get(loc.key)
		switch {
		case v == "":
		case len(v) == 2 && strings.ToUpper(v) == v:
			e.Set(loc.dst+".geo.country_iso_code", v)
		default:
			e.Set("panw.panos."+loc.dst+".zone_location", v)
		}
	}
	allow := action == "allow" || action == "alert"
	if typ == "TRAFFIC" {
		e.SetCategory(schema.CategoryNetwork)
		if allow {
			e.SetTypes(schema.TypeConnection, schema.TypeAllowed)
			e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
		} else {
			e.SetTypes(schema.TypeConnection, schema.TypeDenied)
			e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		}
		parsers.SetInt(e, "network.bytes", get("bytes"))
		parsers.SetInt(e, "source.bytes", get("bytes_sent"))
		parsers.SetInt(e, "destination.bytes", get("bytes_received"))
		parsers.SetInt(e, "network.packets", get("packets"))
		parsers.SetInt(e, "source.packets", get("pkts_sent"))
		parsers.SetInt(e, "destination.packets", get("pkts_received"))
		parsers.SetTime(e, "event.start", get("start"))
		if el, err := strconv.ParseInt(get("elapsed"), 10, 64); err == nil {
			e.Set("event.duration", el*1e9)
		}
		e.Set(schema.FieldMessage, "TRAFFIC "+get("subtype")+" "+action+" "+get("app"))
		return
	}
	// THREAT
	e.Set(schema.FieldEventKind, schema.KindAlert)
	e.SetCategory(schema.CategoryNetwork, schema.CategoryIntrusionDetection)
	switch {
	case action == "allow":
		e.SetTypes(schema.TypeAllowed)
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	case action == "alert":
		e.SetTypes(schema.TypeInfo)
		e.Set(schema.FieldEventOutcome, schema.OutcomeUnknown)
	default:
		e.SetTypes(schema.TypeDenied)
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	}
	tid := get("threatid")
	if m := threatIDRe.FindStringSubmatch(tid); m != nil {
		e.Set("panw.panos.threat.name", strings.TrimSpace(m[1]))
		e.Set("panw.panos.threat.id", m[2])
	} else {
		e.Set("panw.panos.threat.name", tid)
	}
	if sev, ok := parsers.Severity0to100(get("severity")); ok {
		e.Set(schema.FieldEventSeverity, sev)
	}
	e.Set("panw.panos.severity", get("severity"))
	e.Set("panw.panos.direction", get("direction"))
	misc := strings.Trim(get("misc"), `"`)
	switch e.String("panw.panos.sub_type") {
	case "url":
		if misc != "" {
			parsers.SetURL(e, misc)
		}
	case "file", "virus", "wildfire", "wildfire-virus", "ml-virus", "data":
		e.Set("file.name", misc)
	default:
		e.Set("panw.panos.misc", misc)
	}
	if fd := get("filedigest"); fd != "" {
		parsers.SetHashByLength(e, "file.hash", fd)
	}
	e.Set("user_agent.original", strings.Trim(get("user_agent"), `"`))
	if xff := get("xff"); xff != "" {
		e.Set("network.forwarded_ip", xff)
	}
	e.Set("http.request.referrer", strings.Trim(get("referer"), `"`))
	e.Set("http.request.method", get("http_method"))
	e.Set("email.from.address", get("sender"))
	e.Set("email.subject", get("subject"))
	e.Set("email.to.address", get("recipient"))
	for _, k := range []string{"contenttype", "pcap_id", "cloud", "url_idx", "filetype", "reportid", "thr_category", "contentver", "sig_flags", "partial_hash"} {
		e.Set("panw.panos."+k, get(k))
	}
	e.Set(schema.FieldMessage, e.String("panw.panos.threat.name"))
}
