// Package fortinet parses Fortinet FortiGate key=value syslog into ECS per
// docs/SCHEMA.md §16.
package fortinet

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
	"github.com/lumidren/argus/internal/syslog"
)

// Parser implements parsers.Parser.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string       { return "fortinet" }
func (*Parser) Version() string    { return "1.0.0" }
func (*Parser) Datasets() []string { return []string{"fortinet.firewall"} }

var errNotFortiGate = errors.New("fortinet: not a FortiGate log")

func body(raw []byte, ref time.Time) (string, syslog.Header, bool) {
	s := strings.TrimRight(string(raw), "\r\n")
	if h, err := syslog.Parse([]byte(s), ref); err == nil && h.Format != "bare" {
		return h.Message, h, true
	}
	return s, syslog.Header{}, false
}

func looksForti(b string) bool {
	b = strings.TrimSpace(b)
	if strings.HasPrefix(b, "date=") || strings.HasPrefix(b, "logver=") || strings.HasPrefix(b, "eventtime=") {
		return strings.Contains(b, "type=")
	}
	return strings.Contains(b, "devname=") && strings.Contains(b, "logid=") && strings.Contains(b, "type=")
}

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, _ map[string]string) bool {
	b, _, _ := body(raw, parsers.Now())
	return looksForti(b)
}

// direct copies.
var direct = map[string]string{
	"devname": "observer.name", "devid": "observer.serial_number", "vd": "fortinet.firewall.vd",
	"type": "fortinet.firewall.type", "subtype": "fortinet.firewall.subtype", "logid": "fortinet.firewall.logid",
	"eventtype": "fortinet.firewall.eventtype", "logdesc": "fortinet.firewall.logdesc", "msg": "message",
	"srcmac": "source.mac", "dstmac": "destination.mac", "srcintf": "observer.ingress.interface.name",
	"dstintf": "observer.egress.interface.name", "app": "network.application", "policyname": "rule.name",
	"poluuid": "rule.uuid", "policyid": "rule.id", "user": "user.name", "group": "user.group.name",
	"attack": "rule.name", "hostname": "url.domain", "method": "http.request.method", "referralurl": "http.request.referrer",
	"agent": "user_agent.original", "filename": "file.name", "qname": "dns.question.name", "qtype": "dns.question.type",
	"xid": "dns.id", "xauthuser": "user.name",
}

var ints = map[string]string{
	"sentbyte": "source.bytes", "rcvdbyte": "destination.bytes", "sentpkt": "source.packets", "rcvdpkt": "destination.packets",
	"filesize": "file.size",
}

var ips = map[string]string{
	"srcip": "source.ip", "dstip": "destination.ip", "remip": "source.ip",
}

var ports = map[string]string{"srcport": "source.port", "dstport": "destination.port"}

var adminLogin = map[string]bool{"0100032001": true, "0100032002": true, "0100032003": true, "0100032006": true, "0100032301": true, "0100032302": true, "0100032303": true}

var uiIPRe = regexp.MustCompile(`\(([0-9a-fA-F.:]+)\)`)

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	b, hdr, hasHdr := body(in.Raw, in.ReceivedAt)
	if !looksForti(b) {
		return nil, errNotFortiGate
	}
	keys, kv := parsers.ParseKV(b)
	e := parsers.Base(in, "fortinet", "fortinet.firewall")
	if hasHdr {
		syslog.Apply(e, hdr)
		e.Set("observer.hostname", hdr.Hostname)
		e.Delete(schema.FieldHostName)
	}
	e.Set("observer.vendor", "Fortinet")
	e.Set("observer.product", "FortiGate")
	e.Set("observer.type", "firewall")
	get := func(k string) string {
		v := kv[k]
		if v == "N/A" {
			return ""
		}
		return v
	}
	// time
	if et := get("eventtime"); et != "" {
		if n, err := strconv.ParseInt(et, 10, 64); err == nil {
			e.SetTimestamp(schema.EpochInt(n))
		}
	}
	if !e.Has(schema.FieldTimestamp) && get("date") != "" {
		ts := get("date") + " " + get("time")
		layout := "2006-01-02 15:04:05"
		if tz := get("tz"); tz != "" {
			if t, err := time.Parse(layout+" -0700", ts+" "+strings.Trim(tz, `"`)); err == nil {
				e.SetTimestamp(t)
			}
		}
		if !e.Has(schema.FieldTimestamp) {
			parsers.SetTime(e, schema.FieldTimestamp, ts)
		}
	}
	consumed := map[string]bool{"eventtime": true, "date": true, "time": true, "tz": true}
	for _, k := range keys {
		v := get(k)
		if v == "" {
			consumed[k] = true
			continue
		}
		if dst, ok := direct[k]; ok {
			e.Set(dst, v)
			consumed[k] = true
		} else if dst, ok := ints[k]; ok {
			parsers.SetInt(e, dst, v)
			consumed[k] = true
		} else if dst, ok := ips[k]; ok {
			parsers.SetIP(e, dst, v)
			consumed[k] = true
		} else if dst, ok := ports[k]; ok {
			parsers.SetPort(e, dst, v)
			consumed[k] = true
		}
	}
	e.Set(schema.FieldEventCode, get("logid"))
	e.Set("log.level", get("level"))
	consumed["level"] = true
	// NAT
	switch get("trandisp") {
	case "snat", "snat+dnat":
		parsers.SetIP(e, "source.nat.ip", get("transip"))
		parsers.SetPort(e, "source.nat.port", get("transport"))
		consumed["transip"], consumed["transport"] = true, true
		if get("trandisp") == "snat+dnat" {
			parsers.SetIP(e, "destination.nat.ip", get("tranip"))
			parsers.SetPort(e, "destination.nat.port", get("tranport"))
		}
	case "dnat":
		parsers.SetIP(e, "destination.nat.ip", get("tranip"))
		parsers.SetPort(e, "destination.nat.port", get("tranport"))
	}
	if pr := get("proto"); pr != "" {
		parsers.SetTransport(e, pr)
		consumed["proto"] = true
	}
	for _, k := range []string{"srcname", "dstname"} {
		if v := get(k); v != "" {
			dst := "source.domain"
			if k == "dstname" {
				dst = "destination.domain"
			}
			e.Set(dst, v)
			consumed[k] = true
		}
	}
	for _, c := range []struct{ k, dst string }{{"srccountry", "source.geo.country_name"}, {"dstcountry", "destination.geo.country_name"}} {
		if v := get(c.k); v != "" && v != "Reserved" {
			e.Set(c.dst, v)
		}
		consumed[c.k] = true
	}
	if d := get("duration"); d != "" {
		if n, err := strconv.ParseInt(d, 10, 64); err == nil {
			e.Set("event.duration", n*1e9)
		}
		consumed["duration"] = true
	}
	sb, _ := e.Int64("source.bytes")
	db, _ := e.Int64("destination.bytes")
	if e.Has("source.bytes") || e.Has("destination.bytes") {
		e.Set("network.bytes", sb+db)
	}
	sp, _ := e.Int64("source.packets")
	dp, _ := e.Int64("destination.packets")
	if e.Has("source.packets") || e.Has("destination.packets") {
		e.Set("network.packets", sp+dp)
	}
	if u := get("url"); u != "" {
		parsers.SetURL(e, u)
		if h := get("hostname"); h != "" {
			e.Set("url.domain", strings.ToLower(h))
		}
		consumed["url"] = true
	}
	if ipaddr := get("ipaddr"); ipaddr != "" {
		var resolved []string
		for _, f := range strings.FieldsFunc(ipaddr, func(r rune) bool { return r == ' ' || r == ',' }) {
			if ip := parsers.NormalizeIP(f); ip != "" {
				resolved = append(resolved, ip)
			}
		}
		if len(resolved) > 0 {
			e.Set("dns.resolved_ip", resolved)
		}
		consumed["ipaddr"] = true
	}
	if sev := get("severity"); sev != "" {
		if s, ok := parsers.Severity0to100(sev); ok {
			e.Set(schema.FieldEventSeverity, s)
		}
	}
	if dir := get("direction"); dir != "" {
		switch dir {
		case "incoming":
			e.Set("network.direction", "inbound")
		case "outgoing":
			e.Set("network.direction", "outbound")
		}
	}
	if aid := get("attackid"); aid != "" {
		e.Set("rule.id", aid)
	}
	if ui := get("ui"); ui != "" {
		if m := uiIPRe.FindStringSubmatch(ui); m != nil {
			parsers.SetIP(e, "source.ip", m[1])
		}
	}
	action := get("action")
	if action == "" {
		action = get("utmaction")
	}
	e.Set(schema.FieldEventAction, action)
	switch strings.ToLower(action) {
	case "accept", "pass", "allow", "allowed", "close", "timeout", "server-rst", "client-rst", "passthrough", "login", "logout", "tunnel-up", "tunnel-down":
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	case "deny", "block", "blocked", "drop", "dropped", "reset", "reject":
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	case "":
	default:
		e.Set(schema.FieldEventOutcome, schema.OutcomeUnknown)
	}
	if st := strings.ToLower(get("status")); st == "failed" || st == "failure" {
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	} else if st == "success" {
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	}
	classify(e, get("type"), get("subtype"), get("logid"), strings.ToLower(get("logdesc")), e.String(schema.FieldEventOutcome))
	for _, k := range keys {
		if consumed[k] {
			continue
		}
		if v := get(k); v != "" {
			e.Set("fortinet.firewall."+parsers.Snake(k), v)
		}
	}
	if !e.Has(schema.FieldMessage) {
		e.Set(schema.FieldMessage, get("type")+" "+get("subtype")+" "+action)
	}
	return []*schema.Event{e}, nil
}

func classify(e *schema.Event, typ, sub, logid, desc, outcome string) {
	denied := outcome == schema.OutcomeFailure
	allowOrDeny := schema.TypeAllowed
	if denied {
		allowOrDeny = schema.TypeDenied
	}
	switch typ {
	case "traffic":
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeConnection, allowOrDeny)
	case "utm", "anomaly":
		switch sub {
		case "ips", "anomaly":
			e.Set(schema.FieldEventKind, schema.KindAlert)
			e.SetCategory(schema.CategoryNetwork, schema.CategoryIntrusionDetection)
			e.SetTypes(allowOrDeny)
		case "virus":
			e.Set(schema.FieldEventKind, schema.KindAlert)
			e.SetCategory(schema.CategoryNetwork, schema.CategoryMalware)
			e.SetTypes(allowOrDeny)
		default:
			e.SetCategory(schema.CategoryNetwork)
			e.SetTypes(allowOrDeny)
		}
		if typ == "anomaly" {
			e.Set(schema.FieldEventKind, schema.KindAlert)
			e.SetCategory(schema.CategoryNetwork, schema.CategoryIntrusionDetection)
		}
	case "event":
		if adminLogin[logid] || strings.Contains(desc, "login") || strings.Contains(desc, "logout") || strings.Contains(desc, "authentication") {
			e.SetCategory(schema.CategoryAuthentication)
			if strings.Contains(desc, "logout") {
				e.SetTypes(schema.TypeEnd)
			} else {
				e.SetTypes(schema.TypeStart)
			}
			if strings.Contains(desc, "fail") {
				e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
			}
			return
		}
		if sub == "vpn" {
			e.SetCategory(schema.CategoryNetwork)
			e.SetTypes(schema.TypeConnection)
			return
		}
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeInfo)
		if strings.Contains(desc, "change") || strings.Contains(desc, "edit") || strings.Contains(desc, "attribute configured") || strings.Contains(desc, "object") {
			e.SetTypes(schema.TypeChange)
		}
	default:
		e.SetTypes(schema.TypeInfo)
	}
}
