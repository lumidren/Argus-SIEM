// Package suricata parses Suricata EVE JSON into ECS per docs/SCHEMA.md §7.
package suricata

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// Parser implements parsers.Parser.
type Parser struct{}

// New returns the parser.
func New() *Parser { return &Parser{} }

func (*Parser) Name() string       { return "suricata" }
func (*Parser) Version() string    { return "1.0.0" }
func (*Parser) Datasets() []string { return []string{"suricata.eve"} }

var errNotEVE = errors.New("suricata: record has no event_type")

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, _ map[string]string) bool {
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 || b[0] != '{' || !bytes.Contains(b, []byte(`"event_type"`)) {
		return false
	}
	return bytes.Contains(b, []byte(`"src_ip"`)) || bytes.Contains(b, []byte(`"flow_id"`)) || bytes.Contains(b, []byte(`"stats"`))
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	obj, err := parsers.DecodeJSON(in.Raw)
	if err != nil {
		return nil, err
	}
	et := parsers.GetString(obj, "event_type")
	if et == "" {
		return nil, errNotEVE
	}
	e := parsers.Base(in, "suricata", "suricata.eve")
	c := map[string]bool{}
	common(e, obj, c)
	e.SetCategory(schema.CategoryNetwork)
	switch et {
	case "alert":
		alert(e, obj, c)
	case "dns":
		dns(e, parsers.GetMap(obj, "dns"))
		c["dns"] = true
	case "http":
		e.SetCategory(schema.CategoryNetwork, schema.CategoryWeb)
		e.SetTypes(schema.TypeAccess)
		http(e, parsers.GetMap(obj, "http"))
		c["http"] = true
	case "tls":
		e.SetTypes(schema.TypeProtocol)
		tls(e, parsers.GetMap(obj, "tls"))
		c["tls"] = true
	case "flow", "netflow":
		e.SetTypes(schema.TypeConnection, schema.TypeEnd)
		flow(e, parsers.GetMap(obj, et), "suricata.eve."+et)
		c[et] = true
	case "fileinfo":
		e.SetCategory(schema.CategoryNetwork, schema.CategoryFile)
		e.SetTypes(schema.TypeInfo)
		fileinfo(e, parsers.GetMap(obj, "fileinfo"))
		c["fileinfo"] = true
	case "krb5":
		e.SetCategory(schema.CategoryNetwork, schema.CategoryAuthentication)
		k := parsers.GetMap(obj, "krb5")
		e.Set("user.name", parsers.GetString(k, "cname"))
		e.Set("user.domain", parsers.GetString(k, "realm"))
	case "smb":
		s := parsers.GetMap(obj, "smb")
		if fn := parsers.GetString(s, "filename"); fn != "" {
			e.Set("file.path", fn)
			e.Set("file.name", parsers.BaseName(fn))
		}
		e.Set("user.name", parsers.GetString(s, "ntlmssp.user"))
		e.Set("user.domain", parsers.GetString(s, "ntlmssp.domain"))
	case "anomaly":
		e.Set(schema.FieldEventKind, schema.KindAlert)
		e.SetTypes(schema.TypeInfo)
	case "stats":
		e.Set(schema.FieldEventKind, schema.KindMetric)
		e.SetCategory(schema.CategoryHost)
		e.SetTypes(schema.TypeInfo)
	case "drop":
		e.SetTypes(schema.TypeConnection, schema.TypeDenied)
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	}
	if !e.Has(schema.FieldEventType) {
		e.SetTypes(schema.TypeProtocol)
	}
	if !e.Has(schema.FieldEventAction) {
		e.Set(schema.FieldEventAction, et)
	}
	// Embedded flow stats on non-flow events.
	if et != "flow" && et != "netflow" {
		if f := parsers.GetMap(obj, "flow"); f != nil {
			flow(e, f, "suricata.eve.flow")
			c["flow"] = true
		}
	}
	keep(e, obj, c)
	return []*schema.Event{e}, nil
}

func common(e *schema.Event, obj map[string]any, c map[string]bool) {
	for _, k := range []string{"timestamp", "event_type", "flow_id", "in_iface", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "app_proto", "community_id", "host", "direction", "pcap_cnt", "tx_id"} {
		c[k] = true
	}
	parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(obj, "timestamp"))
	e.Set("suricata.eve.event_type", parsers.GetString(obj, "event_type"))
	e.Set("suricata.eve.flow_id", parsers.GetString(obj, "flow_id"))
	e.Set("suricata.eve.in_iface", parsers.GetString(obj, "in_iface"))
	parsers.SetInt(e, "suricata.eve.pcap_cnt", parsers.GetString(obj, "pcap_cnt"))
	parsers.SetInt(e, "suricata.eve.tx_id", parsers.GetString(obj, "tx_id"))
	parsers.SetIP(e, "source.ip", parsers.GetString(obj, "src_ip"))
	parsers.SetPort(e, "source.port", parsers.GetString(obj, "src_port"))
	parsers.SetIP(e, "destination.ip", parsers.GetString(obj, "dest_ip"))
	parsers.SetPort(e, "destination.port", parsers.GetString(obj, "dest_port"))
	if pr := strings.ToLower(parsers.GetString(obj, "proto")); pr != "" {
		e.Set("network.transport", pr)
	}
	if ap := parsers.GetString(obj, "app_proto"); ap != "" && ap != "failed" {
		e.Set("network.protocol", strings.ToLower(ap))
	}
	e.Set("network.community_id", parsers.GetString(obj, "community_id"))
	switch parsers.GetString(obj, "direction") {
	case "to_server":
		e.Set("suricata.eve.direction", "to_server")
	case "to_client":
		e.Set("suricata.eve.direction", "to_client")
	}
	e.Set("observer.product", "Suricata")
	e.Set("observer.type", "ids")
	e.Set("observer.hostname", parsers.GetString(obj, "host"))
	if ip := e.String("source.ip"); ip != "" {
		e.Set("network.type", parsers.NetworkType(ip))
	}
}

var alertSeverity = map[int64]int64{1: 75, 2: 50, 3: 25, 4: 10}

func alert(e *schema.Event, obj map[string]any, c map[string]bool) {
	c["alert"] = true
	a := parsers.GetMap(obj, "alert")
	e.Set(schema.FieldEventKind, schema.KindAlert)
	e.SetCategory(schema.CategoryNetwork, schema.CategoryIntrusionDetection)
	action := parsers.GetString(a, "action")
	e.Set(schema.FieldEventAction, action)
	switch action {
	case "allowed":
		e.SetTypes(schema.TypeAllowed)
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	case "blocked", "drop", "rejected":
		e.SetTypes(schema.TypeDenied)
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	default:
		e.SetTypes(schema.TypeInfo)
	}
	e.Set("rule.id", parsers.GetString(a, "signature_id"))
	e.Set("rule.name", parsers.GetString(a, "signature"))
	e.Set("rule.category", parsers.GetString(a, "category"))
	e.Set("rule.version", parsers.GetString(a, "rev"))
	parsers.SetInt(e, "suricata.eve.alert.gid", parsers.GetString(a, "gid"))
	if sev, ok := parsers.GetInt(a, "severity"); ok {
		e.Set("suricata.eve.alert.severity", sev)
		if s, ok := alertSeverity[sev]; ok {
			e.Set(schema.FieldEventSeverity, s)
		}
	}
	if md := parsers.GetMap(a, "metadata"); md != nil {
		keys := make([]string, 0, len(md))
		for k := range md {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			vals := parsers.GetStrings(md, k)
			if len(vals) == 0 {
				continue
			}
			e.Set("suricata.eve.alert.metadata."+parsers.Snake(k), vals)
			switch k {
			case "mitre_technique_id":
				e.Set("threat.technique.id", vals)
				e.Set("threat.framework", "MITRE ATT&CK")
			case "mitre_technique_name":
				e.Set("threat.technique.name", vals)
			case "mitre_tactic_id":
				e.Set("threat.tactic.id", vals)
			case "mitre_tactic_name":
				e.Set("threat.tactic.name", vals)
			case "ruleset":
				e.Set("rule.ruleset", vals[0])
			case "signature_severity":
				e.Set("suricata.eve.alert.signature_severity", vals)
			case "affected_product":
				e.Set("suricata.eve.alert.affected_product", vals)
			case "attack_target":
				e.Set("suricata.eve.alert.attack_target", vals)
			case "created_at":
				e.Set("suricata.eve.alert.created_at", vals[0])
			case "updated_at":
				e.Set("suricata.eve.alert.updated_at", vals[0])
			}
		}
	}
	for _, k := range []string{"payload", "payload_printable", "packet", "stream"} {
		if v := parsers.GetString(obj, k); v != "" {
			e.Set("suricata.eve."+k, v)
			c[k] = true
		}
	}
	if h := parsers.GetMap(obj, "http"); h != nil {
		http(e, h)
		c["http"] = true
	}
	if d := parsers.GetMap(obj, "dns"); d != nil {
		dns(e, d)
		c["dns"] = true
	}
	if t := parsers.GetMap(obj, "tls"); t != nil {
		tls(e, t)
		c["tls"] = true
	}
	if f := parsers.GetMap(obj, "fileinfo"); f != nil {
		fileinfo(e, f)
		c["fileinfo"] = true
	}
	e.Set(schema.FieldMessage, e.String("rule.name"))
}

func dns(e *schema.Event, d map[string]any) {
	if d == nil {
		return
	}
	e.Set("dns.type", parsers.GetString(d, "type"))
	e.Set("dns.id", parsers.GetString(d, "id"))
	e.Set("dns.response_code", parsers.GetString(d, "rcode"))
	e.Set("suricata.eve.dns.version", parsers.GetString(d, "version"))
	e.Set("suricata.eve.dns.flags", parsers.GetString(d, "flags"))
	for _, f := range []string{"qr", "aa", "tc", "rd", "ra"} {
		if b, ok := parsers.GetBool(d, f); ok {
			e.Set("suricata.eve.dns."+f, b)
		}
	}
	if !e.Has(schema.FieldEventType) {
		e.SetTypes(schema.TypeProtocol)
	}
	// v2: queries[] / answers[]; v1: rrname/rrtype/rdata on the record.
	name := parsers.GetString(d, "rrname")
	typ := parsers.GetString(d, "rrtype")
	if q := parsers.GetSlice(d, "queries"); len(q) > 0 {
		if qm, ok := q[0].(map[string]any); ok {
			name = parsers.GetString(qm, "rrname")
			typ = parsers.GetString(qm, "rrtype")
		}
	}
	e.Set("dns.question.name", name)
	e.Set("dns.question.type", typ)
	var answers []any
	var resolved []string
	addAns := func(n, t, data string, ttl int64, hasTTL bool) {
		a := map[string]any{}
		if n != "" {
			a["name"] = n
		}
		if t != "" {
			a["type"] = t
		}
		if data != "" {
			a["data"] = data
		}
		if hasTTL {
			a["ttl"] = ttl
		}
		answers = append(answers, a)
		if (t == "A" || t == "AAAA") && parsers.NormalizeIP(data) != "" {
			resolved = append(resolved, parsers.NormalizeIP(data))
		}
	}
	if parsers.GetString(d, "type") == "answer" && parsers.GetString(d, "rdata") != "" {
		ttl, ok := parsers.GetInt(d, "ttl")
		addAns(name, typ, parsers.GetString(d, "rdata"), ttl, ok)
	}
	for _, a := range parsers.GetSlice(d, "answers") {
		if am, ok := a.(map[string]any); ok {
			ttl, ok := parsers.GetInt(am, "ttl")
			addAns(parsers.GetString(am, "rrname"), parsers.GetString(am, "rrtype"), parsers.GetString(am, "rdata"), ttl, ok)
		}
	}
	if len(answers) == 0 {
		if g := parsers.GetMap(d, "grouped"); g != nil {
			keys := make([]string, 0, len(g))
			for k := range g {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, t := range keys {
				for _, v := range parsers.GetStrings(g, t) {
					addAns("", t, v, 0, false)
				}
			}
		}
	}
	if len(answers) > 0 {
		e.Set("dns.answers", answers)
	}
	if len(resolved) > 0 {
		e.Set("dns.resolved_ip", resolved)
	}
}

func http(e *schema.Event, h map[string]any) {
	if h == nil {
		return
	}
	host := parsers.GetString(h, "hostname")
	u := parsers.GetString(h, "url")
	if u != "" {
		parsers.SetURL(e, u)
		if host != "" && strings.HasPrefix(u, "/") {
			e.Set("url.original", host+u)
		}
	}
	if host != "" {
		if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[:i], ":") {
			host = host[:i]
		}
		e.Set("url.domain", strings.ToLower(host))
	}
	e.Set("http.request.method", parsers.GetString(h, "http_method"))
	parsers.SetInt(e, "http.response.status_code", parsers.GetString(h, "status"))
	parsers.SetInt(e, "http.response.body.bytes", parsers.GetString(h, "length"))
	e.Set("http.request.referrer", parsers.GetString(h, "http_refer"))
	e.Set("user_agent.original", parsers.GetString(h, "http_user_agent"))
	if pv := parsers.GetString(h, "protocol"); strings.HasPrefix(pv, "HTTP/") {
		e.Set("http.version", pv[5:])
	}
	if ct := parsers.GetString(h, "http_content_type"); ct != "" {
		e.Set("http.response.mime_type", strings.SplitN(ct, ";", 2)[0])
	}
	e.Set("suricata.eve.http.redirect", parsers.GetString(h, "redirect"))
	parsers.SetPort(e, "suricata.eve.http.http_port", parsers.GetString(h, "http_port"))
	if sc, ok := e.Int64("http.response.status_code"); ok && e.String(schema.FieldEventKind) != schema.KindAlert {
		e.Set(schema.FieldEventOutcome, parsers.OutcomeFromBool(sc < 400))
	}
}

func tls(e *schema.Event, t map[string]any) {
	if t == nil {
		return
	}
	e.Set("tls.client.server_name", parsers.GetString(t, "sni"))
	if v := parsers.GetString(t, "version"); v != "" {
		proto, ver := "tls", v
		switch {
		case strings.HasPrefix(v, "TLS "):
			ver = strings.TrimPrefix(v, "TLS ")
		case strings.HasPrefix(v, "TLSv"):
			ver = strings.TrimPrefix(v, "TLSv")
		case strings.HasPrefix(v, "SSLv"):
			proto, ver = "ssl", strings.TrimPrefix(v, "SSLv")
		}
		e.Set("tls.version", ver)
		e.Set("tls.version_protocol", proto)
	}
	e.Set("tls.server.subject", parsers.GetString(t, "subject"))
	e.Set("tls.server.issuer", parsers.GetString(t, "issuerdn"))
	if fp := parsers.GetString(t, "fingerprint"); fp != "" {
		e.Set("tls.server.hash.sha1", strings.ToLower(strings.ReplaceAll(fp, ":", "")))
	}
	parsers.SetTime(e, "tls.server.not_before", parsers.GetString(t, "notbefore"))
	parsers.SetTime(e, "tls.server.not_after", parsers.GetString(t, "notafter"))
	e.Set("tls.client.ja3", parsers.GetString(t, "ja3.hash"))
	e.Set("suricata.eve.tls.ja3.string", parsers.GetString(t, "ja3.string"))
	e.Set("tls.server.ja3s", parsers.GetString(t, "ja3s.hash"))
	e.Set("suricata.eve.tls.serial", parsers.GetString(t, "serial"))
	if b, ok := parsers.GetBool(t, "session_resumed"); ok {
		e.Set("suricata.eve.tls.session_resumed", b)
	}
}

func flow(e *schema.Event, f map[string]any, prefix string) {
	if f == nil {
		return
	}
	start := parsers.GetString(f, "start")
	end := parsers.GetString(f, "end")
	parsers.SetTime(e, "event.start", start)
	parsers.SetTime(e, "event.end", end)
	if ts, ok := schema.ParseTime(start); ok {
		if te, ok := schema.ParseTime(end); ok && !te.Before(ts) {
			e.Set("event.duration", schema.Duration(te.Sub(ts)))
		}
	}
	var sb, db, sp, dp int64
	var hb, hp bool
	if v, ok := parsers.GetInt(f, "bytes_toserver"); ok {
		sb, hb = v, true
		e.Set("source.bytes", v)
	}
	if v, ok := parsers.GetInt(f, "bytes_toclient"); ok {
		db, hb = v, true
		e.Set("destination.bytes", v)
	}
	if v, ok := parsers.GetInt(f, "pkts_toserver"); ok {
		sp, hp = v, true
		e.Set("source.packets", v)
	}
	if v, ok := parsers.GetInt(f, "pkts_toclient"); ok {
		dp, hp = v, true
		e.Set("destination.packets", v)
	}
	if hb {
		e.Set("network.bytes", sb+db)
	}
	if hp {
		e.Set("network.packets", sp+dp)
	}
	for _, k := range []string{"state", "reason", "age"} {
		e.Set(prefix+"."+k, parsers.GetString(f, k))
	}
	if b, ok := parsers.GetBool(f, "alerted"); ok {
		e.Set(prefix+".alerted", b)
	}
	_ = time.Second
}

func fileinfo(e *schema.Event, f map[string]any) {
	if f == nil {
		return
	}
	if fn := parsers.GetString(f, "filename"); fn != "" {
		parsers.SetFile(e, fn)
	}
	parsers.SetInt(e, "file.size", parsers.GetString(f, "size"))
	e.Set("file.hash.md5", parsers.GetString(f, "md5"))
	e.Set("file.hash.sha1", parsers.GetString(f, "sha1"))
	e.Set("file.hash.sha256", parsers.GetString(f, "sha256"))
	e.Set("suricata.eve.fileinfo.magic", parsers.GetString(f, "magic"))
	e.Set("suricata.eve.fileinfo.state", parsers.GetString(f, "state"))
	if b, ok := parsers.GetBool(f, "stored"); ok {
		e.Set("suricata.eve.fileinfo.stored", b)
	}
	if b, ok := parsers.GetBool(f, "gaps"); ok {
		e.Set("suricata.eve.fileinfo.gaps", b)
	}
	parsers.SetInt(e, "suricata.eve.fileinfo.tx_id", parsers.GetString(f, "tx_id"))
	parsers.SetInt(e, "suricata.eve.fileinfo.file_id", parsers.GetString(f, "file_id"))
}

// keep stores every unconsumed top-level object under suricata.eve.<key>.
func keep(e *schema.Event, obj map[string]any, c map[string]bool) {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		if !c[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		flat := map[string]any{}
		schema.Flatten("", map[string]any{parsers.Snake(k): obj[k]}, flat)
		for fk, fv := range flat {
			if n, ok := fv.(json.Number); ok {
				fv = n.String()
			}
			e.Set("suricata.eve."+parsers.SnakePath(fk), fv)
		}
	}
}
