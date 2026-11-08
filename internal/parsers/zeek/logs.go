package zeek

import (
	"strconv"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

var connStates = map[string]string{
	"S0":     "Connection attempt seen, no reply",
	"S1":     "Connection established, not terminated",
	"SF":     "Normal SYN/FIN completion",
	"REJ":    "Connection attempt rejected",
	"S2":     "Established, close attempt by originator seen (but no reply from responder)",
	"S3":     "Established, close attempt by responder seen (but no reply from originator)",
	"RSTO":   "Connection established, originator aborted (sent a RST)",
	"RSTR":   "Established, responder aborted",
	"RSTOS0": "Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder",
	"RSTRH":  "Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator",
	"SH":     "Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was 'half' open)",
	"SHR":    "Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator",
	"OTH":    "No SYN seen, just midstream traffic (a 'partial connection' that was not later closed)",
}

// fieldMap describes a straight copy from a Zeek key to an ECS/zeek field.
type fieldMap struct {
	from, to string
	kind     byte // 's' string, 'i' int, 'f' float, 'b' bool, 'a' string array, 'd' duration seconds, 'p' port, 'n' ip
}

func apply(e *schema.Event, obj map[string]any, consumed map[string]bool, maps []fieldMap) {
	for _, m := range maps {
		v, ok := obj[m.from]
		if !ok {
			continue
		}
		consumed[m.from] = true
		s := getS(obj, m.from)
		switch m.kind {
		case 's':
			e.Set(m.to, s)
		case 'i':
			parsers.SetInt(e, m.to, s)
		case 'f':
			parsers.SetFloat(e, m.to, s)
		case 'b':
			if b, ok := v.(bool); ok {
				e.Set(m.to, b)
			} else {
				parsers.SetBool(e, m.to, s)
			}
		case 'a':
			if arr := getStrs(obj, m.from); len(arr) > 0 {
				e.Set(m.to, arr)
			} else if s != "" {
				e.Set(m.to, []string{s})
			}
		case 'd':
			if f, err := strconv.ParseFloat(s, 64); err == nil {
				e.Set(m.to, schema.SecondsToNanos(f))
			}
		case 'p':
			parsers.SetPort(e, m.to, s)
		case 'n':
			parsers.SetIP(e, m.to, s)
		}
	}
}

func mapLog(e *schema.Event, log string, obj map[string]any) map[string]bool {
	c := map[string]bool{}
	switch log {
	case "conn":
		mapConn(e, obj, c)
	case "dns":
		mapDNS(e, obj, c)
	case "http":
		mapHTTP(e, obj, c)
	case "ssl":
		mapSSL(e, obj, c)
	case "files":
		mapFiles(e, obj, c)
	case "notice":
		e.Set(schema.FieldEventKind, schema.KindAlert)
		e.SetCategory(schema.CategoryNetwork, schema.CategoryIntrusionDetection)
		e.SetTypes(schema.TypeInfo)
		apply(e, obj, c, []fieldMap{
			{"note", "rule.name", 's'}, {"msg", "message", 's'}, {"sub", "zeek.notice.sub", 's'},
			{"src", "source.ip", 'n'}, {"dst", "destination.ip", 'n'}, {"p", "destination.port", 'p'},
			{"n", "zeek.notice.n", 'i'}, {"peer_descr", "zeek.notice.peer_descr", 's'}, {"actions", "zeek.notice.actions", 'a'},
			{"suppress_for", "zeek.notice.suppress_for", 'f'}, {"dropped", "zeek.notice.dropped", 'b'},
			{"file_mime_type", "zeek.notice.file_mime_type", 's'}, {"file_desc", "zeek.notice.file_desc", 's'},
		})
		e.Set(schema.FieldEventAction, e.String("rule.name"))
	case "weird":
		e.SetTypes(schema.TypeInfo)
		apply(e, obj, c, []fieldMap{
			{"name", "zeek.weird.name", 's'}, {"addl", "zeek.weird.additional_info", 's'},
			{"notice", "zeek.weird.notice", 'b'}, {"peer", "zeek.weird.peer", 's'}, {"source", "zeek.weird.source", 's'},
		})
		e.Set(schema.FieldEventAction, e.String("zeek.weird.name"))
	case "ssh":
		e.SetCategory(schema.CategoryNetwork, schema.CategoryAuthentication)
		e.SetTypes(schema.TypeInfo)
		apply(e, obj, c, []fieldMap{
			{"version", "zeek.ssh.version", 'i'}, {"auth_success", "zeek.ssh.auth.success", 'b'},
			{"auth_attempts", "zeek.ssh.auth.attempts", 'i'}, {"direction", "zeek.ssh.direction", 's'},
			{"client", "zeek.ssh.client", 's'}, {"server", "zeek.ssh.server", 's'},
			{"cipher_alg", "zeek.ssh.algorithm.cipher", 's'}, {"mac_alg", "zeek.ssh.algorithm.mac", 's'},
			{"compression_alg", "zeek.ssh.algorithm.compression", 's'}, {"kex_alg", "zeek.ssh.algorithm.key_exchange", 's'},
			{"host_key_alg", "zeek.ssh.algorithm.host_key", 's'}, {"host_key", "zeek.ssh.host_key", 's'},
			{"hassh", "zeek.ssh.hassh", 's'}, {"hasshServer", "zeek.ssh.hasshServer", 's'},
		})
		if ok, has := e.Bool("zeek.ssh.auth.success"); has {
			e.Set(schema.FieldEventOutcome, parsers.OutcomeFromBool(ok))
		}
		e.Set("network.protocol", "ssh")
	case "kerberos":
		e.SetCategory(schema.CategoryNetwork, schema.CategoryAuthentication)
		e.SetTypes(schema.TypeInfo)
		if cl := getS(obj, "client"); cl != "" {
			c["client"] = true
			user, realm, found := strings.Cut(cl, "@")
			if !found {
				user, realm, _ = strings.Cut(cl, "/")
			}
			e.Set("user.name", user)
			e.Set("user.domain", realm)
		}
		apply(e, obj, c, []fieldMap{
			{"request_type", "zeek.kerberos.request_type", 's'}, {"service", "zeek.kerberos.service", 's'},
			{"success", "zeek.kerberos.success", 'b'}, {"error_code", "zeek.kerberos.error.code", 'i'},
			{"error_msg", "zeek.kerberos.error.msg", 's'}, {"from", "zeek.kerberos.valid.from", 's'},
			{"till", "zeek.kerberos.valid.until", 's'}, {"cipher", "zeek.kerberos.cipher", 's'},
			{"forwardable", "zeek.kerberos.forwardable", 'b'}, {"renewable", "zeek.kerberos.renewable", 'b'},
			{"auth_ticket", "zeek.kerberos.ticket.auth", 's'}, {"new_ticket", "zeek.kerberos.ticket.new", 's'},
		})
		if ok, has := e.Bool("zeek.kerberos.success"); has {
			e.Set(schema.FieldEventOutcome, parsers.OutcomeFromBool(ok))
		}
		e.Set("network.protocol", "kerberos")
	case "smb_files":
		e.SetCategory(schema.CategoryNetwork, schema.CategoryFile)
		e.SetTypes(schema.TypeInfo)
		name := getS(obj, "name")
		path := getS(obj, "path")
		if name != "" {
			c["name"], c["path"] = true, true
			e.Set("file.name", name)
			full := name
			if path != "" {
				full = strings.TrimRight(path, `\`) + `\` + name
			}
			e.Set("file.path", full)
		}
		apply(e, obj, c, []fieldMap{
			{"action", "zeek.smb_files.action", 's'}, {"size", "file.size", 'i'}, {"prev_name", "zeek.smb_files.prev_name", 's'},
			{"times.accessed", "zeek.smb_files.times.accessed", 's'}, {"times.changed", "zeek.smb_files.times.changed", 's'},
			{"times.created", "zeek.smb_files.times.created", 's'}, {"times.modified", "zeek.smb_files.times.modified", 's'},
			{"fuid", "zeek.smb_files.fuid", 's'},
		})
		e.Set(schema.FieldEventAction, e.String("zeek.smb_files.action"))
		e.Set("network.protocol", "smb")
	case "smb_mapping":
		e.SetTypes(schema.TypeInfo)
		apply(e, obj, c, []fieldMap{
			{"path", "zeek.smb_mapping.path", 's'}, {"service", "zeek.smb_mapping.service", 's'},
			{"native_file_system", "zeek.smb_mapping.native_file_system", 's'}, {"share_type", "zeek.smb_mapping.share_type", 's'},
		})
		e.Set("network.protocol", "smb")
	case "dce_rpc":
		e.SetTypes(schema.TypeInfo)
		apply(e, obj, c, []fieldMap{
			{"rtt", "zeek.dce_rpc.rtt", 'f'}, {"named_pipe", "zeek.dce_rpc.named_pipe", 's'},
			{"endpoint", "zeek.dce_rpc.endpoint", 's'}, {"operation", "zeek.dce_rpc.operation", 's'},
		})
		e.Set(schema.FieldEventAction, e.String("zeek.dce_rpc.operation"))
		e.Set("network.protocol", "dce_rpc")
	case "ntlm":
		e.SetCategory(schema.CategoryNetwork, schema.CategoryAuthentication)
		e.SetTypes(schema.TypeInfo)
		apply(e, obj, c, []fieldMap{
			{"username", "user.name", 's'}, {"domainname", "user.domain", 's'}, {"hostname", "source.domain", 's'},
			{"server_nb_computer_name", "destination.domain", 's'}, {"server_dns_computer_name", "zeek.ntlm.server.dns.name", 's'},
			{"server_tree_name", "zeek.ntlm.server.tree.name", 's'}, {"success", "zeek.ntlm.success", 'b'}, {"status", "zeek.ntlm.status", 's'},
		})
		e.Set("zeek.ntlm.server.nb.name", e.String("destination.domain"))
		if ok, has := e.Bool("zeek.ntlm.success"); has {
			e.Set(schema.FieldEventOutcome, parsers.OutcomeFromBool(ok))
		}
		e.Set("network.protocol", "ntlm")
	case "rdp":
		e.SetTypes(schema.TypeInfo)
		apply(e, obj, c, []fieldMap{
			{"cookie", "zeek.rdp.cookie", 's'}, {"result", "zeek.rdp.result", 's'}, {"security_protocol", "zeek.rdp.security_protocol", 's'},
			{"client_build", "zeek.rdp.client.build", 's'}, {"client_name", "zeek.rdp.client.client_name", 's'},
			{"client_dig_product_id", "zeek.rdp.client.product_id", 's'}, {"desktop_width", "zeek.rdp.desktop.width", 'i'},
			{"desktop_height", "zeek.rdp.desktop.height", 'i'}, {"requested_color_depth", "zeek.rdp.desktop.color_depth", 's'},
			{"keyboard_layout", "zeek.rdp.keyboard_layout", 's'}, {"encryption_level", "zeek.rdp.encryption.level", 's'},
			{"encryption_method", "zeek.rdp.encryption.method", 's'}, {"cert_type", "zeek.rdp.cert.type", 's'},
			{"cert_count", "zeek.rdp.cert.count", 'i'}, {"cert_permanent", "zeek.rdp.cert.permanent", 'b'},
		})
		e.Set("network.protocol", "rdp")
	case "intel":
		e.Set(schema.FieldEventKind, schema.KindAlert)
		e.SetCategory(schema.CategoryNetwork, schema.CategoryThreat)
		e.SetTypes(schema.TypeIndicator)
		ind := getS(obj, "seen.indicator")
		switch getS(obj, "seen.indicator_type") {
		case "Intel::ADDR":
			parsers.SetIP(e, "threat.indicator.ip", ind)
		case "Intel::DOMAIN":
			e.Set("threat.indicator.domain", ind)
		case "Intel::URL":
			e.Set("threat.indicator.url.full", ind)
		case "Intel::FILE_HASH":
			parsers.SetHashByLength(e, "threat.indicator.file.hash", ind)
		case "Intel::EMAIL":
			e.Set("threat.indicator.email.address", ind)
		default:
			e.Set("threat.indicator.description", ind)
		}
		e.Set("threat.indicator.type", getS(obj, "seen.indicator_type"))
		if src := getStrs(obj, "sources"); len(src) > 0 {
			e.Set("threat.indicator.provider", src[0])
		}
		c["seen.indicator"], c["seen.indicator_type"], c["sources"] = true, true, true
		apply(e, obj, c, []fieldMap{{"seen.where", "zeek.intel.seen.where", 's'}, {"matched", "zeek.intel.matched", 'a'}, {"seen.node", "zeek.intel.seen.node", 's'}})
	default:
		e.SetTypes(schema.TypeInfo)
	}
	return c
}

func mapConn(e *schema.Event, obj map[string]any, c map[string]bool) {
	e.SetTypes(schema.TypeConnection, schema.TypeEnd)
	apply(e, obj, c, []fieldMap{
		{"proto", "network.transport", 's'}, {"service", "network.protocol", 's'}, {"duration", "event.duration", 'd'},
		{"orig_bytes", "source.bytes", 'i'}, {"resp_bytes", "destination.bytes", 'i'}, {"orig_pkts", "source.packets", 'i'},
		{"resp_pkts", "destination.packets", 'i'}, {"conn_state", "zeek.conn.state", 's'}, {"history", "zeek.conn.history", 's'},
		{"local_orig", "zeek.conn.local_orig", 'b'}, {"local_resp", "zeek.conn.local_resp", 'b'},
		{"missed_bytes", "zeek.conn.missed_bytes", 'i'}, {"orig_ip_bytes", "zeek.conn.orig_ip_bytes", 'i'},
		{"resp_ip_bytes", "zeek.conn.resp_ip_bytes", 'i'}, {"vlan", "zeek.conn.vlan", 'i'}, {"inner_vlan", "zeek.conn.inner_vlan", 'i'},
		{"tunnel_parents", "zeek.conn.tunnel_parents", 'a'},
	})
	if st := e.String("zeek.conn.state"); st != "" {
		e.Set("zeek.conn.state_message", connStates[st])
		if st == "REJ" || st == "S0" {
			e.SetTypes(schema.TypeConnection, schema.TypeDenied)
		}
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
	lo, hasLo := e.Bool("zeek.conn.local_orig")
	lr, hasLr := e.Bool("zeek.conn.local_resp")
	if hasLo && hasLr {
		switch {
		case lo && lr:
			e.Set("network.direction", "internal")
		case lo:
			e.Set("network.direction", "outbound")
		case lr:
			e.Set("network.direction", "inbound")
		default:
			e.Set("network.direction", "external")
		}
	}
}

func mapDNS(e *schema.Event, obj map[string]any, c map[string]bool) {
	e.SetTypes(schema.TypeProtocol, schema.TypeInfo)
	e.Set("network.protocol", "dns")
	apply(e, obj, c, []fieldMap{
		{"trans_id", "dns.id", 's'}, {"query", "dns.question.name", 's'}, {"qclass_name", "dns.question.class", 's'},
		{"qtype_name", "dns.question.type", 's'}, {"rcode_name", "dns.response_code", 's'}, {"proto", "network.transport", 's'},
		{"AA", "zeek.dns.AA", 'b'}, {"TC", "zeek.dns.TC", 'b'}, {"RD", "zeek.dns.RD", 'b'}, {"RA", "zeek.dns.RA", 'b'},
		{"Z", "zeek.dns.Z", 'i'}, {"rejected", "zeek.dns.rejected", 'b'}, {"rtt", "zeek.dns.rtt", 'f'},
		{"qclass", "zeek.dns.qclass", 'i'}, {"qtype", "zeek.dns.qtype", 'i'}, {"rcode", "zeek.dns.rcode", 'i'},
	})
	answers := getStrs(obj, "answers")
	ttls := getSlice(obj, "TTLs")
	c["answers"], c["TTLs"] = true, true
	if len(answers) > 0 {
		arr := make([]any, 0, len(answers))
		var resolved []string
		for i, a := range answers {
			ans := map[string]any{"data": a}
			if i < len(ttls) {
				if f, err := strconv.ParseFloat(toString(ttls[i]), 64); err == nil {
					ans["ttl"] = int64(f)
				}
			}
			arr = append(arr, ans)
			if ip := parsers.NormalizeIP(a); ip != "" {
				resolved = append(resolved, ip)
			}
		}
		e.Set("dns.answers", arr)
		if len(resolved) > 0 {
			e.Set("dns.resolved_ip", resolved)
		}
	}
	if rc := e.String("dns.response_code"); rc != "" {
		e.Set(schema.FieldEventOutcome, parsers.OutcomeFromBool(rc == "NOERROR"))
	}
}

func mapHTTP(e *schema.Event, obj map[string]any, c map[string]bool) {
	e.SetCategory(schema.CategoryNetwork, schema.CategoryWeb)
	e.SetTypes(schema.TypeAccess)
	e.Set("network.protocol", "http")
	host := getS(obj, "host")
	uri := getS(obj, "uri")
	c["host"], c["uri"] = true, true
	if uri != "" {
		parsers.SetURL(e, uri)
		if host != "" {
			e.Set("url.original", host+uri)
		}
	}
	if host != "" {
		h := host
		if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[:i], ":") {
			h = h[:i]
		}
		e.Set("url.domain", strings.ToLower(h))
	}
	apply(e, obj, c, []fieldMap{
		{"method", "http.request.method", 's'}, {"referrer", "http.request.referrer", 's'}, {"version", "http.version", 's'},
		{"user_agent", "user_agent.original", 's'}, {"request_body_len", "http.request.body.bytes", 'i'},
		{"response_body_len", "http.response.body.bytes", 'i'}, {"status_code", "http.response.status_code", 'i'},
		{"status_msg", "zeek.http.status_msg", 's'}, {"trans_depth", "zeek.http.trans_depth", 'i'}, {"tags", "zeek.http.tags", 'a'},
		{"username", "url.username", 's'}, {"proxied", "zeek.http.proxied", 'a'}, {"orig_fuids", "zeek.http.orig_fuids", 'a'},
		{"resp_fuids", "zeek.http.resp_fuids", 'a'}, {"origin", "zeek.http.origin", 's'}, {"info_code", "zeek.http.info_code", 'i'},
		{"info_msg", "zeek.http.info_msg", 's'},
	})
	if mt := getStrs(obj, "orig_mime_types"); len(mt) > 0 {
		e.Set("http.request.mime_type", mt[0])
	}
	if mt := getStrs(obj, "resp_mime_types"); len(mt) > 0 {
		e.Set("http.response.mime_type", mt[0])
	}
	c["orig_mime_types"], c["resp_mime_types"] = true, true
	if sc, ok := e.Int64("http.response.status_code"); ok {
		e.Set(schema.FieldEventOutcome, parsers.OutcomeFromBool(sc < 400))
	}
}

func mapSSL(e *schema.Event, obj map[string]any, c map[string]bool) {
	e.SetTypes(schema.TypeProtocol)
	e.Set("network.protocol", "tls")
	if v := getS(obj, "version"); v != "" {
		c["version"] = true
		proto, ver := tlsVersion(v)
		e.Set("tls.version_protocol", proto)
		e.Set("tls.version", ver)
		e.Set("zeek.ssl.version", v)
	}
	apply(e, obj, c, []fieldMap{
		{"cipher", "tls.cipher", 's'}, {"curve", "tls.curve", 's'}, {"server_name", "tls.client.server_name", 's'},
		{"resumed", "tls.resumed", 'b'}, {"established", "tls.established", 'b'}, {"next_protocol", "tls.next_protocol", 's'},
		{"ja3", "tls.client.ja3", 's'}, {"ja3s", "tls.server.ja3s", 's'}, {"subject", "tls.server.subject", 's'},
		{"issuer", "tls.server.issuer", 's'}, {"client_subject", "tls.client.subject", 's'}, {"client_issuer", "tls.client.issuer", 's'},
		{"validation_status", "zeek.ssl.validation_status", 's'}, {"cert_chain_fuids", "zeek.ssl.cert_chain_fuids", 'a'},
		{"last_alert", "zeek.ssl.last_alert", 's'}, {"sni_matches_cert", "zeek.ssl.sni_matches_cert", 'b'},
		{"ssl_history", "zeek.ssl.history", 's'},
	})
}

func tlsVersion(v string) (string, string) {
	switch strings.ToUpper(v) {
	case "TLSV10":
		return "tls", "1.0"
	case "TLSV11":
		return "tls", "1.1"
	case "TLSV12":
		return "tls", "1.2"
	case "TLSV13":
		return "tls", "1.3"
	case "SSLV3":
		return "ssl", "3.0"
	case "SSLV2":
		return "ssl", "2.0"
	case "DTLSV10":
		return "dtls", "1.0"
	case "DTLSV12":
		return "dtls", "1.2"
	}
	return strings.ToLower(v), v
}

func mapFiles(e *schema.Event, obj map[string]any, c map[string]bool) {
	e.SetCategory(schema.CategoryFile, schema.CategoryNetwork)
	e.SetTypes(schema.TypeInfo)
	if tx := getStrs(obj, "tx_hosts"); len(tx) > 0 {
		parsers.SetIP(e, "server.ip", tx[0])
	}
	if rx := getStrs(obj, "rx_hosts"); len(rx) > 0 {
		parsers.SetIP(e, "client.ip", rx[0])
	}
	c["tx_hosts"], c["rx_hosts"] = true, true
	apply(e, obj, c, []fieldMap{
		{"fuid", "zeek.files.fuid", 's'}, {"conn_uids", "zeek.files.session_ids", 'a'}, {"source", "zeek.files.source", 's'},
		{"depth", "zeek.files.depth", 'i'}, {"analyzers", "zeek.files.analyzers", 'a'}, {"mime_type", "file.mime_type", 's'},
		{"filename", "file.name", 's'}, {"duration", "event.duration", 'd'}, {"local_orig", "zeek.files.local_orig", 'b'},
		{"is_orig", "zeek.files.is_orig", 'b'}, {"total_bytes", "file.size", 'i'}, {"seen_bytes", "zeek.files.seen_bytes", 'i'},
		{"missing_bytes", "zeek.files.missing_bytes", 'i'}, {"overflow_bytes", "zeek.files.overflow_bytes", 'i'},
		{"timedout", "zeek.files.timedout", 'b'}, {"md5", "file.hash.md5", 's'}, {"sha1", "file.hash.sha1", 's'},
		{"sha256", "file.hash.sha256", 's'}, {"extracted", "zeek.files.extracted", 's'}, {"extracted_cutoff", "zeek.files.extracted_cutoff", 'b'},
	})
}

func toString(v any) string {
	e := schema.New()
	e.Set("v", v)
	return e.String("v")
}

// Zeek JSON uses literal dotted keys ("id.orig_h"); these helpers look the
// key up literally first and fall back to a nested path.
func getRaw(obj map[string]any, k string) (any, bool) {
	if v, ok := obj[k]; ok {
		return v, true
	}
	return parsers.GetPath(obj, k)
}

func getS(obj map[string]any, k string) string {
	v, ok := getRaw(obj, k)
	if !ok || v == nil {
		return ""
	}
	switch v.(type) {
	case map[string]any, []any:
		return ""
	}
	return toString(v)
}

func getSlice(obj map[string]any, k string) []any {
	v, _ := getRaw(obj, k)
	s, _ := v.([]any)
	return s
}

func getStrs(obj map[string]any, k string) []string {
	v, ok := getRaw(obj, k)
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s := toString(x); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	}
	return nil
}
