// Package zeek parses Zeek logs (JSON lines, or TSV lines with the #fields
// header supplied as a hint) into ECS per docs/SCHEMA.md §6.
package zeek

import (
	"bytes"
	"encoding/json"
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

func (*Parser) Name() string    { return "zeek" }
func (*Parser) Version() string { return "1.0.0" }

var knownLogs = []string{
	"conn", "dns", "http", "ssl", "files", "notice", "weird", "ssh", "kerberos", "smb_files", "smb_mapping",
	"dce_rpc", "ntlm", "rdp", "ftp", "smtp", "sip", "snmp", "tunnel", "x509", "software", "pe", "dhcp",
	"radius", "irc", "mysql", "socks", "dpd", "intel", "signatures", "capture_loss", "stats",
}

var knownSet = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range knownLogs {
		m[l] = true
	}
	return m
}()

// Datasets implements parsers.Parser.
func (*Parser) Datasets() []string {
	out := make([]string, 0, len(knownLogs)+1)
	for _, l := range knownLogs {
		out = append(out, "zeek."+l)
	}
	return append(out, "zeek.unknown")
}

var errNotZeek = errors.New("zeek: not a zeek log record")

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, hints map[string]string) bool {
	if hints != nil && hints["zeek_fields"] != "" {
		return true
	}
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 || b[0] != '{' {
		return false
	}
	if bytes.Contains(b, []byte(`"event_type"`)) {
		return false // Suricata EVE
	}
	if bytes.Contains(b, []byte(`"_path"`)) || bytes.Contains(b, []byte(`"id.orig_h"`)) {
		return true
	}
	return bytes.Contains(b, []byte(`"ts"`)) && bytes.Contains(b, []byte(`"uid"`)) &&
		(bytes.Contains(b, []byte(`"fuid"`)) || bytes.Contains(b, []byte(`"query"`)) || bytes.Contains(b, []byte(`"note"`)))
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	line := strings.TrimRight(string(in.Raw), "\r\n")
	if strings.HasPrefix(line, "#") {
		return nil, nil // TSV header/footer lines
	}
	var obj map[string]any
	var err error
	if fields := in.Hint("zeek_fields"); fields != "" && !strings.HasPrefix(strings.TrimSpace(line), "{") {
		obj = parseTSV(line, fields)
	} else {
		obj, err = parsers.DecodeJSON([]byte(line))
		if err != nil {
			return nil, err
		}
	}
	if len(obj) == 0 {
		return nil, errNotZeek
	}
	log := logType(obj, in)
	e := parsers.Base(in, "zeek", "zeek."+log)
	if !mapCommon(e, obj) && log == "unknown" {
		return nil, errNotZeek
	}
	consumed := mapLog(e, log, obj)
	for _, k := range commonKeys {
		consumed[k] = true
	}
	keepRest(e, log, obj, consumed)
	return []*schema.Event{e}, nil
}

// parseTSV builds an object from a tab-separated line and the #fields list.
func parseTSV(line, fields string) map[string]any {
	names := strings.Split(fields, "\t")
	if len(names) == 1 {
		names = strings.Fields(fields)
	}
	vals := strings.Split(line, "\t")
	obj := make(map[string]any, len(names))
	for i, n := range names {
		if i >= len(vals) {
			break
		}
		v := vals[i]
		if v == "-" || v == "(empty)" || v == "" {
			continue
		}
		if strings.Contains(v, ",") && setLike(n) {
			parts := strings.Split(v, ",")
			arr := make([]any, len(parts))
			for j, s := range parts {
				arr[j] = s
			}
			obj[n] = arr
			continue
		}
		obj[n] = v
	}
	return obj
}

// setLike lists Zeek set/vector columns that are comma-separated in TSV.
func setLike(name string) bool {
	switch name {
	case "answers", "TTLs", "tags", "proxied", "orig_fuids", "resp_fuids", "orig_mime_types", "resp_mime_types",
		"tx_hosts", "rx_hosts", "conn_uids", "analyzers", "cert_chain_fuids", "client_cert_chain_fuids",
		"actions", "sources", "matched", "server_addr", "mailfrom", "rcptto", "path":
		return true
	}
	return false
}

func logType(obj map[string]any, in *parsers.Input) string {
	if p := getS(obj, "_path"); p != "" {
		if knownSet[p] {
			return p
		}
		return "unknown"
	}
	for _, h := range []string{in.Hint("zeek_path"), in.Hint("path")} {
		if h == "" {
			continue
		}
		base := parsers.BaseName(h)
		base = strings.TrimSuffix(strings.TrimSuffix(base, ".gz"), ".log")
		if i := strings.IndexByte(base, '.'); i > 0 {
			base = base[:i]
		}
		if knownSet[base] {
			return base
		}
	}
	has := func(keys ...string) bool {
		for _, k := range keys {
			if _, ok := obj[k]; !ok {
				return false
			}
		}
		return true
	}
	switch {
	case has("conn_state") || has("proto", "history"):
		return "conn"
	case has("query", "qtype_name") || has("query", "rcode_name") || has("trans_id", "query"):
		return "dns"
	case has("method", "host", "uri"):
		return "http"
	case has("version", "cipher") || has("server_name", "ja3"):
		return "ssl"
	case has("fuid", "mime_type") || has("fuid", "tx_hosts"):
		return "files"
	case has("note", "msg"):
		return "notice"
	case has("name", "addl") || has("name", "notice", "peer"):
		return "weird"
	case has("auth_success") || has("auth_attempts", "client"):
		return "ssh"
	case has("request_type", "service"):
		return "kerberos"
	case has("action", "name", "fuid") || has("action", "path", "name"):
		return "smb_files"
	case has("path", "share_type"):
		return "smb_mapping"
	case has("endpoint", "operation"):
		return "dce_rpc"
	case has("username", "server_nb_computer_name") || has("domainname", "hostname", "success"):
		return "ntlm"
	case has("cookie", "security_protocol") || has("cookie", "result"):
		return "rdp"
	case has("certificate.version") || has("certificate.serial"):
		return "x509"
	case has("software_type", "name"):
		return "software"
	}
	return "unknown"
}

var commonKeys = []string{"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "community_id", "_system_name", "_path", "_write_ts", "id.vlan", "id.vlan_inner"}

// mapCommon writes the fields shared by every Zeek log. It reports whether
// the record had a timestamp or a uid.
func mapCommon(e *schema.Event, obj map[string]any) bool {
	ok := false
	if ts := getS(obj, "ts"); ts != "" {
		ok = parsers.SetTime(e, schema.FieldTimestamp, ts)
	}
	if uid := getS(obj, "uid"); uid != "" {
		e.Set("zeek.session_id", uid)
		ok = true
	}
	src := getS(obj, "id.orig_h")
	dst := getS(obj, "id.resp_h")
	parsers.SetIP(e, "source.ip", src)
	parsers.SetPort(e, "source.port", getS(obj, "id.orig_p"))
	parsers.SetIP(e, "destination.ip", dst)
	parsers.SetPort(e, "destination.port", getS(obj, "id.resp_p"))
	e.Set("network.community_id", getS(obj, "community_id"))
	e.Set("observer.hostname", getS(obj, "_system_name"))
	if src != "" {
		e.Set("network.type", parsers.NetworkType(parsers.NormalizeIP(src)))
	}
	e.SetCategory(schema.CategoryNetwork)
	return ok
}

// keepRest stores every unconsumed key under zeek.<log>.<key> (snake_case).
func keepRest(e *schema.Event, log string, obj map[string]any, consumed map[string]bool) {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		if !consumed[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		e.Set("zeek."+log+"."+parsers.SnakePath(k), normalize(obj[k]))
	}
}

func normalize(v any) any {
	switch t := v.(type) {
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return n
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	case []any:
		allStr := true
		for _, x := range t {
			if _, ok := x.(string); !ok {
				allStr = false
			}
		}
		if allStr {
			out := make([]string, len(t))
			for i, x := range t {
				out[i] = x.(string)
			}
			return out
		}
		for i := range t {
			t[i] = normalize(t[i])
		}
		return t
	case map[string]any:
		for k := range t {
			t[k] = normalize(t[k])
		}
		return t
	}
	return v
}
