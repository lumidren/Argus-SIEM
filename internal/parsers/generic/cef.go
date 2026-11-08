package generic

import (
	"errors"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

var errCEFHeader = errors.New("generic: CEF header has fewer than 7 fields")

// splitCEFHeader splits on unescaped '|' up to n fields, the last field
// holding the remainder (the extension).
func splitCEFHeader(s string, n int) []string {
	out := make([]string, 0, n)
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if len(out) == n-1 {
			out = append(out, s[i:])
			return out
		}
		if c == '\\' && i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '\\') {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		if c == '|' {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	out = append(out, b.String())
	return out
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

// parseCEFExtension parses "k=v k2=v with spaces k3=v" honouring escapes.
func parseCEFExtension(s string) (keys []string, kv map[string]string) {
	kv = make(map[string]string)
	// Find key positions: a key starts at the beginning or after a space and is
	// followed by an unescaped '='.
	type pos struct{ keyStart, eq int }
	var ps []pos
	for i := 0; i < len(s); i++ {
		if i > 0 && s[i-1] != ' ' {
			continue
		}
		j := i
		for j < len(s) && isKeyChar(s[j]) {
			j++
		}
		if j > i && j < len(s) && s[j] == '=' && (j == 0 || s[j-1] != '\\') {
			ps = append(ps, pos{i, j})
			i = j
		}
	}
	for idx, p := range ps {
		end := len(s)
		if idx+1 < len(ps) {
			end = ps[idx+1].keyStart
		}
		key := s[p.keyStart:p.eq]
		val := strings.TrimRight(s[p.eq+1:end], " ")
		val = unescapeCEF(val)
		if _, dup := kv[key]; !dup {
			keys = append(keys, key)
		}
		kv[key] = val
	}
	return keys, kv
}

func unescapeCEF(v string) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			switch v[i+1] {
			case '=', '\\', '|':
				b.WriteByte(v[i+1])
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(v[i])
				b.WriteByte(v[i+1])
			}
			i++
			continue
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

// cefMap maps simple extension keys to ECS fields.
var cefMap = map[string]string{
	"smac": "source.mac", "shost": "source.domain", "suid": "source.user.id", "sntdom": "source.user.domain",
	"spriv": "source.user.group.name", "dmac": "destination.mac", "dhost": "destination.domain",
	"duid": "destination.user.id", "dntdom": "destination.user.domain", "dpriv": "destination.user.group.name",
	"app": "network.protocol", "act": "event.action", "reason": "event.reason", "fname": "file.name",
	"filePath": "file.path", "fileType": "file.type", "requestMethod": "http.request.method",
	"requestClientApplication": "user_agent.original", "requestContext": "http.request.referrer",
	"dvchost": "observer.hostname", "deviceExternalId": "observer.serial_number",
	"deviceInboundInterface": "observer.ingress.interface.name", "deviceOutboundInterface": "observer.egress.interface.name",
	"externalId": "event.id", "cat": "cef.extensions.device_event_category",
}

func parseCEF(in *parsers.Input, body string) (*schema.Event, error) {
	f := splitCEFHeader(body, 8)
	if len(f) < 7 {
		return nil, errCEFHeader
	}
	e := parsers.Base(in, "generic", "generic.cef")
	ver := strings.TrimPrefix(f[0], "CEF:")
	parsers.SetInt(e, "cef.version", ver)
	e.Set("cef.device.vendor", f[1])
	e.Set("cef.device.product", f[2])
	e.Set("cef.device.version", f[3])
	e.Set("cef.signature_id", f[4])
	e.Set("cef.name", f[5])
	e.Set("cef.severity", f[6])
	e.Set("observer.vendor", f[1])
	e.Set("observer.product", f[2])
	e.Set("observer.version", f[3])
	e.Set(schema.FieldEventCode, f[4])
	e.Set(schema.FieldEventAction, f[5])
	e.Set("rule.name", f[5])
	if sev, ok := severityFromNumber(f[6]); ok {
		e.Set(schema.FieldEventSeverity, sev)
	}
	ext := ""
	if len(f) == 8 {
		ext = f[7]
	}
	keys, kv := parseCEFExtension(ext)
	labels := map[string]string{}
	for _, k := range keys {
		if strings.HasSuffix(k, "Label") {
			labels[strings.TrimSuffix(k, "Label")] = kv[k]
		}
	}
	for _, k := range keys {
		v := kv[k]
		if v == "" || strings.HasSuffix(k, "Label") {
			continue
		}
		if dst, ok := cefMap[k]; ok {
			e.Set(dst, v)
			continue
		}
		switch k {
		case "rt", "start", "end":
			dst := map[string]string{"rt": schema.FieldTimestamp, "start": "event.start", "end": "event.end"}[k]
			parsers.SetTime(e, dst, cefTime(v))
		case "src":
			parsers.SetIP(e, "source.ip", v)
		case "dst":
			parsers.SetIP(e, "destination.ip", v)
		case "dvc":
			parsers.SetIP(e, "observer.ip", v)
		case "spt":
			parsers.SetPort(e, "source.port", v)
		case "dpt":
			parsers.SetPort(e, "destination.port", v)
		case "suser":
			e.Set("source.user.name", v)
			e.Set("user.name", v)
		case "duser":
			e.Set("destination.user.name", v)
			e.Set("user.target.name", v)
		case "proto":
			parsers.SetTransport(e, v)
		case "msg":
			e.Set(schema.FieldMessage, v)
		case "in":
			parsers.SetInt(e, "source.bytes", v)
		case "out":
			parsers.SetInt(e, "destination.bytes", v)
		case "fsize":
			parsers.SetInt(e, "file.size", v)
		case "fileHash":
			parsers.SetHashByLength(e, "file.hash", v)
		case "request":
			parsers.SetURL(e, v)
		case "dvcpid":
			parsers.SetInt(e, "process.pid", v)
		case "sproc", "dproc":
			e.Set("process.name", v)
		case "deviceDirection":
			switch v {
			case "0":
				e.Set("network.direction", "inbound")
			case "1":
				e.Set("network.direction", "outbound")
			}
		case "outcome":
			switch strings.ToLower(v) {
			case "success", "succeeded", "allowed":
				e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
			case "failure", "failed", "denied", "blocked":
				e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
			default:
				e.Set(schema.FieldEventOutcome, schema.OutcomeUnknown)
			}
		case "cnt":
			parsers.SetInt(e, "cef.extensions.base_event_count", v)
		default:
			if custom, idx, ok := customField(k); ok {
				raw := "cef.extensions." + custom + "_" + idx
				if strings.HasPrefix(custom, "custom_number") || strings.HasPrefix(custom, "flex_number") {
					if !parsers.SetInt(e, raw, v) {
						e.Set(raw, v)
					}
				} else {
					e.Set(raw, v)
				}
				if lbl := labels[k]; lbl != "" {
					e.Set("cef.extensions."+parsers.Snake(sanitizeLabel(lbl)), v)
				}
				continue
			}
			e.Set("cef.extensions."+k, v)
		}
	}
	if !e.Has(schema.FieldMessage) {
		e.Set(schema.FieldMessage, f[5])
	}
	if e.Has("source.ip") || e.Has("destination.ip") {
		e.SetCategory(schema.CategoryNetwork)
	}
	return e, nil
}

// customField maps cs1..cs6, cn1..cn3, flexString1/2, flexNumber1/2,
// flexDate1 to their generic names.
func customField(k string) (string, string, bool) {
	prefixes := []struct{ p, name string }{
		{"flexString", "flex_string"}, {"flexNumber", "flex_number"}, {"flexDate", "flex_date"},
		{"cs", "custom_string"}, {"cn", "custom_number"}, {"cfp", "custom_float"}, {"c6a", "custom_ipv6"},
	}
	for _, pr := range prefixes {
		if strings.HasPrefix(k, pr.p) {
			idx := k[len(pr.p):]
			if len(idx) == 1 && idx[0] >= '1' && idx[0] <= '9' {
				return pr.name, idx, true
			}
		}
	}
	return "", "", false
}

func sanitizeLabel(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, strings.TrimSpace(s))
}

// cefTime normalizes "MMM dd yyyy HH:mm:ss[.SSS] [zone]" to a parseable form;
// epoch milliseconds pass through.
func cefTime(v string) string {
	v = strings.TrimSpace(v)
	parts := strings.Fields(v)
	if len(parts) >= 4 && len(parts[0]) == 3 && len(parts[2]) == 4 {
		day := parts[1]
		if len(day) == 1 {
			day = "0" + day
		}
		months := map[string]string{"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06", "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"}
		if m, ok := months[parts[0]]; ok {
			return parts[2] + "-" + m + "-" + day + "T" + parts[3] + "Z"
		}
	}
	return v
}
