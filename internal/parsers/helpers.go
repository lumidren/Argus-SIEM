package parsers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/lumidren/argus/internal/schema"
)

// Base returns an event pre-populated with the module/dataset and the
// time-source default. Parsers call it first.
func Base(in *Input, module, dataset string) *schema.Event {
	e := schema.New()
	e.Set(schema.FieldEventModule, module)
	e.Set(schema.FieldEventDataset, dataset)
	e.Set(schema.FieldEventKind, schema.KindEvent)
	return e
}

// SetIP validates s as an IP address and stores it at key. IPv4-mapped IPv6
// addresses ("::ffff:10.0.0.1") are unwrapped. Placeholders ("-", "", "N/A",
// "LOCAL", "::1", "127.0.0.1" when dropLoopback) are ignored. Returns whether
// a value was stored.
func SetIP(e *schema.Event, key, s string) bool {
	ip := NormalizeIP(s)
	if ip == "" {
		return false
	}
	e.Set(key, ip)
	return true
}

// NormalizeIP returns the canonical string form of s if it is an IP, else "".
func NormalizeIP(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	switch strings.ToUpper(s) {
	case "", "-", "N/A", "NONE", "LOCAL", "UNKNOWN", "NULL":
		return ""
	}
	// strip a zone id like fe80::1%eth0
	if i := strings.IndexByte(s, '%'); i > 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// IsPublicIP reports whether ip is globally routable (used by GeoIP to skip
// private addresses).
func IsPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast() || isSharedAddressSpace(ip))
}

func isSharedAddressSpace(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 100 && v4[1]&0xC0 == 64 // 100.64.0.0/10
}

// SetPort parses s as a TCP/UDP port and stores it as int64. Ports outside
// 0..65535 or non-numeric values are ignored.
func SetPort(e *schema.Event, key, s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return false
	}
	e.Set(key, int64(n))
	return true
}

// SetInt parses s as an integer (decimal, or hex with 0x prefix) and stores it.
func SetInt(e *schema.Event, key, s string) bool {
	n, ok := ParseInt(s)
	if !ok {
		return false
	}
	e.Set(key, n)
	return true
}

// ParseInt parses decimal or 0x-prefixed hexadecimal integers.
func ParseInt(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0, false
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return 0, false
		}
		return int64(n), true
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		f, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil {
			return 0, false
		}
		return int64(f), true
	}
	return n, true
}

// SetFloat parses s as a float and stores it.
func SetFloat(e *schema.Event, key, s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return false
	}
	e.Set(key, f)
	return true
}

// SetBool parses common boolean spellings.
func SetBool(e *schema.Event, key, s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "1", "t", "y", "on":
		e.Set(key, true)
	case "false", "no", "0", "f", "n", "off":
		e.Set(key, false)
	default:
		return false
	}
	return true
}

// SetTime parses s with schema.ParseTime and stores it at key (RFC 3339).
func SetTime(e *schema.Event, key, s string) bool {
	t, ok := schema.ParseTime(s)
	if !ok {
		return false
	}
	if key == schema.FieldTimestamp {
		e.SetTimestamp(t)
	} else {
		e.Set(key, t)
	}
	return true
}

// SplitDomainUser splits "DOMAIN\user", "user@domain" or "domain/user" into
// (user, domain). A bare user returns ("user", "").
func SplitDomainUser(s string) (user, domain string) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return "", ""
	}
	if i := strings.LastIndexByte(s, '\\'); i >= 0 {
		return s[i+1:], s[:i]
	}
	if i := strings.IndexByte(s, '@'); i > 0 {
		return s[:i], s[i+1:]
	}
	if i := strings.IndexByte(s, '/'); i > 0 && !strings.Contains(s, "://") {
		return s[i+1:], s[:i]
	}
	return s, ""
}

// SetUser stores user.name and user.domain from a possibly qualified name.
// Placeholders like "-" and "SYSTEM"? are kept: SYSTEM is a real account.
func SetUser(e *schema.Event, prefix, s string) {
	u, d := SplitDomainUser(s)
	if u == "" || u == "-" {
		return
	}
	e.Set(prefix+".name", u)
	if d != "" && d != "-" {
		e.Set(prefix+".domain", d)
	}
}

// BaseName returns the final path element for Windows or POSIX paths.
func BaseName(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.TrimRight(p, `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// DirName returns the directory part of a Windows or POSIX path.
func DirName(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexAny(p, `\/`); i > 0 {
		return p[:i]
	}
	return ""
}

// Extension returns the lower-case file extension without the dot.
func Extension(name string) string {
	base := BaseName(name)
	if i := strings.LastIndexByte(base, '.'); i > 0 && i < len(base)-1 {
		return strings.ToLower(base[i+1:])
	}
	return ""
}

// SetFile sets file.path, file.name, file.directory and file.extension.
func SetFile(e *schema.Event, path string) {
	path = strings.TrimSpace(path)
	if path == "" || path == "-" {
		return
	}
	e.Set("file.path", path)
	e.Set("file.name", BaseName(path))
	e.Set("file.directory", DirName(path))
	e.Set("file.extension", Extension(path))
}

// SetProcessExecutable sets process.executable and process.name (and the
// parent variants with prefix "process.parent").
func SetProcessExecutable(e *schema.Event, prefix, path string) {
	path = strings.TrimSpace(path)
	if path == "" || path == "-" {
		return
	}
	e.Set(prefix+".executable", path)
	e.Set(prefix+".name", BaseName(path))
}

// SetHashes parses a Sysmon-style "SHA256=..,MD5=..,IMPHASH=.." list (or a
// bare hash) and stores under prefix (e.g. "process.hash", "file.hash").
func SetHashes(e *schema.Event, prefix, hashes string) {
	hashes = strings.TrimSpace(hashes)
	if hashes == "" || hashes == "-" {
		return
	}
	for _, part := range strings.Split(hashes, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			SetHashByLength(e, prefix, part)
			continue
		}
		val = strings.ToLower(strings.TrimSpace(val))
		switch strings.ToUpper(strings.TrimSpace(name)) {
		case "MD5":
			e.Set(prefix+".md5", val)
		case "SHA1":
			e.Set(prefix+".sha1", val)
		case "SHA256":
			e.Set(prefix+".sha256", val)
		case "SHA512":
			e.Set(prefix+".sha512", val)
		case "IMPHASH":
			e.Set(prefix+".imphash", val)
		case "SSDEEP":
			e.Set(prefix+".ssdeep", val)
		}
	}
}

// SetHashByLength stores a bare hex hash as md5/sha1/sha256/sha512 by length.
func SetHashByLength(e *schema.Event, prefix, h string) {
	h = strings.ToLower(strings.TrimSpace(h))
	if !isHex(h) {
		return
	}
	switch len(h) {
	case 32:
		e.Set(prefix+".md5", h)
	case 40:
		e.Set(prefix+".sha1", h)
	case 64:
		e.Set(prefix+".sha256", h)
	case 128:
		e.Set(prefix+".sha512", h)
	}
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// SetURL splits a URL or path into url.original, url.path, url.query,
// url.fragment and, when present, url.scheme / url.domain / url.port.
func SetURL(e *schema.Event, original string) {
	original = strings.TrimSpace(original)
	if original == "" || original == "-" {
		return
	}
	e.Set("url.original", original)
	rest := original
	if i := strings.Index(rest, "://"); i > 0 && i < 10 {
		e.Set("url.scheme", strings.ToLower(rest[:i]))
		rest = rest[i+3:]
		hostEnd := strings.IndexAny(rest, "/?#")
		host := rest
		if hostEnd >= 0 {
			host = rest[:hostEnd]
			rest = rest[hostEnd:]
		} else {
			rest = ""
		}
		if at := strings.LastIndexByte(host, '@'); at >= 0 {
			e.Set("url.username", strings.SplitN(host[:at], ":", 2)[0])
			host = host[at+1:]
		}
		if h, p, err := net.SplitHostPort(host); err == nil {
			e.Set("url.domain", strings.ToLower(h))
			SetPort(e, "url.port", p)
		} else {
			e.Set("url.domain", strings.ToLower(strings.Trim(host, "[]")))
		}
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		e.Set("url.fragment", rest[i+1:])
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		e.Set("url.query", rest[i+1:])
		rest = rest[:i]
	}
	if rest != "" {
		e.Set("url.path", rest)
		if ext := Extension(rest); ext != "" && !strings.ContainsAny(ext, "/") {
			e.Set("url.extension", ext)
		}
	}
}

// IANAProtocolName maps a protocol number to its ECS network.transport name.
func IANAProtocolName(n int64) string {
	switch n {
	case 1:
		return "icmp"
	case 2:
		return "igmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 41:
		return "ipv6"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 51:
		return "ah"
	case 58:
		return "ipv6-icmp"
	case 89:
		return "ospf"
	case 132:
		return "sctp"
	}
	return strconv.FormatInt(n, 10)
}

// SetTransport stores network.transport from a name or IANA number and
// network.iana_number when numeric.
func SetTransport(e *schema.Event, s string) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "-" {
		return
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		e.Set("network.iana_number", strconv.FormatInt(n, 10))
		e.Set("network.transport", IANAProtocolName(n))
		return
	}
	e.Set("network.transport", s)
}

// NetworkType returns "ipv4" or "ipv6" for an IP string.
func NetworkType(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if p.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

// ---- JSON helpers with resource limits (THREAT_MODEL T2.2) ----

// MaxJSONBytes caps the size of one JSON record a parser will decode.
const MaxJSONBytes = 1 << 20

// MaxJSONDepth caps nesting.
const MaxJSONDepth = 64

// ErrTooLarge is returned for oversize records.
var ErrTooLarge = errors.New("parsers: record exceeds size limit")

// ErrTooDeep is returned for over-nested JSON.
var ErrTooDeep = errors.New("parsers: json nesting exceeds depth limit")

// DecodeJSON decodes raw into a generic object with size and depth limits,
// using json.Number for numbers so int64 precision is preserved.
func DecodeJSON(raw []byte) (map[string]any, error) {
	if len(raw) > MaxJSONBytes {
		return nil, ErrTooLarge
	}
	if err := checkDepth(raw, MaxJSONDepth); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// DecodeJSONAny decodes an object or an array.
func DecodeJSONAny(raw []byte) (any, error) {
	if len(raw) > MaxJSONBytes {
		return nil, ErrTooLarge
	}
	if err := checkDepth(raw, MaxJSONDepth); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func checkDepth(raw []byte, max int) error {
	depth := 0
	inStr := false
	esc := false
	for _, c := range raw {
		if inStr {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			if depth > max {
				return ErrTooDeep
			}
		case '}', ']':
			depth--
		}
	}
	return nil
}

// LooksLikeJSONObject reports whether raw (after whitespace) starts with '{'.
func LooksLikeJSONObject(raw []byte) bool {
	raw = bytes.TrimLeft(raw, " \t\r\n\xef\xbb\xbf")
	return len(raw) > 1 && raw[0] == '{'
}

// FlattenInto flattens a decoded JSON object under prefix into e, converting
// keys to snake_case when snake is true.
func FlattenInto(e *schema.Event, prefix string, obj map[string]any, snake bool) {
	flat := make(map[string]any, len(obj)*2)
	schema.Flatten("", obj, flat)
	for k, v := range flat {
		key := k
		if snake {
			key = SnakePath(k)
		}
		if prefix != "" {
			key = prefix + "." + key
		}
		e.Set(key, v)
	}
}

// SnakePath converts each dotted segment from camelCase to snake_case
// ("userIdentity.sessionContext" -> "user_identity.session_context").
func SnakePath(p string) string {
	parts := strings.Split(p, ".")
	for i, part := range parts {
		parts[i] = Snake(part)
	}
	return strings.Join(parts, ".")
}

// Snake converts camelCase / PascalCase to snake_case, keeping existing
// underscores and lower-casing acronyms (e.g. "callerIPAddress" -> "caller_ip_address").
func Snake(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	runes := []rune(s)
	for i, r := range runes {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				prev := runes[i-1]
				nextLower := i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z'
				if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') || (prev >= 'A' && prev <= 'Z' && nextLower) {
					b.WriteByte('_')
				}
			}
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		if r == '-' || r == ' ' {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// GetPath walks a decoded JSON object by dotted path.
func GetPath(obj map[string]any, path string) (any, bool) {
	cur := any(obj)
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// GetString returns a string at path ("" when missing or not scalar).
func GetString(obj map[string]any, path string) string {
	v, ok := GetPath(obj, path)
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(t, 10)
	}
	return ""
}

// GetInt returns an int64 at path.
func GetInt(obj map[string]any, path string) (int64, bool) {
	v, ok := GetPath(obj, path)
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			f, ferr := t.Float64()
			if ferr != nil {
				return 0, false
			}
			return int64(f), true
		}
		return n, true
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case string:
		return ParseInt(t)
	}
	return 0, false
}

// GetBool returns a bool at path.
func GetBool(obj map[string]any, path string) (bool, bool) {
	v, ok := GetPath(obj, path)
	if !ok {
		return false, false
	}
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		switch strings.ToLower(t) {
		case "true", "yes":
			return true, true
		case "false", "no":
			return false, true
		}
	}
	return false, false
}

// GetMap returns a nested object at path.
func GetMap(obj map[string]any, path string) map[string]any {
	v, ok := GetPath(obj, path)
	if !ok {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

// GetSlice returns an array at path.
func GetSlice(obj map[string]any, path string) []any {
	v, ok := GetPath(obj, path)
	if !ok {
		return nil
	}
	s, _ := v.([]any)
	return s
}

// GetStrings returns an array of strings at path (scalars become one element).
func GetStrings(obj map[string]any, path string) []string {
	v, ok := GetPath(obj, path)
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			} else if n, ok := x.(json.Number); ok {
				out = append(out, n.String())
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

// CompactJSON re-serializes v compactly (for *_text fields searched with
// contains); output is bounded to limit bytes.
func CompactJSON(v any, limit int) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	if len(b) > limit {
		b = b[:limit]
	}
	return string(b)
}

// ---- key=value helpers ----

// ParseKV parses `key=value key2="quoted value" key3=` pairs. Quoted values
// may contain spaces and escaped quotes. Keys are returned in order.
func ParseKV(s string) (keys []string, kv map[string]string) {
	kv = make(map[string]string, 32)
	i := 0
	n := len(s)
	for i < n {
		for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == ',') {
			i++
		}
		if i >= n {
			break
		}
		ks := i
		for i < n && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= n || s[i] != '=' {
			// token without '=': skip it
			continue
		}
		key := s[ks:i]
		i++ // skip '='
		var val string
		if i < n && s[i] == '"' {
			i++
			var b strings.Builder
			for i < n {
				if s[i] == '\\' && i+1 < n {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
			val = b.String()
		} else {
			vs := i
			for i < n && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			val = s[vs:i]
		}
		if key == "" {
			continue
		}
		if _, dup := kv[key]; !dup {
			keys = append(keys, key)
		}
		kv[key] = val
	}
	return keys, kv
}

// SplitCSVLine splits a comma-separated line honouring double quotes
// (PAN-OS syslog bodies quote fields containing commas).
func SplitCSVLine(s string) []string {
	out := make([]string, 0, 64)
	var b strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			if inQ && i+1 < len(s) && s[i+1] == '"' {
				b.WriteByte('"')
				i++
				continue
			}
			inQ = !inQ
		case c == ',' && !inQ:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	out = append(out, b.String())
	return out
}

// Severity0to100 maps textual severities to the ECS 0-100 scale used in
// event.severity.
func Severity0to100(s string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "informational", "information", "info", "notice", "debug", "0", "informative":
		return 10, true
	case "low", "1", "minor":
		return 25, true
	case "medium", "med", "2", "warning", "warn", "moderate":
		return 50, true
	case "high", "3", "error", "err", "major":
		return 75, true
	case "critical", "crit", "4", "5", "alert", "emergency", "emerg", "fatal", "very-high", "very high", "severe":
		return 100, true
	}
	return 0, false
}

// OutcomeFromBool maps a success flag.
func OutcomeFromBool(ok bool) string {
	if ok {
		return schema.OutcomeSuccess
	}
	return schema.OutcomeFailure
}

// Must is a test helper that panics on error.
func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// Sprintf is a thin alias to keep parser files free of fmt imports when only
// one format call is needed.
func Sprintf(format string, a ...any) string { return fmt.Sprintf(format, a...) }

// Now is replaced in tests.
var Now = time.Now
