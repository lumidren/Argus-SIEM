package linux

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

var auditHeader = regexp.MustCompile(`msg=audit\((\d+)\.(\d+):(\d+)\):\s?`)

var errNoAuditHeader = errors.New("linux: audit record without msg=audit() header")

// auditRecord is one "type=X msg=audit(ts:serial): k=v ..." line.
type auditRecord struct {
	typ    string
	secs   int64
	millis int64
	serial string
	fields map[string]string
	order  []string
}

// syscallNames maps syscall numbers per audit arch.
var syscallNames = map[string]map[string]string{
	"c000003e": { // x86_64
		"0": "read", "1": "write", "2": "open", "41": "socket", "42": "connect", "43": "accept", "49": "bind",
		"56": "clone", "57": "fork", "59": "execve", "62": "kill", "82": "rename", "87": "unlink", "90": "chmod",
		"92": "chown", "101": "ptrace", "105": "setuid", "106": "setgid", "165": "mount", "175": "init_module",
		"257": "openat", "260": "fchownat", "263": "unlinkat", "264": "renameat", "268": "fchmodat",
		"288": "accept4", "313": "finit_module", "322": "execveat",
	},
	"c00000b7": { // aarch64
		"63": "read", "64": "write", "198": "socket", "203": "connect", "202": "accept", "200": "bind",
		"220": "clone", "221": "execve", "129": "kill", "38": "renameat", "35": "unlinkat", "53": "fchmodat",
		"54": "fchownat", "117": "ptrace", "146": "setuid", "144": "setgid", "40": "mount", "105": "init_module",
		"56": "openat", "242": "accept4", "273": "finit_module", "281": "execveat",
	},
}

var archNames = map[string]string{"c000003e": "x86_64", "c00000b7": "aarch64", "40000003": "i386", "40000028": "arm"}

// auditTypeNames maps go-audit numeric types.
var auditTypeNames = map[int64]string{
	1300: "SYSCALL", 1309: "EXECVE", 1307: "CWD", 1302: "PATH", 1327: "PROCTITLE", 1306: "SOCKADDR",
	1112: "USER_LOGIN", 1100: "USER_AUTH", 1101: "USER_ACCT", 1105: "USER_START", 1106: "USER_END",
	1103: "CRED_ACQ", 1104: "CRED_DISP", 1006: "LOGIN", 1130: "SERVICE_START", 1131: "SERVICE_STOP",
	1400: "AVC", 1114: "ADD_USER", 1115: "DEL_USER", 1116: "ADD_GROUP", 1117: "DEL_GROUP",
	1108: "USER_CHAUTHTOK", 1305: "CONFIG_CHANGE", 1326: "SECCOMP", 1701: "ANOM_ABEND",
}

func parseAuditLine(line string) (*auditRecord, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "type=") {
		return nil, errNoAuditHeader
	}
	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		return nil, errNoAuditHeader
	}
	r := &auditRecord{typ: line[5:sp], fields: map[string]string{}}
	loc := auditHeader.FindStringSubmatchIndex(line)
	if loc == nil {
		return nil, errNoAuditHeader
	}
	r.secs, _ = strconv.ParseInt(line[loc[2]:loc[3]], 10, 64)
	r.millis, _ = strconv.ParseInt(line[loc[4]:loc[5]], 10, 64)
	r.serial = line[loc[6]:loc[7]]
	parseAuditFields(r, line[loc[1]:])
	return r, nil
}

// parseAuditFields parses k=v pairs, including the nested msg='...' of
// USER_* records, into r.
func parseAuditFields(r *auditRecord, s string) {
	if i := strings.Index(s, "msg='"); i >= 0 {
		end := strings.LastIndexByte(s, '\'')
		if end > i+5 {
			inner := s[i+5 : end]
			s = s[:i] + " " + inner + " " + s[end+1:]
		}
	}
	keys, kv := parsers.ParseKV(s)
	for _, k := range keys {
		if _, dup := r.fields[k]; !dup {
			r.order = append(r.order, k)
		}
		r.fields[k] = kv[k]
	}
}

// decodeHexField decodes unquoted hex values (EXECVE args, proctitle, names
// with spaces); quoted values were already unquoted by ParseKV and are
// returned unchanged.
func decodeHexField(raw, original string) string {
	if strings.Contains(original, `"`) || len(raw) < 2 || len(raw)%2 != 0 {
		return raw
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return raw
		}
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return raw
	}
	return strings.TrimRight(strings.ReplaceAll(string(b), "\x00", " "), " ")
}

func parseAuditText(in *parsers.Input, text string) ([]*schema.Event, error) {
	groups := map[string][]*auditRecord{}
	var order []string
	var lastErr error
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		r, err := parseAuditLine(line)
		if err != nil {
			lastErr = err
			continue
		}
		// keep the raw line for hex-vs-quoted decisions
		r.fields["__raw"] = line
		if _, ok := groups[r.serial]; !ok {
			order = append(order, r.serial)
		}
		groups[r.serial] = append(groups[r.serial], r)
	}
	if len(order) == 0 {
		if lastErr == nil {
			lastErr = errNoAuditHeader
		}
		return nil, lastErr
	}
	out := make([]*schema.Event, 0, len(order))
	for _, serial := range order {
		out = append(out, buildAudit(in, groups[serial], nil))
	}
	return out, nil
}

func parseGoAudit(in *parsers.Input, b []byte) ([]*schema.Event, error) {
	obj, err := parsers.DecodeJSON(b)
	if err != nil {
		return nil, err
	}
	seq := parsers.GetString(obj, "sequence")
	ts := parsers.GetString(obj, "timestamp")
	secs, millis := int64(0), int64(0)
	if whole, frac, ok := strings.Cut(ts, "."); ok {
		secs, _ = strconv.ParseInt(whole, 10, 64)
		millis, _ = strconv.ParseInt((frac + "000")[:3], 10, 64)
	} else {
		secs, _ = strconv.ParseInt(ts, 10, 64)
	}
	var recs []*auditRecord
	for _, m := range parsers.GetSlice(obj, "messages") {
		mm, ok := m.(map[string]any)
		if !ok {
			continue
		}
		t, _ := parsers.GetInt(mm, "type")
		name, ok := auditTypeNames[t]
		if !ok {
			name = strconv.FormatInt(t, 10)
		}
		r := &auditRecord{typ: name, secs: secs, millis: millis, serial: seq, fields: map[string]string{}}
		data := parsers.GetString(mm, "data")
		parseAuditFields(r, data)
		r.fields["__raw"] = data
		recs = append(recs, r)
	}
	if len(recs) == 0 {
		return nil, errors.New("linux: go-audit record without messages")
	}
	uidMap := map[string]string{}
	for k, v := range parsers.GetMap(obj, "uid_map") {
		if s, ok := v.(string); ok {
			uidMap[k] = s
		}
	}
	return []*schema.Event{buildAudit(in, recs, uidMap)}, nil
}

// buildAudit merges the records of one audit serial into one event.
func buildAudit(in *parsers.Input, recs []*auditRecord, uidMap map[string]string) *schema.Event {
	e := parsers.Base(in, "linux", "linux.auditd")
	primary := recs[0]
	for _, r := range recs {
		if r.typ == "SYSCALL" {
			primary = r
			break
		}
	}
	e.SetTimestamp(timeOf(primary.secs, primary.millis))
	e.Set("auditd.log.sequence", primary.serial)
	if n, err := strconv.ParseInt(primary.serial, 10, 64); err == nil {
		e.Set("auditd.log.sequence", n)
	}
	e.Set("auditd.log.record_type", primary.typ)
	types := make([]string, 0, len(recs))
	for _, r := range recs {
		types = append(types, r.typ)
	}
	e.Set("auditd.log.record_types", types)
	if len(recs) > 1 {
		e.Set("auditd.log.coalesced", true)
	}
	var paths []any
	for _, r := range recs {
		switch r.typ {
		case "SYSCALL":
			applySyscall(e, r)
		case "EXECVE":
			applyExecve(e, r)
		case "CWD":
			e.Set("process.working_directory", r.fields["cwd"])
		case "PROCTITLE":
			e.Set("process.title", decodeHexField(r.fields["proctitle"], rawValue(r, "proctitle")))
		case "PATH":
			p := map[string]any{}
			for _, k := range []string{"item", "name", "inode", "dev", "mode", "ouid", "ogid", "rdev", "nametype", "objtype"} {
				if v := r.fields[k]; v != "" {
					if k == "name" {
						v = decodeHexField(v, rawValue(r, "name"))
					}
					p[k] = v
				}
			}
			paths = append(paths, p)
			nt := r.fields["nametype"]
			if !e.Has("file.path") && (nt == "NORMAL" || nt == "CREATE" || nt == "") && r.fields["name"] != "" {
				name := decodeHexField(r.fields["name"], rawValue(r, "name"))
				parsers.SetFile(e, name)
				e.Set("file.inode", r.fields["inode"])
				e.Set("file.device", r.fields["dev"])
				e.Set("file.mode", r.fields["mode"])
				e.Set("file.uid", r.fields["ouid"])
				e.Set("file.gid", r.fields["ogid"])
			}
		case "SOCKADDR":
			applySockaddr(e, r.fields["saddr"])
		default:
			applyUserRecord(e, r)
		}
	}
	if len(paths) > 0 {
		e.Set("auditd.paths", paths)
	}
	classifyAudit(e, primary)
	if uidMap != nil {
		if n := uidMap[e.String("user.id")]; n != "" {
			e.Set("user.name", n)
		}
		if n := uidMap[e.String("user.audit.id")]; n != "" {
			e.Set("user.audit.name", n)
		}
		if n := uidMap[e.String("user.effective.id")]; n != "" {
			e.Set("user.effective.name", n)
		}
	}
	if !e.Has(schema.FieldMessage) {
		e.Set(schema.FieldMessage, "audit "+strings.ToLower(primary.typ)+" "+e.String(schema.FieldEventAction))
	}
	return e
}

func rawValue(r *auditRecord, key string) string {
	raw := r.fields["__raw"]
	i := strings.Index(raw, " "+key+"=")
	if i < 0 {
		return ""
	}
	v := raw[i+len(key)+2:]
	if j := strings.IndexByte(v, ' '); j >= 0 {
		v = v[:j]
	}
	return v
}

func setID(e *schema.Event, key, v string) {
	if v == "" || v == "4294967295" || v == "-1" || v == "unset" {
		return
	}
	e.Set(key, v)
}

func applySyscall(e *schema.Event, r *auditRecord) {
	f := r.fields
	arch := f["arch"]
	e.Set("auditd.log.arch", archNames[arch])
	if archNames[arch] == "" {
		e.Set("auditd.log.arch", arch)
	}
	if sc := f["syscall"]; sc != "" {
		name := sc
		if tbl, ok := syscallNames[arch]; ok {
			if n, ok := tbl[sc]; ok {
				name = n
			}
		}
		e.Set("auditd.log.syscall", name)
		e.Set("auditd.log.syscall_number", sc)
	}
	parsers.SetInt(e, "process.pid", f["pid"])
	parsers.SetInt(e, "process.parent.pid", f["ppid"])
	e.Set("process.name", f["comm"])
	e.Set("process.executable", f["exe"])
	setID(e, "user.id", f["uid"])
	setID(e, "user.group.id", f["gid"])
	setID(e, "user.effective.id", f["euid"])
	setID(e, "user.saved.id", f["suid"])
	setID(e, "user.filesystem.id", f["fsuid"])
	setID(e, "user.audit.id", f["auid"])
	setID(e, "auditd.log.ses", f["ses"])
	for _, k := range []string{"tty", "subj", "exit", "items"} {
		e.Set("auditd.log."+k, f[k])
	}
	for _, k := range []string{"a0", "a1", "a2", "a3"} {
		e.Set("auditd.log."+k, f[k])
	}
	if k := f["key"]; k != "" && k != "(null)" {
		e.Set("auditd.log.key", k)
	}
	switch f["success"] {
	case "yes":
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	case "no":
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	}
}

func applyExecve(e *schema.Event, r *auditRecord) {
	argc, _ := strconv.Atoi(r.fields["argc"])
	if argc <= 0 {
		// count a0..aN
		for i := 0; ; i++ {
			if _, ok := r.fields["a"+strconv.Itoa(i)]; !ok {
				break
			}
			argc = i + 1
		}
	}
	args := make([]string, 0, argc)
	for i := 0; i < argc && i < 4096; i++ {
		k := "a" + strconv.Itoa(i)
		v, ok := r.fields[k]
		if !ok {
			break
		}
		args = append(args, decodeHexField(v, rawValue(r, k)))
	}
	if len(args) > 0 {
		e.Set("process.args", args)
		e.Set("process.args_count", int64(len(args)))
		e.Set("process.command_line", strings.Join(args, " "))
	}
}

func applySockaddr(e *schema.Event, saddr string) {
	b, err := hex.DecodeString(saddr)
	if err != nil || len(b) < 2 {
		return
	}
	family := binary.LittleEndian.Uint16(b[0:2])
	var ip net.IP
	var port uint16
	switch family {
	case 2: // AF_INET
		if len(b) < 8 {
			return
		}
		port = binary.BigEndian.Uint16(b[2:4])
		ip = net.IP(b[4:8])
	case 10: // AF_INET6
		if len(b) < 24 {
			return
		}
		port = binary.BigEndian.Uint16(b[2:4])
		ip = net.IP(b[8:24])
	case 1: // AF_UNIX
		path := strings.TrimRight(string(b[2:]), "\x00")
		e.Set("auditd.log.sockaddr.path", path)
		e.Set("auditd.log.sockaddr.family", "unix")
		return
	default:
		return
	}
	e.Set("auditd.log.sockaddr.family", map[uint16]string{2: "inet", 10: "inet6"}[family])
	e.Set("destination.ip", parsers.NormalizeIP(ip.String()))
	e.Set("destination.port", int64(port))
}

func applyUserRecord(e *schema.Event, r *auditRecord) {
	f := r.fields
	parsers.SetInt(e, "process.pid", f["pid"])
	setID(e, "user.id", f["uid"])
	setID(e, "user.audit.id", f["auid"])
	setID(e, "auditd.log.ses", f["ses"])
	if exe := f["exe"]; exe != "" {
		e.Set("process.executable", exe)
		e.Set("process.name", parsers.BaseName(exe))
	}
	if acct := f["acct"]; acct != "" {
		e.Set("user.name", decodeHexField(acct, rawValue(r, "acct")))
		e.Set("auditd.log.acct", e.String("user.name"))
	}
	if id := f["id"]; id != "" && (r.typ == "ADD_USER" || r.typ == "DEL_USER") {
		e.Set("user.target.id", id)
	}
	if addr := f["addr"]; addr != "" && addr != "?" {
		e.Set("source.address", addr)
		parsers.SetIP(e, "source.ip", addr)
	}
	if h := f["hostname"]; h != "" && h != "?" {
		e.Set("auditd.log.hostname", h)
	}
	if t := f["terminal"]; t != "" && t != "?" {
		e.Set("auditd.log.terminal", t)
	}
	e.Set("auditd.log.op", f["op"])
	switch f["res"] {
	case "success", "1":
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	case "failed", "0":
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	}
	// keep any remaining keys
	known := map[string]bool{"pid": true, "uid": true, "auid": true, "ses": true, "exe": true, "acct": true, "addr": true,
		"hostname": true, "terminal": true, "op": true, "res": true, "__raw": true, "id": true}
	keys := make([]string, 0, len(f))
	for k := range f {
		if !known[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		e.Set("auditd.log.data."+k, f[k])
	}
}

func classifyAudit(e *schema.Event, primary *auditRecord) {
	typ := primary.typ
	switch {
	case typ == "SYSCALL":
		switch e.String("auditd.log.syscall") {
		case "execve", "execveat":
			e.SetCategory(schema.CategoryProcess)
			e.SetTypes(schema.TypeStart)
		case "connect", "accept", "accept4", "bind", "socket":
			e.SetCategory(schema.CategoryNetwork)
			e.SetTypes(schema.TypeConnection)
		case "open", "openat":
			e.SetCategory(schema.CategoryFile)
			e.SetTypes(schema.TypeAccess)
		case "unlink", "unlinkat":
			e.SetCategory(schema.CategoryFile)
			e.SetTypes(schema.TypeDeletion)
		case "rename", "renameat", "chmod", "fchmodat", "chown", "fchownat":
			e.SetCategory(schema.CategoryFile)
			e.SetTypes(schema.TypeChange)
		case "init_module", "finit_module":
			e.SetCategory(schema.CategoryDriver)
			e.SetTypes(schema.TypeStart)
		default:
			e.SetCategory(schema.CategoryProcess)
			e.SetTypes(schema.TypeInfo)
		}
	case strings.HasPrefix(typ, "USER_") && typ != "USER_CHAUTHTOK" && typ != "USER_MGMT" || typ == "LOGIN" || typ == "CRED_ACQ" || typ == "CRED_DISP" || typ == "CRED_REFR":
		e.SetCategory(schema.CategoryAuthentication)
		switch typ {
		case "USER_END", "CRED_DISP":
			e.SetTypes(schema.TypeEnd)
		case "USER_ACCT":
			e.SetTypes(schema.TypeInfo)
		default:
			e.SetTypes(schema.TypeStart)
		}
	case typ == "ADD_USER" || typ == "DEL_USER" || typ == "ADD_GROUP" || typ == "DEL_GROUP" || typ == "USER_CHAUTHTOK" || typ == "USER_MGMT" || typ == "GRP_MGMT":
		e.SetCategory(schema.CategoryIAM)
		switch typ {
		case "ADD_USER", "ADD_GROUP":
			e.SetTypes(schema.TypeCreation)
		case "DEL_USER", "DEL_GROUP":
			e.SetTypes(schema.TypeDeletion)
		default:
			e.SetTypes(schema.TypeChange)
		}
	case typ == "CONFIG_CHANGE" || strings.HasPrefix(typ, "SERVICE_") || strings.HasPrefix(typ, "SYSTEM_") || strings.HasPrefix(typ, "DAEMON_"):
		e.SetCategory(schema.CategoryConfiguration)
		switch {
		case strings.HasSuffix(typ, "_START") || typ == "SYSTEM_BOOT":
			e.SetTypes(schema.TypeStart)
		case strings.HasSuffix(typ, "_STOP") || strings.HasSuffix(typ, "_END") || typ == "SYSTEM_SHUTDOWN":
			e.SetTypes(schema.TypeEnd)
		default:
			e.SetTypes(schema.TypeChange)
		}
	case typ == "AVC" || typ == "SELINUX_ERR" || strings.HasPrefix(typ, "ANOM_") || strings.HasPrefix(typ, "MAC_") || typ == "SECCOMP":
		e.SetCategory(schema.CategoryIntrusionDetection)
		e.SetTypes(schema.TypeInfo)
	case typ == "SOCKADDR":
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeInfo)
	case typ == "PATH":
		e.SetCategory(schema.CategoryFile)
		e.SetTypes(schema.TypeInfo)
	default:
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeInfo)
	}
	if k := e.String("auditd.log.key"); k != "" {
		e.Set(schema.FieldEventAction, k)
	} else {
		e.Set(schema.FieldEventAction, strings.ToLower(typ))
	}
}
