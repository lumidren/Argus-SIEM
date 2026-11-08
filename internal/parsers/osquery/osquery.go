// Package osquery parses osquery result logs (event, snapshot and
// differential formats) into ECS per docs/SCHEMA.md §17.
package osquery

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

func (*Parser) Name() string       { return "osquery" }
func (*Parser) Version() string    { return "1.0.0" }
func (*Parser) Datasets() []string { return []string{"osquery.result"} }

var errNotOsquery = errors.New("osquery: not an osquery result")

// Detect implements parsers.Parser.
func (p *Parser) Detect(raw []byte, _ map[string]string) bool {
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 || b[0] != '{' || !bytes.Contains(b, []byte(`"hostIdentifier"`)) || !bytes.Contains(b, []byte(`"name"`)) {
		return false
	}
	return bytes.Contains(b, []byte(`"columns"`)) || bytes.Contains(b, []byte(`"snapshot"`)) || bytes.Contains(b, []byte(`"diffResults"`))
}

type row struct {
	action string
	cols   map[string]string
}

func toRow(x any, action string) (row, bool) {
	m, ok := x.(map[string]any)
	if !ok {
		return row{}, false
	}
	r := row{action: action, cols: map[string]string{}}
	for k, v := range m {
		if s := parsers.GetString(m, k); s != "" {
			r.cols[k] = s
		}
		_ = v
	}
	return r, true
}

// Parse implements parsers.Parser.
func (p *Parser) Parse(in *parsers.Input) ([]*schema.Event, error) {
	obj, err := parsers.DecodeJSON(in.Raw)
	if err != nil {
		return nil, err
	}
	name := parsers.GetString(obj, "name")
	if name == "" || parsers.GetString(obj, "hostIdentifier") == "" {
		return nil, errNotOsquery
	}
	var rows []row
	if cols := parsers.GetMap(obj, "columns"); cols != nil {
		if r, ok := toRow(cols, parsers.GetString(obj, "action")); ok {
			rows = append(rows, r)
		}
	}
	for _, x := range parsers.GetSlice(obj, "snapshot") {
		if r, ok := toRow(x, "snapshot"); ok {
			rows = append(rows, r)
		}
	}
	for _, act := range []string{"added", "removed"} {
		for _, x := range parsers.GetSlice(obj, "diffResults."+act) {
			if r, ok := toRow(x, act); ok {
				rows = append(rows, r)
			}
		}
	}
	if len(rows) == 0 {
		return nil, errNotOsquery
	}
	out := make([]*schema.Event, 0, len(rows))
	for _, r := range rows {
		out = append(out, build(in, obj, name, r))
	}
	return out, nil
}

func build(in *parsers.Input, obj map[string]any, name string, r row) *schema.Event {
	e := parsers.Base(in, "osquery", "osquery.result")
	if !parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(obj, "unixTime")) {
		parsers.SetTime(e, schema.FieldTimestamp, parsers.GetString(obj, "calendarTime"))
	}
	host := parsers.GetString(obj, "decorations.hostname")
	if host == "" {
		host = parsers.GetString(obj, "hostIdentifier")
	}
	e.Set(schema.FieldHostName, host)
	e.Set("host.hostname", host)
	e.Set("host.id", parsers.GetString(obj, "decorations.host_uuid"))
	e.Set("osquery.result.name", name)
	e.Set("osquery.result.action", r.action)
	e.Set("osquery.result.calendar_time", parsers.GetString(obj, "calendarTime"))
	parsers.SetInt(e, "osquery.result.unix_time", parsers.GetString(obj, "unixTime"))
	parsers.SetInt(e, "osquery.result.epoch", parsers.GetString(obj, "epoch"))
	parsers.SetInt(e, "osquery.result.counter", parsers.GetString(obj, "counter"))
	if b, ok := parsers.GetBool(obj, "numerics"); ok {
		e.Set("osquery.result.numerics", b)
	}
	e.Set("osquery.result.host_identifier", parsers.GetString(obj, "hostIdentifier"))
	for k, v := range parsers.GetMap(obj, "decorations") {
		e.Set("osquery.result.decorations."+k, str(v))
	}
	keys := make([]string, 0, len(r.cols))
	for k := range r.cols {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e.Set("osquery.result.columns."+k, r.cols[k])
	}
	e.SetCategory(schema.CategoryHost)
	e.SetTypes(schema.TypeInfo)
	e.Set(schema.FieldEventAction, name)
	promote(e, name, r)
	e.Set(schema.FieldMessage, "osquery "+name+" "+r.action)
	return e
}

func has(c map[string]string, keys ...string) bool {
	for _, k := range keys {
		if _, ok := c[k]; !ok {
			return false
		}
	}
	return true
}

func table(name string, c map[string]string) string {
	n := strings.ToLower(name)
	for _, t := range []string{"process_events", "process_open_sockets", "socket_events", "listening_ports", "logged_in_users", "file_events", "shell_history", "crontab", "startup_items", "scheduled_tasks", "launchd", "services", "registry", "users", "processes"} {
		if strings.Contains(n, t) {
			return t
		}
	}
	switch {
	case has(c, "pid", "path", "cmdline"):
		return "processes"
	case has(c, "local_address", "remote_address"):
		return "process_open_sockets"
	case has(c, "target_path", "action"):
		return "file_events"
	case has(c, "username", "uid", "directory"):
		return "users"
	case has(c, "user", "tty", "host"):
		return "logged_in_users"
	}
	return ""
}

func promote(e *schema.Event, name string, r row) {
	c := r.cols
	switch table(name, c) {
	case "process_events", "processes":
		e.SetCategory(schema.CategoryProcess)
		switch r.action {
		case "removed":
			e.SetTypes(schema.TypeEnd)
		case "added":
			e.SetTypes(schema.TypeStart)
		default:
			e.SetTypes(schema.TypeInfo)
		}
		parsers.SetInt(e, "process.pid", c["pid"])
		parsers.SetProcessExecutable(e, "process", c["path"])
		e.Set("process.command_line", c["cmdline"])
		parsers.SetInt(e, "process.parent.pid", c["parent"])
		e.Set("process.working_directory", c["cwd"])
		e.Set("user.id", c["uid"])
		e.Set("user.group.id", c["gid"])
		e.Set("user.effective.id", c["euid"])
		parsers.SetTime(e, "process.start", c["time"])
		e.Set("process.hash.sha256", c["sha256"])
	case "process_open_sockets", "socket_events":
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeConnection)
		parsers.SetIP(e, "source.ip", c["local_address"])
		parsers.SetPort(e, "source.port", c["local_port"])
		parsers.SetIP(e, "destination.ip", c["remote_address"])
		parsers.SetPort(e, "destination.port", c["remote_port"])
		parsers.SetTransport(e, c["protocol"])
		parsers.SetInt(e, "process.pid", c["pid"])
		parsers.SetProcessExecutable(e, "process", c["path"])
	case "listening_ports":
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeInfo)
		parsers.SetPort(e, "destination.port", c["port"])
		parsers.SetIP(e, "destination.ip", c["address"])
		parsers.SetTransport(e, c["protocol"])
		parsers.SetInt(e, "process.pid", c["pid"])
	case "logged_in_users":
		e.SetCategory(schema.CategorySession)
		e.SetTypes(schema.TypeInfo)
		e.Set("user.name", c["user"])
		if !parsers.SetIP(e, "source.ip", c["host"]) {
			e.Set("source.address", c["host"])
		}
	case "users":
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeUser, schema.TypeInfo)
		e.Set("user.name", c["username"])
		e.Set("user.id", c["uid"])
		e.Set("user.group.id", c["gid"])
		e.Set("user.home", c["directory"])
	case "file_events":
		e.SetCategory(schema.CategoryFile)
		switch strings.ToUpper(c["action"]) {
		case "CREATED":
			e.SetTypes(schema.TypeCreation)
		case "DELETED":
			e.SetTypes(schema.TypeDeletion)
		case "UPDATED", "ATTRIBUTES_MODIFIED", "MOVED_TO", "MOVED_FROM":
			e.SetTypes(schema.TypeChange)
		default:
			e.SetTypes(schema.TypeInfo)
		}
		parsers.SetFile(e, c["target_path"])
		e.Set("file.hash.md5", c["md5"])
		e.Set("file.hash.sha1", c["sha1"])
		e.Set("file.hash.sha256", c["sha256"])
		parsers.SetInt(e, "file.size", c["size"])
		e.Set("file.mode", c["mode"])
		e.Set("file.uid", c["uid"])
		e.Set("file.gid", c["gid"])
	case "shell_history":
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeInfo)
		e.Set("user.id", c["uid"])
		e.Set("process.command_line", c["command"])
		e.Set("file.path", c["history_file"])
	case "crontab":
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeInfo)
		e.Set("process.command_line", c["command"])
		e.Set("file.path", c["path"])
	case "services", "startup_items", "launchd", "scheduled_tasks":
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeInfo)
		e.Set("service.name", c["name"])
		path := c["path"]
		if path == "" {
			path = c["program"]
		}
		parsers.SetProcessExecutable(e, "process", path)
	case "registry":
		e.SetCategory(schema.CategoryRegistry)
		e.SetTypes(schema.TypeInfo)
		e.Set("registry.path", c["path"])
		e.Set("registry.key", c["key"])
		e.Set("registry.value", c["name"])
		if d := c["data"]; d != "" {
			e.Set("registry.data.strings", []string{d})
		}
	}
}

func str(v any) string {
	e := schema.New()
	e.Set("v", v)
	return e.String("v")
}
