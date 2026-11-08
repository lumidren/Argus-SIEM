package generic

import (
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// ecsRoots are the ECS top-level field sets passed through unchanged.
var ecsRoots = map[string]bool{
	"event": true, "host": true, "user": true, "source": true, "destination": true, "client": true,
	"server": true, "network": true, "process": true, "file": true, "registry": true, "dns": true,
	"http": true, "url": true, "user_agent": true, "tls": true, "cloud": true, "container": true,
	"orchestrator": true, "observer": true, "rule": true, "threat": true, "related": true, "log": true,
	"agent": true, "ecs": true, "error": true, "service": true, "group": true, "organization": true,
	"package": true, "email": true, "vulnerability": true, "device": true, "faas": true, "dll": true,
	"span": true, "trace": true, "transaction": true, "labels": true,
}

var timeKeys = []string{"@timestamp", "timestamp", "time", "ts", "eventTime", "event_time", "date", "datetime", "created_at", "_time"}
var messageKeys = []string{"message", "msg", "log", "text", "Message"}
var hostKeys = []string{"host.name", "hostname", "Hostname", "host", "computer"}
var levelKeys = []string{"level", "severity", "log_level", "log.level"}

// Reserved Argus fields may never be supplied by a payload.
func reserved(k string) bool { return strings.HasPrefix(k, "argus.") }

func parseJSON(in *parsers.Input, body string) (*schema.Event, error) {
	obj, err := parsers.DecodeJSON([]byte(body))
	if err != nil {
		return nil, err
	}
	flat := make(map[string]any, len(obj)*2)
	schema.Flatten("", obj, flat)
	e := parsers.Base(in, "generic", "generic.json")
	consumed := make(map[string]bool)
	for _, k := range timeKeys {
		if v, ok := flat[k]; ok {
			if parsers.SetTime(e, schema.FieldTimestamp, toStr(v)) {
				consumed[k] = true
				break
			}
		}
	}
	for _, k := range messageKeys {
		if v, ok := flat[k].(string); ok && v != "" {
			e.Set(schema.FieldMessage, v)
			consumed[k] = true
			break
		}
	}
	for _, k := range hostKeys {
		if v, ok := flat[k].(string); ok && v != "" {
			e.Set(schema.FieldHostName, v)
			consumed[k] = true
			break
		}
	}
	for _, k := range levelKeys {
		if v, ok := flat[k].(string); ok && v != "" {
			e.Set("log.level", strings.ToLower(v))
			consumed[k] = true
			break
		}
	}
	for k, v := range flat {
		if consumed[k] || reserved(k) {
			continue
		}
		if k == "tags" {
			if ss, ok := v.([]string); ok {
				e.AddTag(ss...)
			} else if s, ok := v.(string); ok {
				e.AddTag(s)
			}
			continue
		}
		root := k
		if i := strings.IndexByte(k, '.'); i > 0 {
			root = k[:i]
		}
		if ecsRoots[root] && strings.Contains(k, ".") {
			e.Set(k, v)
			continue
		}
		e.Set("generic.json."+k, v)
	}
	return e, nil
}

func toStr(v any) string {
	e := schema.New()
	e.Set("v", v)
	return e.String("v")
}
