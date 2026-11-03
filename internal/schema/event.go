// Package schema defines the normalized Argus event: a flat map of dotted ECS
// field paths to values, plus the helpers every parser and processor uses to
// populate it consistently. See docs/SCHEMA.md for the field contract.
package schema

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Version is the Argus schema version written to argus.schema.version.
// It is bumped only for breaking field renames (see docs/SCHEMA.md §21).
const Version = 1

// ECSVersion is the ECS release the field vocabulary is taken from.
const ECSVersion = "8.11.0"

// Well-known field paths used across packages. Keeping them as constants
// avoids typos silently producing unmapped fields.
const (
	FieldTimestamp          = "@timestamp"
	FieldMessage            = "message"
	FieldEventKind          = "event.kind"
	FieldEventCategory      = "event.category"
	FieldEventType          = "event.type"
	FieldEventAction        = "event.action"
	FieldEventOutcome       = "event.outcome"
	FieldEventModule        = "event.module"
	FieldEventDataset       = "event.dataset"
	FieldEventOriginal      = "event.original"
	FieldEventHash          = "event.hash"
	FieldEventIngested      = "event.ingested"
	FieldEventCode          = "event.code"
	FieldEventProvider      = "event.provider"
	FieldEventID            = "event.id"
	FieldEventSeverity      = "event.severity"
	FieldHostName           = "host.name"
	FieldTenantID           = "argus.tenant.id"
	FieldSourceID           = "argus.source.id"
	FieldSourceKind         = "argus.source.kind"
	FieldSchemaVersion      = "argus.schema.version"
	FieldParser             = "argus.pipeline.parser"
	FieldParserVersion      = "argus.pipeline.parser_version"
	FieldParseStatus        = "argus.pipeline.parse_status"
	FieldParseError         = "argus.pipeline.parse_error"
	FieldReceivedAt         = "argus.pipeline.received_at"
	FieldProcessorID        = "argus.pipeline.processor_id"
	FieldTimeSource         = "argus.pipeline.time_source"
	FieldTruncatedFields    = "argus.pipeline.truncated_fields"
	FieldHostMismatch       = "argus.pipeline.host_mismatch"
	FieldDedupeKey          = "argus.pipeline.dedupe_key"
	FieldEntityKey          = "argus.entity.key"
	FieldCollectorName      = "argus.collector.name"
	FieldCollectorType      = "argus.collector.type"
	FieldCollectorHost      = "argus.collector.host"
	FieldCollectorAddress   = "argus.collector.address"
	FieldRelatedIP          = "related.ip"
	FieldRelatedUser        = "related.user"
	FieldRelatedHosts       = "related.hosts"
	FieldRelatedHash        = "related.hash"
	FieldTags               = "tags"
	FieldECSVersion         = "ecs.version"
	FieldAgentType          = "agent.type"
	FieldAgentVersion       = "agent.version"
	FieldAgentID            = "agent.id"
	FieldLogSourceAddress   = "log.source.address"
	FieldEventRiskScore     = "event.risk_score"
	FieldEntityUserRisk     = "argus.entity.user.risk"
	FieldEntityHostRisk     = "argus.entity.host.risk"
	FieldAssetCriticality   = "argus.asset.criticality"
	FieldPIIMaskedFields    = "argus.pii.masked_fields"
	FieldDetectionLatencyMS = "argus.detection.latency_ms"
)

// Parse status values for argus.pipeline.parse_status.
const (
	ParseStatusOK           = "ok"
	ParseStatusPartial      = "partial"
	ParseStatusFailed       = "failed"
	ParseStatusSinkRejected = "sink_rejected"
)

// event.kind values.
const (
	KindEvent  = "event"
	KindAlert  = "alert"
	KindMetric = "metric"
	KindState  = "state"
)

// event.outcome values.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeUnknown = "unknown"
)

// ECS event.category allowed values.
const (
	CategoryAuthentication     = "authentication"
	CategoryConfiguration      = "configuration"
	CategoryDatabase           = "database"
	CategoryDriver             = "driver"
	CategoryEmail              = "email"
	CategoryFile               = "file"
	CategoryHost               = "host"
	CategoryIAM                = "iam"
	CategoryIntrusionDetection = "intrusion_detection"
	CategoryMalware            = "malware"
	CategoryNetwork            = "network"
	CategoryPackage            = "package"
	CategoryProcess            = "process"
	CategoryRegistry           = "registry"
	CategorySession            = "session"
	CategoryThreat             = "threat"
	CategoryVulnerability      = "vulnerability"
	CategoryWeb                = "web"
	CategoryAPI                = "api"
	CategoryLibrary            = "library"
)

// ECS event.type allowed values.
const (
	TypeAccess       = "access"
	TypeAdmin        = "admin"
	TypeAllowed      = "allowed"
	TypeChange       = "change"
	TypeConnection   = "connection"
	TypeCreation     = "creation"
	TypeDeletion     = "deletion"
	TypeDenied       = "denied"
	TypeEnd          = "end"
	TypeError        = "error"
	TypeGroup        = "group"
	TypeIndicator    = "indicator"
	TypeInfo         = "info"
	TypeInstallation = "installation"
	TypeProtocol     = "protocol"
	TypeStart        = "start"
	TypeUser         = "user"
)

// Event is a flat, dotted-path representation of one normalized log record.
// The zero value is not usable; use New.
type Event struct {
	m map[string]any
}

// New returns an empty event.
func New() *Event { return &Event{m: make(map[string]any, 48)} }

// FromFlat wraps an existing flat map (no copy).
func FromFlat(m map[string]any) *Event {
	if m == nil {
		m = make(map[string]any)
	}
	return &Event{m: m}
}

// Set stores v at the dotted path key. Nil values, empty strings, empty
// slices and empty maps are ignored so parsers can call Set unconditionally.
func (e *Event) Set(key string, v any) {
	if key == "" || v == nil {
		return
	}
	switch t := v.(type) {
	case string:
		if t == "" {
			return
		}
	case []string:
		if len(t) == 0 {
			return
		}
	case []any:
		if len(t) == 0 {
			return
		}
	case map[string]any:
		if len(t) == 0 {
			return
		}
	case *string:
		if t == nil || *t == "" {
			return
		}
		v = *t
	case time.Time:
		if t.IsZero() {
			return
		}
		v = t.UTC().Format(time.RFC3339Nano)
	case int:
		v = int64(t)
	case int32:
		v = int64(t)
	case uint:
		v = int64(t)
	case uint32:
		v = int64(t)
	case uint64:
		v = int64(t)
	case float32:
		v = float64(t)
	}
	e.m[key] = v
}

// SetNonEmpty is an alias of Set kept for readability in parsers that mix
// mandatory and optional fields.
func (e *Event) SetNonEmpty(key string, v any) { e.Set(key, v) }

// Get returns the value at key.
func (e *Event) Get(key string) (any, bool) {
	v, ok := e.m[key]
	return v, ok
}

// Has reports whether key is set.
func (e *Event) Has(key string) bool {
	_, ok := e.m[key]
	return ok
}

// Delete removes key.
func (e *Event) Delete(key string) { delete(e.m, key) }

// Len returns the number of set fields.
func (e *Event) Len() int { return len(e.m) }

// String returns the value at key as a string ("" if missing). Numbers and
// booleans are formatted; slices return their first element.
func (e *Event) String(key string) string {
	v, ok := e.m[key]
	if !ok {
		return ""
	}
	return toString(v)
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []string:
		if len(t) > 0 {
			return t[0]
		}
		return ""
	case []any:
		if len(t) > 0 {
			return toString(t[0])
		}
		return ""
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case json.Number:
		return t.String()
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// Int64 returns the value at key as int64, converting from string or float.
func (e *Event) Int64(key string) (int64, bool) {
	v, ok := e.m[key]
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	case json.Number:
		n, err := t.Int64()
		return n, err == nil
	}
	return 0, false
}

// Float64 returns the value at key as float64.
func (e *Event) Float64(key string) (float64, bool) {
	v, ok := e.m[key]
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return t, true
	case int64:
		return float64(t), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	}
	return 0, false
}

// Bool returns the value at key as bool, accepting "true"/"false" strings.
func (e *Event) Bool(key string) (bool, bool) {
	v, ok := e.m[key]
	if !ok {
		return false, false
	}
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "yes", "1":
			return true, true
		case "false", "no", "0":
			return false, true
		}
	}
	return false, false
}

// Strings returns the value at key as a string slice (a scalar becomes a
// one-element slice).
func (e *Event) Strings(key string) []string {
	v, ok := e.m[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			out = append(out, toString(x))
		}
		return out
	default:
		return []string{toString(v)}
	}
}

// Append adds vals to the string array at key, skipping empties and
// duplicates and preserving insertion order.
func (e *Event) Append(key string, vals ...string) {
	cur := e.Strings(key)
	for _, v := range vals {
		if v == "" {
			continue
		}
		dup := false
		for _, c := range cur {
			if c == v {
				dup = true
				break
			}
		}
		if !dup {
			cur = append(cur, v)
		}
	}
	if len(cur) > 0 {
		e.m[key] = cur
	}
}

// AddTag appends to tags.
func (e *Event) AddTag(tags ...string) { e.Append(FieldTags, tags...) }

// Keys returns the sorted field paths.
func (e *Event) Keys() []string {
	keys := make([]string, 0, len(e.m))
	for k := range e.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Flat returns a shallow copy of the underlying map.
func (e *Event) Flat() map[string]any {
	out := make(map[string]any, len(e.m))
	for k, v := range e.m {
		out[k] = v
	}
	return out
}

// Raw returns the underlying map without copying. Callers must not retain it
// across mutations.
func (e *Event) Raw() map[string]any { return e.m }

// Clone returns a deep-enough copy (string slices are copied).
func (e *Event) Clone() *Event {
	out := New()
	for k, v := range e.m {
		if s, ok := v.([]string); ok {
			c := make([]string, len(s))
			copy(c, s)
			out.m[k] = c
			continue
		}
		out.m[k] = v
	}
	return out
}

// Timestamp returns @timestamp parsed, or the zero time.
func (e *Event) Timestamp() time.Time {
	s := e.String(FieldTimestamp)
	if s == "" {
		return time.Time{}
	}
	t, ok := ParseTime(s)
	if !ok {
		return time.Time{}
	}
	return t
}

// SetTimestamp sets @timestamp in RFC 3339 UTC with millisecond precision.
func (e *Event) SetTimestamp(t time.Time) {
	if t.IsZero() {
		return
	}
	e.m[FieldTimestamp] = t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// SetCategory sets event.category (replacing) and SetTypes event.type.
func (e *Event) SetCategory(cats ...string) {
	if len(cats) > 0 {
		e.m[FieldEventCategory] = append([]string(nil), cats...)
	}
}

// SetTypes sets event.type (replacing).
func (e *Event) SetTypes(types ...string) {
	if len(types) > 0 {
		e.m[FieldEventType] = append([]string(nil), types...)
	}
}

// Nested converts the flat map into a nested object suitable for JSON
// indexing. Conflicts (a key that is both a leaf and a prefix, e.g.
// "process" and "process.name") are resolved by keeping the object and moving
// the scalar under "<key>.value".
func (e *Event) Nested() map[string]any {
	root := make(map[string]any, len(e.m))
	for _, k := range e.Keys() {
		v := e.m[k]
		parts := strings.Split(k, ".")
		cur := root
		for i, p := range parts {
			last := i == len(parts)-1
			if last {
				if existing, ok := cur[p]; ok {
					if obj, isObj := existing.(map[string]any); isObj {
						obj["value"] = v
						continue
					}
				}
				cur[p] = v
				continue
			}
			next, ok := cur[p]
			if !ok {
				m := make(map[string]any)
				cur[p] = m
				cur = m
				continue
			}
			m, isMap := next.(map[string]any)
			if !isMap {
				m = map[string]any{"value": next}
				cur[p] = m
			}
			cur = m
		}
	}
	return root
}

// MarshalJSON renders the nested form.
func (e *Event) MarshalJSON() ([]byte, error) { return json.Marshal(e.Nested()) }

// UnmarshalJSON accepts either nested or flat JSON and flattens it.
func (e *Event) UnmarshalJSON(b []byte) error {
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return err
	}
	if e.m == nil {
		e.m = make(map[string]any, len(obj))
	}
	Flatten("", obj, e.m)
	return nil
}

// Flatten writes v into out under prefix using dotted keys. Arrays of
// scalars are kept as []any / []string; arrays of objects are kept as []any
// (indexable as nested) because ECS uses them (dns.answers, threat.enrichments).
func Flatten(prefix string, v any, out map[string]any) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 && prefix != "" {
			return
		}
		for k, child := range t {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			Flatten(key, child, out)
		}
	case json.Number:
		if n, err := t.Int64(); err == nil {
			out[prefix] = n
			return
		}
		if f, err := t.Float64(); err == nil {
			out[prefix] = f
			return
		}
		out[prefix] = t.String()
	case []any:
		if prefix == "" {
			return
		}
		allStrings := len(t) > 0
		for _, x := range t {
			if _, ok := x.(string); !ok {
				allStrings = false
				break
			}
		}
		if allStrings {
			ss := make([]string, len(t))
			for i, x := range t {
				ss[i] = x.(string)
			}
			out[prefix] = ss
			return
		}
		// Normalize json.Number inside arrays of objects for stable typing.
		out[prefix] = normalizeNumbers(t)
	default:
		if prefix != "" {
			out[prefix] = v
		}
	}
}

func normalizeNumbers(v any) any {
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
		for i := range t {
			t[i] = normalizeNumbers(t[i])
		}
		return t
	case map[string]any:
		for k := range t {
			t[k] = normalizeNumbers(t[k])
		}
		return t
	}
	return v
}
