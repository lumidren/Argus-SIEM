// Package parsers defines the parser contract every source integration
// implements and the registry that routes raw records to parsers.
//
// A parser turns one raw record (a syslog line, a JSON object, an XML event)
// into zero or more schema.Events populated per docs/SCHEMA.md. Parsers are
// pure: no I/O, no global state, safe for concurrent use.
package parsers

import (
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/lumidren/argus/internal/schema"
)

// Collector identifies the component that delivered the record to Argus. It
// is the authority for host identity (THREAT_MODEL T1.1).
type Collector struct {
	Name    string // e.g. "argus-agent", "vector", "api-ingest", "puller"
	Type    string // ECS agent.type
	Version string
	ID      string
	Host    string // hostname the collector runs on (empty for pullers)
	Address string // network address the record arrived from, when known
}

// Source describes the registered data source a record belongs to.
type Source struct {
	TenantID string
	SourceID string
	// Kind names the parser to use ("windows", "zeek", ...). Empty means sniff.
	Kind      string
	Collector Collector
	Tags      []string
}

// Input is one raw record plus its provenance.
type Input struct {
	Raw        []byte
	ReceivedAt time.Time
	Source     Source
	// Hints carry transport-level context a parser may need: "channel" for
	// Windows events delivered without XML System section, "path" for file
	// tailing (Zeek log type is derived from the file name), "syslog_host",
	// "syslog_app" when the syslog header was already stripped by a relay.
	Hints map[string]string
}

// Hint returns a hint value or "".
func (in *Input) Hint(k string) string {
	if in == nil || in.Hints == nil {
		return ""
	}
	return in.Hints[k]
}

// Parser is implemented by every source integration.
type Parser interface {
	// Name is the event.module value and the registry key.
	Name() string
	// Version is the parser's semantic version, written to
	// argus.pipeline.parser_version so regressions can be scoped.
	Version() string
	// Datasets lists the event.dataset values the parser can emit.
	Datasets() []string
	// Detect reports whether raw looks like this parser's format. It must be
	// cheap (prefix checks, a few bytes) and must not allocate heavily.
	Detect(raw []byte, hints map[string]string) bool
	// Parse converts one record into events. Returning (nil, nil) means the
	// record was intentionally dropped (e.g. a heartbeat). An error with
	// partial events means a partial parse; the registry marks the status.
	Parse(in *Input) ([]*schema.Event, error)
}

// ErrUnrecognized is returned by the registry when no parser claims a record.
var ErrUnrecognized = errors.New("parsers: unrecognized format")

// ErrPanic wraps a recovered parser panic.
var ErrPanic = errors.New("parsers: parser panicked")

// Result is the outcome of routing one Input through the registry.
type Result struct {
	Parser  Parser
	Events  []*schema.Event
	Status  string // schema.ParseStatus*
	Err     error
	Panic   bool
	Elapsed time.Duration
}

// Registry holds parsers and the sniffing order.
type Registry struct {
	mu      sync.RWMutex
	byName  map[string]Parser
	ordered []Parser
	// sniffOrder optionally fixes the order Detect is tried in; parsers not
	// listed are tried afterwards in registration order.
	sniffOrder []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]Parser)}
}

// Register adds a parser; registering the same name twice panics because it
// indicates a build error.
func (r *Registry) Register(p Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byName[p.Name()]; dup {
		panic(fmt.Sprintf("parsers: duplicate parser %q", p.Name()))
	}
	r.byName[p.Name()] = p
	r.ordered = append(r.ordered, p)
}

// SetSniffOrder fixes the order in which Detect is attempted. The most
// specific formats (CEF, LEEF, Windows XML, EVE) should come before generic
// JSON and syslog.
func (r *Registry) SetSniffOrder(names ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sniffOrder = names
}

// Get returns a parser by name.
func (r *Registry) Get(name string) (Parser, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byName[name]
	return p, ok
}

// Names returns registered parser names sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Sniff returns the first parser whose Detect accepts raw.
func (r *Registry) Sniff(raw []byte, hints map[string]string) (Parser, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tried := make(map[string]bool, len(r.ordered))
	for _, name := range r.sniffOrder {
		p, ok := r.byName[name]
		if !ok {
			continue
		}
		tried[name] = true
		if p.Detect(raw, hints) {
			return p, true
		}
	}
	for _, p := range r.ordered {
		if tried[p.Name()] {
			continue
		}
		if p.Detect(raw, hints) {
			return p, true
		}
	}
	return nil, false
}

// Parse routes in to the parser named by in.Source.Kind (or sniffs when
// empty), runs it with panic recovery, and stamps provenance fields on every
// event. When parsing fails entirely, a single raw event with
// parse_status=failed is returned so that nothing is lost.
func (r *Registry) Parse(in *Input) Result {
	start := time.Now()
	var p Parser
	if in.Source.Kind != "" {
		if got, ok := r.Get(in.Source.Kind); ok {
			p = got
		}
	}
	if p == nil {
		if got, ok := r.Sniff(in.Raw, in.Hints); ok {
			p = got
		}
	}
	res := Result{Parser: p}
	if p == nil {
		res.Status = schema.ParseStatusFailed
		res.Err = ErrUnrecognized
		raw := RawEvent(in, "", "", res.Err)
		Stamp(raw, in, nil, res.Status, res.Err)
		res.Events = []*schema.Event{raw}
		res.Elapsed = time.Since(start)
		return res
	}
	events, err, panicked := safeParse(p, in)
	res.Panic = panicked
	res.Err = err
	switch {
	case err == nil && len(events) > 0:
		res.Status = schema.ParseStatusOK
	case err != nil && len(events) > 0:
		res.Status = schema.ParseStatusPartial
	case err == nil && len(events) == 0:
		// intentionally dropped record
		res.Status = schema.ParseStatusOK
	default:
		res.Status = schema.ParseStatusFailed
		events = []*schema.Event{RawEvent(in, p.Name(), p.Version(), err)}
	}
	for _, e := range events {
		Stamp(e, in, p, res.Status, err)
	}
	res.Events = events
	res.Elapsed = time.Since(start)
	return res
}

func safeParse(p Parser, in *Input) (events []*schema.Event, err error, panicked bool) {
	defer func() {
		if rec := recover(); rec != nil {
			events = nil
			err = fmt.Errorf("%w: %s: %v\n%s", ErrPanic, p.Name(), rec, debug.Stack())
			panicked = true
		}
	}()
	events, err = p.Parse(in)
	return events, err, false
}

// RawEvent builds the fallback event for an unparsable record: the raw
// payload in event.original, module/dataset generic.unparsed, and the error.
func RawEvent(in *Input, parserName, parserVersion string, err error) *schema.Event {
	e := schema.New()
	e.SetTimestamp(in.ReceivedAt)
	e.Set(schema.FieldTimeSource, "processing")
	e.Set(schema.FieldEventModule, "generic")
	e.Set(schema.FieldEventDataset, "generic.unparsed")
	e.Set(schema.FieldEventKind, schema.KindEvent)
	e.Set(schema.FieldEventOriginal, string(in.Raw))
	e.Set(schema.FieldMessage, schema.StripControl(string(in.Raw)))
	if err != nil {
		e.Set(schema.FieldParseError, truncateErr(err))
	}
	e.AddTag("unparsed")
	_ = parserName
	_ = parserVersion
	return e
}

func truncateErr(err error) string {
	s := err.Error()
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

// Stamp writes the provenance fields common to every event. Tenant and
// source identity always come from in.Source, never from the payload.
func Stamp(e *schema.Event, in *Input, p Parser, status string, err error) {
	src := in.Source
	// Payload-supplied tenant ids are dropped and replaced (THREAT_MODEL T3.4).
	e.Delete(schema.FieldTenantID)
	e.Set(schema.FieldTenantID, src.TenantID)
	e.Set(schema.FieldSourceID, src.SourceID)
	if p != nil {
		e.Set(schema.FieldSourceKind, p.Name())
		e.Set(schema.FieldParser, p.Name())
		e.Set(schema.FieldParserVersion, p.Version())
		if !e.Has(schema.FieldEventModule) {
			e.Set(schema.FieldEventModule, p.Name())
		}
	}
	e.Set(schema.FieldParseStatus, status)
	if err != nil && status != schema.ParseStatusFailed {
		e.Set(schema.FieldParseError, truncateErr(err))
	}
	if !in.ReceivedAt.IsZero() {
		e.Set(schema.FieldReceivedAt, in.ReceivedAt.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	if !e.Has(schema.FieldTimestamp) {
		e.SetTimestamp(in.ReceivedAt)
		e.Set(schema.FieldTimeSource, "processing")
	} else if !e.Has(schema.FieldTimeSource) {
		e.Set(schema.FieldTimeSource, "event")
	}
	c := src.Collector
	e.Set(schema.FieldCollectorName, c.Name)
	e.Set(schema.FieldCollectorType, c.Type)
	e.Set(schema.FieldCollectorHost, c.Host)
	e.Set(schema.FieldCollectorAddress, c.Address)
	e.Set(schema.FieldAgentType, c.Type)
	e.Set(schema.FieldAgentVersion, c.Version)
	e.Set(schema.FieldAgentID, c.ID)
	if c.Address != "" {
		e.Set(schema.FieldLogSourceAddress, c.Address)
	}
	// Host identity: a host-based collector asserts the host. If the payload
	// named a different host, keep the payload value (it may be a relay for
	// many hosts) but flag the mismatch for rules (THREAT_MODEL T1.1).
	if c.Host != "" {
		if h := e.String(schema.FieldHostName); h == "" {
			e.Set(schema.FieldHostName, c.Host)
		} else if !equalFoldHost(h, c.Host) && collectorIsHostBound(c) {
			e.Set(schema.FieldHostMismatch, true)
		}
	}
	if len(src.Tags) > 0 {
		e.AddTag(src.Tags...)
	}
	if !e.Has(schema.FieldEventOriginal) {
		e.Set(schema.FieldEventOriginal, string(in.Raw))
	}
	schema.Sanitize(e)
}

func collectorIsHostBound(c Collector) bool {
	return c.Name == "argus-agent"
}

func equalFoldHost(a, b string) bool {
	if len(a) != len(b) {
		// allow short name vs FQDN
		return shortHost(a) == shortHost(b)
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func shortHost(h string) string {
	for i := 0; i < len(h); i++ {
		if h[i] == '.' {
			h = h[:i]
			break
		}
	}
	b := []byte(h)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
