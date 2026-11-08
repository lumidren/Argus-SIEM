// Package pipeline implements the Argus processing pipeline: raw envelopes
// from the bus are parsed, normalized, enriched, deduplicated and written to
// the search tier and the normalized-event topic with exactly-once-effective
// semantics (docs/adr/0004-exactly-once-effective-delivery.md).
package pipeline

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/lumidren/argus/internal/parsers"
)

// Envelope is the value written to argus.raw.<source> topics by every
// collector. The raw payload is carried verbatim; tenant and source are
// assigned by the authenticated ingestion edge, never by the payload.
type Envelope struct {
	TenantID   string            `json:"tenant_id"`
	SourceID   string            `json:"source_id"`
	Kind       string            `json:"kind,omitempty"`
	Collector  parsers.Collector `json:"collector"`
	ReceivedAt time.Time         `json:"received_at"`
	Hints      map[string]string `json:"hints,omitempty"`
	// ProviderID is the collector-side sequence: file offset, record id,
	// cloud event id. It disambiguates legitimately repeated payloads.
	ProviderID string   `json:"provider_id,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Raw        string   `json:"raw"`
	// TraceParent carries the W3C trace context from the collector.
	TraceParent string `json:"traceparent,omitempty"`
}

// ErrInvalidEnvelope is returned for envelopes missing tenant or payload.
var ErrInvalidEnvelope = errors.New("pipeline: envelope missing tenant_id or raw payload")

// Encode serializes the envelope.
func (e *Envelope) Encode() ([]byte, error) { return json.Marshal(e) }

// DecodeEnvelope parses and validates an envelope.
func DecodeEnvelope(b []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	if e.TenantID == "" || e.Raw == "" {
		return nil, ErrInvalidEnvelope
	}
	if e.ReceivedAt.IsZero() {
		e.ReceivedAt = time.Now().UTC()
	}
	return &e, nil
}

// Input converts the envelope to a parser input.
func (e *Envelope) Input() *parsers.Input {
	return &parsers.Input{
		Raw:        []byte(e.Raw),
		ReceivedAt: e.ReceivedAt,
		Hints:      e.Hints,
		Source: parsers.Source{
			TenantID:  e.TenantID,
			SourceID:  e.SourceID,
			Kind:      e.Kind,
			Collector: e.Collector,
			Tags:      e.Tags,
		},
	}
}

// RawTopic returns the bus topic for a source kind.
func RawTopic(kind string) string {
	if kind == "" {
		kind = "generic"
	}
	return "argus.raw." + kind
}

// Topic names.
const (
	TopicEvents   = "argus.events"
	TopicUnparsed = "argus.events.unparsed"
	TopicAlerts   = "argus.alerts"
	TopicAudit    = "argus.audit"
	TopicSighting = "argus.ti.sightings"
)
