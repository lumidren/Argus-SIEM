package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// Enricher adds context to an event in place (GeoIP, assets, identities,
// threat intel, PII masking). Enrichers must not block on slow I/O; lookups
// are expected to be served from local caches.
type Enricher interface {
	Name() string
	Enrich(ctx context.Context, e *schema.Event)
}

// Config tunes the processor.
type Config struct {
	// ProcessorID is stamped into argus.pipeline.processor_id.
	ProcessorID string
	// DedupeWindow applies to records without a provider-side id.
	DedupeWindow time.Duration
	// IDDedupeWindow applies to records with a provider-side id.
	IDDedupeWindow time.Duration
}

// Processor turns raw envelopes into normalized, enriched, deduplicated
// events and writes them durably before reporting success.
type Processor struct {
	Registry  *parsers.Registry
	Dedupe    Deduper
	Enrichers []Enricher
	Index     IndexSink
	Bus       Producer
	Metrics   *Metrics
	Log       *slog.Logger
	Config    Config
	Now       func() time.Time
}

// BatchResult summarizes one processed batch.
type BatchResult struct {
	Messages   int
	Events     int
	Indexed    int
	Duplicates int
	Unparsed   int
	Invalid    int
	Rejected   int
}

type pending struct {
	doc      Doc
	unparsed bool
}

func (p *Processor) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Processor) logger() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

// ProcessBatch handles one batch. It returns nil only when every resulting
// event is durably indexed and produced; the caller commits offsets only in
// that case. Any error means the whole batch must be replayed.
func (p *Processor) ProcessBatch(ctx context.Context, msgs []Message) (BatchResult, error) {
	res := BatchResult{Messages: len(msgs)}
	var items []pending
	seenInBatch := make(map[string]bool)
	for _, m := range msgs {
		env, err := DecodeEnvelope(m.Value)
		if err != nil {
			res.Invalid++
			p.Metrics.invalid()
			p.logger().Warn("dropping invalid envelope", "topic", m.Topic, "partition", m.Partition, "offset", m.Offset, "error", err)
			continue
		}
		in := env.Input()
		pr := p.Registry.Parse(in)
		parserName := "none"
		if pr.Parser != nil {
			parserName = pr.Parser.Name()
		}
		p.Metrics.parsed(env.TenantID, parserName, pr.Status, pr.Elapsed, pr.Panic)
		for i, e := range pr.Events {
			p.enrich(ctx, e)
			e.Set(schema.FieldProcessorID, p.Config.ProcessorID)
			schema.Finalize(e, p.now())
			provider := env.ProviderID
			if provider == "" {
				provider = providerIDFromEvent(e)
			}
			if len(pr.Events) > 1 {
				provider += "#" + strconv.Itoa(i)
			}
			raw := []byte(env.Raw)
			if len(pr.Events) > 1 && provider == "#"+strconv.Itoa(i) {
				// multi-event record without ids: hash the normalized event too
				b, _ := json.Marshal(e.Nested())
				raw = append(raw, b...)
			}
			h := schema.ComputeHash(env.TenantID, env.SourceID, raw, provider)
			e.Set(schema.FieldEventHash, h)
			if seenInBatch[h] {
				res.Duplicates++
				p.Metrics.duplicate(env.TenantID)
				continue
			}
			seenInBatch[h] = true
			unparsed := e.String(schema.FieldParseStatus) == schema.ParseStatusFailed
			items = append(items, pending{doc: Doc{ID: h, TenantID: env.TenantID, Dataset: DatasetFamily(e), Event: e}, unparsed: unparsed})
		}
	}
	res.Events = len(items)
	if len(items) == 0 {
		return res, nil
	}
	keys := make([]string, len(items))
	for i, it := range items {
		keys[i] = it.doc.TenantID + ":" + it.doc.ID
	}
	seen, err := p.Dedupe.Seen(ctx, keys)
	if err != nil {
		return res, fmt.Errorf("%w: dedupe lookup: %v", ErrRetryable, err)
	}
	fresh := items[:0]
	freshKeys := keys[:0]
	for i, it := range items {
		if seen[i] {
			res.Duplicates++
			p.Metrics.duplicate(it.doc.TenantID)
			continue
		}
		fresh = append(fresh, it)
		freshKeys = append(freshKeys, keys[i])
	}
	if len(fresh) == 0 {
		return res, nil
	}
	docs := make([]Doc, len(fresh))
	for i, it := range fresh {
		docs[i] = it.doc
	}
	// Index and produce concurrently; both must succeed.
	var wg sync.WaitGroup
	var idxRes []ItemResult
	var idxErr, busErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		idxRes, idxErr = p.Index.Bulk(ctx, docs)
	}()
	recs := make([]Record, 0, len(fresh))
	for _, it := range fresh {
		rec, err := toRecord(it)
		if err != nil {
			return res, err
		}
		recs = append(recs, rec)
	}
	busErr = p.Bus.Produce(ctx, recs)
	wg.Wait()
	if idxErr != nil {
		return res, fmt.Errorf("%w: index: %v", ErrRetryable, idxErr)
	}
	if busErr != nil {
		return res, fmt.Errorf("%w: produce: %v", ErrRetryable, busErr)
	}
	var rejected []Record
	for i, r := range idxRes {
		switch r {
		case ItemCreated:
			res.Indexed++
		case ItemDuplicate:
			res.Duplicates++
			p.Metrics.sinkConflict(docs[i].TenantID)
		case ItemRetry:
			return res, fmt.Errorf("%w: index item %s throttled", ErrRetryable, docs[i].ID)
		case ItemRejected:
			res.Rejected++
			e := docs[i].Event.Clone()
			e.Set(schema.FieldParseStatus, schema.ParseStatusSinkRejected)
			b, _ := json.Marshal(e)
			rejected = append(rejected, Record{Topic: TopicUnparsed, Key: []byte(docs[i].TenantID), Value: b})
		}
		if fresh[i].unparsed {
			res.Unparsed++
		}
	}
	if len(rejected) > 0 {
		if err := p.Bus.Produce(ctx, rejected); err != nil {
			return res, fmt.Errorf("%w: produce rejected: %v", ErrRetryable, err)
		}
	}
	ttl := p.Config.DedupeWindow
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	if err := p.Dedupe.Mark(ctx, freshKeys, ttl); err != nil {
		// Writes are durable; failing to mark only weakens dedupe for a
		// later duplicate, which the idempotent sink still absorbs.
		p.logger().Warn("dedupe mark failed", "error", err)
	}
	p.Metrics.batch(res)
	return res, nil
}

func (p *Processor) enrich(ctx context.Context, e *schema.Event) {
	for _, en := range p.Enrichers {
		func() {
			defer func() {
				if r := recover(); r != nil {
					p.logger().Error("enricher panicked", "enricher", en.Name(), "panic", fmt.Sprint(r))
				}
			}()
			en.Enrich(ctx, e)
		}()
	}
}

func toRecord(it pending) (Record, error) {
	b, err := json.Marshal(it.doc.Event)
	if err != nil {
		return Record{}, err
	}
	topic := TopicEvents
	if it.unparsed {
		topic = TopicUnparsed
	}
	key := it.doc.Event.String(schema.FieldEntityKey)
	return Record{Topic: topic, Key: []byte(key), Value: b, Headers: map[string]string{"tenant": it.doc.TenantID, "event.hash": it.doc.ID}}, nil
}

// providerIDFromEvent derives a provider-side unique id when the collector
// did not supply one (ADR-0004).
func providerIDFromEvent(e *schema.Event) string {
	if rid := e.String("winlog.record_id"); rid != "" {
		return "winlog:" + e.String("winlog.computer_name") + ":" + e.String("winlog.channel") + ":" + rid
	}
	if id := e.String(schema.FieldEventID); id != "" {
		return e.String(schema.FieldEventModule) + ":" + id
	}
	if uid := e.String("zeek.session_id"); uid != "" {
		return "zeek:" + e.String(schema.FieldEventDataset) + ":" + uid + ":" + e.String(schema.FieldTimestamp)
	}
	return ""
}

// DatasetFamily maps a module to the index family (docs/adr/0002).
func DatasetFamily(e *schema.Event) string {
	if e.String(schema.FieldParseStatus) == schema.ParseStatusFailed {
		return "unparsed"
	}
	switch e.String(schema.FieldEventModule) {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "zeek", "suricata", "panw", "fortinet":
		return "network"
	case "nginx", "apache":
		return "web"
	case "aws", "azure", "gcp", "kubernetes":
		return "cloud"
	case "okta", "o365", "google_workspace":
		return "identity"
	case "osquery":
		return "endpoint"
	case "argus":
		return "alerts"
	}
	return "generic"
}

// Run consumes from src until ctx ends, committing after each successful
// batch. Retryable failures back off and replay the batch without commit.
func (p *Processor) Run(ctx context.Context, src Source) error {
	backoff := 100 * time.Millisecond
	var held []Message
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msgs := held
		if msgs == nil {
			var err error
			msgs, err = src.Fetch(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				p.logger().Warn("fetch failed", "error", err)
				sleep(ctx, backoff)
				continue
			}
		}
		if len(msgs) == 0 {
			continue
		}
		if _, err := p.ProcessBatch(ctx, msgs); err != nil {
			if !errors.Is(err, ErrRetryable) {
				return err
			}
			held = msgs
			p.logger().Warn("batch failed, retrying", "error", err, "backoff", backoff)
			sleep(ctx, backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		held = nil
		backoff = 100 * time.Millisecond
		if err := src.Commit(ctx, msgs); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Commit failure is safe: the batch replays and dedupes.
			p.logger().Warn("commit failed", "error", err)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
