package pipeline

import (
	"context"
	"errors"

	"github.com/lumidren/argus/internal/schema"
)

// Doc is one event to index, with the routing the sink needs.
type Doc struct {
	ID       string // event.hash
	TenantID string
	Dataset  string // event.dataset family, e.g. "windows", "network"
	Event    *schema.Event
}

// ItemResult is the per-document outcome of a bulk write.
type ItemResult int

const (
	// ItemCreated means the document was written.
	ItemCreated ItemResult = iota
	// ItemDuplicate means a document with the same _id already existed (409).
	ItemDuplicate
	// ItemRetry means a transient failure (429/5xx); the batch must be retried.
	ItemRetry
	// ItemRejected means a permanent failure (mapping error); the event is
	// routed to the unparsed topic with parse_status=sink_rejected.
	ItemRejected
)

// IndexSink writes documents to the search tier.
type IndexSink interface {
	Bulk(ctx context.Context, docs []Doc) ([]ItemResult, error)
}

// Record is one message to produce to the bus.
type Record struct {
	Topic   string
	Key     []byte
	Value   []byte
	Headers map[string]string
}

// Producer writes records to the bus and waits for acknowledgement.
type Producer interface {
	Produce(ctx context.Context, recs []Record) error
}

// Message is one consumed record with its position.
type Message struct {
	Topic     string
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
	Headers   map[string]string
}

// Source delivers batches of raw messages and commits positions.
type Source interface {
	// Fetch blocks until at least one message is available or ctx ends.
	Fetch(ctx context.Context) ([]Message, error)
	// Commit marks every message up to and including msgs as processed.
	Commit(ctx context.Context, msgs []Message) error
}

// ErrRetryable signals that a batch must be reprocessed without committing.
var ErrRetryable = errors.New("pipeline: transient downstream failure")
