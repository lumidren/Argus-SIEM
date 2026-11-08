package pipeline

import (
	"context"
	"sync"
	"time"
)

// MemoryLog is an in-process, partitioned append-only log with consumer-group
// offsets. It mirrors the Kafka semantics the processor relies on (ordered
// partitions, commit-after-process, replay from the last commit) so the
// pipeline and the chaos test run without a broker.
type MemoryLog struct {
	mu        sync.Mutex
	cond      *sync.Cond
	topic     string
	parts     [][]Message
	committed []int64 // next offset to read per partition
	batchSize int
}

// NewMemoryLog creates a log with n partitions.
func NewMemoryLog(topic string, partitions, batchSize int) *MemoryLog {
	if partitions <= 0 {
		partitions = 1
	}
	if batchSize <= 0 {
		batchSize = 500
	}
	l := &MemoryLog{topic: topic, parts: make([][]Message, partitions), committed: make([]int64, partitions), batchSize: batchSize}
	l.cond = sync.NewCond(&l.mu)
	return l
}

// Append writes a value keyed to a partition by hash of key.
func (l *MemoryLog) Append(key, value []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p := int(fnv32(key) % uint32(len(l.parts)))
	off := int64(len(l.parts[p]))
	l.parts[p] = append(l.parts[p], Message{Topic: l.topic, Partition: int32(p), Offset: off, Key: key, Value: value})
	l.cond.Broadcast()
}

// Len returns the total number of messages.
func (l *MemoryLog) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, p := range l.parts {
		n += len(p)
	}
	return n
}

// Lag returns uncommitted messages across partitions.
func (l *MemoryLog) Lag() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	var lag int64
	for i, p := range l.parts {
		lag += int64(len(p)) - l.committed[i]
	}
	return lag
}

// Consumer returns a Source reading from the committed offsets. Each
// consumer starts from the group's committed position, like a restarted
// Kafka consumer.
func (l *MemoryLog) Consumer() Source {
	l.mu.Lock()
	defer l.mu.Unlock()
	pos := make([]int64, len(l.committed))
	copy(pos, l.committed)
	return &memConsumer{log: l, pos: pos}
}

type memConsumer struct {
	log *MemoryLog
	pos []int64
	rr  int
}

func (c *memConsumer) Fetch(ctx context.Context) ([]Message, error) {
	l := c.log
	stop := context.AfterFunc(ctx, func() {
		l.mu.Lock()
		l.cond.Broadcast()
		l.mu.Unlock()
	})
	defer stop()
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for i := 0; i < len(l.parts); i++ {
			p := (c.rr + i) % len(l.parts)
			if c.pos[p] < int64(len(l.parts[p])) {
				end := c.pos[p] + int64(l.batchSize)
				if end > int64(len(l.parts[p])) {
					end = int64(len(l.parts[p]))
				}
				out := make([]Message, end-c.pos[p])
				copy(out, l.parts[p][c.pos[p]:end])
				c.pos[p] = end
				c.rr = p + 1
				return out, nil
			}
		}
		l.cond.Wait()
	}
}

func (c *memConsumer) Commit(_ context.Context, msgs []Message) error {
	l := c.log
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range msgs {
		if next := m.Offset + 1; next > l.committed[m.Partition] {
			l.committed[m.Partition] = next
		}
	}
	return nil
}

// MemoryIndex is an idempotent document store keyed by tenant and _id.
type MemoryIndex struct {
	mu   sync.Mutex
	docs map[string]Doc
	// Hook, when set, runs after the documents of a bulk call are stored and
	// before Bulk returns; the chaos test uses it to crash mid-batch.
	Hook func(stored int) error
}

// NewMemoryIndex returns an empty index.
func NewMemoryIndex() *MemoryIndex { return &MemoryIndex{docs: map[string]Doc{}} }

// Bulk implements IndexSink.
func (x *MemoryIndex) Bulk(_ context.Context, docs []Doc) ([]ItemResult, error) {
	x.mu.Lock()
	out := make([]ItemResult, len(docs))
	for i, d := range docs {
		k := d.TenantID + "/" + d.ID
		if _, ok := x.docs[k]; ok {
			out[i] = ItemDuplicate
			continue
		}
		x.docs[k] = d
		out[i] = ItemCreated
	}
	hook := x.Hook
	x.mu.Unlock()
	if hook != nil {
		if err := hook(len(docs)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Count returns the number of stored documents.
func (x *MemoryIndex) Count() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.docs)
}

// IDs returns the stored document ids.
func (x *MemoryIndex) IDs() map[string]bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := make(map[string]bool, len(x.docs))
	for _, d := range x.docs {
		out[d.ID] = true
	}
	return out
}

// Docs returns a snapshot of stored documents.
func (x *MemoryIndex) Docs() []Doc {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := make([]Doc, 0, len(x.docs))
	for _, d := range x.docs {
		out = append(out, d)
	}
	return out
}

// MemoryBus records produced messages per topic.
type MemoryBus struct {
	mu     sync.Mutex
	topics map[string][]Record
	Hook   func(n int) error
	// Delay simulates broker acknowledgement latency.
	Delay time.Duration
}

// NewMemoryBus returns an empty bus.
func NewMemoryBus() *MemoryBus { return &MemoryBus{topics: map[string][]Record{}} }

// Produce implements Producer.
func (b *MemoryBus) Produce(ctx context.Context, recs []Record) error {
	if b.Delay > 0 {
		sleep(ctx, b.Delay)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	for _, r := range recs {
		b.topics[r.Topic] = append(b.topics[r.Topic], r)
	}
	hook := b.Hook
	b.mu.Unlock()
	if hook != nil {
		return hook(len(recs))
	}
	return nil
}

// Records returns the records produced to topic.
func (b *MemoryBus) Records(topic string) []Record {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Record, len(b.topics[topic]))
	copy(out, b.topics[topic])
	return out
}

func fnv32(b []byte) uint32 {
	h := uint32(2166136261)
	for _, c := range b {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}
