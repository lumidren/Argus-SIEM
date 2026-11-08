package pipeline

import (
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Deduper tracks content hashes of events that have been durably written.
//
// The processor checks keys with Seen before writing and marks them with
// Mark only after the index write and the bus produce are both acknowledged
// (ADR-0004). A processor that crashes between those steps therefore leaves
// no mark behind, and the replayed batch is processed again instead of being
// mistaken for duplicates. Implementations must be safe for concurrent use.
type Deduper interface {
	Seen(ctx context.Context, keys []string) ([]bool, error)
	Mark(ctx context.Context, keys []string, ttl time.Duration) error
}

// MemoryDeduper is a bounded LRU with per-entry expiry, used when Redis is
// disabled and in tests. Evicting an unexpired key can only let a duplicate
// through, which the sink's idempotent _id still absorbs.
type MemoryDeduper struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List
	items    map[string]*list.Element
	now      func() time.Time
	evicted  uint64
}

type memEntry struct {
	key     string
	expires time.Time
}

// NewMemoryDeduper returns a deduper holding at most capacity keys.
func NewMemoryDeduper(capacity int) *MemoryDeduper {
	if capacity <= 0 {
		capacity = 1 << 20
	}
	return &MemoryDeduper{capacity: capacity, ll: list.New(), items: make(map[string]*list.Element), now: time.Now}
}

// Seen implements Deduper.
func (d *MemoryDeduper) Seen(_ context.Context, keys []string) ([]bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	out := make([]bool, len(keys))
	for i, k := range keys {
		if el, ok := d.items[k]; ok && now.Before(el.Value.(*memEntry).expires) {
			out[i] = true
		}
	}
	return out, nil
}

// Mark implements Deduper.
func (d *MemoryDeduper) Mark(_ context.Context, keys []string, ttl time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	exp := d.now().Add(ttl)
	for _, k := range keys {
		if el, ok := d.items[k]; ok {
			el.Value.(*memEntry).expires = exp
			d.ll.MoveToFront(el)
			continue
		}
		d.items[k] = d.ll.PushFront(&memEntry{key: k, expires: exp})
	}
	for d.ll.Len() > d.capacity {
		last := d.ll.Back()
		d.ll.Remove(last)
		delete(d.items, last.Value.(*memEntry).key)
		d.evicted++
	}
	return nil
}

// Len returns the number of tracked keys.
func (d *MemoryDeduper) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ll.Len()
}

// Evicted returns how many unexpired keys were dropped for capacity.
func (d *MemoryDeduper) Evicted() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.evicted
}

// RedisDeduper shares one dedupe view across processor replicas.
type RedisDeduper struct {
	Client redis.UniversalClient
	Prefix string
}

// Seen implements Deduper with a single EXISTS-per-key pipeline.
func (d *RedisDeduper) Seen(ctx context.Context, keys []string) ([]bool, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	pipe := d.Client.Pipeline()
	cmds := make([]*redis.IntCmd, len(keys))
	for i, k := range keys {
		cmds[i] = pipe.Exists(ctx, d.Prefix+k)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}
	out := make([]bool, len(keys))
	for i, c := range cmds {
		out[i] = c.Val() > 0
	}
	return out, nil
}

// Mark implements Deduper.
func (d *RedisDeduper) Mark(ctx context.Context, keys []string, ttl time.Duration) error {
	if len(keys) == 0 {
		return nil
	}
	pipe := d.Client.Pipeline()
	for _, k := range keys {
		pipe.Set(ctx, d.Prefix+k, 1, ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}
