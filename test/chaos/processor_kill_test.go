// Package chaos kills the processor mid-stream and asserts the pipeline's
// exactly-once-effective guarantee (docs/adr/0004): every produced event is
// indexed exactly once and appears on argus.events at least once, with no
// loss, across repeated crashes at the worst possible moments.
package chaos

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/parsers/all"
	"github.com/lumidren/argus/internal/pipeline"
	"github.com/lumidren/argus/internal/schema"
	"github.com/twmb/franz-go/pkg/kfake"
)

var errCrash = errors.New("chaos: simulated crash")

// crashPoint makes the process "die" right after a downstream write was made
// durable but before control returned. Crashes fire at pre-chosen call
// numbers spread over the run, so every run injects the planned number.
type crashPoint struct {
	mu      sync.Mutex
	calls   int
	at      map[int]bool
	crashes atomic.Int32
	cancel  context.CancelFunc
}

// newCrashPoint schedules count crashes among the first span calls.
func newCrashPoint(seed int64, count, span int) *crashPoint {
	rng := rand.New(rand.NewSource(seed))
	at := map[int]bool{}
	if span < count*2 {
		span = count * 2
	}
	for len(at) < count {
		at[1+rng.Intn(span)] = true
	}
	return &crashPoint{at: at}
}

func (c *crashPoint) maybe() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel == nil {
		return nil
	}
	c.calls++
	if c.at[c.calls] {
		c.crashes.Add(1)
		c.cancel()
		return errCrash
	}
	return nil
}

func (c *crashPoint) arm(cancel context.CancelFunc) {
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()
}

// idSink is an idempotent index that keeps only ids (memory-light for 100k events).
type idSink struct {
	mu    sync.Mutex
	ids   map[string]int
	crash *crashPoint
}

func (s *idSink) Bulk(_ context.Context, docs []pipeline.Doc) ([]pipeline.ItemResult, error) {
	s.mu.Lock()
	out := make([]pipeline.ItemResult, len(docs))
	for i, d := range docs {
		s.ids[d.ID]++
		if s.ids[d.ID] > 1 {
			out[i] = pipeline.ItemDuplicate
		}
	}
	s.mu.Unlock()
	if err := s.crash.maybe(); err != nil {
		return nil, err
	}
	return out, nil
}

// hashBus records hashes produced to argus.events.
type hashBus struct {
	mu     sync.Mutex
	hashes map[string]int
	crash  *crashPoint
	inner  pipeline.Producer
}

func (b *hashBus) Produce(ctx context.Context, recs []pipeline.Record) error {
	if b.inner != nil {
		if err := b.inner.Produce(ctx, recs); err != nil {
			return err
		}
	}
	b.mu.Lock()
	for _, r := range recs {
		if r.Topic == pipeline.TopicEvents {
			b.hashes[r.Headers["event.hash"]]++
		}
	}
	b.mu.Unlock()
	return b.crash.maybe()
}

// crashingSource wraps a Source and may die right after a commit.
type crashingSource struct {
	pipeline.Source
	crash *crashPoint
}

func (s crashingSource) Commit(ctx context.Context, msgs []pipeline.Message) error {
	if err := s.Source.Commit(ctx, msgs); err != nil {
		return err
	}
	return s.crash.maybe()
}

func envelope(i int) (*pipeline.Envelope, string) {
	raw := fmt.Sprintf(`<38>Jun  1 09:%02d:%02d web%02d sshd[%d]: Accepted publickey for user%d from 10.%d.%d.%d port %d ssh2`,
		(i/60)%60, i%60, i%20, 1000+i%5000, i%500, (i>>16)&255, (i>>8)&255, i&255, 1024+i%60000)
	e := &pipeline.Envelope{TenantID: "tenant-" + strconv.Itoa(i%3), SourceID: "syslog-1", Raw: raw, ProviderID: "file:/var/log/auth.log:" + strconv.Itoa(i),
		ReceivedAt: time.Date(2024, 6, 1, 9, 0, 0, 0, time.UTC), Collector: parsers.Collector{Name: "vector", Type: "vector"}}
	return e, schema.ComputeHash(e.TenantID, e.SourceID, []byte(e.Raw), e.ProviderID)
}

func eventCount(t *testing.T, full, short int) int {
	if testing.Short() {
		return short
	}
	if v := os.Getenv("ARGUS_CHAOS_EVENTS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	return full
}

// TestProcessorKillMemoryLog: 100,000 events, at least 3 crashes at random
// points (after index write, after produce, after commit).
func TestProcessorKillMemoryLog(t *testing.T) {
	n := eventCount(t, 100_000, 10_000)
	log := pipeline.NewMemoryLog("argus.raw.linux", 8, 500)
	want := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		e, h := envelope(i)
		b, _ := e.Encode()
		log.Append([]byte(e.TenantID+"/web"), b)
		want[h] = true
	}
	crash := newCrashPoint(42, 6, 3*n/500)
	sink := &idSink{ids: map[string]int{}, crash: crash}
	bus := &hashBus{hashes: map[string]int{}, crash: crash}
	dedupe := pipeline.NewMemoryDeduper(0) // survives restarts, like Redis
	registry := all.Registry()
	restarts := 0
	deadline := time.Now().Add(5 * time.Minute)
	for log.Lag() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("did not drain: lag %d after %d restarts", log.Lag(), restarts)
		}
		ctx, cancel := context.WithCancel(context.Background())
		crash.arm(cancel)
		p := &pipeline.Processor{Registry: registry, Dedupe: dedupe, Index: sink, Bus: bus,
			Config: pipeline.Config{ProcessorID: "p-" + strconv.Itoa(restarts), DedupeWindow: time.Hour}}
		done := make(chan error, 1)
		go func() { done <- p.Run(ctx, crashingSource{Source: log.Consumer(), crash: crash}) }()
		for log.Lag() > 0 && ctx.Err() == nil {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		<-done
		restarts++
	}
	if c := crash.crashes.Load(); c < 3 {
		t.Fatalf("only %d crashes were injected", c)
	}
	verify(t, want, sink.ids, bus.hashes)
	t.Logf("events=%d crashes=%d restarts=%d", n, crash.crashes.Load(), restarts)
}

// TestProcessorKillKafka repeats the experiment over the real Kafka protocol
// (franz-go's in-process broker) with consumer-group restarts.
func TestProcessorKillKafka(t *testing.T) {
	n := eventCount(t, 20_000, 3_000)
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(6, "argus.raw.linux", pipeline.TopicEvents, pipeline.TopicUnparsed))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	cfg := pipeline.KafkaConfig{Brokers: cluster.ListenAddrs(), ClientID: "chaos"}
	prod, err := pipeline.NewKafkaProducer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer prod.Close()
	want := make(map[string]bool, n)
	ctx := context.Background()
	var recs []pipeline.Record
	for i := 0; i < n; i++ {
		e, h := envelope(i)
		b, _ := e.Encode()
		recs = append(recs, pipeline.Record{Topic: "argus.raw.linux", Key: []byte(strconv.Itoa(i % 64)), Value: b})
		want[h] = true
		if len(recs) == 1000 {
			if err := prod.Produce(ctx, recs); err != nil {
				t.Fatal(err)
			}
			recs = recs[:0]
		}
	}
	if err := prod.Produce(ctx, recs); err != nil {
		t.Fatal(err)
	}
	crash := newCrashPoint(7, 4, 3*n/2000)
	sink := &idSink{ids: map[string]int{}, crash: crash}
	bus := &hashBus{hashes: map[string]int{}, crash: crash, inner: prod}
	dedupe := pipeline.NewMemoryDeduper(0)
	registry := all.Registry()
	deadline := time.Now().Add(3 * time.Minute)
	restarts := 0
	// Drained means every event is both indexed and on argus.events; stopping
	// on the index count alone would cut off a batch whose produce is in flight.
	drained := func() bool { return len(sink.snapshot()) >= n && len(bus.snapshot()) >= n }
	for !drained() {
		if time.Now().After(deadline) {
			t.Fatalf("indexed %d, produced %d of %d after %d restarts", len(sink.snapshot()), len(bus.snapshot()), n, restarts)
		}
		gcfg := cfg
		gcfg.Group = "argus-processor"
		gcfg.Topics = []string{"argus.raw.linux"}
		src, err := pipeline.NewKafkaSource(gcfg)
		if err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(ctx)
		crash.arm(cancel)
		p := &pipeline.Processor{Registry: registry, Dedupe: dedupe, Index: sink, Bus: bus,
			Config: pipeline.Config{ProcessorID: "k-" + strconv.Itoa(restarts), DedupeWindow: time.Hour}}
		done := make(chan error, 1)
		go func() { done <- p.Run(runCtx, crashingSource{Source: src, crash: crash}) }()
		idle := time.Now()
		last := len(sink.snapshot()) + len(bus.snapshot())
		for runCtx.Err() == nil && !drained() {
			time.Sleep(10 * time.Millisecond)
			if cur := len(sink.snapshot()) + len(bus.snapshot()); cur != last {
				last, idle = cur, time.Now()
			} else if time.Since(idle) > 10*time.Second {
				break
			}
		}
		cancel()
		<-done
		src.Close() // abrupt: uncommitted batches are redelivered to the next member
		restarts++
	}
	if c := crash.crashes.Load(); c < 3 {
		t.Fatalf("only %d crashes were injected", c)
	}
	verify(t, want, sink.snapshot(), bus.snapshot())
	t.Logf("events=%d crashes=%d restarts=%d", n, crash.crashes.Load(), restarts)
}

func (s *idSink) snapshot() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.ids))
	for k, v := range s.ids {
		out[k] = v
	}
	return out
}

func (b *hashBus) snapshot() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]int, len(b.hashes))
	for k, v := range b.hashes {
		out[k] = v
	}
	return out
}

func verify(t *testing.T, want map[string]bool, indexed, produced map[string]int) {
	t.Helper()
	missingIdx, missingBus, extra := 0, 0, 0
	for h := range want {
		if indexed[h] == 0 {
			missingIdx++
		}
		if produced[h] == 0 {
			missingBus++
		}
	}
	for h := range indexed {
		if !want[h] {
			extra++
		}
	}
	if missingIdx != 0 || missingBus != 0 || extra != 0 || len(indexed) != len(want) {
		t.Fatalf("loss detected: want=%d indexed_distinct=%d missing_index=%d missing_events_topic=%d unexpected=%d",
			len(want), len(indexed), missingIdx, missingBus, extra)
	}
}
