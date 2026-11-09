package ship

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lumidren/argus/internal/agent/wal"
	"github.com/lumidren/argus/internal/pipeline"
)

// outageProducer fails while down is true, then records everything.
type outageProducer struct {
	mu   sync.Mutex
	down bool
	recs []pipeline.Record
}

func (p *outageProducer) Produce(_ context.Context, recs []pipeline.Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.down {
		return errors.New("broker unavailable")
	}
	p.recs = append(p.recs, recs...)
	return nil
}

func (p *outageProducer) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.recs)
}

func TestShipThroughOutage(t *testing.T) {
	w, err := wal.Open(t.TempDir(), wal.Options{SyncEvery: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 30; i++ {
		e := pipeline.Envelope{TenantID: "t1", Kind: "linux", Raw: "line " + strconv.Itoa(i), ProviderID: strconv.Itoa(i)}
		b, _ := e.Encode()
		if err := w.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Append([]byte("{corrupt")) // undecodable records are skipped, not retried forever
	prod := &outageProducer{down: true}
	s := &Shipper{WAL: w, Producer: prod, Batch: 10, MaxBackoff: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	if prod.count() != 0 || w.Pending() == 0 {
		t.Fatal("nothing may be acked during the outage")
	}
	prod.mu.Lock()
	prod.down = false
	prod.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for w.Pending() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if prod.count() != 30 || w.Pending() != 0 {
		t.Fatalf("delivered %d, pending %d", prod.count(), w.Pending())
	}
	if prod.recs[0].Topic != "argus.raw.linux" || string(prod.recs[0].Key) != "t1/" {
		t.Fatalf("routing: %s %s", prod.recs[0].Topic, prod.recs[0].Key)
	}
	seen := map[string]bool{}
	for _, r := range prod.recs {
		seen[string(r.Value)] = true
	}
	if len(seen) != 30 {
		t.Fatalf("records lost or duplicated in delivery set: %d distinct", len(seen))
	}
	if sent, failed := s.Stats(); sent != 30 || failed == 0 {
		t.Fatalf("stats sent=%d failed=%d", sent, failed)
	}
}
