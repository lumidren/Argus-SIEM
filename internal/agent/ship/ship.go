// Package ship moves buffered envelopes from the agent WAL to the bus. A
// batch is acknowledged in the WAL only after the destination confirmed it,
// so an outage or crash replays unconfirmed records (at-least-once).
package ship

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/lumidren/argus/internal/agent/wal"
	"github.com/lumidren/argus/internal/pipeline"
)

// Shipper drains a WAL into a pipeline.Producer.
type Shipper struct {
	WAL      *wal.WAL
	Producer pipeline.Producer
	Batch    int
	Log      *slog.Logger
	// MaxBackoff caps the retry delay during an outage.
	MaxBackoff time.Duration

	sent   atomic.Int64
	failed atomic.Int64
}

// Stats returns delivered records and failed send attempts.
func (s *Shipper) Stats() (sent, failed int64) { return s.sent.Load(), s.failed.Load() }

// Run ships until ctx ends.
func (s *Shipper) Run(ctx context.Context) error {
	batch := s.Batch
	if batch <= 0 {
		batch = 500
	}
	maxBackoff := s.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 30 * time.Second
	}
	backoff := 200 * time.Millisecond
	for {
		recs, err := s.WAL.ReadBatch(batch, ctx.Done())
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if recs == nil {
			return nil // stop requested
		}
		out := make([]pipeline.Record, 0, len(recs))
		for _, r := range recs {
			var env pipeline.Envelope
			if err := json.Unmarshal(r.Data, &env); err != nil {
				// A corrupt record cannot be repaired; skip it rather than
				// blocking the buffer forever.
				if s.Log != nil {
					s.Log.Error("skipping undecodable buffered record", "error", err)
				}
				continue
			}
			out = append(out, pipeline.Record{Topic: pipeline.RawTopic(env.Kind), Key: []byte(env.TenantID + "/" + env.Collector.Host), Value: r.Data})
		}
		if len(out) > 0 {
			if err := s.Producer.Produce(ctx, out); err != nil {
				s.failed.Add(1)
				s.WAL.Rewind()
				if s.Log != nil {
					s.Log.Warn("ship failed; will retry", "records", len(out), "backoff", backoff, "error", err)
				}
				if !sleep(ctx, backoff) {
					return nil
				}
				if backoff *= 2; backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
		}
		backoff = 200 * time.Millisecond
		if err := s.WAL.Ack(recs[len(recs)-1].Next); err != nil {
			return err
		}
		s.sent.Add(int64(len(out)))
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
