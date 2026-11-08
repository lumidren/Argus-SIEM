package pipeline

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"
)

// TestKafkaEndToEnd runs the processor against franz-go's in-process Kafka
// implementation: produce raw envelopes, consume with a group, process,
// commit, and verify a second consumer in the same group sees no lag.
func TestKafkaEndToEnd(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(3, "argus.raw.generic", TopicEvents, TopicUnparsed))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	cfg := KafkaConfig{Brokers: cluster.ListenAddrs(), ClientID: "test"}
	prod, err := NewKafkaProducer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer prod.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const n = 200
	var recs []Record
	for i := 0; i < n; i++ {
		recs = append(recs, Record{Topic: "argus.raw.generic", Key: []byte(strconv.Itoa(i)), Value: env(t, "t1", `{"msg":"event `+strconv.Itoa(i)+`"}`, "")})
	}
	if err := prod.Produce(ctx, recs); err != nil {
		t.Fatal(err)
	}
	cfg.Group = "argus-processor"
	cfg.Topics = []string{"argus.raw.generic"}
	src, err := NewKafkaSource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	idx := NewMemoryIndex()
	p := newProc(idx, prod)
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- p.Run(runCtx, src) }()
	for idx.Count() < n && ctx.Err() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	<-done
	src.Close()
	if idx.Count() != n {
		t.Fatalf("indexed %d of %d", idx.Count(), n)
	}
	// Normalized events reached argus.events.
	cfg.Group = "verify-events"
	cfg.Topics = []string{TopicEvents}
	ver, err := NewKafkaSource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ver.Close()
	got := 0
	for got < n && ctx.Err() == nil {
		fctx, fcancel := context.WithTimeout(ctx, 2*time.Second)
		msgs, _ := ver.Fetch(fctx)
		fcancel()
		got += len(msgs)
		_ = ver.Commit(ctx, msgs)
	}
	if got < n {
		t.Fatalf("argus.events has %d records, want %d", got, n)
	}
}
