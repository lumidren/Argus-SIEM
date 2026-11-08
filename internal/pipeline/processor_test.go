package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/parsers/all"
	"github.com/lumidren/argus/internal/schema"
)

func env(t testing.TB, tenant, raw, provider string) []byte {
	t.Helper()
	e := Envelope{TenantID: tenant, SourceID: "src-1", Raw: raw, ProviderID: provider, ReceivedAt: time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		Collector: parsers.Collector{Name: "vector", Type: "vector"}}
	b, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newProc(idx IndexSink, bus Producer) *Processor {
	return &Processor{Registry: all.Registry(), Dedupe: NewMemoryDeduper(0), Index: idx, Bus: bus, Config: Config{ProcessorID: "p1", DedupeWindow: time.Minute}}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	b := env(t, "t1", "hello", "")
	e, err := DecodeEnvelope(b)
	if err != nil || e.TenantID != "t1" || e.Input().Source.SourceID != "src-1" {
		t.Fatalf("round trip: %+v %v", e, err)
	}
	if _, err := DecodeEnvelope([]byte(`{"raw":"x"}`)); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatal("missing tenant must be rejected")
	}
	if RawTopic("") != "argus.raw.generic" || RawTopic("zeek") != "argus.raw.zeek" {
		t.Fatal("topic names")
	}
}

func TestProcessBatchIndexesAndProduces(t *testing.T) {
	idx, bus := NewMemoryIndex(), NewMemoryBus()
	p := newProc(idx, bus)
	msgs := []Message{
		{Value: env(t, "t1", `<38>Jun  1 09:00:01 web01 sshd[1]: Accepted publickey for alice from 10.0.0.5 port 51234 ssh2`, "")},
		{Value: env(t, "t1", `<38>Jun  1 09:00:01 web01 sshd[1]: Accepted publickey for alice from 10.0.0.5 port 51234 ssh2`, "")}, // exact duplicate
		{Value: env(t, "t1", `{"service":"billing","msg":"ok"}`, "")},
		{Value: env(t, "t2", `{"service":"billing","msg":"ok"}`, "")}, // same raw, other tenant: distinct
		{Value: []byte(`not an envelope`)},
	}
	res, err := p.ProcessBatch(context.Background(), msgs)
	if err != nil {
		t.Fatal(err)
	}
	if res.Indexed != 3 || res.Duplicates != 1 || res.Invalid != 1 {
		t.Fatalf("result %+v", res)
	}
	if got := len(bus.Records(TopicEvents)); got != 3 {
		t.Fatalf("produced %d", got)
	}
	var e schema.Event
	if err := json.Unmarshal(bus.Records(TopicEvents)[0].Value, &e); err != nil {
		t.Fatal(err)
	}
	if e.String(schema.FieldEventHash) == "" || e.String(schema.FieldProcessorID) != "p1" || e.String(schema.FieldTenantID) == "" {
		t.Fatalf("event fields missing: %v", e.Keys())
	}
	// Replaying the same batch must not index anything new.
	res, err = p.ProcessBatch(context.Background(), msgs)
	if err != nil || res.Indexed != 0 || res.Duplicates != 4 || idx.Count() != 3 {
		t.Fatalf("replay %+v %v count=%d", res, err, idx.Count())
	}
}

func TestUnparsedRouting(t *testing.T) {
	idx, bus := NewMemoryIndex(), NewMemoryBus()
	p := newProc(idx, bus)
	p.Registry = parsers.NewRegistry() // no parsers: everything is unrecognized
	_, err := p.ProcessBatch(context.Background(), []Message{{Value: env(t, "t1", "opaque", "")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(bus.Records(TopicUnparsed)) != 1 || len(bus.Records(TopicEvents)) != 0 {
		t.Fatal("unparsed must go to the unparsed topic")
	}
	if idx.Docs()[0].Dataset != "unparsed" {
		t.Fatalf("dataset %s", idx.Docs()[0].Dataset)
	}
}

type flakyIndex struct {
	*MemoryIndex
	fail int
}

func (f *flakyIndex) Bulk(ctx context.Context, docs []Doc) ([]ItemResult, error) {
	if f.fail > 0 {
		f.fail--
		return nil, errors.New("503")
	}
	return f.MemoryIndex.Bulk(ctx, docs)
}

func TestFailedBatchIsNotMarkedSeen(t *testing.T) {
	idx := &flakyIndex{MemoryIndex: NewMemoryIndex(), fail: 1}
	p := newProc(idx, NewMemoryBus())
	msgs := []Message{{Value: env(t, "t1", `{"msg":"a"}`, "")}}
	if _, err := p.ProcessBatch(context.Background(), msgs); !errors.Is(err, ErrRetryable) {
		t.Fatalf("expected retryable, got %v", err)
	}
	res, err := p.ProcessBatch(context.Background(), msgs)
	if err != nil || res.Indexed != 1 {
		t.Fatalf("retry must index the event: %+v %v", res, err)
	}
}

func TestProviderIDDistinguishesRepeats(t *testing.T) {
	idx := NewMemoryIndex()
	p := newProc(idx, NewMemoryBus())
	var msgs []Message
	for i := 0; i < 3; i++ {
		msgs = append(msgs, Message{Value: env(t, "t1", "heartbeat", "file:/var/log/app.log:"+strconv.Itoa(i))})
	}
	if _, err := p.ProcessBatch(context.Background(), msgs); err != nil {
		t.Fatal(err)
	}
	if idx.Count() != 3 {
		t.Fatalf("distinct offsets must give distinct events, got %d", idx.Count())
	}
}

func TestMultiEventRecordsGetDistinctHashes(t *testing.T) {
	idx := NewMemoryIndex()
	p := newProc(idx, NewMemoryBus())
	raw := `{"name":"listening_ports","hostIdentifier":"h","unixTime":1717233332,"snapshot":[{"port":"22","pid":"1"},{"port":"443","pid":"2"}]}`
	if _, err := p.ProcessBatch(context.Background(), []Message{{Value: env(t, "t1", raw, "")}}); err != nil {
		t.Fatal(err)
	}
	if idx.Count() != 2 {
		t.Fatalf("each snapshot row is its own event, got %d", idx.Count())
	}
}

func TestDatasetFamily(t *testing.T) {
	cases := map[string]string{"windows": "windows", "zeek": "network", "okta": "identity", "aws": "cloud", "nginx": "web", "osquery": "endpoint", "generic": "generic", "linux": "linux"}
	for mod, want := range cases {
		e := schema.New()
		e.Set(schema.FieldEventModule, mod)
		if got := DatasetFamily(e); got != want {
			t.Errorf("%s -> %s, want %s", mod, got, want)
		}
	}
}

func TestMemoryDeduperExpiryAndCapacity(t *testing.T) {
	d := NewMemoryDeduper(2)
	now := time.Unix(0, 0)
	d.now = func() time.Time { return now }
	ctx := context.Background()
	_ = d.Mark(ctx, []string{"a", "b"}, time.Second)
	seen, _ := d.Seen(ctx, []string{"a", "b", "c"})
	if !seen[0] || !seen[1] || seen[2] {
		t.Fatalf("seen %v", seen)
	}
	now = now.Add(2 * time.Second)
	seen, _ = d.Seen(ctx, []string{"a"})
	if seen[0] {
		t.Fatal("expired key must not be seen")
	}
	_ = d.Mark(ctx, []string{"c"}, time.Minute)
	if d.Len() != 2 || d.Evicted() != 1 {
		t.Fatalf("capacity: len=%d evicted=%d", d.Len(), d.Evicted())
	}
}

func TestRunCommitsAndStops(t *testing.T) {
	log := NewMemoryLog("argus.raw.generic", 2, 10)
	for i := 0; i < 25; i++ {
		log.Append([]byte(strconv.Itoa(i)), env(t, "t1", `{"msg":"m`+strconv.Itoa(i)+`"}`, ""))
	}
	idx := NewMemoryIndex()
	p := newProc(idx, NewMemoryBus())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx, log.Consumer()) }()
	deadline := time.Now().Add(5 * time.Second)
	for log.Lag() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if log.Lag() != 0 || idx.Count() != 25 {
		t.Fatalf("lag=%d indexed=%d", log.Lag(), idx.Count())
	}
}
