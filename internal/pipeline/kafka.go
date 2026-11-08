package pipeline

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// KafkaConfig configures the franz-go client used for every bus role.
type KafkaConfig struct {
	Brokers  []string
	ClientID string
	TLS      *tls.Config
	// SASL SCRAM-SHA-512 credentials (MSK and Redpanda both support it).
	Username string
	Password string
	// Consumer settings.
	Group          string
	Topics         []string
	TopicRegex     bool
	FetchMaxBytes  int32
	MaxPollRecords int
}

func (c KafkaConfig) baseOpts() []kgo.Opt {
	opts := []kgo.Opt{
		kgo.SeedBrokers(c.Brokers...),
		kgo.ClientID(c.ClientID),
		kgo.ProducerBatchCompression(kgo.ZstdCompression(), kgo.Lz4Compression(), kgo.NoCompression()),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerLinger(5 * time.Millisecond),
		kgo.RecordRetries(10),
		kgo.RetryTimeout(30 * time.Second),
	}
	if c.TLS != nil {
		opts = append(opts, kgo.DialTLSConfig(c.TLS))
	}
	if c.Username != "" {
		opts = append(opts, kgo.SASL(scram.Auth{User: c.Username, Pass: c.Password}.AsSha512Mechanism()))
	}
	return opts
}

// KafkaSource is a consumer-group Source with manual commits: offsets are
// committed only after ProcessBatch reports durable success (ADR-0004).
type KafkaSource struct {
	client  *kgo.Client
	maxPoll int
}

// NewKafkaSource joins the consumer group.
func NewKafkaSource(c KafkaConfig) (*KafkaSource, error) {
	if c.Group == "" || len(c.Topics) == 0 {
		return nil, errors.New("pipeline: kafka source needs a group and topics")
	}
	opts := append(c.baseOpts(),
		kgo.ConsumerGroup(c.Group),
		kgo.DisableAutoCommit(),
		kgo.BlockRebalanceOnPoll(),
		kgo.ConsumeTopics(c.Topics...),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if c.TopicRegex {
		opts = append(opts, kgo.ConsumeRegex())
	}
	if c.FetchMaxBytes > 0 {
		opts = append(opts, kgo.FetchMaxBytes(c.FetchMaxBytes))
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	maxPoll := c.MaxPollRecords
	if maxPoll <= 0 {
		maxPoll = 2000
	}
	return &KafkaSource{client: cl, maxPoll: maxPoll}, nil
}

// Fetch implements Source. Rebalances are blocked while a batch is in
// flight and allowed again on Commit, so a partition cannot move to another
// replica mid-batch.
func (s *KafkaSource) Fetch(ctx context.Context) ([]Message, error) {
	fs := s.client.PollRecords(ctx, s.maxPoll)
	if fs.IsClientClosed() {
		return nil, errors.New("pipeline: kafka client closed")
	}
	var errs []error
	fs.EachError(func(topic string, p int32, err error) {
		errs = append(errs, fmt.Errorf("%s[%d]: %w", topic, p, err))
	})
	out := make([]Message, 0, fs.NumRecords())
	fs.EachRecord(func(r *kgo.Record) {
		m := Message{Topic: r.Topic, Partition: r.Partition, Offset: r.Offset, Key: r.Key, Value: r.Value}
		if len(r.Headers) > 0 {
			m.Headers = make(map[string]string, len(r.Headers))
			for _, h := range r.Headers {
				m.Headers[h.Key] = string(h.Value)
			}
		}
		out = append(out, m)
	})
	// Records already polled are returned even when ctx ended during the
	// poll: the client has advanced past them, so dropping them here would
	// lose them for the rest of this session.
	if len(out) == 0 {
		s.client.AllowRebalance()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(errs) > 0 {
			return nil, errors.Join(errs...)
		}
	}
	return out, nil
}

// Commit implements Source.
func (s *KafkaSource) Commit(ctx context.Context, msgs []Message) error {
	defer s.client.AllowRebalance()
	recs := make([]*kgo.Record, len(msgs))
	for i, m := range msgs {
		recs[i] = &kgo.Record{Topic: m.Topic, Partition: m.Partition, Offset: m.Offset}
	}
	return s.client.CommitRecords(ctx, recs...)
}

// Close leaves the group. A batch fetched but never committed (shutdown or
// failure mid-batch) still holds the poll's rebalance block; it is released
// first, otherwise leaving the group would wait forever. The uncommitted
// batch is redelivered to the next group member.
func (s *KafkaSource) Close() {
	s.client.AllowRebalance()
	s.client.Close()
}

// KafkaProducer is an idempotent producer that waits for all-ISR acks.
type KafkaProducer struct{ client *kgo.Client }

// NewKafkaProducer creates the producer.
func NewKafkaProducer(c KafkaConfig) (*KafkaProducer, error) {
	cl, err := kgo.NewClient(c.baseOpts()...)
	if err != nil {
		return nil, err
	}
	return &KafkaProducer{client: cl}, nil
}

// Produce implements Producer; it returns only after every record is acked.
func (p *KafkaProducer) Produce(ctx context.Context, recs []Record) error {
	krs := make([]*kgo.Record, len(recs))
	for i, r := range recs {
		kr := &kgo.Record{Topic: r.Topic, Key: r.Key, Value: r.Value}
		for k, v := range r.Headers {
			kr.Headers = append(kr.Headers, kgo.RecordHeader{Key: k, Value: []byte(v)})
		}
		krs[i] = kr
	}
	return p.client.ProduceSync(ctx, krs...).FirstErr()
}

// Close flushes and closes.
func (p *KafkaProducer) Close() { p.client.Close() }
