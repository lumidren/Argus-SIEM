// Command argus-processor consumes raw envelopes from argus.raw.*, parses,
// normalizes, enriches and deduplicates them, and writes them to OpenSearch
// and argus.events with exactly-once-effective semantics.
//
// Configuration (environment):
//
//	ARGUS_KAFKA_BROKERS        comma-separated seed brokers (required)
//	ARGUS_KAFKA_GROUP          consumer group (default argus-processor)
//	ARGUS_KAFKA_TOPICS         topic regex (default ^argus\.raw\..*)
//	ARGUS_KAFKA_USERNAME / ARGUS_KAFKA_PASSWORD[_FILE]  SASL SCRAM-SHA-512
//	ARGUS_KAFKA_TLS            true to dial TLS
//	ARGUS_OPENSEARCH_URL       e.g. https://opensearch:9200 (required)
//	ARGUS_OPENSEARCH_USERNAME / ARGUS_OPENSEARCH_PASSWORD[_FILE]
//	ARGUS_REDIS_ADDR           Redis for shared dedupe; in-memory when empty
//	ARGUS_DEDUPE_WINDOW        default 2m
//	ARGUS_GEOIP_CITY / ARGUS_GEOIP_ASN  mmdb paths (optional)
//	ARGUS_ADMIN_ADDR           metrics and probes (default :9090)
//	ARGUS_LOG_LEVEL            debug|info|warn|error
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/lumidren/argus/internal/config"
	"github.com/lumidren/argus/internal/enrich"
	"github.com/lumidren/argus/internal/parsers/all"
	"github.com/lumidren/argus/internal/pipeline"
	"github.com/lumidren/argus/internal/store/opensearch"
	"github.com/lumidren/argus/internal/telemetry"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "argus-processor:", err)
		os.Exit(1)
	}
}

type settings struct {
	brokers      []string
	group        string
	topics       string
	kafkaUser    string
	kafkaPass    string
	kafkaTLS     bool
	osURL        string
	osUser       string
	osPass       string
	redisAddr    string
	dedupeWindow time.Duration
	geoCity      string
	geoASN       string
	adminAddr    string
	logLevel     string
	processorID  string
}

func load() (settings, error) {
	env := config.New("ARGUS_")
	host, _ := os.Hostname()
	s := settings{
		brokers:      env.List("KAFKA_BROKERS", nil),
		group:        env.String("KAFKA_GROUP", "argus-processor"),
		topics:       env.String("KAFKA_TOPICS", `^argus\.raw\..*`),
		kafkaUser:    env.String("KAFKA_USERNAME", ""),
		kafkaPass:    env.File("KAFKA_PASSWORD", ""),
		kafkaTLS:     env.Bool("KAFKA_TLS", false),
		osURL:        env.String("OPENSEARCH_URL", ""),
		osUser:       env.String("OPENSEARCH_USERNAME", ""),
		osPass:       env.File("OPENSEARCH_PASSWORD", ""),
		redisAddr:    env.String("REDIS_ADDR", ""),
		dedupeWindow: env.Duration("DEDUPE_WINDOW", 2*time.Minute),
		geoCity:      env.String("GEOIP_CITY", ""),
		geoASN:       env.String("GEOIP_ASN", ""),
		adminAddr:    env.String("ADMIN_ADDR", ":9090"),
		logLevel:     env.String("LOG_LEVEL", "info"),
		processorID:  env.String("PROCESSOR_ID", host),
	}
	if len(s.brokers) == 0 {
		env.Require("KAFKA_BROKERS", "")
	}
	env.Require("OPENSEARCH_URL", s.osURL)
	return s, env.Err()
}

// beatingSource marks the service live every time a fetch returns.
type beatingSource struct {
	pipeline.Source
	health *telemetry.Health
}

func (b beatingSource) Fetch(ctx context.Context) ([]pipeline.Message, error) {
	msgs, err := b.Source.Fetch(ctx)
	b.health.Beat()
	return msgs, err
}

func run() error {
	s, err := load()
	if err != nil {
		return err
	}
	log := telemetry.NewLogger(os.Stdout, "argus-processor", version, s.logLevel)
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg := telemetry.NewRegistry()
	health := &telemetry.Health{MaxStall: 2 * time.Minute}
	go telemetry.ServeAdmin(ctx, s.adminAddr, telemetry.AdminMux(reg, health), log)

	kcfg := pipeline.KafkaConfig{Brokers: s.brokers, ClientID: "argus-processor-" + s.processorID, Username: s.kafkaUser, Password: s.kafkaPass,
		Group: s.group, Topics: []string{s.topics}, TopicRegex: true}
	if s.kafkaTLS {
		kcfg.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	src, err := pipeline.NewKafkaSource(kcfg)
	if err != nil {
		return err
	}
	defer src.Close()
	prod, err := pipeline.NewKafkaProducer(kcfg)
	if err != nil {
		return err
	}
	defer prod.Close()

	osClient, err := opensearch.New(opensearch.Config{URL: s.osURL, Username: s.osUser, Password: s.osPass, TLS: &tls.Config{MinVersion: tls.VersionTLS12}})
	if err != nil {
		return err
	}

	var dedupe pipeline.Deduper = pipeline.NewMemoryDeduper(1 << 21)
	if s.redisAddr != "" {
		rc := redis.NewClient(&redis.Options{Addr: s.redisAddr})
		defer rc.Close()
		dedupe = &pipeline.RedisDeduper{Client: rc, Prefix: "dedupe:"}
		log.Info("using redis dedupe", "addr", s.redisAddr)
	} else {
		log.Warn("REDIS_ADDR not set: dedupe is per-replica (in-memory)")
	}

	var enrichers []pipeline.Enricher
	if s.geoCity != "" || s.geoASN != "" {
		db, err := enrich.OpenMMDB(s.geoCity, s.geoASN)
		if err != nil {
			return fmt.Errorf("geoip: %w", err)
		}
		defer db.Close()
		enrichers = append(enrichers, &enrich.Geo{DB: db})
	}

	p := &pipeline.Processor{
		Registry:  all.Registry(),
		Dedupe:    dedupe,
		Enrichers: enrichers,
		Index:     &opensearch.BulkSink{Client: osClient},
		Bus:       prod,
		Metrics:   pipeline.NewMetrics(reg),
		Log:       log,
		Config:    pipeline.Config{ProcessorID: s.processorID, DedupeWindow: s.dedupeWindow},
	}
	if err := osClient.Ping(ctx); err != nil {
		log.Warn("opensearch not reachable yet; batches will retry", "error", err)
	}
	health.SetReady(true)
	log.Info("processor started", "brokers", s.brokers, "group", s.group, "topics", s.topics)
	err = p.Run(ctx, beatingSource{Source: src, health: health})
	if ctx.Err() != nil {
		log.Info("processor stopping")
		return nil
	}
	return err
}
