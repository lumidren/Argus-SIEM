# ADR-0003: Kafka-protocol message bus (Redpanda locally, MSK in AWS) with Go stream processors

- Status: Accepted
- Date: 2026-11-03

## Context

The pipeline must absorb ≥ 50,000 events/sec sustained with bursts, survive processor crashes
without loss, give back-pressure to collectors, and let independent consumers (indexing,
detection, threat-intel matching, metrics) read the same normalized stream. Processing options
were Apache Flink and a purpose-built Go service.

## Decision

- **Bus**: Kafka protocol. Redpanda in docker-compose and self-hosted Kubernetes (single
  binary, no ZooKeeper, low memory floor); Amazon MSK in the Terraform stack. The code depends
  only on the Kafka protocol (franz-go client).
- **Processors**: Go services (`cmd/argus-processor`, `cmd/argus-detect`) using franz-go
  consumer groups with manual offset commits.

## Topics

| Topic | Key | Producer | Consumers | Retention |
|---|---|---|---|---|
| `argus.raw.<source>` | `tenant/host` | agents, Vector, API `/ingest` | processor | 24 h (replay window) |
| `argus.events` | `tenant/entity` | processor | indexer sink, detect, TI matcher, metrics | 24 h |
| `argus.events.unparsed` | `tenant/source` | processor | indexer sink (unparsed index), source-health | 7 d |
| `argus.alerts` | `tenant/rule` | detect | API alert manager | 7 d |
| `argus.audit` | `tenant` | all services | audit sink (hash chain anchor) | compact + 30 d |
| `argus.ti.sightings` | `tenant/indicator` | detect, processor | API TI service | 7 d |

Partitioning `argus.events` by `tenant/entity` (the primary user or host of the event) gives
stateful correlation rules partition-local state: all events for a given entity land on the same
detect instance, so sequence and threshold rules do not need distributed coordination for the
common case; Redis is used only for cross-entity rules (for example lateral movement chains).

## Why Go rather than Flink

Flink gives exactly-once state and event-time windows out of the box, and we would pick it for a
team already running it. We chose Go because:

1. The parsers, the Sigma AST evaluator, the enrichers and the agent share one language and one
   test harness; a Flink job would have forced a JVM re-implementation of the matchers or a
   slow sidecar hop.
2. Deployment footprint: one static binary per service, no JobManager/TaskManager cluster, HPA
   on Kafka consumer lag is trivial.
3. Correctness goals are achievable without Flink: at-least-once consumption + idempotent
   writes keyed by content hash yields exactly-once-*effective* output (ADR-0004); window state
   lives in Redis/RocksDB with explicit bounds.

The trade-off is that we own windowing, watermarks, and state TTLs. Those live in
`internal/detect/state` and are tested directly, including the chaos test that kills a
processor mid-stream.

## Back-pressure

- Collectors buffer on disk (agent WAL, Vector disk buffer) and retry with jitter when the broker
  rejects writes; the API `/ingest` endpoint returns `429` with `Retry-After` when its producer
  buffer is full.
- Processors use franz-go's bounded fetch (`FetchMaxBytes`, `MaxConcurrentFetches`) and pause
  partitions when the downstream bulk indexer queue is full; consumer lag is the HPA signal.
- The indexer sink uses OpenSearch `_bulk` with adaptive batch sizing and honours `429` from
  OpenSearch by halving batch size and backing off.
