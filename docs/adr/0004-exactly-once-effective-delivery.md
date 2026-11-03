# ADR-0004: Exactly-once-effective delivery via at-least-once transport and idempotent sinks

- Status: Accepted
- Date: 2026-11-03

## Problem

Every hop (agent → broker → processor → OpenSearch / detection) can fail after a message was
sent but before its acknowledgement was recorded. Retrying is mandatory to avoid loss, so
duplicates are inevitable at the transport level. Analysts must nevertheless see each real
event once, and detection counters must not double-count.

## Decision

Argus guarantees **at-least-once** delivery at every hop and makes every sink **idempotent**
on a deterministic **event hash**, so the observable result is exactly-once.

### Event hash (`event.hash`)

```
event.hash = sha256(
    argus.tenant.id      || 0x1F ||
    argus.source.id      || 0x1F ||
    canonical(raw bytes) || 0x1F ||
    collector-side sequence (file offset / record id / cloud event id when present)
)
```

- `canonical(raw bytes)` is the raw payload with trailing whitespace trimmed. For sources with a
  provider-side unique id (CloudTrail `eventID`, Windows `EventRecordID` + `Computer`, Okta
  `uuid`, O365 `Id`, GCP `insertId`, Kubernetes audit `auditID`, Zeek `uid`+`ts`+log type) the
  id is included so a legitimately repeated identical payload (same syslog line at a later
  time) is not swallowed when the source itself disambiguates it.
- For sources with no id (plain syslog, access logs) the hash is paired with a **dedupe window**
  (default 120 s, configurable per source): identical lines within the window are duplicates;
  identical lines outside it are distinct events. The window bounds memory.

### Where idempotency is enforced

| Hop | Mechanism |
|---|---|
| Agent → broker | WAL with per-record ack; records are re-sent after crash. Duplicate production is possible and accepted. |
| Processor dedupe | `SET NX PX <window>` on `dedupe:{tenant}:{hash}` in Redis (or in-memory LRU when Redis is disabled). First writer wins; duplicates increment `argus_pipeline_duplicates_total` and are dropped. |
| Processor → OpenSearch | Bulk `create` op with `_id = event.hash`; `409 version_conflict` is counted as a duplicate, not an error. |
| Processor → `argus.events` | Kafka producer with `idempotent=true`, acks=all. Consumer offsets are committed only after the OpenSearch bulk response and the `argus.events` produce ack are both received. |
| Detection state | Stateful rules record the set of `event.hash` values that advanced a window (bounded ring per window); a replayed event that is already in the window is ignored. |
| Alerts | `alert.dedupe_key = sha256(tenant, rule.id, entity, window_start)`; Postgres `INSERT ... ON CONFLICT DO NOTHING`. |

### Ordering and commit discipline

The processor's loop per partition is:

1. Fetch a batch.
2. Parse/normalize/enrich; compute hashes; dedupe.
3. Issue OpenSearch bulk and `argus.events` produce concurrently.
4. Wait for both acknowledgements. On partial bulk failure (`429`, `503`) retry the failed
   items with back-off; on permanent item failure (mapping exception) route to
   `argus.events.unparsed` with `argus.pipeline.parse_status=sink_rejected`.
5. Commit the batch's offsets.

A crash between step 3 and step 5 replays the batch; step 2 and step 3 are idempotent, so the
result is unchanged.

## Verification

- `internal/pipeline/dedupe_test.go` covers window semantics and id-bearing sources.
- `test/chaos/processor_kill_test.go` (integration tag) produces 100,000 events with known
  hashes, SIGKILLs the processor three times at random points, restarts it, and asserts:
  distinct `_id` count in OpenSearch == 100,000, `argus.events` distinct hashes == 100,000, and
  no event is missing. It runs in CI against Redpanda + OpenSearch service containers.
- `argus_pipeline_duplicates_total` and `argus_sink_conflicts_total` are exported so that a
  duplicate storm (a looping collector) is visible on the source-health dashboard.
