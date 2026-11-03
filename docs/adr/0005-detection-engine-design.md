# ADR-0005: Detection engine — compiled Sigma AST, partition-local state, three evaluation modes

- Status: Accepted
- Date: 2026-11-03

## Rule kinds

| Kind | Example | Evaluation |
|---|---|---|
| `sigma` (stateless) | SigmaHQ rule, or an Argus rule written in Sigma syntax | Streaming, per event |
| `threshold` | ≥ 10 failed logons from one IP in 5 min | Streaming, windowed counter keyed by entity |
| `sequence` | failed-logon burst → successful logon → new admin share within 30 min, same user | Streaming, per-entity state machine |
| `aggregation` | rare parent/child process, first-seen user↔host, spike vs rolling baseline | Streaming, sketches + baselines |
| `scheduled` | OpenSearch DSL / KQL run every N minutes | Scheduled, query against hot tier |
| `ueba` | impossible travel, lateral movement chain, privilege-escalation sequence | Streaming, built on sequence + baselines |

## Sigma compilation path

```
SigmaHQ YAML ──pySigma──▶ processing pipeline (field mapping to ECS, per logsource)
            ──Argus backend──▶ rules/compiled/*.json   (boolean AST over ECS fields)
            ──OpenSearch backend──▶ DSL for retro-hunt / scheduled mode
```

`tools/sigma/argus_backend.py` is a pySigma `TextQueryBackend` subclass that emits a JSON AST
instead of a query string: nodes are `and`/`or`/`not`, field comparisons with Sigma modifiers
(`contains`, `startswith`, `endswith`, `re`, `cidr`, `base64offset`, `windash`, `all`, `lt/gt`,
`fieldref`, `exists`), and `null`. Unsupported constructs (aggregations in the deprecated
`count()` form, `near`) are reported and the rule is marked `unsupported` with the reason; the
compile report commits those counts.

The Go evaluator (`internal/detect/sigma`) compiles each AST once into closures over a flat
event map. Rules are indexed by **logsource selector** (`event.category`, `event.module`,
`event.dataset`, `winlog.channel`, `event.code`) so each event is tested only against the rule
subset whose logsource can match — typically 1–5 % of the corpus.

## Stateful evaluation

- Events for one entity (`argus.entity.key` = tenant + primary user or host) are partition-local
  (ADR-0003). Window state is kept in a per-partition **RocksDB-style embedded store**
  (`internal/detect/state/local`, backed by Pebble) with TTL compaction, and mirrored to **Redis**
  for rules declared `scope: global` (cross-host chains). Both implement one `State` interface;
  tests run against the in-memory implementation.
- Memory bounds: each window has a max cardinality (`max_keys`, default 100k per rule per
  partition) and a max per-key element count; eviction is LRU with a `argus_detect_state_evictions_total`
  counter so bounded memory never silently becomes silent misses.
- Watermarks: event time is `@timestamp`; allowed lateness is per rule (default 5 min);
  late events are evaluated but cannot re-open closed windows. Processing-time fallback is used
  when `@timestamp` is absent or implausible (> 24 h skew), and the event is tagged
  `argus.pipeline.time_source=processing`.

## Latency measurement

Every alert carries `argus.detection.latency_ms = alert.created_at − argus.pipeline.received_at`
(received_at is stamped by the first Argus component that touched the event). The engine
exports a Prometheus histogram and the load-test harness commits p50/p95/p99 to
`test/load/results/`.

## Rule lifecycle

- Rules are files under `rules/` (YAML), versioned in Git. Each rule has `id` (UUID), `version`,
  `status` (`experimental` → `staging` → `production` → `deprecated`), `severity`, ATT&CK tags,
  `falsepositives`, `response` guidance, and a `tests:` block with true-positive and
  true-negative sample events.
- `argus-rules test` runs all rule tests; CI fails on any mismatch. `staging` rules evaluate in
  the engine and record matches in `argus.alerts` with `alert.suppressed=true` (visible in the
  rule's tuning view, no notifications, no incidents).
- Analyst false-positive feedback on alerts is aggregated per rule and field value; the API
  proposes tuning suggestions (exclusion filters for the top recurring FP values) that an
  engineer can accept, producing a new rule version with a `filter` selection.
- ATT&CK coverage is computed from rule tags against the bundled ATT&CK Enterprise matrix
  (`rules/attack/enterprise-attack-techniques.json`) and rendered as a heat-map in the UI and
  in `docs/DETECTIONS.md`.
