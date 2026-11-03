# ADR-0002: OpenSearch as the hot/warm search tier

- Status: Accepted
- Date: 2026-11-03

## Context

The hot tier must serve three very different workloads: full-text and wildcard search over
semi-structured security events, high-cardinality aggregations for dashboards and UEBA
baselines, and Sigma-compiled detection queries for scheduled rules and retro-hunts. It must
support tiering (NVMe → warm → object storage) with per-tenant and per-source retention, WORM /
legal hold, encryption, and tenant isolation. Candidates: OpenSearch 2.x and ClickHouse.

## Decision

**OpenSearch 2.19** is the hot and warm tier, with Index State Management (ISM) policies for
rollover and tiering, searchable snapshots on S3-compatible object storage for the cold tier,
and the OpenSearch Security plugin for TLS, field-level security and document-level security.

## Rationale

| Requirement | OpenSearch | ClickHouse |
|---|---|---|
| KQL / Lucene query path required by the brief | Native (`query_string`, DQL grammar maps 1:1) | Would require writing a KQL→SQL compiler and emulating analyzers |
| Sigma compile target | First-party `pysigma-backend-opensearch` | Community `pysigma-backend-sqlite`/ClickHouse backends are partial (no `re`, limited modifiers) |
| Wildcard / substring on `process.command_line` | Inverted index + `wildcard` field type | Full scan or token bloom filters, tuneable but costly |
| Tiering | ISM: hot → warm (replica shrink, force-merge) → cold (searchable snapshot) → delete | Storage policies with volumes; cold tier via S3 disks but not "searchable snapshot" semantics |
| Multi-tenant isolation | Index-per-tenant naming plus security plugin role → index pattern; DLS as defence in depth | Row policies; one shared table makes noisy-neighbour control harder |
| WORM / legal hold | Index block `write: true` + snapshot to S3 Object Lock bucket | S3 Object Lock on parts; no index-level immutability primitive |
| Aggregations at scale | Adequate; cardinality via HyperLogLog++; slower than ClickHouse on wide scans | Clearly superior |
| Operational familiarity in SOCs | Very high (Elastic SIEM, Wazuh, Graylog all use it) | Growing |

ClickHouse wins on cost-per-TB and on analytical throughput, and we expect it would halve
storage for a pure "long-term archive + aggregation" workload. It loses on the two hard
requirements of the brief: a Kibana-compatible query language and a Sigma compile path with
full modifier coverage. Building those ourselves would be a larger risk than the storage cost.

## Mitigations for OpenSearch's weaknesses

- **Expensive wildcards**: the query planner (`internal/search/planner`) rewrites leading
  wildcards onto `wildcard`-typed fields, converts `*foo*` on `keyword` fields to `wildcard`
  queries, refuses unbounded regexps, and enforces per-tenant time and size limits
  (ADR-0005).
- **Aggregation cost for UEBA**: baselines are computed incrementally in the streaming engine
  (Redis) rather than by scanning OpenSearch; OpenSearch is only used for retro-hunt and ad-hoc
  analytics.
- **Heap pressure**: `event.original` is stored but not indexed; `index.codec: zstd_no_dict`;
  `index.mapping.total_fields.limit` is capped and unmapped keys live under a `flattened`
  (`flat_object`) field.

## Consequences

- Index naming: `argus-{tenant}-{dataset}-{yyyy.MM.dd}-{nnnnnn}` behind write alias
  `argus-{tenant}-{dataset}-write`. Dataset is the ECS `event.dataset` family (for example
  `windows`, `linux`, `network`, `cloud`, `identity`, `web`, `generic`).
- ISM policies are rendered per tenant and per dataset from `deploy/opensearch/ism/` templates
  by the API server when a tenant or source is created, so retention is configurable at both
  levels.
- The cold tier uses the `remote_snapshot` storage type (searchable snapshots) against an S3 /
  MinIO bucket with Object Lock enabled when WORM is on for the tenant.
