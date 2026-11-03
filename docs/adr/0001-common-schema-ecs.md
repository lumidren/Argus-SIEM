# ADR-0001: Elastic Common Schema (ECS) as the normalized event schema

- Status: Accepted
- Date: 2026-11-03
- Deciders: Argus core team

## Context

Argus ingests events from more than fifteen heterogeneous sources (Windows Security/Sysmon,
auditd, Zeek, Suricata, web servers, four cloud audit trails, three identity providers, two
firewall families, osquery, Kubernetes audit and generic fallbacks). Every downstream component
(detections, UEBA, search, dashboards, entity pages) needs one field vocabulary. Two mature
candidates exist: Elastic Common Schema (ECS, now donated to OpenTelemetry semantic conventions)
and the Open Cybersecurity Schema Framework (OCSF).

## Decision

Argus normalizes to **ECS 8.11** with a namespaced extension tree `argus.*` for fields ECS does
not define (tenant, pipeline provenance, entity risk, asset context, PII masking metadata) and
the de-facto standard `winlog.*` extension used by Winlogbeat and the Sigma community for raw
Windows event data.

## Rationale

1. **Detection content compiles natively.** The detection engine imports the SigmaHQ rule
   corpus through pySigma. pySigma's maintained processing pipelines (`ecs_windows`,
   `ecs_windows_old`, `sysmon`, `ecs_zeek_*`, `ecs_kubernetes`) target ECS field names. Choosing
   ECS lets ~3,000 community rules map onto our fields with first-party pipelines, and our own
   pipelines only have to cover the sources pySigma does not (cloud, identity, firewalls). With
   OCSF we would own every mapping and would be the sole consumer of them.
2. **Storage and query tooling assume it.** OpenSearch index templates, Kibana-style KQL
   autocomplete, and the Lucene/KQL search path (ADR-0002) all expect dotted ECS fields. The
   same field names flow from parser to index to rule to UI with no translation layer.
3. **Flat enough to evaluate in a hot loop.** ECS is a dotted-key vocabulary. Our streaming
   evaluator holds events as a flat `map[string]any` keyed by dotted path and does O(1) field
   lookups while matching thousands of rules per event. OCSF's deeply nested objects
   (`actor.process.file.hashes[]`) would require path walking or a flattening step that is
   itself a mapping.
4. **Reference mappings exist for every source we ship.** Elastic's integrations repository
   documents ECS mappings for CloudTrail, Azure, GCP, Okta, O365, Google Workspace, Palo Alto,
   Fortinet, Zeek, Suricata, osquery and Kubernetes audit. Our parser tests cross-check field
   choices against those published mappings so analysts migrating from Elastic SIEM find the
   same field names.

## Why not OCSF

OCSF has a stronger, class-based model for cloud and identity events and is the native format
of Amazon Security Lake. We considered it seriously and rejected it for v1 because:

- No maintained Sigma→OCSF pipeline exists for the Windows corpus, which is where most of the
  high-value community detections live.
- OCSF's `class_uid`/`activity_id` enumerations push normalization decisions into every parser
  and every rule; an unknown activity falls into `Other (99)` and loses specificity, whereas ECS
  degrades gracefully with free-text `event.action`.
- OCSF nesting costs more to flatten and to index than ECS.

An OCSF export mapping (ECS→OCSF for the classes we populate) is a tracked roadmap item so that
Argus can write to Security Lake; it does not change the internal model.

## Consequences

- `docs/SCHEMA.md` is the authority for the field subset we populate and the per-source mapping
  tables. Every parser carries a `schema_version` and emits `argus.schema.version`.
- Raw payloads are preserved in `event.original` (unindexed `keyword` with `index: false` and
  `doc_values: false` to save heap) so re-parsing is always possible.
- Unknown fields are never dropped: a parser that cannot map a key places it under
  `<module>.raw.<key>` (for example `okta.raw.debugContext`) so nothing is lost, and the
  unmapped-key count is exported as a metric per source so coverage can be tracked.
- The schema is versioned (`argus.schema.version`, currently `1`). Breaking field renames bump
  the version, ship a reindex script under `tools/schema/`, and keep the old alias readable for
  one release.
