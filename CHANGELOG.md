# Changelog

All notable changes to Argus are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Phase 1: architecture decision records (ECS schema, OpenSearch storage, Kafka-protocol bus with
  Go processors, exactly-once-effective delivery, detection engine design).
- Phase 1: `docs/ARCHITECTURE.md` with C4 context/container/component views, end-to-end data
  flow, tenant isolation and deployment views.
- Phase 1: `docs/SCHEMA.md` — ECS 8.11 field contract and per-source mapping tables for Windows
  Security/Sysmon, Linux auth/auditd/journald, Zeek, Suricata EVE, Nginx/Apache, AWS CloudTrail,
  Azure sign-in/audit/activity, GCP audit, Okta, Office 365, Google Workspace, PAN-OS, FortiGate,
  osquery, Kubernetes audit, and generic JSON/CEF/LEEF/syslog.
- Phase 1: `docs/THREAT_MODEL.md` — STRIDE threat catalogue with mitigations and code locations;
  `SECURITY.md`.
- Phase 2: ECS event model (`internal/schema`), parser registry with sniffing and panic recovery, and
  parsers for Windows XML/JSON, Linux auth/auditd/journald, Zeek, Suricata EVE, Nginx, Apache, AWS
  CloudTrail, Azure, GCP, Okta, Office 365, Google Workspace, PAN-OS, FortiGate, osquery, Kubernetes
  audit, and generic JSON/CEF/LEEF/syslog. Fuzz targets and seed corpora for every parser.
- Phase 2: processing pipeline with envelope format, dedupe that marks events only after durable
  writes, Kafka source/producer (franz-go), OpenSearch bulk sink, GeoIP/ASN enricher, metrics and the
  `argus-processor` service.
- Phase 2: `argus-agent` with disk WAL, file tailing with checkpoints and rotation handling, syslog
  over UDP/TCP/TLS with an allow-list, Windows Event Log subscriptions with bookmarks, and Vector /
  Fluent Bit configs.
- Phase 2: chaos tests that kill the processor mid-stream (100,000 events on the in-memory log,
  20,000 over the Kafka protocol) and verify no loss.
- Phase 8 (ahead of order): Next.js 15 analyst application with search, dashboards and a panel
  builder, alert queue, incident workspace, entity pages, rules with a test runner, ATT&CK coverage
  heat-map, playbook editor and runner, threat intel, source health and administration. Runs on a
  seeded demo tenant until argus-api exists, and proxies to argus-api when `ARGUS_API_URL` is set.

### Fixed
- Kafka source no longer hangs on close mid-batch and no longer drops records already polled when
  the fetch context expires.
- Records no parser recognises now carry tenant and parse-status fields.
