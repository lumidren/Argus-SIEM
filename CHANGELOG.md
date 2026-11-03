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
