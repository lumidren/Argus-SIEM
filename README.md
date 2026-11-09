# Argus

Argus is a multi-tenant SIEM. Collectors ship logs from hosts, network sensors, cloud audit
trails and identity providers onto a Kafka-protocol bus. Go stream processors normalize every
record to the Elastic Common Schema (ECS), enrich it, deduplicate it and index it in OpenSearch.
A detection engine, case management with response playbooks, and a Next.js analyst application
sit on top.

> **Status: work in progress.** The ingestion layer (parsers, pipeline, agent, chaos test) and the
> analyst web application are built and tested. The search API, the detection engine and the other
> back-end services are not built yet. Until they exist, the web app runs on a built-in demo tenant.
> See [Project status](#project-status) for exactly what exists.

## Try it in five minutes

You need Node.js 20 or newer for the web app, and Go 1.25 or newer for the back end. No Docker is
needed for either.

### Analyst web app (demo tenant)

```bash
npm --prefix web ci
```

```bash
npm --prefix web run dev
```

Open <http://localhost:3000>. The app serves a seeded demo tenant that includes the scripted attack
from the project brief:

1. An external address guesses the password of the `svc_backup` service account 18 times.
2. The 19th attempt succeeds.
3. The account then moves across `app01`, `fs01` and `dc01`, opening their `ADMIN$` share, and
   installs a service on the domain controller.
4. Five correlated detections fire and are grouped into incident **INC-1042**.
5. The *Enrich incident entities* playbook has already run on it.

Things to try:

- **Overview:** open incidents, riskiest entities and alert trends.
- **Search** for `argus.scenario:bruteforce-lateral`. Click any field value to filter for it or
  exclude it, or jump to the user, host or IP it belongs to.
- **Incidents → INC-1042:** the full timeline. Add notes, change status or assignee, and dry-run or
  run playbooks. Destructive steps stop and wait for a second approver.
- **Alerts:** triage one alert or several at once, and close them as true positive, benign true
  positive or false positive.
- **Rules:** see each rule's YAML definition, run the test runner against a pasted event, and read
  the tuning suggestions built from false-positive closures.
- **ATT&CK coverage:** a heat-map of rule coverage per technique.
- **Threat intel, Sources, Administration:** feeds and indicators, source health with parse
  errors, and tenants, SSO, roles and the hash-chained audit log.

To point the app at a running `argus-api` instead of the demo data, set `ARGUS_API_URL` (see
`web/.env.example`). The API routes then proxy every request.

### Back end

```bash
go test ./...
```

```bash
go build -o bin/ ./cmd/...
```

`go test ./...` runs every parser test and the pipeline tests. It also runs the chaos tests, which
kill the processor mid-stream (100,000 events on an in-memory log, 20,000 over the Kafka protocol)
and check that nothing is lost or indexed twice. The Kafka tests use franz-go's in-process broker,
so no external services are required.

`argus-processor` expects Kafka (or Redpanda) and OpenSearch. Configuration is read from `ARGUS_*`
environment variables, which are documented at the top of `cmd/argus-processor/main.go`.
`argus-agent` reads a YAML file; validate one with:

```bash
bin/argus-agent -config deploy/agent/agent.example.yaml -check
```

## What is in the box

| Area | What exists |
|---|---|
| Parsers | 17 sources: Windows Security, Sysmon and other channels (XML and JSON), Linux auth, auditd and journald, Zeek, Suricata EVE, Nginx, Apache, AWS CloudTrail, Azure sign-in/audit/activity, GCP audit, Okta, Office 365, Google Workspace, PAN-OS, FortiGate, osquery, Kubernetes audit, and a generic JSON/CEF/LEEF/syslog fallback. Each has table-driven tests, a fuzz target and a seed corpus, except the Windows parser, which has no tests yet. |
| Pipeline | Envelope format, a parser registry that sniffs formats and recovers from panics, GeoIP/ASN enrichment, dedupe that marks an event only after it is durably written, an idempotent OpenSearch bulk sink, a Kafka source and producer, and Prometheus metrics. |
| Collectors | `argus-agent`: disk write-ahead log, file tailing with checkpoints that survive rotation and truncation, syslog over UDP, TCP and TLS with a sender allow-list, and Windows Event Log subscriptions with bookmarks. Vector and Fluent Bit configs that produce the same envelope. |
| Web app | Next.js 15, strict TypeScript, Tailwind 4. Search, dashboards and a panel builder, alert queue, incident workspace, entity pages, rules with a test runner, ATT&CK heat-map, playbook editor and runner, threat intel, source health and administration. Light and dark themes, keyboard navigation and a strict content security policy. |
| Docs | [Architecture](docs/ARCHITECTURE.md) with C4 and data-flow diagrams, the [ECS mapping per source](docs/SCHEMA.md), the [threat model](docs/THREAT_MODEL.md), and [architecture decision records](docs/adr/). |

## Project status

The build follows the eleven phases of the project brief.

| Phase | State |
|---|---|
| 1. Threat model, architecture, schema | Done |
| 2. Ingestion, parsers, chaos test | Done, except PII masking and asset/identity enrichment |
| 3. Storage, ILM, search API | Not started (the OpenSearch bulk sink exists) |
| 4. Detection engine, Sigma import, rule tests | Not started |
| 5. UEBA and built-in detections | Not started |
| 6. Alerting, case management, playbooks | Not started on the back end; built in the web app against demo data |
| 7. Threat intel | Not started on the back end; built in the web app against demo data |
| 8. Analyst web app | Built against demo data; Lighthouse and automated accessibility audits not yet run |
| 9. Multi-tenancy, RBAC, SSO | Designed in the threat model; not implemented |
| 10. Infrastructure, CI/CD, observability | Not started (no Compose file, Helm chart, Terraform or CI yet) |
| 11. Load test, DR, paper | Not started |

Known gaps in the finished phases:

- The Windows parser and the GeoIP enricher have no unit tests.
- Combined Go test coverage is about 73%, short of the 90% target.
- The Go race detector needs cgo and has not been run yet; it will run in CI once Phase 10 adds it.

## Repository layout

```text
cmd/           service entry points (argus-agent, argus-processor)
internal/      Go packages: schema, parsers, syslog, pipeline, enrich, store, agent, config, telemetry
web/           Next.js analyst application
deploy/        agent example config, Vector and Fluent Bit configs
docs/          architecture, schema, threat model, decision records
test/          chaos tests and fuzz corpora
```

## Development

| Task | Command |
|---|---|
| Go tests with coverage | `go test ./... -cover` |
| Fuzz one parser | `go test ./internal/parsers/zeek -run x -fuzz FuzzParse -fuzztime 60s` |
| Web unit tests | `npm --prefix web test` |
| Web type-check and lint | `npm --prefix web run typecheck` then `npm --prefix web run lint` |
| Web production build | `npm --prefix web run build` |

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability, and the
[threat model](docs/THREAT_MODEL.md) for the design of the SIEM's own defenses.

## License

Apache License 2.0. See [LICENSE](LICENSE).

Built by [lumidren](https://github.com/lumidren).
