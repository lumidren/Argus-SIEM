# Argus Architecture

Argus is a multi-tenant SIEM: collectors ship logs to a Kafka-protocol bus, Go stream
processors normalize them to ECS, enrich them, deduplicate them and write them to OpenSearch;
a streaming detection engine evaluates Sigma, threshold, sequence, anomaly and UEBA rules with
partition-local state; alerts are grouped into incidents and handled through a SOC case
workflow with notifications and YAML playbooks; a Next.js analyst application sits on a Go API.

Design decisions with their alternatives are recorded in [`docs/adr/`](adr/). This document
describes the system as built.

---

## 1. C4 Level 1 — System context

```mermaid
C4Context
    title Argus — system context
    Person(analyst, "SOC analyst / detection engineer", "Triages alerts, hunts, tunes rules")
    Person(admin, "Tenant / platform admin", "Manages tenants, sources, RBAC, SSO")
    System(argus, "Argus SIEM", "Ingest, normalize, detect, respond, search")
    System_Ext(hosts, "Endpoints & servers", "Windows Event Log, auditd, journald, files")
    System_Ext(net, "Network sensors & firewalls", "Zeek, Suricata, PAN-OS, FortiGate (syslog)")
    System_Ext(cloud, "Cloud & SaaS audit APIs", "CloudTrail (S3/SQS), Azure Event Hub, GCP Pub/Sub, Okta, O365, Google Workspace, Kubernetes audit webhook")
    System_Ext(ti, "Threat-intel providers", "MISP, AlienVault OTX, abuse.ch, STIX/TAXII 2.1")
    System_Ext(idp, "Identity provider", "OIDC SSO for analysts")
    System_Ext(resp, "Response targets", "EDR (Defender for Endpoint), IdP (Okta), Firewall (PAN-OS)")
    System_Ext(notify, "Notification channels", "Email, Slack, Teams, PagerDuty, Opsgenie, webhooks")
    Rel(hosts, argus, "argus-agent / Vector → Kafka or HTTPS /ingest")
    Rel(net, argus, "Syslog UDP/TCP/TLS, EVE JSON, Zeek JSON")
    Rel(argus, cloud, "Pulls audit logs")
    Rel(argus, ti, "Pulls indicators; pushes sightings (MISP)")
    Rel(analyst, argus, "HTTPS, WebSocket")
    Rel(admin, argus, "HTTPS")
    Rel(argus, idp, "OIDC authorization code + PKCE")
    Rel(argus, resp, "Playbook adapters (dry-run, approval-gated)")
    Rel(argus, notify, "Alert / incident notifications")
```

## 2. C4 Level 2 — Containers

```mermaid
flowchart LR
    subgraph Collection
        AG[argus-agent<br/>Go · WAL-buffered]
        VEC[Vector / Fluent Bit<br/>config shipped]
        PULL[argus-puller<br/>CloudTrail S3+SQS · Azure · GCP · Okta · O365 · GWS]
        ING[API /ingest<br/>HTTPS, mTLS/API-key]
    end
    subgraph Bus["Kafka protocol (Redpanda / MSK)"]
        RAW[(argus.raw.*)]
        EV[(argus.events)]
        UNP[(argus.events.unparsed)]
        AL[(argus.alerts)]
        AUD[(argus.audit)]
    end
    subgraph Processing
        PROC[argus-processor<br/>parse · normalize · enrich · dedupe · sink]
        DET[argus-detect<br/>Sigma AST · threshold · sequence · anomaly · UEBA]
        SCHED[argus-detect scheduler<br/>scheduled queries · retro-hunt]
    end
    subgraph Storage
        OS[(OpenSearch<br/>hot → warm → cold snapshot)]
        PG[(PostgreSQL<br/>tenants · rules · alerts · incidents · cases · TI · audit chain)]
        RD[(Redis<br/>dedupe · global correlation state · rate limits)]
        S3[(Object storage<br/>snapshots · WORM · raw archive)]
    end
    subgraph Serving
        API[argus-api<br/>Go · REST + WebSocket · OIDC · RBAC · query planner · alert manager · playbooks · TI · notifications]
        WEB[argus-web<br/>Next.js 15 · TypeScript strict]
    end
    AG --> RAW
    VEC --> RAW
    PULL --> RAW
    ING --> RAW
    RAW --> PROC
    PROC --> EV
    PROC --> UNP
    PROC --> OS
    EV --> DET
    DET --> AL
    DET <--> RD
    PROC <--> RD
    SCHED --> OS
    SCHED --> AL
    AL --> API
    UNP --> OS
    API <--> PG
    API <--> OS
    API --> AUD
    PROC --> AUD
    DET --> AUD
    AUD --> OS
    OS --> S3
    WEB <--> API
```

### Container responsibilities

| Container | Binary / package | Scales on | State |
|---|---|---|---|
| Agent | `cmd/argus-agent` | per host | disk WAL + checkpoints under `--data-dir` |
| Puller | `cmd/argus-puller` | one per tenant/source (leader-elected via Postgres advisory lock) | cursor per source in Postgres |
| Processor | `cmd/argus-processor` | Kafka lag on `argus.raw.*` (HPA) | stateless except Redis dedupe keys |
| Detect | `cmd/argus-detect` | Kafka lag on `argus.events`; partitions ↔ instances | Pebble store per partition + Redis for global rules |
| API | `cmd/argus-api` | CPU / request latency | Postgres |
| Web | `web/` | CPU | none |
| OpenSearch | Helm StatefulSet / AWS OpenSearch Service | storage | ISM-managed indices |
| PostgreSQL | StatefulSet / RDS | storage | WAL-archived, PITR |
| Redis | StatefulSet / ElastiCache | memory | AOF everysec |

## 3. C4 Level 3 — Detection engine components

```mermaid
flowchart TB
    IN[Kafka consumer<br/>partition = tenant/entity] --> DEC[Decode ECS event<br/>flat map]
    DEC --> IDX[Logsource index<br/>category/module/dataset/channel/code → rule subset]
    IDX --> SIG[Sigma AST evaluator<br/>compiled closures]
    IDX --> THR[Threshold windows<br/>count / distinct-count by key]
    IDX --> SEQ[Sequence state machines<br/>A→B→C within T by entity]
    IDX --> AGG[Anomaly / aggregation<br/>first-seen sets · rolling baselines · rarity]
    IDX --> UEBA[UEBA<br/>entity baselines · risk decay · impossible travel · lateral movement]
    THR <--> ST[(State: Pebble local + Redis global<br/>TTL · bounded cardinality)]
    SEQ <--> ST
    AGG <--> ST
    UEBA <--> ST
    SIG --> OUT[Alert builder<br/>dedupe key · latency stamp · ATT&CK tags · entity · severity inputs]
    THR --> OUT
    SEQ --> OUT
    AGG --> OUT
    UEBA --> OUT
    OUT --> KAF[(argus.alerts)]
    OUT --> MET[Prometheus<br/>detection latency histogram · rule eval time · state size]
    RL[Rule loader<br/>Git-backed YAML + compiled Sigma JSON<br/>hot reload on version change] --> IDX
    SCH[Scheduler<br/>cron · OpenSearch DSL · retro-hunt] --> OUT
```

## 4. Data flow — one event, end to end

```mermaid
sequenceDiagram
    autonumber
    participant H as Windows host
    participant A as argus-agent
    participant K as Kafka (argus.raw.windows)
    participant P as argus-processor
    participant R as Redis
    participant O as OpenSearch
    participant E as Kafka (argus.events)
    participant D as argus-detect
    participant AL as Kafka (argus.alerts)
    participant API as argus-api
    participant W as argus-web
    H->>A: EvtSubscribe push (XML)
    A->>A: append to WAL, stamp received_at
    A->>K: produce (key tenant/host), ack → WAL mark
    K->>P: fetch batch
    P->>P: parse XML → winlog.* → ECS (4624 → authentication/start/success)
    P->>P: enrich: GeoIP/ASN on source.ip, asset criticality, identity, TI match, PII mask
    P->>P: event.hash = sha256(tenant,source,raw,record_id)
    P->>R: SET NX dedupe:{tenant}:{hash} PX 120000
    R-->>P: OK (first time)
    par sink
        P->>O: _bulk create _id=event.hash
        P->>E: produce normalized event (key tenant/entity)
    end
    O-->>P: 201 (or 409 = duplicate)
    E-->>P: ack
    P->>K: commit offsets
    E->>D: fetch (partition-local for user "alice")
    D->>D: logsource index → ~40 of 2,900 rules
    D->>D: threshold "≥10 failures/5m" + sequence "burst→success→new share"
    D->>AL: alert (dedupe_key, latency_ms, technique T1110)
    AL->>API: consume → group into incident (entity+technique+window) → severity → SLA
    API->>W: WebSocket push: incident created
    API->>API: run playbook "enrich-and-contain" (dry-run unless approved)
```

## 5. Tenant isolation

- Every event carries `argus.tenant.id`, assigned by the first Argus component to receive it from
  an authenticated channel: the agent's enrolment token, the API key / mTLS client certificate
  of `/ingest`, or the puller's source configuration. Collectors cannot set it themselves; the
  processor overwrites any inbound value.
- OpenSearch indices are per tenant (`argus-{tenant}-*`). The API's query planner forces an
  index pattern derived from the caller's tenant claim and rejects any explicit index in the
  request. The OpenSearch security plugin role per tenant is a second barrier, and document-level
  security on `argus.tenant.id` a third.
- PostgreSQL uses row-level security with `SET LOCAL argus.tenant_id` per transaction; every
  table that holds tenant data has a `tenant_id` column and an RLS policy.
- Redis keys and Kafka message keys are prefixed with the tenant id.
- Isolation is tested end to end in `test/integration/tenant_isolation_test.go`.

## 6. Deployment view

```mermaid
flowchart TB
    subgraph AWS["AWS (Terraform: deploy/terraform/aws)"]
        ALB[ALB + WAF] --> ING[Ingress-nginx]
        subgraph EKS["EKS (Helm: deploy/helm/argus)"]
            WEB[argus-web ×2]
            API[argus-api ×3  HPA]
            PROC[argus-processor HPA on Kafka lag]
            DET[argus-detect StatefulSet N = partitions/k]
            PULL[argus-puller]
            OTEL[OTel Collector]
        end
        MSK[(Amazon MSK)]
        OSS[(OpenSearch Service<br/>or self-managed StatefulSet)]
        RDS[(RDS PostgreSQL Multi-AZ)]
        EC[(ElastiCache Redis)]
        S3[(S3 + Object Lock)]
        KMS[KMS]
        CW[CloudWatch]
    end
    ING --> WEB
    ING --> API
    API --> RDS
    API --> OSS
    PROC --> MSK
    PROC --> OSS
    PROC --> EC
    DET --> MSK
    DET --> EC
    OSS --> S3
    RDS --> S3
    KMS -.encrypts.-> S3
    KMS -.encrypts.-> RDS
    KMS -.encrypts.-> OSS
    KMS -.encrypts.-> MSK
    OTEL --> CW
```

Local development uses `deploy/compose/docker-compose.yml` with Redpanda, OpenSearch,
PostgreSQL, Redis, all Argus services, Grafana/Prometheus/Tempo, and `argus-loadgen` producing
realistic multi-source traffic including the scripted brute-force → lateral-movement scenario.

## 7. Cross-cutting concerns

| Concern | Mechanism |
|---|---|
| Observability | OpenTelemetry traces propagate via Kafka headers (`traceparent`) from agent to alert; Prometheus metrics per service (`internal/telemetry`); Grafana dashboards in `deploy/grafana/dashboards/`; alert rules in `deploy/prometheus/rules/`. |
| Audit | Every privileged API action, rule change, playbook run and evidence operation writes an entry to the hash-chained `audit_log` table; the chain head is also published to `argus.audit` and anchored daily into object storage. |
| Secrets | Read from environment / mounted files only; the structured logger has a redaction hook for known secret field names and high-entropy strings; `test/security/log_secret_scan_test.go` runs every service with secrets set and scans captured logs. |
| PII | `internal/pii` detects email, phone, national-id and card patterns in configured fields and masks them at ingest when the tenant policy requires, storing the HMAC token for pivoting; `pii:unmask` permission reveals the clear value through the API. |
| Supply chain | Go modules with checksums, `npm ci` with lockfile, Semgrep + gosec + Bandit, Trivy, SBOM (Syft), cosign-signed images, CI fails on HIGH/CRITICAL. |

## 8. Repository layout

```
cmd/                  service entrypoints (agent, processor, detect, api, puller, loadgen, replay, rules)
internal/schema       ECS event model, flattening, versioning
internal/parsers      one package per source + registry + fuzz corpus
internal/syslog       RFC 3164/5424 framing and header parsing
internal/enrich       GeoIP, ASN, threat intel, asset/identity, risk, PII
internal/pipeline     Kafka I/O, dedupe, backpressure, OpenSearch sink
internal/store        OpenSearch client, index templates, ISM, snapshots, legal hold
internal/search       KQL parser → OpenSearch DSL, query planner, limits
internal/detect       rule model, Sigma evaluator, stateful engines, scheduler, state stores
internal/ueba         baselines, risk scoring, built-in behavioural detections
internal/alerting     grouping, severity, SLA
internal/cases        case management
internal/notify       channels and escalation policies
internal/playbook     YAML playbooks, runner, adapters (real + mock)
internal/ti           feeds, STIX/TAXII, IOC store, matching, sightings
internal/auth         OIDC, RBAC, tenant resolution
internal/audit        hash-chained audit log
internal/api          HTTP handlers, WebSocket hub
rules/                detection content (Argus YAML, Sigma import tooling output, tests, ATT&CK data)
tools/sigma           pySigma Argus backend, processing pipelines, compile and report scripts
web/                  Next.js analyst application
deploy/               Dockerfiles, compose, Helm, k8s, Terraform, Grafana, Prometheus, Vector, Fluent Bit
test/                 integration, chaos, load, fuzz, dataset validation
docs/                 this document, ADRs, schema, threat model, runbooks, paper
```
