// Domain types shared by the UI and the data layer. They mirror the
// argus-api resources (docs/ARCHITECTURE.md) and ECS field names
// (docs/SCHEMA.md).

export type Severity = "low" | "medium" | "high" | "critical";
export const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

export type Role = "admin" | "engineer" | "analyst" | "viewer";

/** A normalized event: flat dotted ECS keys. */
export type EventDoc = {
  id: string; // event.hash
  "@timestamp": string;
  [field: string]: string | number | boolean | string[] | undefined;
};

export type AlertStatus = "open" | "acknowledged" | "in_progress" | "closed";

export type EntityRef = { kind: "user" | "host" | "ip"; id: string };

export type Alert = {
  id: string;
  tenant: string;
  ruleId: string;
  ruleName: string;
  ruleKind: RuleKind;
  severity: Severity;
  score: number; // 0-100 combined score
  status: AlertStatus;
  createdAt: string;
  entity: EntityRef;
  entities: EntityRef[];
  tactics: string[];
  techniques: string[];
  incidentId?: string;
  dataset: string;
  evidence: string[]; // event ids
  latencyMs: number;
  summary: string;
  closure?: Closure;
};

export type Closure = "true_positive" | "false_positive" | "benign_true_positive";

export type IncidentStatus = "new" | "triage" | "investigating" | "contained" | "resolved" | "closed";
export const INCIDENT_STATUSES: IncidentStatus[] = ["new", "triage", "investigating", "contained", "resolved", "closed"];

export type TimelineEntry = {
  at: string;
  kind: "alert" | "event" | "note" | "status" | "playbook" | "evidence" | "assignment";
  actor: string;
  text: string;
  ref?: string;
};

export type Note = { id: string; at: string; author: string; text: string };

export type Evidence = { id: string; name: string; sha256: string; size: number; addedBy: string; at: string };

export type Incident = {
  id: string;
  tenant: string;
  title: string;
  severity: Severity;
  score: number;
  status: IncidentStatus;
  assignee: string | null;
  createdAt: string;
  updatedAt: string;
  slaDueAt: string;
  alertIds: string[];
  entities: EntityRef[];
  tactics: string[];
  techniques: string[];
  timeline: TimelineEntry[];
  notes: Note[];
  evidence: Evidence[];
  tags: string[];
  closure?: Closure;
};

export type RuleKind = "sigma" | "threshold" | "sequence" | "aggregation" | "scheduled" | "ueba";
export type RuleStatus = "experimental" | "staging" | "production" | "deprecated";

export type RuleTest = { name: string; kind: "true_positive" | "true_negative"; passed: boolean };

export type Rule = {
  id: string;
  name: string;
  kind: RuleKind;
  status: RuleStatus;
  severity: Severity;
  version: number;
  description: string;
  tactics: string[];
  techniques: string[];
  logsource: string;
  definition: string; // YAML as stored in Git
  falsePositives: string[];
  response: string;
  tests: RuleTest[];
  alerts7d: number;
  fpRate: number; // 0..1 from analyst feedback
  updatedAt: string;
  author: string;
};

export type EntityProfile = {
  ref: EntityRef;
  displayName: string;
  risk: number;
  riskHistory: { at: string; value: number }[];
  firstSeen: string;
  lastSeen: string;
  attributes: Record<string, string>;
  peers: EntityRef[];
};

export type PlaybookStep = {
  id: string;
  name: string;
  action: string; // enrich_ioc, isolate_host, disable_user, block_ip, notify, create_ticket
  adapter: string;
  destructive: boolean;
  requiresApproval: boolean;
  params: Record<string, string>;
};

export type PlaybookRunStatus = "succeeded" | "failed" | "awaiting_approval" | "running" | "dry_run";

export type PlaybookRun = {
  id: string;
  playbookId: string;
  incidentId?: string;
  startedAt: string;
  status: PlaybookRunStatus;
  dryRun: boolean;
  triggeredBy: string;
  steps: { stepId: string; status: "ok" | "skipped" | "failed" | "pending_approval"; output: string }[];
};

export type Playbook = {
  id: string;
  name: string;
  description: string;
  version: number;
  enabled: boolean;
  trigger: string;
  steps: PlaybookStep[];
  yaml: string;
  updatedAt: string;
};

export type IndicatorType = "ipv4" | "domain" | "url" | "sha256" | "md5" | "email";

export type Indicator = {
  id: string;
  type: IndicatorType;
  value: string;
  provider: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  expiresAt: string;
  sightings: number;
  tags: string[];
  tlp: "clear" | "green" | "amber" | "red";
};

export type Feed = { id: string; name: string; kind: "misp" | "taxii" | "otx" | "abuse_ch" | "csv"; indicators: number; lastPull: string; status: "ok" | "error"; error?: string };

export type SourceHealth = "healthy" | "degraded" | "silent";

export type Source = {
  id: string;
  name: string;
  kind: string;
  dataset: string;
  status: SourceHealth;
  eps: number;
  parseFailureRate: number;
  lastEventAt: string;
  lagSeconds: number;
  eventsToday: number;
  collector: string;
};

export type ParseError = { at: string; sourceId: string; parser: string; error: string; sample: string };

export type Tenant = { id: string; name: string; plan: string; retentionDays: number; eventsPerDay: number; users: number; worm: boolean };

export type User = { id: string; name: string; email: string; role: Role; tenant: string; lastLogin: string; mfa: boolean; sso: boolean };

export type AuditEntry = { seq: number; at: string; actor: string; action: string; target: string; hash: string; prevHash: string };

export type SearchResult = {
  total: number;
  tookMs: number;
  events: EventDoc[];
  histogram: { at: string; count: number }[];
  fields: { name: string; count: number; top: { value: string; count: number }[] }[];
  error?: string;
};

export type DashboardPanel =
  | { kind: "stat"; title: string; value: string; delta?: string; tone?: "good" | "bad" | "neutral" }
  | { kind: "series"; title: string; points: { at: string; value: number }[] }
  | { kind: "bars"; title: string; rows: { label: string; value: number }[] }
  | { kind: "table"; title: string; columns: string[]; rows: string[][] };

export type Dashboard = { id: string; title: string; description: string; category: string; panels: DashboardPanel[] };
