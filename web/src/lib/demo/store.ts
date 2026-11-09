// In-memory demo store: answers every UI query and applies mutations for the
// lifetime of the server process. The same function signatures are served
// by argus-api when ARGUS_API_URL is configured (see src/lib/api.ts).
import "server-only";
import type { ChainEdge, ChainNode } from "@/components/charts";
import { evaluate, KQLError, parse } from "@/lib/kql";
import type {
  Alert,
  AlertStatus,
  Closure,
  Dashboard,
  DashboardPanel,
  EntityProfile,
  EntityRef,
  EventDoc,
  Incident,
  IncidentStatus,
  PlaybookRun,
  SearchResult,
} from "@/lib/types";
import { generate, type DemoData } from "./generate";

const g = globalThis as unknown as { __argusDemo?: DemoData };

export function data(): DemoData {
  if (!g.__argusDemo) {
    const now = Math.floor(Date.now() / 60_000) * 60_000;
    g.__argusDemo = generate(now);
  }
  return g.__argusDemo;
}

// ---- search ----

export type SearchParams = { q: string; from?: number; to?: number; size?: number; buckets?: number };

export function search({ q, from, to, size = 100, buckets = 48 }: SearchParams): SearchResult {
  const started = performance.now();
  const d = data();
  const end = to ?? d.now;
  const start = from ?? end - 24 * 3_600_000;
  let ast;
  try {
    ast = parse(q);
  } catch (e) {
    const msg = e instanceof KQLError ? `${e.message} (at character ${e.position + 1})` : String(e);
    return { total: 0, tookMs: 0, events: [], histogram: [], fields: [], error: msg };
  }
  const hits: EventDoc[] = [];
  for (const e of d.events) {
    const t = Date.parse(e["@timestamp"]);
    if (t < start || t > end) continue;
    if (evaluate(ast, e)) hits.push(e);
  }
  const width = (end - start) / buckets;
  const histogram = Array.from({ length: buckets }, (_, i) => ({ at: new Date(start + i * width).toISOString(), count: 0 }));
  for (const e of hits) {
    const i = Math.min(buckets - 1, Math.floor((Date.parse(e["@timestamp"]) - start) / width));
    histogram[i]!.count++;
  }
  const counts = new Map<string, Map<string, number>>();
  for (const e of hits.slice(0, 2000)) {
    for (const [k, v] of Object.entries(e)) {
      if (k === "id" || k === "@timestamp" || k === "message" || v === undefined) continue;
      const m = counts.get(k) ?? new Map<string, number>();
      for (const x of Array.isArray(v) ? v : [v]) m.set(String(x), (m.get(String(x)) ?? 0) + 1);
      counts.set(k, m);
    }
  }
  const fields = [...counts.entries()]
    .map(([name, m]) => ({
      name,
      count: [...m.values()].reduce((a, b) => a + b, 0),
      top: [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([value, count]) => ({ value, count })),
    }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  return { total: hits.length, tookMs: Math.max(1, Math.round(performance.now() - started)), events: hits.slice(0, size), histogram, fields };
}

export function eventById(id: string): EventDoc | undefined {
  return data().events.find((e) => e.id === id);
}

// ---- alerts ----

export type AlertFilter = { status?: AlertStatus | "all"; severity?: string; q?: string };

export function listAlerts(f: AlertFilter = {}): Alert[] {
  return data().alerts.filter(
    (a) =>
      (!f.status || f.status === "all" || a.status === f.status) &&
      (!f.severity || f.severity === "all" || a.severity === f.severity) &&
      (!f.q || `${a.ruleName} ${a.summary} ${a.entity.id}`.toLowerCase().includes(f.q.toLowerCase())),
  );
}

export function getAlert(id: string): Alert | undefined {
  return data().alerts.find((a) => a.id === id);
}

export function updateAlert(id: string, patch: { status?: AlertStatus; closure?: Closure }, actor: string): Alert | undefined {
  const a = getAlert(id);
  if (!a) return undefined;
  if (patch.status) a.status = patch.status;
  if (patch.closure) {
    a.closure = patch.closure;
    a.status = "closed";
  }
  audit(actor, "alert.update", `${id} ${patch.status ?? ""} ${patch.closure ?? ""}`.trim());
  return a;
}

// ---- incidents ----

export function listIncidents(status?: IncidentStatus | "open" | "all"): Incident[] {
  const all = data().incidents;
  if (!status || status === "all") return all;
  if (status === "open") return all.filter((i) => i.status !== "closed" && i.status !== "resolved");
  return all.filter((i) => i.status === status);
}

export function getIncident(id: string): Incident | undefined {
  return data().incidents.find((i) => i.id === id);
}

export type IncidentPatch = { status?: IncidentStatus; assignee?: string | null; note?: string; closure?: Closure };

export function updateIncident(id: string, p: IncidentPatch, actor: string): Incident | undefined {
  const inc = getIncident(id);
  if (!inc) return undefined;
  const at = new Date().toISOString();
  if (p.status && p.status !== inc.status) {
    inc.status = p.status;
    inc.timeline.push({ at, kind: "status", actor, text: `Status changed to ${p.status}` });
  }
  if (p.assignee !== undefined && p.assignee !== inc.assignee) {
    inc.assignee = p.assignee;
    inc.timeline.push({ at, kind: "assignment", actor, text: p.assignee ? `Assigned to ${p.assignee}` : "Unassigned" });
  }
  if (p.note && p.note.trim()) {
    const note = { id: `n${inc.notes.length + 1}-${Date.now()}`, at, author: actor, text: p.note.trim().slice(0, 4000) };
    inc.notes.push(note);
    inc.timeline.push({ at, kind: "note", actor, text: note.text.slice(0, 140) });
  }
  if (p.closure) {
    inc.closure = p.closure;
    inc.status = "closed";
    inc.timeline.push({ at, kind: "status", actor, text: `Closed as ${p.closure.replace(/_/g, " ")}` });
  }
  inc.updatedAt = at;
  audit(actor, "incident.update", `${id} ${JSON.stringify(p).slice(0, 120)}`);
  return inc;
}

// ---- entities ----

export function entityKey(ref: EntityRef) {
  return `${ref.kind}:${ref.id}`;
}

export function getEntity(kind: EntityRef["kind"], id: string): EntityProfile | undefined {
  return data().profiles.get(`${kind}:${id}`);
}

export function entityEvents(ref: EntityRef, limit = 200): EventDoc[] {
  const field = ref.kind === "user" ? "user.name" : ref.kind === "host" ? "host.name" : null;
  return data()
    .events.filter((e) => (field ? e[field] === ref.id : e["source.ip"] === ref.id || e["destination.ip"] === ref.id))
    .slice(0, limit);
}

export function entityAlerts(ref: EntityRef): Alert[] {
  return data().alerts.filter((a) => a.entities.some((x) => x.kind === ref.kind && x.id === ref.id));
}

export function topEntities(kind: EntityRef["kind"], n = 8): EntityProfile[] {
  return [...data().profiles.values()].filter((p) => p.ref.kind === kind).sort((a, b) => b.risk - a.risk).slice(0, n);
}

// ---- rules, playbooks, intel, sources, admin ----

export const rules = () => data().rules;
export const getRule = (id: string) => data().rules.find((r) => r.id === id);
export const playbooks = () => data().playbooks;
export const getPlaybook = (id: string) => data().playbooks.find((p) => p.id === id);
export const runs = (playbookId?: string) => data().runs.filter((r) => !playbookId || r.playbookId === playbookId);
export const indicators = (q?: string) => data().indicators.filter((i) => !q || i.value.includes(q) || i.tags.some((t) => t.includes(q)));
export const feeds = () => data().feeds;
export const sources = () => data().sources;
export const parseErrors = () => data().parseErrors;
export const tenants = () => data().tenants;
export const users = () => data().users;
export const auditLog = () => data().audit;

export function runPlaybook(playbookId: string, opts: { dryRun: boolean; incidentId?: string }, actor: string): PlaybookRun | undefined {
  const pb = getPlaybook(playbookId);
  if (!pb) return undefined;
  let blocked = false;
  const steps = pb.steps.map((s) => {
    if (blocked) return { stepId: s.id, status: "skipped" as const, output: "" };
    if (opts.dryRun) return { stepId: s.id, status: "ok" as const, output: `dry run: would ${s.action.replace(/_/g, " ")} via ${s.adapter}` };
    if (s.requiresApproval) {
      blocked = true;
      return { stepId: s.id, status: "pending_approval" as const, output: `${s.name}: waiting for a second approver` };
    }
    return { stepId: s.id, status: "ok" as const, output: `${s.action.replace(/_/g, " ")} completed via ${s.adapter}` };
  });
  const run: PlaybookRun = {
    id: `run-${data().runs.length + 1}-${Date.now().toString(36)}`,
    playbookId,
    ...(opts.incidentId ? { incidentId: opts.incidentId } : {}),
    startedAt: new Date().toISOString(),
    status: opts.dryRun ? "dry_run" : blocked ? "awaiting_approval" : "succeeded",
    dryRun: opts.dryRun,
    triggeredBy: actor,
    steps,
  };
  data().runs.unshift(run);
  if (opts.incidentId) {
    const inc = getIncident(opts.incidentId);
    inc?.timeline.push({ at: run.startedAt, kind: "playbook", actor, text: `Playbook "${pb.name}" ${opts.dryRun ? "dry run" : run.status.replace(/_/g, " ")}`, ref: run.id });
  }
  audit(actor, "playbook.run", `${playbookId}${opts.dryRun ? " (dry run)" : ""}${opts.incidentId ? " on " + opts.incidentId : ""}`);
  return run;
}

function audit(actor: string, action: string, target: string) {
  const log = data().audit;
  const prev = log[log.length - 1];
  const prevHash = prev?.hash ?? "0".repeat(64);
  let h = 0x811c9dc5;
  for (const c of prevHash + actor + action + target) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
  log.push({ seq: (prev?.seq ?? 0) + 1, at: new Date().toISOString(), actor, action, target, hash: h.toString(16).padStart(8, "0").repeat(8), prevHash });
}

// ---- dashboards ----

function series(events: EventDoc[], now: number, pred: (e: EventDoc) => boolean, buckets = 24) {
  const start = now - 24 * 3_600_000;
  const w = (now - start) / buckets;
  const pts = Array.from({ length: buckets }, (_, i) => ({ at: new Date(start + i * w).toISOString(), value: 0 }));
  for (const e of events) {
    if (!pred(e)) continue;
    const t = Date.parse(e["@timestamp"]);
    if (t < start) continue;
    pts[Math.min(buckets - 1, Math.floor((t - start) / w))]!.value++;
  }
  return pts;
}

function top(events: EventDoc[], field: string, pred: (e: EventDoc) => boolean, n = 6) {
  const m = new Map<string, number>();
  for (const e of events) {
    if (!pred(e)) continue;
    const v = e[field];
    if (v === undefined) continue;
    m.set(String(v), (m.get(String(v)) ?? 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([label, value]) => ({ label, value }));
}

const fmt = (n: number) => n.toLocaleString("en-US");

export function dashboards(): Dashboard[] {
  const { events, now, alerts, incidents } = data();
  const auth = (e: EventDoc) => Array.isArray(e["event.category"]) && e["event.category"].includes("authentication");
  const fail = (e: EventDoc) => auth(e) && e["event.outcome"] === "failure";
  const net = (e: EventDoc) => ["zeek", "suricata", "panw"].includes(String(e["event.module"]));
  const proc = (e: EventDoc) => e["event.dataset"] === "windows.sysmon_operational";
  const cloud = (e: EventDoc) => e["event.module"] === "aws";
  const idp = (e: EventDoc) => e["event.module"] === "okta";
  const count = (p: (e: EventDoc) => boolean) => events.filter(p).length;
  const openAlerts = alerts.filter((a) => a.status !== "closed").length;
  const soc: DashboardPanel[] = [
    { kind: "stat", title: "Open alerts", value: fmt(openAlerts), tone: openAlerts > 20 ? "bad" : "neutral" },
    { kind: "stat", title: "Open incidents", value: fmt(incidents.filter((i) => i.status !== "closed" && i.status !== "resolved").length), tone: "bad" },
    { kind: "stat", title: "Events (24h)", value: fmt(events.length * 1800), delta: "+4.1% vs prior day", tone: "neutral" },
    { kind: "stat", title: "Detection latency p95", value: `${(alerts.map((a) => a.latencyMs).sort((a, b) => a - b)[Math.floor(alerts.length * 0.95)]! / 1000).toFixed(1)} s`, tone: "good" },
    { kind: "series", title: "Alerts per hour", points: series(alerts.map((a) => ({ id: a.id, "@timestamp": a.createdAt })), now, () => true) },
    { kind: "bars", title: "Alerts by rule", rows: [...alerts.reduce((m, a) => m.set(a.ruleName, (m.get(a.ruleName) ?? 0) + 1), new Map<string, number>())].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([label, value]) => ({ label, value })) },
  ];
  return [
    { id: "soc", title: "SOC overview", description: "Queue health, detection latency and alert trends.", category: "overview", panels: soc },
    {
      id: "auth",
      title: "Authentication",
      description: "Logon volume, failures and the sources behind them across Windows, Linux and identity providers.",
      category: "auth",
      panels: [
        { kind: "stat", title: "Logons (sample)", value: fmt(count(auth)) },
        { kind: "stat", title: "Failures", value: fmt(count(fail)), tone: "bad" },
        { kind: "stat", title: "Failure rate", value: `${((count(fail) / Math.max(1, count(auth))) * 100).toFixed(1)}%` },
        { kind: "series", title: "Failed logons per hour", points: series(events, now, fail) },
        { kind: "bars", title: "Top failing accounts", rows: top(events, "user.name", fail) },
        { kind: "bars", title: "Top failing sources", rows: top(events, "source.ip", fail) },
      ],
    },
    {
      id: "endpoint",
      title: "Endpoint",
      description: "Process activity from Sysmon and auditd.",
      category: "endpoint",
      panels: [
        { kind: "stat", title: "Process starts", value: fmt(count(proc)) },
        { kind: "series", title: "Process starts per hour", points: series(events, now, proc) },
        { kind: "bars", title: "Top processes", rows: top(events, "process.name", proc) },
        { kind: "bars", title: "Busiest hosts", rows: top(events, "host.name", proc) },
      ],
    },
    {
      id: "network",
      title: "Network",
      description: "Connections, DNS and IDS alerts from Zeek, Suricata and firewalls.",
      category: "network",
      panels: [
        { kind: "stat", title: "Flows and queries", value: fmt(count(net)) },
        { kind: "stat", title: "Firewall denies", value: fmt(count((e) => e["event.action"] === "deny")), tone: "bad" },
        { kind: "series", title: "Network events per hour", points: series(events, now, net) },
        { kind: "bars", title: "Top destination ports", rows: top(events, "destination.port", net) },
        { kind: "bars", title: "Top DNS names", rows: top(events, "dns.question.name", (e) => e["event.dataset"] === "zeek.dns") },
      ],
    },
    {
      id: "cloud",
      title: "Cloud",
      description: "API activity across AWS accounts.",
      category: "cloud",
      panels: [
        { kind: "stat", title: "API calls", value: fmt(count(cloud)) },
        { kind: "series", title: "API calls per hour", points: series(events, now, cloud) },
        { kind: "bars", title: "Top actions", rows: top(events, "event.action", cloud) },
        { kind: "bars", title: "Top callers", rows: top(events, "user.name", cloud) },
      ],
    },
    {
      id: "identity",
      title: "Identity",
      description: "Identity-provider sign-ins and where they come from.",
      category: "identity",
      panels: [
        { kind: "stat", title: "Sign-ins", value: fmt(count(idp)) },
        { kind: "stat", title: "Failed sign-ins", value: fmt(count((e) => idp(e) && e["event.outcome"] === "failure")), tone: "bad" },
        { kind: "bars", title: "Sign-ins by country", rows: top(events, "source.geo.country_iso_code", idp) },
        { kind: "table", title: "Recent failures", columns: ["Time", "User", "Source"], rows: events.filter((e) => idp(e) && e["event.outcome"] === "failure").slice(0, 6).map((e) => [e["@timestamp"].slice(11, 19), String(e["user.name"]), String(e["source.ip"])]) },
      ],
    },
  ];
}

// ---- attack chain ----


/** Builds the left-to-right attack chain for an incident: external sources,
 * then accounts, then the hosts reached, in the order they were touched. */
export function attackChain(inc: Incident): { columns: ChainNode[][]; edges: ChainEdge[] } {
  const d = data();
  const sc = d.scenario;
  if (inc.id === "INC-1042") {
    const hosts = sc.hosts;
    const columns: ChainNode[][] = [
      [{ id: "ip", kind: "ip", label: sc.attacker, sub: "SG · AS64512", severity: "critical" }],
      [{ id: "user", kind: "user", label: sc.user, sub: "service account", severity: "critical" }],
      ...hosts.map((h, i) => [{ id: `h${i}`, kind: "host" as const, label: h.split(".")[0]!, sub: h.startsWith("dc") ? "domain controller" : "server", severity: "high" as const }]),
    ];
    const edges: ChainEdge[] = [
      { from: "ip", to: "user", label: "18 failures → logon" },
      { from: "user", to: "h0", label: "logon + ADMIN$" },
      { from: "h0", to: "h1", label: "logon + ADMIN$" },
      { from: "h1", to: "h2", label: "service install" },
    ];
    return { columns, edges };
  }
  const ips = inc.entities.filter((e) => e.kind === "ip");
  const users = inc.entities.filter((e) => e.kind === "user");
  const hosts = inc.entities.filter((e) => e.kind === "host");
  const columns = [ips, users, hosts]
    .filter((c) => c.length)
    .map((c) => c.slice(0, 4).map((e) => ({ id: `${e.kind}:${e.id}`, kind: e.kind, label: e.kind === "host" ? e.id.split(".")[0]! : e.id })));
  const edges: ChainEdge[] = [];
  for (let i = 0; i + 1 < columns.length; i++) {
    for (const a of columns[i]!) for (const b of columns[i + 1]!) edges.push({ from: a.id, to: b.id, label: "" });
  }
  return { columns, edges };
}
