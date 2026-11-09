"use client";

import { BellRing, Check, FileText, FlaskConical, Globe, MessageSquare, Monitor, Paperclip, PlayCircle, RefreshCw, User, UserCheck } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { AttackChain, Gauge, type ChainEdge, type ChainNode } from "@/components/charts";
import { Button, Card, CardBody, CardHeader, Label, Segmented, segmentClass, Select, SeverityBadge, SeverityStrip, StatusBadge, Textarea } from "@/components/ui/primitives";
import { tacticById, techniqueById } from "@/lib/attack";
import type { Alert, Closure, Incident, IncidentStatus, Playbook, PlaybookRun, TimelineEntry } from "@/lib/types";
import { INCIDENT_STATUSES } from "@/lib/types";
import { cn, entityHref, relTime, slaLeft, utc } from "@/lib/utils";

const kindStyle: Record<TimelineEntry["kind"], { icon: typeof BellRing; ring: string }> = {
  alert: { icon: BellRing, ring: "bg-sev-high/15 text-sev-high ring-sev-high/40" },
  event: { icon: FileText, ring: "bg-surface-2 text-muted-foreground ring-border-strong" },
  note: { icon: MessageSquare, ring: "bg-chart-2/15 text-chart-2 ring-chart-2/40" },
  status: { icon: RefreshCw, ring: "bg-primary/15 text-primary ring-primary/40" },
  playbook: { icon: PlayCircle, ring: "bg-chart-3/15 text-chart-3 ring-chart-3/40" },
  evidence: { icon: Paperclip, ring: "bg-good/15 text-good ring-good/40" },
  assignment: { icon: UserCheck, ring: "bg-primary/15 text-primary ring-primary/40" },
};

const entityIcon = { user: User, host: Monitor, ip: Globe } as const;

type Props = { inc: Incident; alerts: Alert[]; playbooks: Playbook[]; runs: PlaybookRun[]; analysts: string[]; now: number; chain: { columns: ChainNode[][]; edges: ChainEdge[] } };

export function Workspace({ inc, alerts, playbooks, runs, analysts, now, chain }: Props) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [tab, setTab] = useState<"timeline" | "alerts" | "notes" | "evidence" | "response">("timeline");
  const [kinds, setKinds] = useState<Set<TimelineEntry["kind"]>>(new Set(["alert", "event", "note", "status", "playbook", "evidence", "assignment"]));
  const sla = slaLeft(inc.slaDueAt, now);
  const done = inc.status === "closed" || inc.status === "resolved";
  const slaTotal = Date.parse(inc.slaDueAt) - Date.parse(inc.createdAt);
  const slaUsed = Math.min(100, Math.max(0, ((now - Date.parse(inc.createdAt)) / slaTotal) * 100));
  const stepIndex = INCIDENT_STATUSES.indexOf(inc.status);

  const patch = (body: Record<string, unknown>, ok: string) =>
    start(async () => {
      const r = await fetch(`/api/incidents/${inc.id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      setMsg(r.ok ? ok : "Update failed.");
      router.refresh();
    });

  const run = (playbookId: string, dryRun: boolean) =>
    start(async () => {
      const r = await fetch(`/api/playbooks/${playbookId}/run`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ dryRun, incidentId: inc.id }) });
      const body = (await r.json()) as PlaybookRun;
      setMsg(r.ok ? `Run ${body.id}: ${body.status.replace(/_/g, " ")}` : "Playbook run failed.");
      setTab("response");
      router.refresh();
    });

  const tabs = [
    ["timeline", "Timeline", inc.timeline.length],
    ["alerts", "Alerts", alerts.length],
    ["notes", "Notes", inc.notes.length],
    ["evidence", "Evidence", inc.evidence.length],
    ["response", "Response", runs.length],
  ] as const;

  const timeline = [...inc.timeline].reverse().filter((t) => kinds.has(t.kind));

  return (
    <div className="space-y-5">
      {/* Status stepper */}
      <Card className="px-5 py-4">
        <ol className="flex flex-wrap items-center gap-y-3" aria-label="Incident status">
          {INCIDENT_STATUSES.map((s, i) => {
            const reached = i <= stepIndex;
            const current = i === stepIndex;
            return (
              <li key={s} className="flex flex-1 items-center">
                <button
                  type="button"
                  disabled={pending || current}
                  onClick={() => patch({ status: s as IncidentStatus }, `Status set to ${s}.`)}
                  aria-current={current ? "step" : undefined}
                  className={cn("group flex items-center gap-2 rounded-lg px-1 py-0.5 text-sm capitalize", !current && "hover:text-foreground")}
                >
                  <span className={cn("inline-flex size-7 items-center justify-center rounded-full text-xs font-semibold ring-1 transition-colors", current ? "bg-primary text-primary-foreground ring-primary shadow-md shadow-primary/30" : reached ? "bg-primary/15 text-primary ring-primary/40" : "bg-surface-2 text-muted-foreground ring-border-strong group-hover:ring-ring")}>
                    {reached && !current ? <Check className="size-3.5" aria-hidden /> : i + 1}
                  </span>
                  <span className={cn(current ? "font-semibold text-foreground" : reached ? "text-foreground" : "text-muted-foreground")}>{s}</span>
                </button>
                {i < INCIDENT_STATUSES.length - 1 ? <span aria-hidden className={cn("mx-2 h-px min-w-4 flex-1", i < stepIndex ? "bg-primary/50" : "bg-border-strong")} /> : null}
              </li>
            );
          })}
        </ol>
      </Card>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_23rem]">
        <div className="min-w-0 space-y-5">
          {/* Key facts + attack chain */}
          <Card className="overflow-hidden">
            <SeverityStrip severity={inc.severity} />
            <div className="grid gap-5 p-5 lg:grid-cols-[auto_minmax(0,1fr)]">
              <div className="flex items-center justify-around gap-6 lg:flex-col lg:justify-start">
                <Gauge value={inc.score} label="Risk score" />
                <Gauge value={done ? 0 : slaUsed} tone={sla.overdue ? "critical" : slaUsed > 66 ? "high" : "good"} label={done ? "SLA met" : "SLA used %"} sub={done ? undefined : sla.overdue ? sla.text : `${sla.text} left`} />
              </div>
              <div className="min-w-0">
                <p className="mb-2 text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground">Attack chain</p>
                <div className="rounded-xl border bg-background/40 p-3">
                  <AttackChain columns={chain.columns} edges={chain.edges} label={`Attack chain for ${inc.id}`} />
                </div>
                <div className="mt-4 flex flex-wrap gap-1.5">
                  {inc.techniques.map((t) => (
                    <span key={t} className="rounded-md border bg-surface-2/70 px-2 py-0.5 text-xs">
                      <span className="font-mono text-muted-foreground">{t}</span> {techniqueById.get(t.split(".")[0]!)?.name}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </Card>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <Segmented role="tablist" aria-label="Incident sections">
              {tabs.map(([id, label, n]) => (
                <button key={id} role="tab" type="button" id={`tab-${id}`} aria-selected={tab === id} aria-controls={`panel-${id}`} onClick={() => setTab(id)} className={segmentClass(tab === id)}>
                  {label} <span className="ml-1 text-xs text-muted-foreground tabular-nums">{n}</span>
                </button>
              ))}
            </Segmented>
            {tab === "timeline" ? (
              <div className="flex flex-wrap gap-1" aria-label="Timeline filters">
                {(Object.keys(kindStyle) as TimelineEntry["kind"][]).map((k) => (
                  <button
                    key={k}
                    type="button"
                    aria-pressed={kinds.has(k)}
                    onClick={() => {
                      const next = new Set(kinds);
                      if (next.has(k)) next.delete(k);
                      else next.add(k);
                      setKinds(next);
                    }}
                    className={cn("rounded-full border px-2.5 py-0.5 text-xs capitalize", kinds.has(k) ? "border-border-strong bg-surface text-foreground" : "text-muted-foreground opacity-60")}
                  >
                    {k}
                  </button>
                ))}
              </div>
            ) : null}
          </div>

          <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
            {tab === "timeline" ? (
              <Card>
                <ol className="p-5">
                  {timeline.map((t, i) => {
                    const st = kindStyle[t.kind];
                    const Icon = st.icon;
                    return (
                      <li key={i} className="relative flex gap-4 pb-5 last:pb-0">
                        {i < timeline.length - 1 ? <span aria-hidden className="absolute left-4 top-9 bottom-0 w-px bg-border" /> : null}
                        <span className={cn("z-10 inline-flex size-8 shrink-0 items-center justify-center rounded-full ring-1", st.ring)}>
                          <Icon className="size-4" aria-hidden />
                        </span>
                        <div className="min-w-0 flex-1 pt-0.5">
                          <div className="flex flex-wrap items-baseline justify-between gap-x-3">
                            <p className={cn("text-sm", t.kind === "alert" && "font-semibold")}>
                              {t.ref && t.kind === "alert" ? <Link href={`/alerts?focus=${t.ref}`} className="hover:underline">{t.text}</Link> : t.text}
                            </p>
                            <time dateTime={t.at} className="font-mono text-xs text-muted-foreground">{utc(t.at).slice(11)}</time>
                          </div>
                          <p className="text-xs text-muted-foreground">{t.kind} · {t.actor}</p>
                        </div>
                      </li>
                    );
                  })}
                  {timeline.length === 0 ? <li className="py-6 text-center text-sm text-muted-foreground">No entries match the selected types.</li> : null}
                </ol>
              </Card>
            ) : null}
            {tab === "alerts" ? (
              <div className="grid gap-3 md:grid-cols-2">
                {alerts.map((a) => (
                  <Link key={a.id} href={`/alerts?focus=${a.id}`} className="relative block overflow-hidden rounded-xl border bg-surface p-4 hover:border-border-strong">
                    <SeverityStrip severity={a.severity} />
                    <div className="flex items-start justify-between gap-2">
                      <p className="font-medium leading-snug">{a.ruleName}</p>
                      <SeverityBadge severity={a.severity} />
                    </div>
                    <p className="mt-1 text-sm text-muted-foreground">{a.summary}</p>
                    <p className="mt-3 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                      <span>score {a.score}</span>
                      <span>{(a.latencyMs / 1000).toFixed(1)}s to detect</span>
                      <span>{relTime(a.createdAt, now)}</span>
                    </p>
                  </Link>
                ))}
              </div>
            ) : null}
            {tab === "notes" ? (
              <Card>
                <ul className="divide-y">
                  {inc.notes.map((n) => (
                    <li key={n.id} className="flex gap-3 px-5 py-4">
                      <span className="inline-flex size-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-primary/70 to-chart-3/70 text-xs font-semibold uppercase text-white">{n.author.slice(0, 2)}</span>
                      <div className="min-w-0">
                        <p className="text-xs text-muted-foreground"><span className="font-medium text-foreground">{n.author}</span> · {relTime(n.at, now)}</p>
                        <p className="mt-1 whitespace-pre-wrap text-sm">{n.text}</p>
                      </div>
                    </li>
                  ))}
                </ul>
                <form
                  className="space-y-2 border-t p-5"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (!note.trim()) return;
                    patch({ note }, "Note added.");
                    setNote("");
                  }}
                >
                  <Label htmlFor="note">Add a note</Label>
                  <Textarea id="note" rows={3} value={note} onChange={(e) => setNote(e.target.value)} maxLength={4000} placeholder="Findings, decisions, next steps" />
                  <div className="flex justify-end">
                    <Button type="submit" size="sm" disabled={pending || !note.trim()}>Add note</Button>
                  </div>
                </form>
              </Card>
            ) : null}
            {tab === "evidence" ? (
              <Card>
                <CardHeader title="Evidence" description="Stored content-addressed; the SHA-256 is verified on every download." />
                <ul className="divide-y border-t">
                  {inc.evidence.map((ev) => (
                    <li key={ev.id} className="flex items-start gap-3 px-5 py-4 text-sm">
                      <span className="inline-flex size-9 shrink-0 items-center justify-center rounded-lg bg-good/12 text-good"><Paperclip className="size-4" aria-hidden /></span>
                      <div className="min-w-0">
                        <p className="font-medium">{ev.name}</p>
                        <p className="break-all font-mono text-xs text-muted-foreground">sha256:{ev.sha256}</p>
                        <p className="text-xs text-muted-foreground">{(ev.size / 1024).toFixed(1)} KiB · {ev.addedBy} · {utc(ev.at)}</p>
                      </div>
                    </li>
                  ))}
                  {inc.evidence.length === 0 ? <li className="px-5 py-8 text-center text-sm text-muted-foreground">No evidence attached.</li> : null}
                </ul>
              </Card>
            ) : null}
            {tab === "response" ? (
              <div className="space-y-4">
                <div className="grid gap-3 md:grid-cols-2">
                  {playbooks.map((p) => (
                    <Card key={p.id} className="flex flex-col p-4">
                      <div className="flex items-start justify-between gap-2">
                        <Link href={`/playbooks/${p.id}`} className="font-medium hover:underline">{p.name}</Link>
                        {p.steps.some((s) => s.requiresApproval) ? <span className="rounded-full bg-warn/14 px-2 py-0.5 text-[0.7rem] font-medium text-warn">needs approval</span> : null}
                      </div>
                      <p className="mt-1 flex-1 text-sm text-muted-foreground">{p.description}</p>
                      <div className="mt-3 flex gap-2">
                        <Button size="sm" variant="outline" disabled={pending} onClick={() => run(p.id, true)}><FlaskConical aria-hidden /> Dry run</Button>
                        <Button size="sm" disabled={pending} onClick={() => run(p.id, false)}><PlayCircle aria-hidden /> Run</Button>
                      </div>
                    </Card>
                  ))}
                </div>
                <Card>
                  <CardHeader title="Runs on this incident" />
                  <ul className="divide-y border-t">
                    {runs.map((r) => (
                      <li key={r.id} className="px-5 py-3 text-sm">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-medium">{playbooks.find((p) => p.id === r.playbookId)?.name ?? r.playbookId}</span>
                          <StatusBadge status={r.status} />
                          <span className="text-xs text-muted-foreground">{relTime(r.startedAt, now)} · {r.triggeredBy}</span>
                        </div>
                        <ol className="mt-2 space-y-1">
                          {r.steps.map((s) => (
                            <li key={s.stepId} className="flex items-start gap-2 text-xs">
                              <StatusBadge status={s.status} className="shrink-0" />
                              <span className="text-muted-foreground">{s.output || "—"}</span>
                            </li>
                          ))}
                        </ol>
                      </li>
                    ))}
                    {runs.length === 0 ? <li className="px-5 py-8 text-center text-sm text-muted-foreground">No playbook runs yet.</li> : null}
                  </ul>
                </Card>
              </div>
            ) : null}
          </div>
        </div>

        <aside className="space-y-5" aria-label="Incident properties">
          <Card>
            <CardHeader title="Ownership" />
            <CardBody className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="inc-assignee">Assignee</Label>
                <Select id="inc-assignee" className="w-full" value={inc.assignee ?? ""} disabled={pending} onChange={(e) => patch({ assignee: e.target.value || null }, "Assignee updated.")}>
                  <option value="">Unassigned</option>
                  {analysts.map((a) => (
                    <option key={a} value={a}>{a}</option>
                  ))}
                </Select>
              </div>
              {!done ? (
                <div className="space-y-1.5">
                  <Label htmlFor="inc-close">Close as</Label>
                  <Select id="inc-close" className="w-full" value="" disabled={pending} onChange={(e) => e.target.value && patch({ closure: e.target.value as Closure }, "Incident closed.")}>
                    <option value="">Choose a classification…</option>
                    <option value="true_positive">True positive</option>
                    <option value="benign_true_positive">Benign true positive</option>
                    <option value="false_positive">False positive</option>
                  </Select>
                </div>
              ) : (
                <p className="text-sm">Closed as <strong>{inc.closure?.replace(/_/g, " ") ?? "resolved"}</strong></p>
              )}
              <p className="min-h-4 text-xs text-primary" aria-live="polite">{msg}</p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Entities" description={`${inc.entities.length} involved`} />
            <ul className="space-y-1 px-3 pb-3">
              {inc.entities.map((e) => {
                const Icon = entityIcon[e.kind];
                return (
                  <li key={`${e.kind}:${e.id}`}>
                    <Link href={entityHref(e.kind, e.id)} className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-accent/50">
                      <span className="inline-flex size-8 items-center justify-center rounded-lg bg-surface-2 text-muted-foreground"><Icon className="size-4" aria-hidden /></span>
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium">{e.id}</span>
                        <span className="text-[0.7rem] uppercase tracking-wider text-muted-foreground">{e.kind}</span>
                      </span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </Card>
          <Card>
            <CardHeader title="MITRE ATT&CK" />
            <CardBody className="flex flex-wrap gap-1.5">
              {inc.tactics.map((t) => (
                <span key={t} className="rounded-md bg-chart-3/12 px-2 py-0.5 text-xs font-medium text-chart-3">{tacticById.get(t)?.name ?? t}</span>
              ))}
            </CardBody>
          </Card>
          <p className="px-1 text-xs text-muted-foreground">Every change here is written to the hash-chained audit log.</p>
        </aside>
      </div>
    </div>
  );
}
