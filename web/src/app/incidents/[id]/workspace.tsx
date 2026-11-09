"use client";

import { BellRing, FileText, FlaskConical, MessageSquare, Paperclip, PlayCircle, RefreshCw, UserCheck } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { Button, Card, CardBody, CardHeader, Kv, Label, Select, SeverityBadge, StatusBadge, Textarea } from "@/components/ui/primitives";
import { techniqueById } from "@/lib/attack";
import type { Alert, Closure, Incident, IncidentStatus, Playbook, PlaybookRun, TimelineEntry } from "@/lib/types";
import { INCIDENT_STATUSES } from "@/lib/types";
import { cn, entityHref, relTime, slaLeft, utc } from "@/lib/utils";

const kindIcon: Record<TimelineEntry["kind"], typeof BellRing> = {
  alert: BellRing,
  event: FileText,
  note: MessageSquare,
  status: RefreshCw,
  playbook: PlayCircle,
  evidence: Paperclip,
  assignment: UserCheck,
};

export function Workspace({ inc, alerts, playbooks, runs, analysts, now }: { inc: Incident; alerts: Alert[]; playbooks: Playbook[]; runs: PlaybookRun[]; analysts: string[]; now: number }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [tab, setTab] = useState<"timeline" | "alerts" | "notes" | "evidence" | "response">("timeline");
  const sla = slaLeft(inc.slaDueAt, now);
  const done = inc.status === "closed" || inc.status === "resolved";

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
      setMsg(r.ok ? `Playbook run ${body.id}: ${body.status.replace(/_/g, " ")}` : "Playbook run failed.");
      router.refresh();
    });

  const tabs = [
    ["timeline", `Timeline (${inc.timeline.length})`],
    ["alerts", `Alerts (${alerts.length})`],
    ["notes", `Notes (${inc.notes.length})`],
    ["evidence", `Evidence (${inc.evidence.length})`],
    ["response", "Response"],
  ] as const;

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <div className="min-w-0 space-y-4">
        <div role="tablist" aria-label="Incident sections" className="flex flex-wrap gap-1 border-b">
          {tabs.map(([id, label]) => (
            <button key={id} role="tab" type="button" id={`tab-${id}`} aria-selected={tab === id} aria-controls={`panel-${id}`} onClick={() => setTab(id)} className={cn("-mb-px border-b-2 px-3 py-2 text-sm", tab === id ? "border-primary font-medium" : "border-transparent text-muted-foreground hover:text-foreground")}>
              {label}
            </button>
          ))}
        </div>
        <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
          {tab === "timeline" ? (
            <Card>
              <ol className="relative space-y-0 p-4">
                {inc.timeline.map((t, i) => {
                  const Icon = kindIcon[t.kind];
                  return (
                    <li key={i} className="relative flex gap-3 pb-4 last:pb-0">
                      <span className={cn("z-10 mt-0.5 inline-flex size-7 shrink-0 items-center justify-center rounded-full border bg-card", t.kind === "alert" && "border-sev-high/60 text-sev-high")}>
                        <Icon className="size-3.5" aria-hidden />
                      </span>
                      {i < inc.timeline.length - 1 ? <span aria-hidden className="absolute left-3.5 top-8 h-[calc(100%-1.5rem)] w-px bg-border" /> : null}
                      <div className="min-w-0">
                        <p className="text-sm">
                          {t.ref && t.kind === "alert" ? (
                            <Link href={`/alerts?focus=${t.ref}`} className="font-medium hover:underline">{t.text}</Link>
                          ) : (
                            t.text
                          )}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          <time dateTime={t.at}>{utc(t.at)}</time> · {t.kind} · {t.actor}
                        </p>
                      </div>
                    </li>
                  );
                })}
              </ol>
            </Card>
          ) : null}
          {tab === "alerts" ? (
            <Card>
              <ul className="divide-y">
                {alerts.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
                    <div className="min-w-0">
                      <Link href={`/alerts?focus=${a.id}`} className="font-medium hover:underline">{a.ruleName}</Link>
                      <p className="text-xs text-muted-foreground">{a.summary}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={a.severity} />
                      <span className="text-xs text-muted-foreground">{relTime(a.createdAt, now)}</span>
                    </div>
                  </li>
                ))}
              </ul>
            </Card>
          ) : null}
          {tab === "notes" ? (
            <Card>
              <ul className="divide-y">
                {inc.notes.map((n) => (
                  <li key={n.id} className="px-4 py-3">
                    <p className="whitespace-pre-wrap text-sm">{n.text}</p>
                    <p className="mt-1 text-xs text-muted-foreground">{n.author} · {utc(n.at)}</p>
                  </li>
                ))}
              </ul>
              <form
                className="space-y-2 border-t p-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!note.trim()) return;
                  patch({ note }, "Note added.");
                  setNote("");
                }}
              >
                <Label htmlFor="note">Add a note</Label>
                <Textarea id="note" rows={3} value={note} onChange={(e) => setNote(e.target.value)} maxLength={4000} placeholder="Findings, decisions, next steps" />
                <Button type="submit" size="sm" disabled={pending || !note.trim()}>Add note</Button>
              </form>
            </Card>
          ) : null}
          {tab === "evidence" ? (
            <Card>
              <CardHeader title="Evidence" description="Stored content-addressed; the SHA-256 is verified on every download." />
              <ul className="divide-y">
                {inc.evidence.map((ev) => (
                  <li key={ev.id} className="px-4 py-3 text-sm">
                    <p className="font-medium">{ev.name}</p>
                    <p className="break-all font-mono text-xs text-muted-foreground">sha256 {ev.sha256}</p>
                    <p className="text-xs text-muted-foreground">{(ev.size / 1024).toFixed(1)} KiB · added by {ev.addedBy} · {utc(ev.at)}</p>
                  </li>
                ))}
                {inc.evidence.length === 0 ? <li className="px-4 py-6 text-center text-sm text-muted-foreground">No evidence attached.</li> : null}
              </ul>
            </Card>
          ) : null}
          {tab === "response" ? (
            <div className="space-y-4">
              <Card>
                <CardHeader title="Playbooks" description="Destructive steps need a second approver. Dry runs show what would happen without calling any adapter." />
                <ul className="divide-y">
                  {playbooks.map((p) => (
                    <li key={p.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
                      <div className="min-w-0">
                        <Link href={`/playbooks/${p.id}`} className="font-medium hover:underline">{p.name}</Link>
                        <p className="text-xs text-muted-foreground">{p.description}</p>
                      </div>
                      <div className="flex gap-2">
                        <Button size="sm" variant="outline" disabled={pending} onClick={() => run(p.id, true)}>
                          <FlaskConical aria-hidden /> Dry run
                        </Button>
                        <Button size="sm" disabled={pending} onClick={() => run(p.id, false)}>
                          <PlayCircle aria-hidden /> Run
                        </Button>
                      </div>
                    </li>
                  ))}
                </ul>
              </Card>
              <Card>
                <CardHeader title="Runs on this incident" />
                <ul className="divide-y">
                  {runs.map((r) => (
                    <li key={r.id} className="px-4 py-3 text-sm">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium">{playbooks.find((p) => p.id === r.playbookId)?.name ?? r.playbookId}</span>
                        <StatusBadge status={r.status} />
                        <span className="text-xs text-muted-foreground">{relTime(r.startedAt, now)} · {r.triggeredBy}</span>
                      </div>
                      <ul className="mt-1 space-y-0.5 text-xs text-muted-foreground">
                        {r.steps.map((s) => (
                          <li key={s.stepId}>
                            {s.stepId}: {s.status.replace(/_/g, " ")}{s.output ? ` — ${s.output}` : ""}
                          </li>
                        ))}
                      </ul>
                    </li>
                  ))}
                  {runs.length === 0 ? <li className="px-4 py-6 text-center text-sm text-muted-foreground">No playbook runs yet.</li> : null}
                </ul>
              </Card>
            </div>
          ) : null}
        </div>
      </div>

      <aside className="space-y-4" aria-label="Incident properties">
        <Card>
          <CardHeader title="Properties" actions={<SeverityBadge severity={inc.severity} />} />
          <CardBody className="space-y-4">
            <Kv
              items={[
                ["Score", `${inc.score} / 100`],
                ["Created", utc(inc.createdAt)],
                ["SLA", done ? "met" : <span key="s" className={sla.overdue ? "font-medium text-bad" : ""}>{sla.text}</span>],
                ["Tactics", inc.tactics.join(", ")],
                ["Techniques", inc.techniques.map((t) => `${t} ${techniqueById.get(t.split(".")[0]!)?.name ?? ""}`).join(", ")],
                ...(inc.closure ? ([["Closure", inc.closure.replace(/_/g, " ")]] as [string, string][]) : []),
              ]}
            />
            <div className="space-y-1">
              <Label htmlFor="inc-status">Status</Label>
              <Select id="inc-status" className="w-full" value={inc.status} disabled={pending} onChange={(e) => patch({ status: e.target.value as IncidentStatus }, "Status updated.")}>
                {INCIDENT_STATUSES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </Select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="inc-assignee">Assignee</Label>
              <Select id="inc-assignee" className="w-full" value={inc.assignee ?? ""} disabled={pending} onChange={(e) => patch({ assignee: e.target.value || null }, "Assignee updated.")}>
                <option value="">Unassigned</option>
                {analysts.map((a) => (
                  <option key={a} value={a}>{a}</option>
                ))}
              </Select>
            </div>
            {!done ? (
              <div className="space-y-1">
                <Label htmlFor="inc-close">Close as</Label>
                <Select id="inc-close" className="w-full" value="" disabled={pending} onChange={(e) => e.target.value && patch({ closure: e.target.value as Closure }, "Incident closed.")}>
                  <option value="">Choose a classification…</option>
                  <option value="true_positive">True positive</option>
                  <option value="benign_true_positive">Benign true positive</option>
                  <option value="false_positive">False positive</option>
                </Select>
              </div>
            ) : null}
            <p className="text-xs text-muted-foreground" aria-live="polite">{msg}</p>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Entities" />
          <ul className="flex flex-wrap gap-1 p-4">
            {inc.entities.map((e) => (
              <li key={`${e.kind}:${e.id}`}>
                <Link href={entityHref(e.kind, e.id)} className="inline-block rounded-md border px-1.5 py-0.5 text-xs hover:bg-accent">
                  {e.kind}: {e.id}
                </Link>
              </li>
            ))}
          </ul>
        </Card>
        <p className="px-1 text-xs text-muted-foreground">
          <StatusBadge status={inc.status} /> Every change here is written to the hash-chained audit log.
        </p>
      </aside>
    </div>
  );
}
