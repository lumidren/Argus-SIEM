"use client";

import { Check, CheckCheck, ExternalLink, Search, X, XCircle } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState, useTransition } from "react";
import { Button, Card, Input, Kv, Segmented, segmentClass, Select, SeverityBadge, SeverityStrip, StatusBadge } from "@/components/ui/primitives";
import { techniqueById } from "@/lib/attack";
import type { Alert, AlertStatus, Closure } from "@/lib/types";
import { cn, entityHref, relTime, searchHref, utc } from "@/lib/utils";

const STATUSES: (AlertStatus | "all")[] = ["open", "acknowledged", "in_progress", "closed", "all"];

export function AlertsClient({ alerts, now, focus }: { alerts: Alert[]; now: number; focus?: string }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const focused = focus ? alerts.find((a) => a.id === focus) : undefined;
  const [status, setStatus] = useState<AlertStatus | "all">(focused ? (focused.status === "closed" ? "all" : focused.status) : "open");
  const [sev, setSev] = useState("all");
  const [text, setText] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [current, setCurrent] = useState<string | null>(focus ?? null);
  const [error, setError] = useState<string | null>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  const rows = useMemo(
    () =>
      alerts.filter(
        (a) =>
          (status === "all" || a.status === status) &&
          (sev === "all" || a.severity === sev) &&
          (!text || `${a.ruleName} ${a.summary} ${a.entity.id}`.toLowerCase().includes(text.toLowerCase())),
      ),
    [alerts, status, sev, text],
  );
  const active = alerts.find((a) => a.id === current) ?? null;
  const counts = useMemo(() => {
    const m = new Map<string, number>();
    for (const a of alerts) m.set(a.status, (m.get(a.status) ?? 0) + 1);
    m.set("all", alerts.length);
    return m;
  }, [alerts]);

  useEffect(() => {
    if (!active) return;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setCurrent(null);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active]);

  const patch = (ids: string[], body: { status?: AlertStatus; closure?: Closure }) =>
    start(async () => {
      setError(null);
      const results = await Promise.all(ids.map((id) => fetch(`/api/alerts/${id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })));
      if (results.some((r) => !r.ok)) setError("Some alerts could not be updated.");
      setSelected(new Set());
      router.refresh();
    });

  const allChecked = rows.length > 0 && rows.every((r) => selected.has(r.id));
  const ids = [...selected];

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Segmented aria-label="Status filter">
          {STATUSES.map((s) => (
            <button key={s} type="button" aria-pressed={status === s} onClick={() => setStatus(s)} className={segmentClass(status === s)}>
              {s.replace("_", " ")} <span className="ml-1 text-xs tabular-nums text-muted-foreground">{counts.get(s) ?? 0}</span>
            </button>
          ))}
        </Segmented>
        <label htmlFor="f-sev" className="sr-only">Severity</label>
        <Select id="f-sev" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </Select>
        <div className="relative min-w-56 flex-1">
          <label htmlFor="f-text" className="sr-only">Filter</label>
          <Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" aria-hidden />
          <Input id="f-text" value={text} onChange={(e) => setText(e.target.value)} placeholder="Filter by rule, summary or entity" className="pl-9" />
        </div>
      </div>

      {selected.size ? (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-xl border border-primary/40 bg-primary/8 px-4 py-2 text-sm" aria-live="polite">
          <span className="font-medium">{selected.size} selected</span>
          <span className="flex-1" />
          <Button size="sm" variant="outline" disabled={pending} onClick={() => patch(ids, { status: "acknowledged" })}><Check aria-hidden /> Acknowledge</Button>
          <Button size="sm" variant="outline" disabled={pending} onClick={() => patch(ids, { closure: "false_positive" })}><XCircle aria-hidden /> Close as false positive</Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>Clear</Button>
        </div>
      ) : null}
      {error ? <p className="mb-3 text-sm text-bad">{error}</p> : null}

      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[0.7rem] uppercase tracking-wider text-muted-foreground">
                <th scope="col" className="w-10 border-b bg-surface-2/50 py-2.5 pl-5">
                  <input type="checkbox" className="accent-[var(--primary)]" aria-label="Select all visible alerts" checked={allChecked} onChange={(e) => setSelected(e.target.checked ? new Set(rows.map((r) => r.id)) : new Set())} />
                </th>
                <th scope="col" className="border-b bg-surface-2/50 px-3 py-2.5 font-semibold">Alert</th>
                <th scope="col" className="border-b bg-surface-2/50 px-3 py-2.5 font-semibold">Entity</th>
                <th scope="col" className="border-b bg-surface-2/50 px-3 py-2.5 font-semibold">Severity</th>
                <th scope="col" className="border-b bg-surface-2/50 px-3 py-2.5 text-right font-semibold">Score</th>
                <th scope="col" className="border-b bg-surface-2/50 px-3 py-2.5 font-semibold">Status</th>
                <th scope="col" className="border-b bg-surface-2/50 px-5 py-2.5 text-right font-semibold">Created</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} className={cn("relative cursor-pointer transition-colors hover:bg-accent/40", current === a.id && "bg-accent/60")} onClick={() => setCurrent(a.id)}>
                  <td className="relative border-b py-3 pl-5" onClick={(e) => e.stopPropagation()}>
                    <SeverityStrip severity={a.severity} className="rounded-none" />
                    <input
                      type="checkbox"
                      className="accent-[var(--primary)]"
                      aria-label={`Select alert ${a.ruleName}`}
                      checked={selected.has(a.id)}
                      onChange={(e) => {
                        const next = new Set(selected);
                        if (e.target.checked) next.add(a.id);
                        else next.delete(a.id);
                        setSelected(next);
                      }}
                    />
                  </td>
                  <td className="max-w-[34rem] border-b px-3 py-3">
                    <button type="button" className="text-left font-medium hover:underline" onClick={() => setCurrent(a.id)}>{a.ruleName}</button>
                    <div className="truncate text-xs text-muted-foreground">{a.summary}</div>
                  </td>
                  <td className="border-b px-3 py-3">
                    <span className="text-xs uppercase tracking-wider text-muted-foreground">{a.entity.kind}</span>
                    <div className="max-w-48 truncate">{a.entity.id}</div>
                  </td>
                  <td className="border-b px-3 py-3"><SeverityBadge severity={a.severity} /></td>
                  <td className="border-b px-3 py-3 text-right font-semibold tabular-nums">{a.score}</td>
                  <td className="border-b px-3 py-3">
                    <StatusBadge status={a.status} />
                    {a.incidentId ? <div className="mt-1 text-[0.7rem] text-muted-foreground">{a.incidentId}</div> : null}
                  </td>
                  <td className="whitespace-nowrap border-b px-5 py-3 text-right text-muted-foreground">{relTime(a.createdAt, now)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 ? <p className="p-10 text-center text-sm text-muted-foreground">No alerts match these filters.</p> : null}
        </div>
      </Card>

      {active ? (
        <div className="fixed inset-0 z-40" role="dialog" aria-modal="true" aria-labelledby="alert-title">
          <button type="button" aria-label="Close alert details" className="absolute inset-0 bg-black/45 backdrop-blur-[2px]" onClick={() => setCurrent(null)} />
          <aside className="animate-slide-in absolute inset-y-0 right-0 flex w-full max-w-[34rem] flex-col border-l bg-surface shadow-2xl">
            <div className="relative border-b px-6 py-5">
              <SeverityStrip severity={active.severity} className="rounded-none" />
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={active.severity} />
                    <StatusBadge status={active.status} />
                  </div>
                  <h2 id="alert-title" className="mt-2 text-lg font-semibold leading-snug">{active.ruleName}</h2>
                  <p className="mt-1 text-sm text-muted-foreground">{active.summary}</p>
                </div>
                <button ref={closeRef} type="button" onClick={() => setCurrent(null)} className="rounded-lg p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground" aria-label="Close">
                  <X className="size-5" />
                </button>
              </div>
            </div>
            <div className="flex-1 space-y-6 overflow-y-auto px-6 py-5">
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="rounded-xl border bg-surface-2/50 p-3">
                  <p className="text-xl font-semibold tabular-nums">{active.score}</p>
                  <p className="text-[0.7rem] text-muted-foreground">score</p>
                </div>
                <div className="rounded-xl border bg-surface-2/50 p-3">
                  <p className="text-xl font-semibold tabular-nums">{(active.latencyMs / 1000).toFixed(1)}s</p>
                  <p className="text-[0.7rem] text-muted-foreground">to detect</p>
                </div>
                <div className="rounded-xl border bg-surface-2/50 p-3">
                  <p className="text-xl font-semibold tabular-nums">{active.evidence.length}</p>
                  <p className="text-[0.7rem] text-muted-foreground">events</p>
                </div>
              </div>
              <Kv
                items={[
                  ["Created", utc(active.createdAt)],
                  ["Rule", <Link key="r" href={`/rules/${active.ruleId}`} className="text-primary hover:underline">{active.ruleId} · {active.ruleKind}</Link>],
                  ["Dataset", <code key="d" className="font-mono text-xs">{active.dataset}</code>],
                  ["Incident", active.incidentId ? <Link key="i" href={`/incidents/${active.incidentId}`} className="text-primary hover:underline">{active.incidentId}</Link> : "Not grouped"],
                  ...(active.closure ? ([["Closure", active.closure.replace(/_/g, " ")]] as [string, string][]) : []),
                ]}
              />
              <div>
                <p className="mb-2 text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground">Techniques</p>
                <div className="flex flex-wrap gap-1.5">
                  {active.techniques.map((t) => (
                    <span key={t} className="rounded-md border bg-surface-2/70 px-2 py-0.5 text-xs"><span className="font-mono text-muted-foreground">{t}</span> {techniqueById.get(t.split(".")[0]!)?.name}</span>
                  ))}
                </div>
              </div>
              <div>
                <p className="mb-2 text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground">Entities</p>
                <div className="flex flex-wrap gap-1.5">
                  {active.entities.map((e) => (
                    <Link key={`${e.kind}:${e.id}`} href={entityHref(e.kind, e.id)} className="rounded-lg border px-2 py-1 text-xs hover:bg-accent">
                      <span className="text-muted-foreground">{e.kind}</span> {e.id}
                    </Link>
                  ))}
                </div>
              </div>
              <Link
                href={searchHref(active.entity.kind === "ip" ? `source.ip:${active.entity.id}` : `${active.entity.kind === "user" ? "user.name" : "host.name"}:${active.entity.id}`)}
                className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
              >
                Search events for {active.entity.id} <ExternalLink className="size-3.5" aria-hidden />
              </Link>
            </div>
            {active.status !== "closed" ? (
              <div className="space-y-3 border-t bg-surface-2/40 px-6 py-4">
                <p className="text-xs text-muted-foreground">Triage — false-positive closures feed the rule&apos;s tuning suggestions.</p>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="outline" disabled={pending} onClick={() => patch([active.id], { status: "in_progress" })}>Start working</Button>
                  <Button size="sm" disabled={pending} onClick={() => patch([active.id], { closure: "true_positive" })}><CheckCheck aria-hidden /> True positive</Button>
                  <Button size="sm" variant="outline" disabled={pending} onClick={() => patch([active.id], { closure: "benign_true_positive" })}>Benign</Button>
                  <Button size="sm" variant="outline" disabled={pending} onClick={() => patch([active.id], { closure: "false_positive" })}>False positive</Button>
                </div>
              </div>
            ) : null}
          </aside>
        </div>
      ) : null}
    </>
  );
}
