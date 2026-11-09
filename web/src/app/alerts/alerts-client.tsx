"use client";

import { Check, CheckCheck, ExternalLink, XCircle } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState, useTransition } from "react";
import { Badge, Button, Card, CardBody, CardHeader, Input, Kv, Select, SeverityBadge, StatusBadge } from "@/components/ui/primitives";
import { techniqueById } from "@/lib/attack";
import type { Alert, AlertStatus, Closure } from "@/lib/types";
import { cn, entityHref, relTime, searchHref, utc } from "@/lib/utils";

export function AlertsClient({ alerts, now, focus }: { alerts: Alert[]; now: number; focus?: string }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const [status, setStatus] = useState<AlertStatus | "all">("open");
  const [sev, setSev] = useState("all");
  const [text, setText] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [current, setCurrent] = useState<string | null>(focus ?? null);
  const [error, setError] = useState<string | null>(null);

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
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_26rem]">
      <Card>
        <div className="flex flex-wrap items-end gap-2 border-b p-3">
          <div>
            <label htmlFor="f-status" className="sr-only">Status</label>
            <Select id="f-status" value={status} onChange={(e) => setStatus(e.target.value as AlertStatus | "all")}>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="in_progress">In progress</option>
              <option value="closed">Closed</option>
              <option value="all">All statuses</option>
            </Select>
          </div>
          <div>
            <label htmlFor="f-sev" className="sr-only">Severity</label>
            <Select id="f-sev" value={sev} onChange={(e) => setSev(e.target.value)}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </Select>
          </div>
          <div className="min-w-48 flex-1">
            <label htmlFor="f-text" className="sr-only">Filter</label>
            <Input id="f-text" value={text} onChange={(e) => setText(e.target.value)} placeholder="Filter by rule, summary or entity" />
          </div>
          <div className="flex gap-2" aria-live="polite">
            <Button size="sm" variant="outline" disabled={!ids.length || pending} onClick={() => patch(ids, { status: "acknowledged" })}>
              <Check aria-hidden /> Acknowledge {ids.length ? `(${ids.length})` : ""}
            </Button>
            <Button size="sm" variant="outline" disabled={!ids.length || pending} onClick={() => patch(ids, { closure: "false_positive" })}>
              <XCircle aria-hidden /> Close as false positive
            </Button>
          </div>
        </div>
        {error ? <p className="border-b px-3 py-2 text-sm text-bad">{error}</p> : null}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th scope="col" className="w-8 border-b px-3 py-2">
                  <input type="checkbox" aria-label="Select all visible alerts" checked={allChecked} onChange={(e) => setSelected(e.target.checked ? new Set(rows.map((r) => r.id)) : new Set())} />
                </th>
                <th scope="col" className="border-b px-3 py-2 font-medium">Alert</th>
                <th scope="col" className="border-b px-3 py-2 font-medium">Severity</th>
                <th scope="col" className="border-b px-3 py-2 font-medium">Score</th>
                <th scope="col" className="border-b px-3 py-2 font-medium">Status</th>
                <th scope="col" className="border-b px-3 py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} className={cn("cursor-pointer hover:bg-accent/50", current === a.id && "bg-accent")} onClick={() => setCurrent(a.id)}>
                  <td className="border-b px-3 py-2" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
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
                  <td className="border-b px-3 py-2">
                    <button type="button" className="text-left font-medium hover:underline" onClick={() => setCurrent(a.id)}>
                      {a.ruleName}
                    </button>
                    <div className="text-xs text-muted-foreground">{a.summary}</div>
                    {a.incidentId ? <Badge className="mt-1 text-muted-foreground">{a.incidentId}</Badge> : null}
                  </td>
                  <td className="border-b px-3 py-2"><SeverityBadge severity={a.severity} /></td>
                  <td className="border-b px-3 py-2 tabular-nums">{a.score}</td>
                  <td className="border-b px-3 py-2"><StatusBadge status={a.status} /></td>
                  <td className="whitespace-nowrap border-b px-3 py-2 text-muted-foreground">{relTime(a.createdAt, now)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 ? <p className="p-8 text-center text-sm text-muted-foreground">No alerts match these filters.</p> : null}
        </div>
      </Card>

      <aside aria-label="Alert details">
        {active ? (
          <Card className="sticky top-20">
            <CardHeader title={active.ruleName} description={`${active.id} · ${active.ruleKind} rule`} actions={<SeverityBadge severity={active.severity} />} />
            <CardBody className="space-y-4">
              <p className="text-sm">{active.summary}</p>
              <Kv
                items={[
                  ["Created", utc(active.createdAt)],
                  ["Status", <StatusBadge key="s" status={active.status} />],
                  ["Score", `${active.score} / 100`],
                  ["Detection latency", `${(active.latencyMs / 1000).toFixed(2)} s`],
                  ["Dataset", active.dataset],
                  ["Entity", <Link key="e" className="text-primary hover:underline" href={entityHref(active.entity.kind, active.entity.id)}>{active.entity.kind} {active.entity.id}</Link>],
                  ["Techniques", active.techniques.map((t) => `${t} ${techniqueById.get(t.split(".")[0]!)?.name ?? ""}`).join(", ")],
                  ...(active.closure ? ([["Closure", active.closure.replace(/_/g, " ")]] as [string, string][]) : []),
                ]}
              />
              <div>
                <p className="mb-1 text-xs font-medium text-muted-foreground">Related entities</p>
                <div className="flex flex-wrap gap-1">
                  {active.entities.map((e) => (
                    <Link key={`${e.kind}:${e.id}`} href={entityHref(e.kind, e.id)} className="rounded-md border px-1.5 py-0.5 text-xs hover:bg-accent">
                      {e.kind}: {e.id}
                    </Link>
                  ))}
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <Link href={`/rules/${active.ruleId}`} className="inline-flex items-center gap-1 text-sm text-primary hover:underline">
                  Rule <ExternalLink className="size-3.5" aria-hidden />
                </Link>
                <Link href={searchHref(active.entity.kind === "ip" ? `source.ip:${active.entity.id}` : `${active.entity.kind === "user" ? "user.name" : "host.name"}:${active.entity.id}`)} className="inline-flex items-center gap-1 text-sm text-primary hover:underline">
                  Events for entity <ExternalLink className="size-3.5" aria-hidden />
                </Link>
                {active.incidentId ? (
                  <Link href={`/incidents/${active.incidentId}`} className="inline-flex items-center gap-1 text-sm text-primary hover:underline">
                    Incident {active.incidentId} <ExternalLink className="size-3.5" aria-hidden />
                  </Link>
                ) : null}
              </div>
              {active.status !== "closed" ? (
                <div className="space-y-2 border-t pt-3">
                  <p className="text-xs font-medium text-muted-foreground">Triage</p>
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" variant="outline" disabled={pending} onClick={() => patch([active.id], { status: "in_progress" })}>Start working</Button>
                    <Button size="sm" variant="outline" disabled={pending} onClick={() => patch([active.id], { closure: "true_positive" })}>
                      <CheckCheck aria-hidden /> True positive
                    </Button>
                    <Button size="sm" variant="outline" disabled={pending} onClick={() => patch([active.id], { closure: "benign_true_positive" })}>Benign true positive</Button>
                    <Button size="sm" variant="outline" disabled={pending} onClick={() => patch([active.id], { closure: "false_positive" })}>False positive</Button>
                  </div>
                  <p className="text-xs text-muted-foreground">False-positive closures feed the rule&apos;s tuning suggestions.</p>
                </div>
              ) : null}
            </CardBody>
          </Card>
        ) : (
          <Card className="p-6 text-sm text-muted-foreground">Select an alert to see its details.</Card>
        )}
      </aside>
    </div>
  );
}
