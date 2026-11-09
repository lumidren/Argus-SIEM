import { Activity, ArrowRight, BellRing, Briefcase, Clock3, Database, Flame, Gauge as GaugeIcon, Timer } from "lucide-react";
import Link from "next/link";
import { AreaChart, AttackChain, Bars, Gauge, RiskMeter, SeverityDonut, Sparkline } from "@/components/charts";
import { Card, CardBody, CardHeader, PageHeader, SeverityBadge, SeverityStrip, Stat, StatusBadge } from "@/components/ui/primitives";
import { tacticById } from "@/lib/attack";
import { attackChain, data, listIncidents, sources, topEntities } from "@/lib/demo/store";
import type { Severity } from "@/lib/types";
import { cn, compact, entityHref, relTime, slaLeft } from "@/lib/utils";

export const dynamic = "force-dynamic";

const HOUR = 3_600_000;

function hourly(times: number[], now: number, hours = 24) {
  const out = Array.from({ length: hours }, (_, i) => ({ at: new Date(now - (hours - i) * HOUR).toISOString(), value: 0 }));
  for (const t of times) {
    const i = hours - 1 - Math.floor((now - t) / HOUR);
    if (i >= 0 && i < hours) out[i]!.value++;
  }
  return out;
}

export default function OverviewPage() {
  const d = data();
  const { alerts, events, now } = d;
  const open = listIncidents("open").sort((a, b) => b.score - a.score);
  const lead = open[0];
  const openAlerts = alerts.filter((a) => a.status !== "closed");
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<Severity, number>;
  for (const a of openAlerts) sevCounts[a.severity]++;
  const alertSeries = hourly(alerts.map((a) => Date.parse(a.createdAt)), now);
  const eventSeries = hourly(events.map((e) => Date.parse(e["@timestamp"])), now).map((p) => ({ ...p, value: p.value * 1800 }));
  const latencies = alerts.map((a) => a.latencyMs).sort((a, b) => a - b);
  const p95 = latencies[Math.floor(latencies.length * 0.95)]! / 1000;
  const p50 = latencies[Math.floor(latencies.length * 0.5)]! / 1000;
  const tactics = new Map<string, number>();
  for (const a of openAlerts) for (const t of a.tactics) tactics.set(t, (tactics.get(t) ?? 0) + 1);
  const srcs = sources();
  const chain = lead ? attackChain(lead) : null;
  const sla = lead ? slaLeft(lead.slaDueAt, now) : null;

  return (
    <>
      <PageHeader
        eyebrow="Security operations · Acme Corp"
        title="Overview"
        description="What needs attention right now, ranked by risk."
        actions={
          <span className="inline-flex items-center gap-2 rounded-lg border bg-surface px-3 py-1.5 text-xs text-muted-foreground">
            <Clock3 className="size-3.5" aria-hidden /> Last 24 hours · UTC
          </span>
        }
      />

      {lead && chain && sla ? (
        <Card className="mb-6 overflow-hidden border-sev-critical/40">
          <div aria-hidden className="pointer-events-none absolute inset-0 bg-[radial-gradient(700px_220px_at_0%_0%,color-mix(in_oklch,var(--sev-critical)_16%,transparent),transparent)]" />
          <SeverityStrip severity={lead.severity} />
          <div className="relative grid gap-6 p-5 xl:grid-cols-[minmax(0,1fr)_auto]">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-flex items-center gap-1.5 rounded-full bg-sev-critical/15 px-2.5 py-0.5 text-xs font-semibold text-sev-critical">
                  <Flame className="size-3.5" aria-hidden /> Active attack
                </span>
                <span className="text-xs text-muted-foreground">{lead.id} · opened {relTime(lead.createdAt, now)} · assigned to {lead.assignee ?? "nobody"}</span>
              </div>
              <h2 className="mt-2 text-xl font-semibold tracking-tight">{lead.title}</h2>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {lead.tactics.map((t) => (
                  <span key={t} className="rounded-md border bg-surface-2/70 px-2 py-0.5 text-xs">{tacticById.get(t)?.name ?? t}</span>
                ))}
              </div>
              <div className="mt-4 rounded-xl border bg-background/40 p-3">
                <AttackChain columns={chain.columns} edges={chain.edges} label={`Attack chain for ${lead.id}`} />
              </div>
            </div>
            <div className="flex flex-row items-center gap-6 xl:flex-col xl:justify-between">
              <Gauge value={lead.score} label="Risk score" sub="rule × asset × entity" />
              <div className="text-center">
                <p className={cn("text-2xl font-semibold tabular-nums", sla.overdue ? "text-bad" : "text-warn")}>{sla.text}</p>
                <p className="text-xs text-muted-foreground">SLA remaining</p>
              </div>
              <Link href={`/incidents/${lead.id}`} className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow-sm shadow-primary/30 hover:brightness-110">
                Open investigation <ArrowRight className="size-4" aria-hidden />
              </Link>
            </div>
          </div>
        </Card>
      ) : null}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Open alerts" value={openAlerts.length} tone="bad" icon={<BellRing />} sub={`${sevCounts.critical + sevCounts.high} critical or high`}>
          <Sparkline label="Alerts per hour" values={alertSeries.map((p) => p.value)} color="var(--bad)" />
        </Stat>
        <Stat label="Open incidents" value={open.length} tone="warn" icon={<Briefcase />} sub={`${open.filter((i) => i.severity === "critical").length} critical · ${open.filter((i) => !i.assignee).length} unassigned`}>
          <div className="flex gap-1">
            {open.map((i) => (
              <span key={i.id} className={cn("h-2 flex-1 rounded-full", { critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium", low: "bg-sev-low" }[i.severity])} title={`${i.id} ${i.severity}`} />
            ))}
          </div>
        </Stat>
        <Stat label="Events ingested" value={compact(eventSeries.reduce((s, p) => s + p.value, 0))} icon={<Activity />} sub="+4.1% vs prior day">
          <Sparkline label="Events per hour" values={eventSeries.map((p) => p.value)} />
        </Stat>
        <Stat label="Detection latency p95" value={`${p95.toFixed(1)}s`} tone="good" icon={<Timer />} sub={`p50 ${p50.toFixed(1)}s · target < 5s`}>
          <div className="h-1.5 overflow-hidden rounded-full bg-surface-2">
            <div className="h-full rounded-full bg-good" style={{ width: `${Math.min(100, (p95 / 5) * 100)}%` }} />
          </div>
        </Stat>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Alert activity" description="Detections per hour across all rules" icon={<GaugeIcon />} />
          <CardBody>
            <AreaChart label="Alerts per hour" points={alertSeries} height={170} />
            <div className="mt-1 flex justify-between text-[0.7rem] text-muted-foreground">
              <span>24h ago</span>
              <span>12h ago</span>
              <span>now</span>
            </div>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Open alerts by severity" description="Including in-progress and acknowledged" />
          <CardBody className="flex items-center justify-center py-4">
            <SeverityDonut counts={sevCounts} label="Open alerts by severity" />
          </CardBody>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader
            title="Alert stream"
            description="Newest first"
            icon={<BellRing />}
            actions={<Link className="text-sm text-primary hover:underline" href="/alerts">Open queue →</Link>}
          />
          <ul className="divide-y border-t">
            {alerts.slice(0, 7).map((a) => (
              <li key={a.id} className="relative">
                <SeverityStrip severity={a.severity} className="rounded-none" />
                <Link href={`/alerts?focus=${a.id}`} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 px-5 py-3 hover:bg-accent/40">
                  <span className="min-w-0">
                    <span className="flex items-center gap-2">
                      <span className="truncate font-medium">{a.ruleName}</span>
                      {a.incidentId ? <span className="shrink-0 rounded bg-surface-2 px-1.5 text-[0.7rem] text-muted-foreground">{a.incidentId}</span> : null}
                    </span>
                    <span className="block truncate text-xs text-muted-foreground">{a.summary}</span>
                  </span>
                  <span className="flex items-center gap-3">
                    <SeverityBadge severity={a.severity} />
                    <span className="w-20 text-right text-xs text-muted-foreground">{relTime(a.createdAt, now)}</span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
        <Card>
          <CardHeader title="Riskiest entities" description="Behavioural risk, decaying over time" actions={<Link className="text-sm text-primary hover:underline" href="/entities">All →</Link>} />
          <ul className="divide-y border-t">
            {[...topEntities("user", 4), ...topEntities("host", 3), ...topEntities("ip", 1)].sort((a, b) => b.risk - a.risk).slice(0, 7).map((p) => (
              <li key={`${p.ref.kind}:${p.ref.id}`}>
                <Link href={entityHref(p.ref.kind, p.ref.id)} className="flex items-center justify-between gap-3 px-5 py-2.5 hover:bg-accent/40">
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-medium">{p.displayName}</span>
                    <span className="text-[0.7rem] uppercase tracking-wider text-muted-foreground">{p.ref.kind}</span>
                  </span>
                  <RiskMeter value={p.risk} />
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Incidents in flight" actions={<Link className="text-sm text-primary hover:underline" href="/incidents">All incidents →</Link>} />
          <div className="grid gap-3 px-5 pb-5 md:grid-cols-2">
            {open.slice(0, 4).map((i) => {
              const s = slaLeft(i.slaDueAt, now);
              return (
                <Link key={i.id} href={`/incidents/${i.id}`} className="relative overflow-hidden rounded-xl border bg-surface-2/40 p-4 hover:border-border-strong hover:bg-accent/30">
                  <SeverityStrip severity={i.severity} />
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs text-muted-foreground">{i.id}</span>
                    <StatusBadge status={i.status} />
                  </div>
                  <p className="mt-1.5 line-clamp-2 font-medium leading-snug">{i.title}</p>
                  <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground">
                    <span>{i.alertIds.length} alerts · {i.assignee ?? "unassigned"}</span>
                    <span className={s.overdue ? "font-medium text-bad" : ""}>{s.text}</span>
                  </div>
                </Link>
              );
            })}
          </div>
        </Card>
        <Card>
          <CardHeader title="Tactics in open alerts" description="MITRE ATT&CK" />
          <CardBody>
            <Bars rows={[...tactics.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([t, n]) => ({ label: tacticById.get(t)?.name ?? t, value: n }))} color="bg-chart-3" />
          </CardBody>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader title="Source health" icon={<Database />} actions={<Link className="text-sm text-primary hover:underline" href="/sources">Sources →</Link>} />
        <div className="grid gap-px overflow-hidden rounded-b-xl border-t bg-border sm:grid-cols-2 lg:grid-cols-5">
          {srcs.map((s) => (
            <div key={s.id} className="flex items-center justify-between gap-2 bg-surface px-4 py-3">
              <span className="min-w-0">
                <span className="block truncate text-sm">{s.name}</span>
                <span className="text-xs text-muted-foreground">{s.status === "silent" ? `silent ${relTime(s.lastEventAt, now)}` : `${compact(s.eps)} eps`}</span>
              </span>
              <span className={cn("size-2.5 shrink-0 rounded-full", s.status === "healthy" ? "bg-good" : s.status === "degraded" ? "bg-warn" : "bg-bad animate-live")} role="img" aria-label={s.status} />
            </div>
          ))}
        </div>
      </Card>
    </>
  );
}
