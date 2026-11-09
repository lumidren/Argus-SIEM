import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { RiskMeter, Sparkline } from "@/components/charts";
import { Card, CardBody, CardHeader, Kv, PageHeader, SeverityBadge, StatusBadge, Table, Td, Th } from "@/components/ui/primitives";
import { data, entityAlerts, entityEvents, getEntity } from "@/lib/demo/store";
import type { EntityRef } from "@/lib/types";
import { entityHref, relTime, searchHref, utc } from "@/lib/utils";

export const dynamic = "force-dynamic";

const KINDS = ["user", "host", "ip"] as const;

export async function generateMetadata({ params }: { params: Promise<{ kind: string; id: string }> }): Promise<Metadata> {
  const { id } = await params;
  return { title: decodeURIComponent(id) };
}

export default async function EntityPage({ params }: { params: Promise<{ kind: string; id: string }> }) {
  const { kind, id: rawId } = await params;
  if (!(KINDS as readonly string[]).includes(kind)) notFound();
  const id = decodeURIComponent(rawId);
  const ref: EntityRef = { kind: kind as EntityRef["kind"], id };
  const p = getEntity(ref.kind, id);
  const events = entityEvents(ref, 60);
  const alerts = entityAlerts(ref);
  if (!p && events.length === 0 && alerts.length === 0) notFound();
  const now = data().now;
  const field = ref.kind === "user" ? "user.name" : ref.kind === "host" ? "host.name" : "source.ip";
  const hosts = new Map<string, number>();
  for (const e of entityEvents(ref, 2000)) {
    const h = String(ref.kind === "user" ? e["host.name"] ?? "" : e["user.name"] ?? "");
    if (h) hosts.set(h, (hosts.get(h) ?? 0) + 1);
  }
  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-sm text-muted-foreground">
        <Link href="/entities" className="hover:underline">Entities</Link> / {ref.kind}
      </nav>
      <PageHeader
        title={id}
        description={`${ref.kind === "ip" ? "IP address" : ref.kind === "user" ? "User account" : "Host"}${p ? ` · first seen ${relTime(p.firstSeen, now)}, last seen ${relTime(p.lastSeen, now)}` : ""}`}
        actions={<Link href={searchHref(`${field}:${id}`)} className="text-sm text-primary hover:underline">All events in search</Link>}
      />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader title="Risk" description="24-hour history" />
          <CardBody className="space-y-3">
            <RiskMeter value={p?.risk ?? 0} />
            {p ? <Sparkline label="Risk over 24 hours" values={p.riskHistory.map((h) => h.value)} /> : null}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Attributes" description="From asset inventory and the identity directory" />
          <CardBody>{p ? <Kv items={Object.entries(p.attributes)} /> : <p className="text-sm text-muted-foreground">No inventory record.</p>}</CardBody>
        </Card>
        <Card>
          <CardHeader title={ref.kind === "user" ? "Hosts accessed" : "Accounts seen"} />
          <CardBody>
            <ul className="space-y-1 text-sm">
              {[...hosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([h, n]) => (
                <li key={h} className="flex justify-between gap-2">
                  <Link href={entityHref(ref.kind === "user" ? "host" : "user", h)} className="truncate hover:underline">{h}</Link>
                  <span className="tabular-nums text-muted-foreground">{n}</span>
                </li>
              ))}
              {hosts.size === 0 ? <li className="text-muted-foreground">None in range.</li> : null}
            </ul>
            {p?.peers.length ? (
              <div className="mt-3 border-t pt-3">
                <p className="mb-1 text-xs font-medium text-muted-foreground">Linked in incidents</p>
                <div className="flex flex-wrap gap-1">
                  {p.peers.map((x) => (
                    <Link key={`${x.kind}:${x.id}`} href={entityHref(x.kind, x.id)} className="rounded-md border px-1.5 py-0.5 text-xs hover:bg-accent">{x.kind}: {x.id}</Link>
                  ))}
                </div>
              </div>
            ) : null}
          </CardBody>
        </Card>
      </div>
      <Card className="mt-4">
        <CardHeader title={`Alerts (${alerts.length})`} />
        <Table>
          <thead>
            <tr><Th>Alert</Th><Th>Severity</Th><Th>Status</Th><Th>When</Th></tr>
          </thead>
          <tbody>
            {alerts.slice(0, 20).map((a) => (
              <tr key={a.id}>
                <Td><Link href={`/alerts?focus=${a.id}`} className="font-medium hover:underline">{a.ruleName}</Link><div className="text-xs text-muted-foreground">{a.summary}</div></Td>
                <Td><SeverityBadge severity={a.severity} /></Td>
                <Td><StatusBadge status={a.status} /></Td>
                <Td className="whitespace-nowrap text-muted-foreground">{relTime(a.createdAt, now)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
        {alerts.length === 0 ? <p className="p-6 text-center text-sm text-muted-foreground">No alerts for this entity.</p> : null}
      </Card>
      <Card className="mt-4">
        <CardHeader title="Timeline" description="Most recent events" />
        <ol className="divide-y">
          {events.map((e) => (
            <li key={e.id} className="grid gap-1 px-4 py-2 text-sm sm:grid-cols-[12rem_10rem_minmax(0,1fr)]">
              <time dateTime={e["@timestamp"]} className="font-mono text-xs text-muted-foreground">{utc(e["@timestamp"])}</time>
              <span className="truncate text-xs text-muted-foreground">{String(e["event.dataset"])}</span>
              <span className="truncate">{String(e["event.action"] ?? e.message ?? "")} {e["source.ip"] ? <span className="text-muted-foreground">from {String(e["source.ip"])}</span> : null}{e["host.name"] && ref.kind !== "host" ? <span className="text-muted-foreground"> on {String(e["host.name"])}</span> : null}</span>
            </li>
          ))}
        </ol>
      </Card>
    </>
  );
}
