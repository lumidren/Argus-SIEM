import Link from "next/link";
import { RiskMeter } from "@/components/charts";
import { DashboardView } from "@/components/dashboard-view";
import { Card, CardHeader, PageHeader, SeverityBadge, StatusBadge, Table, Td, Th } from "@/components/ui/primitives";
import { dashboards, data, listIncidents, topEntities } from "@/lib/demo/store";
import { entityHref, relTime, slaLeft } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default function OverviewPage() {
  const soc = dashboards().find((d) => d.id === "soc")!;
  const open = listIncidents("open");
  const { alerts, now } = data();
  return (
    <>
      <PageHeader title="Overview" description="What needs attention now across the Acme tenant." />
      <DashboardView panels={soc.panels} />
      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Open incidents" description="Sorted by score" actions={<Link className="text-sm text-primary hover:underline" href="/incidents">All incidents</Link>} />
          <Table>
            <thead>
              <tr>
                <Th>Incident</Th>
                <Th>Severity</Th>
                <Th>Status</Th>
                <Th>Assignee</Th>
                <Th>SLA</Th>
              </tr>
            </thead>
            <tbody>
              {[...open].sort((a, b) => b.score - a.score).map((i) => {
                const sla = slaLeft(i.slaDueAt, now);
                return (
                  <tr key={i.id} className="hover:bg-accent/50">
                    <Td>
                      <Link href={`/incidents/${i.id}`} className="font-medium hover:underline">
                        {i.title}
                      </Link>
                      <div className="text-xs text-muted-foreground">{i.id} · {i.alertIds.length} alerts</div>
                    </Td>
                    <Td><SeverityBadge severity={i.severity} /></Td>
                    <Td><StatusBadge status={i.status} /></Td>
                    <Td>{i.assignee ?? <span className="text-muted-foreground">unassigned</span>}</Td>
                    <Td className={sla.overdue ? "text-bad" : ""}>{sla.text}</Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        </Card>
        <Card>
          <CardHeader title="Riskiest entities" description="UEBA risk with decay" actions={<Link className="text-sm text-primary hover:underline" href="/entities">Entities</Link>} />
          <ul className="divide-y">
            {[...topEntities("user", 4), ...topEntities("host", 3)].sort((a, b) => b.risk - a.risk).map((p) => (
              <li key={`${p.ref.kind}:${p.ref.id}`} className="flex items-center justify-between gap-3 px-4 py-2">
                <Link href={entityHref(p.ref.kind, p.ref.id)} className="min-w-0 truncate text-sm hover:underline">
                  <span className="mr-1.5 text-xs uppercase text-muted-foreground">{p.ref.kind}</span>
                  {p.displayName}
                </Link>
                <RiskMeter value={p.risk} />
              </li>
            ))}
          </ul>
        </Card>
      </div>
      <Card className="mt-4">
        <CardHeader title="Latest alerts" actions={<Link className="text-sm text-primary hover:underline" href="/alerts">Alert queue</Link>} />
        <Table>
          <thead>
            <tr>
              <Th>Alert</Th>
              <Th>Severity</Th>
              <Th>Entity</Th>
              <Th>When</Th>
            </tr>
          </thead>
          <tbody>
            {alerts.slice(0, 8).map((a) => (
              <tr key={a.id}>
                <Td>
                  <Link href={`/alerts?focus=${a.id}`} className="font-medium hover:underline">{a.ruleName}</Link>
                  <div className="text-xs text-muted-foreground">{a.summary}</div>
                </Td>
                <Td><SeverityBadge severity={a.severity} /></Td>
                <Td><Link className="hover:underline" href={entityHref(a.entity.kind, a.entity.id)}>{a.entity.id}</Link></Td>
                <Td className="whitespace-nowrap text-muted-foreground">{relTime(a.createdAt, now)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </>
  );
}
