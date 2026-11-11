import type { Metadata } from "next";
import Link from "next/link";
import { Card, PageHeader, Segmented, segmentClass, SeverityBadge, StatusBadge, Table, Td, Th } from "@/components/ui/primitives";
import { data, listIncidents } from "@/lib/demo/store";
import { INCIDENT_STATUSES } from "@/lib/types";
import { cn, relTime, slaLeft } from "@/lib/utils";

export const metadata: Metadata = { title: "Incidents" };
export const dynamic = "force-dynamic";

const FILTERS = ["open", "all", ...INCIDENT_STATUSES] as const;

export default async function IncidentsPage({ searchParams }: { searchParams: Promise<{ status?: string }> }) {
  const { status = "open" } = await searchParams;
  const filter = (FILTERS as readonly string[]).includes(status) ? (status as (typeof FILTERS)[number]) : "open";
  const rows = listIncidents(filter);
  const now = data().now;
  return (
    <>
      <PageHeader eyebrow="Investigate" title="Incidents" description="Alerts grouped by entity, technique and time window. Each incident carries an SLA timer from its severity." />
      <nav aria-label="Incident status filter" className="mb-4">
        <Segmented>
          {FILTERS.map((f) => (
            <Link key={f} href={`/incidents?status=${f}`} aria-current={f === filter ? "page" : undefined} className={segmentClass(f === filter)}>
              {f}
            </Link>
          ))}
        </Segmented>
      </nav>
      <Card>
        <Table>
          <thead>
            <tr>
              <Th>Incident</Th>
              <Th>Severity</Th>
              <Th>Score</Th>
              <Th>Status</Th>
              <Th>Assignee</Th>
              <Th>Alerts</Th>
              <Th>SLA</Th>
              <Th>Updated</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((i) => {
              const sla = slaLeft(i.slaDueAt, now);
              const done = i.status === "closed" || i.status === "resolved";
              return (
                <tr key={i.id} className="hover:bg-accent/50">
                  <Td>
                    <Link href={`/incidents/${i.id}`} className="font-medium hover:underline">{i.title}</Link>
                    <div className="text-xs text-muted-foreground">{i.id}{i.tags.length ? ` · ${i.tags.join(", ")}` : ""}</div>
                  </Td>
                  <Td><SeverityBadge severity={i.severity} /></Td>
                  <Td className="tabular-nums">{i.score}</Td>
                  <Td><StatusBadge status={i.status} /></Td>
                  <Td>{i.assignee ?? <span className="text-muted-foreground">unassigned</span>}</Td>
                  <Td className="tabular-nums">{i.alertIds.length}</Td>
                  <Td className={cn("whitespace-nowrap", !done && sla.overdue && "font-medium text-bad")}>{done ? "—" : sla.text}</Td>
                  <Td className="whitespace-nowrap text-muted-foreground">{relTime(i.updatedAt, now)}</Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
        {rows.length === 0 ? <p className="p-8 text-center text-sm text-muted-foreground">No incidents with this status.</p> : null}
      </Card>
    </>
  );
}
