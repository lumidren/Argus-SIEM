import type { Metadata } from "next";
import { Card, CardHeader, PageHeader, StatusBadge, Table, Td, Th } from "@/components/ui/primitives";
import { data, parseErrors, sources } from "@/lib/demo/store";
import { cn, compact, pct, relTime, utc } from "@/lib/utils";

export const metadata: Metadata = { title: "Sources" };
export const dynamic = "force-dynamic";

export default function SourcesPage() {
  const now = data().now;
  const all = sources();
  const totalEps = all.reduce((s, x) => s + x.eps, 0);
  return (
    <>
      <PageHeader title="Data sources" description={`${all.length} registered sources at ${compact(totalEps)} events per second. A source goes silent when it stops sending for longer than its learned cadence.`} />
      <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {(["healthy", "degraded", "silent"] as const).map((s) => (
          <Card key={s} className="p-4">
            <p className="text-xs font-medium capitalize text-muted-foreground">{s}</p>
            <p className={cn("mt-1 text-2xl font-semibold", s === "silent" && "text-bad", s === "degraded" && "text-sev-medium")}>{all.filter((x) => x.status === s).length}</p>
          </Card>
        ))}
        <Card className="p-4">
          <p className="text-xs font-medium text-muted-foreground">Events today</p>
          <p className="mt-1 text-2xl font-semibold">{compact(all.reduce((s, x) => s + x.eventsToday, 0))}</p>
        </Card>
      </div>
      <Card>
        <Table>
          <thead>
            <tr><Th>Source</Th><Th>Collector</Th><Th>Status</Th><Th>EPS</Th><Th>Parse failures</Th><Th>Lag</Th><Th>Last event</Th></tr>
          </thead>
          <tbody>
            {all.map((s) => (
              <tr key={s.id}>
                <Td>
                  <span className="font-medium">{s.name}</span>
                  <div className="font-mono text-xs text-muted-foreground">{s.dataset}</div>
                </Td>
                <Td>{s.collector}</Td>
                <Td><StatusBadge status={s.status} /></Td>
                <Td className="tabular-nums">{compact(s.eps)}</Td>
                <Td className={cn("tabular-nums", s.parseFailureRate > 0.01 && "font-medium text-bad")}>{pct(s.parseFailureRate, 2)}</Td>
                <Td className={cn("tabular-nums", s.lagSeconds > 30 && "text-sev-medium")}>{s.lagSeconds}s</Td>
                <Td className="whitespace-nowrap text-muted-foreground">{relTime(s.lastEventAt, now)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
      <Card className="mt-4">
        <CardHeader title="Recent parse errors" description="Unparsed records are preserved raw in the unparsed index and can be re-parsed after a fix." />
        <ul className="divide-y">
          {parseErrors().map((e, i) => (
            <li key={i} className="space-y-1 px-4 py-3 text-sm">
              <p>
                <span className="font-medium">{e.parser}</span> on <span className="font-mono text-xs">{e.sourceId}</span>{" "}
                <span className="text-xs text-muted-foreground">· {utc(e.at)}</span>
              </p>
              <p className="text-bad">{e.error}</p>
              <pre className="overflow-x-auto rounded bg-muted px-2 py-1 font-mono text-xs"><code>{e.sample}</code></pre>
            </li>
          ))}
        </ul>
      </Card>
    </>
  );
}
