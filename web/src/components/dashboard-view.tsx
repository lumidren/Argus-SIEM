import { Bars, Histogram } from "@/components/charts";
import { Card, CardBody, CardHeader, Table, Td, Th } from "@/components/ui/primitives";
import type { DashboardPanel } from "@/lib/types";
import { cn } from "@/lib/utils";

export function DashboardView({ panels }: { panels: DashboardPanel[] }) {
  const stats = panels.filter((p) => p.kind === "stat");
  const rest = panels.filter((p) => p.kind !== "stat");
  return (
    <div className="space-y-4">
      {stats.length ? (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {stats.map((p) =>
            p.kind === "stat" ? (
              <Card key={p.title} className="p-4">
                <p className="text-xs font-medium text-muted-foreground">{p.title}</p>
                <p className={cn("mt-1 text-2xl font-semibold tabular-nums", p.tone === "bad" && "text-bad", p.tone === "good" && "text-good")}>{p.value}</p>
                {p.delta ? <p className="mt-1 text-xs text-muted-foreground">{p.delta}</p> : null}
              </Card>
            ) : null,
          )}
        </div>
      ) : null}
      <div className="grid gap-4 lg:grid-cols-2">
        {rest.map((p) => (
          <Card key={p.title} className={cn(p.kind === "series" && "lg:col-span-2")}>
            <CardHeader title={p.title} />
            <CardBody>
              {p.kind === "series" ? (
                <>
                  <Histogram label={p.title} points={p.points.map((x) => ({ at: x.at, count: x.value }))} />
                  <div className="mt-1 flex justify-between text-[0.7rem] text-muted-foreground">
                    <span>{p.points[0]?.at.slice(11, 16)} UTC</span>
                    <span>now</span>
                  </div>
                </>
              ) : p.kind === "bars" ? (
                p.rows.length ? <Bars rows={p.rows} /> : <p className="text-sm text-muted-foreground">No data in range.</p>
              ) : p.kind === "table" ? (
                <Table>
                  <thead>
                    <tr>
                      {p.columns.map((c) => (
                        <Th key={c}>{c}</Th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {p.rows.map((r, i) => (
                      <tr key={i}>
                        {r.map((c, j) => (
                          <Td key={j} className="font-mono text-xs">
                            {c}
                          </Td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </Table>
              ) : null}
            </CardBody>
          </Card>
        ))}
      </div>
    </div>
  );
}
