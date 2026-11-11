import { AreaChart, Bars } from "@/components/charts";
import { Card, CardBody, CardHeader, Stat, Table, Td, Th } from "@/components/ui/primitives";
import type { DashboardPanel } from "@/lib/types";
import { cn } from "@/lib/utils";

export function DashboardView({ panels }: { panels: DashboardPanel[] }) {
  const stats = panels.filter((p) => p.kind === "stat");
  const rest = panels.filter((p) => p.kind !== "stat");
  return (
    <div className="space-y-4">
      {stats.length ? (
        <div className={cn("grid grid-cols-2 gap-4", stats.length >= 4 ? "lg:grid-cols-4" : "lg:grid-cols-3")}>
          {stats.map((p) =>
            p.kind === "stat" ? <Stat key={p.title} label={p.title} value={p.value} {...(p.delta ? { sub: p.delta } : {})} tone={p.tone ?? "neutral"} /> : null,
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
                  <AreaChart label={p.title} points={p.points} height={180} />
                  <div className="mt-1 flex justify-between text-[0.7rem] text-muted-foreground">
                    <span>{p.points[0]?.at.slice(11, 16)} UTC</span>
                    <span>12h ago</span>
                    <span>now</span>
                  </div>
                </>
              ) : p.kind === "bars" ? (
                p.rows.length ? <Bars rows={p.rows} /> : <p className="text-sm text-muted-foreground">No data in range.</p>
              ) : p.kind === "table" ? (
                <div className="-mx-5">
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
                </div>
              ) : null}
            </CardBody>
          </Card>
        ))}
      </div>
    </div>
  );
}
