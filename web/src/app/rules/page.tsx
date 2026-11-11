import type { Metadata } from "next";
import Link from "next/link";
import { Badge, Card, PageHeader, SeverityBadge, StatusBadge, Table, Td, Th, Segmented, segmentClass } from "@/components/ui/primitives";
import { rules } from "@/lib/demo/store";
import { cn, pct } from "@/lib/utils";

export const metadata: Metadata = { title: "Rules" };
export const dynamic = "force-dynamic";

const KINDS = ["all", "sigma", "threshold", "sequence", "aggregation", "ueba"] as const;

export default async function RulesPage({ searchParams }: { searchParams: Promise<{ kind?: string; status?: string; technique?: string }> }) {
  const { kind = "all", status = "all", technique } = await searchParams;
  const all = rules();
  const rows = all.filter((r) => (kind === "all" || r.kind === kind) && (status === "all" || r.status === status) && (!technique || r.techniques.some((t) => t === technique || t.startsWith(technique + "."))));
  const failing = all.filter((r) => r.tests.some((t) => !t.passed)).length;
  return (
    <>
      <PageHeader eyebrow="Detect & respond"
        title="Detection rules"
        description={`${all.length} rules versioned in Git. ${all.filter((r) => r.status === "production").length} in production, ${all.filter((r) => r.status === "staging").length} in staging (fire silently), ${failing} with failing tests.`}
        actions={<Link href="/coverage" className="text-sm text-primary hover:underline">ATT&CK coverage</Link>}
      />
      <nav aria-label="Rule filters" className="mb-4 flex flex-wrap gap-3">
        <Segmented aria-label="Rule kind">
          {KINDS.map((k) => (
            <Link key={k} href={`/rules?kind=${k}&status=${status}`} aria-current={k === kind ? "page" : undefined} className={segmentClass(k === kind)}>
              {k}
            </Link>
          ))}
        </Segmented>
        <Segmented aria-label="Rule status">
          {["all", "production", "staging", "experimental"].map((st) => (
            <Link key={st} href={`/rules?kind=${kind}&status=${st}`} aria-current={st === status ? "page" : undefined} className={segmentClass(st === status)}>
              {st}
            </Link>
          ))}
        </Segmented>
      </nav>
      {technique ? (
        <p className="mb-3 text-sm">
          Showing rules mapped to <code className="rounded bg-muted px-1 font-mono">{technique}</code>.{" "}
          <Link href="/rules" className="text-primary hover:underline">Clear</Link>
        </p>
      ) : null}
      <Card>
        <Table>
          <thead>
            <tr><Th>Rule</Th><Th>Kind</Th><Th>Severity</Th><Th>Status</Th><Th>ATT&CK</Th><Th>Alerts 7d</Th><Th>FP rate</Th><Th>Tests</Th></tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const passed = r.tests.filter((t) => t.passed).length;
              return (
                <tr key={r.id} className="hover:bg-accent/50">
                  <Td>
                    <Link href={`/rules/${r.id}`} className="font-medium hover:underline">{r.name}</Link>
                    <div className="text-xs text-muted-foreground">{r.id} · v{r.version} · {r.logsource}</div>
                  </Td>
                  <Td className="capitalize">{r.kind}</Td>
                  <Td><SeverityBadge severity={r.severity} /></Td>
                  <Td><StatusBadge status={r.status} /></Td>
                  <Td><div className="flex flex-wrap gap-1">{r.techniques.map((t) => <Badge key={t} className="font-mono">{t}</Badge>)}</div></Td>
                  <Td className="tabular-nums">{r.alerts7d}</Td>
                  <Td className={cn("tabular-nums", r.fpRate > 0.25 && "text-bad")}>{pct(r.fpRate, 0)}</Td>
                  <Td className={cn("tabular-nums", passed < r.tests.length && "text-bad")}>{passed}/{r.tests.length}</Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      </Card>
    </>
  );
}
