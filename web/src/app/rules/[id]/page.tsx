import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Badge, Card, CardBody, CardHeader, Kv, PageHeader, SeverityBadge, StatusBadge } from "@/components/ui/primitives";
import { tacticById, techniqueById } from "@/lib/attack";
import { data, getRule } from "@/lib/demo/store";
import { pct, relTime } from "@/lib/utils";
import { TestRunner } from "./test-runner";

export const dynamic = "force-dynamic";

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }): Promise<Metadata> {
  const { id } = await params;
  return { title: getRule(id)?.name ?? "Rule" };
}

export default async function RulePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const r = getRule(id);
  if (!r) notFound();
  const d = data();
  const alerts = d.alerts.filter((a) => a.ruleId === r.id);
  const fps = alerts.filter((a) => a.closure === "false_positive");
  const fpEntities = new Map<string, number>();
  for (const a of fps) fpEntities.set(a.entity.id, (fpEntities.get(a.entity.id) ?? 0) + 1);
  const sample = JSON.stringify(
    Object.fromEntries(Object.entries(d.events.find((e) => String(e["event.dataset"]).startsWith(r.logsource.split(".")[0]!)) ?? d.events[0]!).filter(([k]) => k !== "id")),
    null,
    2,
  );
  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-sm text-muted-foreground">
        <Link href="/rules" className="hover:underline">Rules</Link> / {r.id}
      </nav>
      <PageHeader eyebrow="Detection rule" title={r.name} description={r.description} actions={<><SeverityBadge severity={r.severity} /><StatusBadge status={r.status} /></>} />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_24rem]">
        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader title="Definition" description={`rules/argus/${r.logsource.split(".")[0]}/${r.id}.yml · version ${r.version}`} />
            <pre className="overflow-x-auto p-4 font-mono text-xs leading-relaxed"><code>{r.definition}</code></pre>
          </Card>
          <TestRunner ruleId={r.id} sample={sample} />
        </div>
        <aside className="space-y-4">
          <Card>
            <CardHeader title="Details" />
            <CardBody>
              <Kv
                items={[
                  ["Kind", <span key="k" className="capitalize">{r.kind}</span>],
                  ["Log source", r.logsource],
                  ["Author", r.author],
                  ["Updated", relTime(r.updatedAt, d.now)],
                  ["Alerts (7 days)", String(r.alerts7d)],
                  ["False-positive rate", pct(r.fpRate, 0)],
                ]}
              />
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="MITRE ATT&CK" />
            <CardBody className="space-y-2 text-sm">
              <div className="flex flex-wrap gap-1">{r.tactics.map((t) => <Badge key={t}>{tacticById.get(t)?.name ?? t}</Badge>)}</div>
              <ul className="space-y-0.5">
                {r.techniques.map((t) => (
                  <li key={t}><span className="font-mono text-xs">{t}</span> {techniqueById.get(t.split(".")[0]!)?.name}</li>
                ))}
              </ul>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Response guidance" />
            <CardBody className="text-sm">{r.response}</CardBody>
          </Card>
          <Card>
            <CardHeader title="Known false positives" />
            <CardBody>
              <ul className="list-disc space-y-1 pl-4 text-sm">{r.falsePositives.map((f) => <li key={f}>{f}</li>)}</ul>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Tuning suggestions" description="From analyst false-positive closures" />
            <CardBody className="text-sm">
              {fpEntities.size ? (
                <ul className="space-y-1">
                  {[...fpEntities.entries()].sort((a, b) => b[1] - a[1]).map(([e, n]) => (
                    <li key={e}>Exclude <code className="rounded bg-muted px-1 font-mono text-xs">{e}</code> — {n} false-positive closure{n > 1 ? "s" : ""}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-muted-foreground">No false-positive closures yet.</p>
              )}
            </CardBody>
          </Card>
        </aside>
      </div>
    </>
  );
}
