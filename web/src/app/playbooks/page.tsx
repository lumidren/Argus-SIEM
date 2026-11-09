import type { Metadata } from "next";
import Link from "next/link";
import { Badge, Card, CardHeader, PageHeader, StatusBadge, Table, Td, Th } from "@/components/ui/primitives";
import { data, playbooks, runs } from "@/lib/demo/store";
import { relTime } from "@/lib/utils";

export const metadata: Metadata = { title: "Playbooks" };
export const dynamic = "force-dynamic";

export default function PlaybooksPage() {
  const now = data().now;
  const all = playbooks();
  return (
    <>
      <PageHeader title="Playbooks" description="YAML-defined, versioned response workflows. Every action supports dry run; destructive actions need approval from a second person and are fully audited." />
      <div className="grid gap-4 md:grid-cols-2">
        {all.map((p) => (
          <Link key={p.id} href={`/playbooks/${p.id}`} className="block rounded-lg">
            <Card className="h-full p-4 hover:bg-accent/40">
              <div className="flex items-start justify-between gap-2">
                <h2 className="font-semibold">{p.name}</h2>
                <Badge>v{p.version}</Badge>
              </div>
              <p className="mt-1 text-sm text-muted-foreground">{p.description}</p>
              <p className="mt-3 text-xs text-muted-foreground">
                Trigger <code className="font-mono">{p.trigger}</code> · {p.steps.length} steps · {p.steps.filter((s) => s.requiresApproval).length} need approval
              </p>
            </Card>
          </Link>
        ))}
      </div>
      <Card className="mt-4">
        <CardHeader title="Recent runs" />
        <Table>
          <thead>
            <tr><Th>Run</Th><Th>Playbook</Th><Th>Incident</Th><Th>Status</Th><Th>Triggered by</Th><Th>Started</Th></tr>
          </thead>
          <tbody>
            {runs().map((r) => (
              <tr key={r.id}>
                <Td className="font-mono text-xs">{r.id}</Td>
                <Td><Link className="hover:underline" href={`/playbooks/${r.playbookId}`}>{all.find((p) => p.id === r.playbookId)?.name}</Link></Td>
                <Td>{r.incidentId ? <Link className="hover:underline" href={`/incidents/${r.incidentId}`}>{r.incidentId}</Link> : "—"}</Td>
                <Td><StatusBadge status={r.status} /></Td>
                <Td>{r.triggeredBy}</Td>
                <Td className="whitespace-nowrap text-muted-foreground">{relTime(r.startedAt, now)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </>
  );
}
