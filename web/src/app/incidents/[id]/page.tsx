import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/ui/primitives";
import { data, getIncident, playbooks, runs } from "@/lib/demo/store";
import { Workspace } from "./workspace";

export const dynamic = "force-dynamic";

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }): Promise<Metadata> {
  const { id } = await params;
  return { title: getIncident(id)?.id ?? "Incident" };
}

export default async function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const inc = getIncident(id);
  if (!inc) notFound();
  const d = data();
  const alerts = d.alerts.filter((a) => inc.alertIds.includes(a.id));
  const analysts = d.users.filter((u) => u.role !== "viewer").map((u) => u.email.split("@")[0]!);
  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-sm text-muted-foreground">
        <Link href="/incidents" className="hover:underline">Incidents</Link> / {inc.id}
      </nav>
      <PageHeader title={inc.title} description={`${inc.id} · ${inc.alertIds.length} correlated alerts · ${inc.entities.length} entities`} />
      <Workspace inc={inc} alerts={alerts} playbooks={playbooks()} runs={runs().filter((r) => r.incidentId === inc.id)} analysts={analysts} now={d.now} />
    </>
  );
}
