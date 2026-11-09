import { ChevronRight } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { SeverityBadge, StatusBadge } from "@/components/ui/primitives";
import { attackChain, data, getIncident, playbooks, runs } from "@/lib/demo/store";
import { relTime } from "@/lib/utils";
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
      <nav aria-label="Breadcrumb" className="mb-3 flex items-center gap-1 text-sm text-muted-foreground">
        <Link href="/incidents" className="hover:text-foreground">Incidents</Link>
        <ChevronRight className="size-3.5" aria-hidden />
        <span className="text-foreground">{inc.id}</span>
      </nav>
      <header className="mb-5">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={inc.severity} />
          <StatusBadge status={inc.status} />
          {inc.tags.map((t) => (
            <span key={t} className="rounded-full border px-2 py-0.5 text-[0.72rem] text-muted-foreground">#{t}</span>
          ))}
        </div>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight md:text-[1.7rem]">{inc.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {inc.id} · opened {relTime(inc.createdAt, d.now)} · {inc.alertIds.length} correlated alerts · {inc.entities.length} entities · owner{" "}
          <span className="font-medium text-foreground">{inc.assignee ?? "unassigned"}</span>
        </p>
      </header>
      <Workspace inc={inc} alerts={alerts} playbooks={playbooks()} runs={runs().filter((r) => r.incidentId === inc.id)} analysts={analysts} now={d.now} chain={attackChain(inc)} />
    </>
  );
}
