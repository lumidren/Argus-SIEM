import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/ui/primitives";
import { getPlaybook, listIncidents } from "@/lib/demo/store";
import { Runner } from "./runner";

export const dynamic = "force-dynamic";

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }): Promise<Metadata> {
  const { id } = await params;
  return { title: getPlaybook(id)?.name ?? "Playbook" };
}

export default async function PlaybookPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const pb = getPlaybook(id);
  if (!pb) notFound();
  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-sm text-muted-foreground">
        <Link href="/playbooks" className="hover:underline">Playbooks</Link> / {pb.id}
      </nav>
      <PageHeader title={pb.name} description={pb.description} />
      <Runner pb={pb} incidents={listIncidents("open").map((i) => ({ id: i.id, title: i.title }))} />
    </>
  );
}
