import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { DashboardView } from "@/components/dashboard-view";
import { PageHeader } from "@/components/ui/primitives";
import { dashboards } from "@/lib/demo/store";

export const dynamic = "force-dynamic";

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }): Promise<Metadata> {
  const { id } = await params;
  return { title: dashboards().find((d) => d.id === id)?.title ?? "Dashboard" };
}

export default async function DashboardPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const d = dashboards().find((x) => x.id === id);
  if (!d) notFound();
  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-sm text-muted-foreground">
        <Link href="/dashboards" className="hover:underline">Dashboards</Link> / {d.title}
      </nav>
      <PageHeader title={d.title} description={d.description} />
      <DashboardView panels={d.panels} />
    </>
  );
}
