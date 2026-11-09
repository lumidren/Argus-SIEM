import type { Metadata } from "next";
import Link from "next/link";
import { Card, PageHeader } from "@/components/ui/primitives";
import { dashboards } from "@/lib/demo/store";
import { PanelBuilder } from "./panel-builder";

export const metadata: Metadata = { title: "Dashboards" };
export const dynamic = "force-dynamic";

export default function DashboardsPage() {
  const all = dashboards();
  return (
    <>
      <PageHeader title="Dashboards" description="Prebuilt views for each data family, plus a builder for ad-hoc panels." />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {all.map((d) => (
          <Link key={d.id} href={`/dashboards/${d.id}`} className="block rounded-lg focus-visible:outline-2">
            <Card className="h-full p-4 transition-colors hover:bg-accent/40">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{d.category}</p>
              <h2 className="mt-1 font-semibold">{d.title}</h2>
              <p className="mt-1 text-sm text-muted-foreground">{d.description}</p>
              <p className="mt-3 text-xs text-muted-foreground">{d.panels.length} panels</p>
            </Card>
          </Link>
        ))}
      </div>
      <div className="mt-6">
        <PanelBuilder />
      </div>
    </>
  );
}
