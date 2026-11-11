import { Cloud, Fingerprint, Gauge, KeyRound, Monitor, Network, type LucideIcon } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { Card, PageHeader } from "@/components/ui/primitives";
import { dashboards } from "@/lib/demo/store";
import { PanelBuilder } from "./panel-builder";

export const metadata: Metadata = { title: "Dashboards" };
export const dynamic = "force-dynamic";

const icons: Record<string, LucideIcon> = { overview: Gauge, auth: KeyRound, endpoint: Monitor, network: Network, cloud: Cloud, identity: Fingerprint };

export default function DashboardsPage() {
  const all = dashboards();
  return (
    <>
      <PageHeader eyebrow="Monitor" title="Dashboards" description="Prebuilt views for each data family, plus a builder for ad-hoc panels." />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {all.map((d) => (
          <Link key={d.id} href={`/dashboards/${d.id}`} className="group block rounded-xl">
            <Card className="h-full p-5 transition-colors group-hover:border-border-strong group-hover:bg-accent/30">
              {(() => {
                const I = icons[d.category] ?? Gauge;
                return (
                  <span className="inline-flex size-10 items-center justify-center rounded-xl bg-gradient-to-br from-primary/25 to-chart-3/20 text-primary">
                    <I className="size-5" aria-hidden />
                  </span>
                );
              })()}
              <h2 className="mt-4 font-semibold">{d.title}</h2>
              <p className="mt-1 text-sm text-muted-foreground">{d.description}</p>
              <p className="mt-4 text-xs font-medium text-primary">{d.panels.length} panels →</p>
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
