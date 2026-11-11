import { Globe, Monitor, User } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { RiskMeter } from "@/components/charts";
import { Card, CardHeader, PageHeader } from "@/components/ui/primitives";
import { data, topEntities } from "@/lib/demo/store";
import type { EntityRef } from "@/lib/types";
import { entityHref, relTime } from "@/lib/utils";

export const metadata: Metadata = { title: "Entities" };
export const dynamic = "force-dynamic";

const icons = { user: User, host: Monitor, ip: Globe } as const;

const groups: { kind: EntityRef["kind"]; title: string; description: string }[] = [
  { kind: "user", title: "Users", description: "Accounts ranked by behavioural risk" },
  { kind: "host", title: "Hosts", description: "Endpoints and servers ranked by risk" },
  { kind: "ip", title: "IP addresses", description: "External addresses seen in alerts" },
];

export default function EntitiesPage() {
  const now = data().now;
  return (
    <>
      <PageHeader eyebrow="Investigate · UEBA" title="Entities" description="Per-user and per-host baselines (logon hours, hosts accessed, volume, geography). Risk rises with alerts and decays over time." />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {groups.map((g) => (
          <Card key={g.kind}>
            <CardHeader title={g.title} description={g.description} icon={(() => { const I = icons[g.kind]; return <I />; })()} />
            <ul className="divide-y border-t">
              {topEntities(g.kind, 12).map((p) => (
                <li key={p.ref.id}>
                  <Link href={entityHref(p.ref.kind, p.ref.id)} className="flex items-center justify-between gap-3 px-5 py-2.5 hover:bg-accent/40">
                    <span className="min-w-0">
                      <span className="block truncate text-sm font-medium">{p.displayName}</span>
                      <span className="text-xs text-muted-foreground">last seen {relTime(p.lastSeen, now)}</span>
                    </span>
                    <RiskMeter value={p.risk} />
                  </Link>
                </li>
              ))}
            </ul>
          </Card>
        ))}
      </div>
    </>
  );
}
