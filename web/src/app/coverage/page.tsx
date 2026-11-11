import type { Metadata } from "next";
import Link from "next/link";
import { Card, PageHeader } from "@/components/ui/primitives";
import { coverage, TACTICS, TECHNIQUES } from "@/lib/attack";
import { rules } from "@/lib/demo/store";
import { cn } from "@/lib/utils";

export const metadata: Metadata = { title: "ATT&CK coverage" };
export const dynamic = "force-dynamic";

function tone(n: number) {
  if (n === 0) return "bg-muted text-muted-foreground";
  if (n === 1) return "bg-chart/20";
  if (n === 2) return "bg-chart/40";
  return "bg-chart/70 text-primary-foreground";
}

export default function CoveragePage() {
  const all = rules();
  const cov = coverage(all);
  const covered = TECHNIQUES.filter((t) => (cov.get(t.id) ?? 0) > 0).length;
  return (
    <>
      <PageHeader eyebrow="Detect & respond"
        title="MITRE ATT&CK coverage"
        description={`${covered} of ${TECHNIQUES.length} tracked techniques have at least one active rule. Cells show the number of non-deprecated rules per technique.`}
      />
      <div className="mb-3 flex items-center gap-3 text-xs text-muted-foreground" aria-hidden>
        <span className="flex items-center gap-1"><span className="inline-block size-3 rounded bg-muted" /> none</span>
        <span className="flex items-center gap-1"><span className="inline-block size-3 rounded bg-chart/20" /> 1</span>
        <span className="flex items-center gap-1"><span className="inline-block size-3 rounded bg-chart/40" /> 2</span>
        <span className="flex items-center gap-1"><span className="inline-block size-3 rounded bg-chart/70" /> 3+</span>
      </div>
      <Card className="overflow-x-auto p-3">
        <div className="grid min-w-[1100px] grid-cols-14 gap-2">
          {TACTICS.map((tac) => {
            const techs = TECHNIQUES.filter((t) => t.tactics.includes(tac.id));
            const n = techs.filter((t) => (cov.get(t.id) ?? 0) > 0).length;
            return (
              <section key={tac.id} aria-labelledby={`tac-${tac.id}`}>
                <h2 id={`tac-${tac.id}`} className="mb-1 min-h-10 text-xs font-semibold leading-tight">
                  {tac.name}
                  <span className="block font-normal text-muted-foreground">{n}/{techs.length}</span>
                </h2>
                <ul className="space-y-1">
                  {techs.map((t) => {
                    const c = cov.get(t.id) ?? 0;
                    return (
                      <li key={t.id}>
                        <Link
                          href={`/rules?technique=${t.id}`}
                          className={cn("block rounded px-1.5 py-1 text-[0.7rem] leading-tight hover:ring-1 hover:ring-ring", tone(c))}
                          title={`${t.id} ${t.name}: ${c} rule${c === 1 ? "" : "s"}`}
                        >
                          <span className="font-mono">{t.id}</span>
                          <span className="block">{t.name}</span>
                          <span className="sr-only">{c} rules</span>
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              </section>
            );
          })}
        </div>
      </Card>
    </>
  );
}
