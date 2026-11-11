import type { Metadata } from "next";
import Link from "next/link";
import { Badge, Card, CardHeader, Input, PageHeader, StatusBadge, Table, Td, Th } from "@/components/ui/primitives";
import { data, feeds, indicators } from "@/lib/demo/store";
import { compact, relTime, searchHref } from "@/lib/utils";

export const metadata: Metadata = { title: "Threat intel" };
export const dynamic = "force-dynamic";

const fieldFor: Record<string, string> = { ipv4: "source.ip", domain: "dns.question.name", url: "url.original", sha256: "file.hash.sha256", md5: "file.hash.md5", email: "email.from.address" };

export default async function IntelPage({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  const { q = "" } = await searchParams;
  const now = data().now;
  const rows = indicators(q.trim() || undefined);
  return (
    <>
      <PageHeader eyebrow="Detect & respond" title="Threat intelligence" description="Indicators from MISP, TAXII 2.1, OTX and abuse.ch. Matched in-stream on every event, with retro-hunts over stored data when a new indicator arrives." />
      <Card>
        <CardHeader title="Feeds" />
        <Table>
          <thead>
            <tr><Th>Feed</Th><Th>Kind</Th><Th>Indicators</Th><Th>Last pull</Th><Th>Status</Th></tr>
          </thead>
          <tbody>
            {feeds().map((f) => (
              <tr key={f.id}>
                <Td className="font-medium">{f.name}</Td>
                <Td className="uppercase text-xs">{f.kind.replace("_", ".")}</Td>
                <Td className="tabular-nums">{compact(f.indicators)}</Td>
                <Td className="whitespace-nowrap text-muted-foreground">{relTime(f.lastPull, now)}</Td>
                <Td>
                  <StatusBadge status={f.status} />
                  {f.error ? <div className="mt-1 text-xs text-bad">{f.error}</div> : null}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
      <Card className="mt-4">
        <CardHeader
          title="Indicators"
          description="Sightings count matches in the last 30 days. Expired indicators stop matching automatically."
          actions={
            <form role="search" className="w-64">
              <label htmlFor="ioc-q" className="sr-only">Filter indicators</label>
              <Input id="ioc-q" name="q" defaultValue={q} placeholder="Filter by value or tag" />
            </form>
          }
        />
        <Table>
          <thead>
            <tr><Th>Indicator</Th><Th>Type</Th><Th>Provider</Th><Th>Confidence</Th><Th>Sightings</Th><Th>TLP</Th><Th>Expires</Th><Th>Hunt</Th></tr>
          </thead>
          <tbody>
            {rows.map((i) => (
              <tr key={i.id}>
                <Td>
                  <span className="break-all font-mono text-xs">{i.value}</span>
                  <div className="mt-1 flex flex-wrap gap-1">{i.tags.map((t) => <Badge key={t} className="text-muted-foreground">{t}</Badge>)}</div>
                </Td>
                <Td className="uppercase text-xs">{i.type}</Td>
                <Td>{i.provider}</Td>
                <Td className="tabular-nums">{i.confidence}</Td>
                <Td className={i.sightings ? "font-medium tabular-nums text-bad" : "tabular-nums text-muted-foreground"}>{i.sightings}</Td>
                <Td className="uppercase text-xs">{i.tlp}</Td>
                <Td className="whitespace-nowrap text-muted-foreground">{relTime(i.expiresAt, now)}</Td>
                <Td><Link className="text-sm text-primary hover:underline" href={searchHref(`${fieldFor[i.type] ?? "message"}:${i.value}`)}>Search</Link></Td>
              </tr>
            ))}
          </tbody>
        </Table>
        {rows.length === 0 ? <p className="p-6 text-center text-sm text-muted-foreground">No indicators match.</p> : null}
      </Card>
    </>
  );
}
