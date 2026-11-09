"use client";

import { Plus, X } from "lucide-react";
import { useEffect, useState } from "react";
import { Bars, Histogram } from "@/components/charts";
import { Button, Card, CardBody, CardHeader, Input, Label, Select } from "@/components/ui/primitives";
import type { SearchResult } from "@/lib/types";

type Panel = { id: string; title: string; q: string; field: string; viz: "bars" | "timeline" };
const KEY = "argus-custom-panels";

const FIELDS = ["user.name", "host.name", "source.ip", "destination.port", "event.action", "event.dataset", "process.name", "dns.question.name", "source.geo.country_iso_code"];

function PanelView({ p, onRemove }: { p: Panel; onRemove: () => void }) {
  const [res, setRes] = useState<SearchResult | null>(null);
  useEffect(() => {
    let live = true;
    fetch(`/api/search?q=${encodeURIComponent(p.q)}&range=24h&size=1`)
      .then((r) => r.json() as Promise<SearchResult>)
      .then((r) => live && setRes(r))
      .catch(() => live && setRes(null));
    return () => {
      live = false;
    };
  }, [p.q]);
  const facet = res?.fields.find((f) => f.name === p.field);
  return (
    <Card>
      <CardHeader
        title={p.title}
        description={<span className="font-mono">{p.q || "*"}</span>}
        actions={
          <button type="button" onClick={onRemove} className="rounded p-1 hover:bg-accent" aria-label={`Remove panel ${p.title}`}>
            <X className="size-4" />
          </button>
        }
      />
      <CardBody>
        {res?.error ? (
          <p className="text-sm text-bad">{res.error}</p>
        ) : p.viz === "timeline" ? (
          <Histogram label={p.title} points={res?.histogram ?? []} />
        ) : facet ? (
          <Bars rows={facet.top.map((t) => ({ label: t.value, value: t.count }))} />
        ) : (
          <p className="text-sm text-muted-foreground">{res ? `No values for ${p.field}.` : "Loading…"}</p>
        )}
      </CardBody>
    </Card>
  );
}

export function PanelBuilder() {
  const [panels, setPanels] = useState<Panel[]>([]);
  const [title, setTitle] = useState("Failed logons by account");
  const [q, setQ] = useState("event.outcome:failure");
  const [field, setField] = useState("user.name");
  const [viz, setViz] = useState<Panel["viz"]>("bars");
  useEffect(() => {
    try {
      const raw = localStorage.getItem(KEY);
      if (raw) setPanels(JSON.parse(raw) as Panel[]);
    } catch {
      // ignore unavailable storage
    }
  }, []);
  const save = (next: Panel[]) => {
    setPanels(next);
    try {
      localStorage.setItem(KEY, JSON.stringify(next));
    } catch {
      // ignore unavailable storage
    }
  };
  return (
    <section aria-labelledby="builder-title">
      <Card>
        <CardHeader title={<span id="builder-title">Dashboard builder</span>} description="Panels are saved in this browser. In a deployment they are stored per user in argus-api." />
        <form
          className="grid gap-3 p-4 md:grid-cols-[1fr_1.5fr_1fr_0.8fr_auto] md:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            save([...panels, { id: `${Date.now()}`, title: title || "Untitled", q, field, viz }]);
          }}
        >
          <div className="space-y-1">
            <Label htmlFor="pb-title">Title</Label>
            <Input id="pb-title" value={title} onChange={(e) => setTitle(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="pb-q">Query</Label>
            <Input id="pb-q" value={q} onChange={(e) => setQ(e.target.value)} className="font-mono" />
          </div>
          <div className="space-y-1">
            <Label htmlFor="pb-field">Group by</Label>
            <Select id="pb-field" value={field} onChange={(e) => setField(e.target.value)} className="w-full">
              {FIELDS.map((f) => (
                <option key={f}>{f}</option>
              ))}
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="pb-viz">Visualization</Label>
            <Select id="pb-viz" value={viz} onChange={(e) => setViz(e.target.value as Panel["viz"])} className="w-full">
              <option value="bars">Top values</option>
              <option value="timeline">Timeline</option>
            </Select>
          </div>
          <Button type="submit">
            <Plus aria-hidden /> Add panel
          </Button>
        </form>
      </Card>
      {panels.length ? (
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          {panels.map((p) => (
            <PanelView key={p.id} p={p} onRemove={() => save(panels.filter((x) => x.id !== p.id))} />
          ))}
        </div>
      ) : null}
    </section>
  );
}
