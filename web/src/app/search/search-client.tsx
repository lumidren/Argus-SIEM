"use client";

import { ChevronDown, ChevronRight, Filter, FilterX, Play, Save, Star, Trash2, UserRound } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Histogram } from "@/components/charts";
import { Badge, Button, Card, CardBody, CardHeader, Input, Select } from "@/components/ui/primitives";
import { costWarnings, KQLError, parse, quote } from "@/lib/kql";
import type { EventDoc, SearchResult } from "@/lib/types";
import { cn, entityHref, utc } from "@/lib/utils";

type Saved = { name: string; q: string };
const STORAGE_KEY = "argus-saved-searches";
const DEFAULT_SAVED: Saved[] = [
  { name: "Failed Windows logons", q: "event.code:4625" },
  { name: "Admin share access", q: "event.code:5140 and file.path:*ADMIN$" },
  { name: "Firewall denies", q: "event.type:denied" },
  { name: "Scenario: password guessing → lateral movement", q: "argus.scenario:bruteforce-lateral" },
];

const ENTITY_FIELDS: Record<string, "user" | "host" | "ip"> = {
  "user.name": "user",
  "host.name": "host",
  "source.ip": "ip",
  "destination.ip": "ip",
};

const COLUMNS = ["event.dataset", "event.action", "user.name", "host.name", "source.ip"];

function loadSaved(): Saved[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Saved[]) : DEFAULT_SAVED;
  } catch {
    return DEFAULT_SAVED;
  }
}

export function SearchClient() {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const initialQ = params.get("q") ?? "";
  const initialRange = params.get("range") ?? "24h";
  const [draft, setDraft] = useState(initialQ);
  const [range, setRange] = useState(initialRange);
  const [res, setRes] = useState<SearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [saved, setSaved] = useState<Saved[]>(DEFAULT_SAVED);

  useEffect(() => setSaved(loadSaved()), []);

  const syntax = useMemo(() => {
    try {
      return { warnings: costWarnings(parse(draft)), error: null as string | null };
    } catch (e) {
      return { warnings: [], error: e instanceof KQLError ? `${e.message} at character ${e.position + 1}` : String(e) };
    }
  }, [draft]);

  const run = useCallback(
    async (q: string, r: string) => {
      setLoading(true);
      try {
        const resp = await fetch(`/api/search?q=${encodeURIComponent(q)}&range=${r}&size=200`);
        setRes((await resp.json()) as SearchResult);
      } catch {
        setRes({ total: 0, tookMs: 0, events: [], histogram: [], fields: [], error: "Search service unreachable" });
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    setDraft(initialQ);
    setRange(initialRange);
    void run(initialQ, initialRange);
  }, [initialQ, initialRange, run]);

  const submit = (q: string, r = range) => {
    router.push(`${pathname}?q=${encodeURIComponent(q)}&range=${r}`);
  };

  const refine = (field: string, value: string, exclude: boolean) => {
    const clause = `${exclude ? "not " : ""}${field}:${quote(value)}`;
    const q = draft.trim() ? `(${draft.trim()}) and ${clause}` : clause;
    submit(q);
  };

  const persist = (next: Saved[]) => {
    setSaved(next);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // storage unavailable: the list stays for this session
    }
  };

  return (
    <div className="grid gap-4 xl:grid-cols-[18rem_minmax(0,1fr)]">
      <div className="space-y-4 xl:order-2">
        <Card>
          <form
            className="flex flex-col gap-2 p-3 md:flex-row"
            onSubmit={(e) => {
              e.preventDefault();
              if (!syntax.error) submit(draft);
            }}
          >
            <label htmlFor="kql" className="sr-only">
              Query
            </label>
            <Input
              id="kql"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder='KQL, e.g. event.code:4625 and not source.ip:10.*'
              className={cn("font-mono", syntax.error && "border-bad")}
              aria-invalid={syntax.error ? true : undefined}
              aria-describedby="kql-help"
              spellCheck={false}
            />
            <label htmlFor="range" className="sr-only">
              Time range
            </label>
            <Select id="range" value={range} onChange={(e) => submit(draft, e.target.value)} className="md:w-36">
              <option value="15m">Last 15 minutes</option>
              <option value="1h">Last hour</option>
              <option value="4h">Last 4 hours</option>
              <option value="24h">Last 24 hours</option>
            </Select>
            <Button type="submit" disabled={!!syntax.error || loading}>
              <Play aria-hidden /> Search
            </Button>
          </form>
          <div id="kql-help" className="px-3 pb-3 text-xs" aria-live="polite">
            {syntax.error ? (
              <span className="text-bad">Syntax error: {syntax.error}</span>
            ) : syntax.warnings.length ? (
              <span className="text-sev-medium">{syntax.warnings.join(" ")}</span>
            ) : (
              <span className="text-muted-foreground">Fields use ECS names. Operators: and, or, not, field:*, field &gt;= n, wildcards with *.</span>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader
            title={res?.error ? "Query error" : loading ? "Searching…" : `${(res?.total ?? 0).toLocaleString("en-US")} events`}
            description={res && !res.error ? `${res.tookMs} ms · sample of the demo tenant` : undefined}
          />
          <CardBody>
            {res?.error ? <p className="text-sm text-bad">{res.error}</p> : <Histogram label="Events over time" points={res?.histogram ?? []} />}
          </CardBody>
        </Card>

        <Card>
          <div className="divide-y" role="list" aria-label="Results">
            {(res?.events ?? []).map((e) => (
              <ResultRow key={e.id} e={e} open={open === e.id} onToggle={() => setOpen(open === e.id ? null : e.id)} onRefine={refine} />
            ))}
            {res && !res.error && res.events.length === 0 ? <p className="p-6 text-center text-sm text-muted-foreground">No events match this query in the selected range.</p> : null}
          </div>
        </Card>
      </div>

      <div className="space-y-4 xl:order-1">
        <Card>
          <CardHeader
            title="Saved searches"
            actions={
              <Button
                size="sm"
                variant="outline"
                disabled={!draft.trim()}
                onClick={() => {
                  const name = window.prompt("Name this search", draft.slice(0, 60));
                  if (name) persist([...saved.filter((s) => s.name !== name), { name, q: draft }]);
                }}
              >
                <Save aria-hidden /> Save
              </Button>
            }
          />
          <ul className="p-2">
            {saved.map((s) => (
              <li key={s.name} className="group flex items-center gap-1">
                <button type="button" onClick={() => submit(s.q)} className="flex min-w-0 flex-1 items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-accent">
                  <Star className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                  <span className="truncate">{s.name}</span>
                </button>
                <button type="button" aria-label={`Delete saved search ${s.name}`} onClick={() => persist(saved.filter((x) => x.name !== s.name))} className="rounded p-1 text-muted-foreground opacity-0 hover:bg-accent group-hover:opacity-100 focus:opacity-100">
                  <Trash2 className="size-3.5" />
                </button>
              </li>
            ))}
          </ul>
        </Card>
        <Card>
          <CardHeader title="Fields" description="Top values in the current results" />
          <ul className="max-h-[60vh] overflow-y-auto p-2 text-sm">
            {(res?.fields ?? []).slice(0, 30).map((f) => (
              <FieldItem key={f.name} f={f} onRefine={refine} />
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}

function FieldItem({ f, onRefine }: { f: SearchResult["fields"][number]; onRefine: (field: string, value: string, exclude: boolean) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <li>
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} className="flex w-full items-center gap-1 rounded px-1.5 py-1 text-left hover:bg-accent">
        {open ? <ChevronDown className="size-3.5" aria-hidden /> : <ChevronRight className="size-3.5" aria-hidden />}
        <span className="min-w-0 flex-1 truncate font-mono text-xs">{f.name}</span>
        <span className="text-xs tabular-nums text-muted-foreground">{f.count}</span>
      </button>
      {open ? (
        <ul className="mb-1 ml-5 space-y-0.5">
          {f.top.map((t) => (
            <li key={t.value} className="flex items-center gap-1 text-xs">
              <span className="min-w-0 flex-1 truncate" title={t.value}>{t.value}</span>
              <span className="tabular-nums text-muted-foreground">{t.count}</span>
              <button type="button" className="rounded p-0.5 hover:bg-accent" aria-label={`Filter for ${f.name} ${t.value}`} onClick={() => onRefine(f.name, t.value, false)}>
                <Filter className="size-3" />
              </button>
              <button type="button" className="rounded p-0.5 hover:bg-accent" aria-label={`Filter out ${f.name} ${t.value}`} onClick={() => onRefine(f.name, t.value, true)}>
                <FilterX className="size-3" />
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function ResultRow({ e, open, onToggle, onRefine }: { e: EventDoc; open: boolean; onToggle: () => void; onRefine: (field: string, value: string, exclude: boolean) => void }) {
  const fields = Object.entries(e).filter(([k]) => k !== "id");
  return (
    <div role="listitem">
      <button type="button" onClick={onToggle} aria-expanded={open} className="grid w-full grid-cols-[1.25rem_10.5rem_minmax(0,1fr)] items-start gap-2 px-3 py-2 text-left text-sm hover:bg-accent/50">
        {open ? <ChevronDown className="mt-0.5 size-4" aria-hidden /> : <ChevronRight className="mt-0.5 size-4" aria-hidden />}
        <span className="font-mono text-xs text-muted-foreground">{utc(e["@timestamp"])}</span>
        <span className="min-w-0">
          <span className="flex flex-wrap gap-1">
            {COLUMNS.filter((c) => e[c] !== undefined).map((c) => (
              <Badge key={c} className="font-mono font-normal">
                <span className="text-muted-foreground">{c}:</span>
                {String(e[c])}
              </Badge>
            ))}
          </span>
          <span className="mt-1 block truncate text-muted-foreground">{String(e.message ?? "")}</span>
        </span>
      </button>
      {open ? (
        <div className="overflow-x-auto bg-muted/40 px-3 py-2">
          <table className="w-full text-xs">
            <tbody>
              {fields.map(([k, v]) => (
                <tr key={k} className="align-top">
                  <th scope="row" className="w-64 py-0.5 pr-3 text-left font-mono font-normal text-muted-foreground">{k}</th>
                  <td className="py-0.5 font-mono break-all">{Array.isArray(v) ? v.join(", ") : String(v)}</td>
                  <td className="w-24 whitespace-nowrap py-0.5 text-right">
                    <button type="button" className="rounded p-0.5 hover:bg-accent" aria-label={`Filter for ${k}`} onClick={() => onRefine(k, Array.isArray(v) ? String(v[0]) : String(v), false)}>
                      <Filter className="size-3" />
                    </button>
                    <button type="button" className="rounded p-0.5 hover:bg-accent" aria-label={`Filter out ${k}`} onClick={() => onRefine(k, Array.isArray(v) ? String(v[0]) : String(v), true)}>
                      <FilterX className="size-3" />
                    </button>
                    {ENTITY_FIELDS[k] ? (
                      <Link className="inline-flex rounded p-0.5 hover:bg-accent" aria-label={`Open entity ${String(v)}`} href={entityHref(ENTITY_FIELDS[k]!, String(v))}>
                        <UserRound className="size-3" />
                      </Link>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
