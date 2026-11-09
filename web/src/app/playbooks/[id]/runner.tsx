"use client";

import { FlaskConical, PlayCircle } from "lucide-react";
import { useState } from "react";
import { Button, Card, CardBody, CardHeader, Label, Select, StatusBadge, Textarea } from "@/components/ui/primitives";
import type { Playbook, PlaybookRun } from "@/lib/types";

// Editor + runner. The YAML is validated for the required keys locally; in a
// deployment, saving opens a merge request against the rules/playbooks repo.
function validate(yaml: string): string[] {
  const problems: string[] = [];
  for (const key of ["id:", "name:", "version:", "trigger:", "steps:"]) if (!new RegExp(`^${key}`, "m").test(yaml)) problems.push(`missing top-level "${key.slice(0, -1)}"`);
  const steps = yaml.split(/^\s*- id:/m).slice(1);
  if (steps.length === 0) problems.push("no steps defined");
  steps.forEach((s, i) => {
    if (!/\baction:\s*\S+/.test(s)) problems.push(`step ${i + 1} has no action`);
    if (!/\badapter:\s*\S+/.test(s)) problems.push(`step ${i + 1} has no adapter`);
    if (/\baction:\s*(isolate_host|disable_user|block_ip|revoke_sessions)\b/.test(s) && !/\bapproval:\s*required\b/.test(s)) problems.push(`step ${i + 1} is destructive and must declare "approval: required"`);
  });
  return problems;
}

export function Runner({ pb, incidents }: { pb: Playbook; incidents: { id: string; title: string }[] }) {
  const [yaml, setYaml] = useState(pb.yaml);
  const [incident, setIncident] = useState(incidents[0]?.id ?? "");
  const [run, setRun] = useState<PlaybookRun | null>(null);
  const [busy, setBusy] = useState(false);
  const problems = validate(yaml);
  const go = async (dryRun: boolean) => {
    setBusy(true);
    try {
      const r = await fetch(`/api/playbooks/${pb.id}/run`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ dryRun, ...(incident ? { incidentId: incident } : {}) }) });
      setRun((await r.json()) as PlaybookRun);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card>
        <CardHeader title="Definition" description={`playbooks/${pb.id}.yml`} />
        <CardBody className="space-y-2">
          <Label htmlFor="pb-yaml" className="sr-only">Playbook YAML</Label>
          <Textarea id="pb-yaml" rows={22} value={yaml} onChange={(e) => setYaml(e.target.value)} className="font-mono text-xs" spellCheck={false} aria-describedby="pb-problems" />
          <div id="pb-problems" aria-live="polite" className="text-xs">
            {problems.length ? (
              <ul className="space-y-0.5 text-bad">{problems.map((p) => <li key={p}>{p}</li>)}</ul>
            ) : (
              <p className="text-good">Valid playbook structure.</p>
            )}
          </div>
        </CardBody>
      </Card>
      <div className="space-y-4">
        <Card>
          <CardHeader title="Run" description="Dry runs never call adapters. Live runs stop at the first step that needs approval." />
          <CardBody className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="pb-incident">Incident context</Label>
              <Select id="pb-incident" value={incident} onChange={(e) => setIncident(e.target.value)} className="w-full">
                <option value="">None</option>
                {incidents.map((i) => (
                  <option key={i.id} value={i.id}>{i.id} — {i.title}</option>
                ))}
              </Select>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => go(true)} disabled={busy || problems.length > 0}>
                <FlaskConical aria-hidden /> Dry run
              </Button>
              <Button onClick={() => go(false)} disabled={busy || problems.length > 0}>
                <PlayCircle aria-hidden /> Run
              </Button>
            </div>
          </CardBody>
        </Card>
        {run ? (
          <Card aria-live="polite">
            <CardHeader title={`Run ${run.id}`} actions={<StatusBadge status={run.status} />} />
            <ol className="divide-y">
              {run.steps.map((s) => {
                const step = pb.steps.find((x) => x.id === s.stepId);
                return (
                  <li key={s.stepId} className="px-4 py-2 text-sm">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{step?.name}</span>
                      <StatusBadge status={s.status} />
                    </div>
                    {s.output ? <p className="text-xs text-muted-foreground">{s.output}</p> : null}
                  </li>
                );
              })}
            </ol>
          </Card>
        ) : null}
        <Card>
          <CardHeader title="Steps" />
          <ol className="divide-y">
            {pb.steps.map((s, i) => (
              <li key={s.id} className="px-4 py-2 text-sm">
                <span className="text-muted-foreground">{i + 1}.</span> <span className="font-medium">{s.name}</span>{" "}
                <span className="text-xs text-muted-foreground">
                  {s.action} via {s.adapter}
                  {s.destructive ? " · destructive" : ""}
                  {s.requiresApproval ? " · approval required" : ""}
                </span>
              </li>
            ))}
          </ol>
        </Card>
      </div>
    </div>
  );
}
