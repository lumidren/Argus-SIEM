"use client";

import { FlaskConical } from "lucide-react";
import { useState } from "react";
import { Button, Card, CardBody, CardHeader, Label, Textarea } from "@/components/ui/primitives";

type Result = { matched: boolean; filter: string; error?: string; tests: { name: string; kind: string; passed: boolean }[] };

export function TestRunner({ ruleId, sample }: { ruleId: string; sample: string }) {
  const [event, setEvent] = useState(sample);
  const [res, setRes] = useState<Result | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setErr(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(event);
    } catch {
      setErr("The sample must be valid JSON.");
      return;
    }
    setBusy(true);
    try {
      const r = await fetch(`/api/rules/${ruleId}/test`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ event: parsed }) });
      const body = (await r.json()) as Result & { error?: string };
      if (!r.ok) setErr(body.error ?? "Test failed.");
      else setRes(body);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card>
      <CardHeader title="Test runner" description="Paste a normalized event (flat ECS JSON) and evaluate the rule's filter against it." />
      <CardBody className="space-y-3">
        <div className="space-y-1">
          <Label htmlFor="sample">Event</Label>
          <Textarea id="sample" rows={9} value={event} onChange={(e) => setEvent(e.target.value)} className="font-mono text-xs" spellCheck={false} />
        </div>
        <Button size="sm" onClick={run} disabled={busy}>
          <FlaskConical aria-hidden /> Evaluate
        </Button>
        <div aria-live="polite" className="space-y-2 text-sm">
          {err ? <p className="text-bad">{err}</p> : null}
          {res ? (
            <>
              <p>
                Filter <code className="rounded bg-muted px-1 font-mono text-xs">{res.filter || "*"}</code>{" "}
                {res.error ? <span className="text-sev-medium">{res.error}</span> : res.matched ? <strong className="text-good">matched</strong> : <strong className="text-muted-foreground">did not match</strong>}
              </p>
              <ul className="space-y-0.5 text-xs">
                {res.tests.map((t) => (
                  <li key={t.name} className={t.passed ? "text-good" : "text-bad"}>
                    {t.passed ? "pass" : "fail"} · {t.kind.replace(/_/g, " ")} · {t.name}
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </div>
      </CardBody>
    </Card>
  );
}
