import { NextResponse } from "next/server";
import { getRule } from "@/lib/demo/store";
import { evaluate, KQLError, parse } from "@/lib/kql";
import { apiBase, bad, proxy } from "@/lib/proxy";

// Evaluates the rule's filter stage (the part before the first "|") against
// a pasted event, so engineers can check field mappings before committing.
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (apiBase) return proxy(req, `/v1/rules/${encodeURIComponent(id)}/test`);
  const rule = getRule(id);
  if (!rule) return bad("not found", 404);
  const body = (await req.json().catch(() => null)) as { event?: unknown; filter?: string } | null;
  if (!body || typeof body.event !== "object" || body.event === null || Array.isArray(body.event)) return bad("event must be a JSON object of ECS fields");
  const condition = rule.definition.split("condition: |\n")[1]?.split("\n")[0]?.trim() ?? "";
  const filter = (body.filter ?? condition.split("|")[0] ?? "").replace(/^seq by .*?:\s*\[/, "").replace(/\].*$/, "").trim();
  try {
    const matched = evaluate(parse(filter), body.event as Record<string, unknown>);
    return NextResponse.json({ matched, filter, tests: rule.tests });
  } catch (e) {
    return NextResponse.json({ matched: false, filter, error: e instanceof KQLError ? `filter not evaluable in the browser runner: ${e.message}` : String(e), tests: rule.tests }, { status: 200 });
  }
}
