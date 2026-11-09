import { NextResponse } from "next/server";
import { runPlaybook } from "@/lib/demo/store";
import { apiBase, bad, proxy } from "@/lib/proxy";

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (apiBase) return proxy(req, `/v1/playbooks/${encodeURIComponent(id)}/runs`);
  const body = (await req.json().catch(() => ({}))) as { dryRun?: boolean; incidentId?: string };
  const run = runPlaybook(id, { dryRun: body.dryRun !== false, ...(body.incidentId ? { incidentId: body.incidentId } : {}) }, "carol");
  return run ? NextResponse.json(run) : bad("not found", 404);
}
