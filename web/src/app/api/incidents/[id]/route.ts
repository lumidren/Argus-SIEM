import { NextResponse } from "next/server";
import { updateIncident, type IncidentPatch } from "@/lib/demo/store";
import { apiBase, bad, proxy } from "@/lib/proxy";
import { INCIDENT_STATUSES } from "@/lib/types";

export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (apiBase) return proxy(req, `/v1/incidents/${encodeURIComponent(id)}`);
  const body = (await req.json().catch(() => null)) as IncidentPatch | null;
  if (!body) return bad("invalid JSON");
  if (body.status && !INCIDENT_STATUSES.includes(body.status)) return bad("invalid status");
  if (body.note !== undefined && (typeof body.note !== "string" || body.note.length > 4000)) return bad("note must be a string up to 4000 characters");
  const inc = updateIncident(id, body, "carol");
  return inc ? NextResponse.json(inc) : bad("not found", 404);
}
