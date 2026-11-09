import { NextResponse } from "next/server";
import { updateAlert } from "@/lib/demo/store";
import { apiBase, bad, proxy } from "@/lib/proxy";
import type { AlertStatus, Closure } from "@/lib/types";

const statuses: AlertStatus[] = ["open", "acknowledged", "in_progress", "closed"];
const closures: Closure[] = ["true_positive", "false_positive", "benign_true_positive"];

export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (apiBase) return proxy(req, `/v1/alerts/${encodeURIComponent(id)}`);
  const body = (await req.json().catch(() => null)) as { status?: AlertStatus; closure?: Closure } | null;
  if (!body) return bad("invalid JSON");
  if (body.status && !statuses.includes(body.status)) return bad("invalid status");
  if (body.closure && !closures.includes(body.closure)) return bad("invalid closure");
  const a = updateAlert(id, body, "carol");
  return a ? NextResponse.json(a) : bad("not found", 404);
}
