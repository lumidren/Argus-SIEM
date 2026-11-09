import { NextResponse } from "next/server";
import { search } from "@/lib/demo/store";
import { apiBase, bad, proxy } from "@/lib/proxy";

const RANGES: Record<string, number> = { "15m": 15 * 60_000, "1h": 3_600_000, "4h": 4 * 3_600_000, "24h": 24 * 3_600_000 };

export async function GET(req: Request) {
  if (apiBase) return proxy(req, "/v1/search");
  const u = new URL(req.url);
  const q = u.searchParams.get("q") ?? "";
  if (q.length > 4000) return bad("query too long");
  const range = RANGES[u.searchParams.get("range") ?? "24h"] ?? RANGES["24h"]!;
  const size = Math.min(500, Math.max(1, Number(u.searchParams.get("size") ?? 100) || 100));
  const res = search({ q, size, from: Date.now() - range, to: Date.now() + 60_000 });
  return NextResponse.json(res, { status: res.error ? 400 : 200 });
}
