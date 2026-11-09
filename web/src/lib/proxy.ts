import "server-only";
import { NextResponse } from "next/server";

/** Base URL of argus-api; when unset the route handlers answer from demo data. */
export const apiBase = process.env.ARGUS_API_URL?.replace(/\/+$/, "") || "";

/** Forwards a request to argus-api, preserving method, query and body. */
export async function proxy(req: Request, path: string): Promise<Response> {
  const url = new URL(req.url);
  const target = `${apiBase}${path}${url.search}`;
  const init: RequestInit = {
    method: req.method,
    headers: { "content-type": req.headers.get("content-type") ?? "application/json", cookie: req.headers.get("cookie") ?? "" },
    cache: "no-store",
  };
  if (req.method !== "GET" && req.method !== "HEAD") init.body = await req.text();
  try {
    const res = await fetch(target, init);
    return new Response(res.body, { status: res.status, headers: { "content-type": res.headers.get("content-type") ?? "application/json" } });
  } catch {
    return NextResponse.json({ error: "argus-api unreachable" }, { status: 502 });
  }
}

export function bad(message: string, status = 400) {
  return NextResponse.json({ error: message }, { status });
}
