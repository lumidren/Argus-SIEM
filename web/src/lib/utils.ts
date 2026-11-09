import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

/** "3 min ago", "in 2 hours". */
export function relTime(iso: string, now = Date.now()): string {
  const diff = Date.parse(iso) - now;
  const abs = Math.abs(diff);
  if (abs < 60_000) return rtf.format(Math.round(diff / 1000), "second");
  if (abs < 3_600_000) return rtf.format(Math.round(diff / 60_000), "minute");
  if (abs < 86_400_000) return rtf.format(Math.round(diff / 3_600_000), "hour");
  return rtf.format(Math.round(diff / 86_400_000), "day");
}

/** "2026-11-09 14:03:12 UTC" — analysts work in UTC. */
export function utc(iso: string, withSeconds = true): string {
  const s = iso.replace("T", " ").replace(/\.\d+Z$/, "").replace("Z", "");
  return (withSeconds ? s.slice(0, 19) : s.slice(0, 16)) + " UTC";
}

export function compact(n: number): string {
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function pct(x: number, digits = 1): string {
  return `${(x * 100).toFixed(digits)}%`;
}

/** Remaining time until a deadline, e.g. "2h 14m" or "overdue 35m". */
export function slaLeft(dueIso: string, now = Date.now()): { text: string; overdue: boolean } {
  const ms = Date.parse(dueIso) - now;
  const abs = Math.abs(ms);
  const h = Math.floor(abs / 3_600_000);
  const m = Math.floor((abs % 3_600_000) / 60_000);
  const t = h > 0 ? `${h}h ${m}m` : `${m}m`;
  return ms >= 0 ? { text: t, overdue: false } : { text: `overdue ${t}`, overdue: true };
}

export function entityHref(kind: string, id: string): string {
  return `/entities/${kind}/${encodeURIComponent(id)}`;
}

export function searchHref(q: string): string {
  return `/search?q=${encodeURIComponent(q)}`;
}
