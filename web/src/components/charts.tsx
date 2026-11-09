// Dependency-free SVG charts. Every chart exposes a text alternative
// (role="img" + aria-label) so screen readers get the numbers.
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

function gid(label: string) {
  let h = 0;
  for (const c of label) h = (Math.imul(h, 31) + c.charCodeAt(0)) | 0;
  return "g" + (h >>> 0).toString(36);
}

/** Smooth area chart with gradient fill. */
export function AreaChart({ points, label, className, height = 120, color = "var(--chart)" }: { points: { at: string; value: number }[]; label: string; className?: string; height?: number; color?: string }) {
  const max = Math.max(1, ...points.map((p) => p.value));
  const W = 400;
  const H = height;
  const xs = points.map((_, i) => (i / Math.max(1, points.length - 1)) * W);
  const ys = points.map((p) => H - 6 - (p.value / max) * (H - 14));
  let d = "";
  for (let i = 0; i < xs.length; i++) {
    if (i === 0) d += `M${xs[0]},${ys[0]}`;
    else {
      const cx = (xs[i - 1]! + xs[i]!) / 2;
      d += ` C${cx},${ys[i - 1]} ${cx},${ys[i]} ${xs[i]},${ys[i]}`;
    }
  }
  const id = gid(label);
  const total = points.reduce((s, p) => s + p.value, 0);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className={cn("w-full", className)} style={{ height }} role="img" aria-label={`${label}: ${total} total, peak ${max}`}>
      <defs>
        <linearGradient id={id} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} x1="0" x2={W} y1={H * f} y2={H * f} stroke="var(--border)" strokeDasharray="2 4" vectorEffect="non-scaling-stroke" />
      ))}
      {d ? <path d={`${d} L${W},${H} L0,${H} Z`} fill={`url(#${id})`} /> : null}
      {d ? <path d={d} fill="none" stroke={color} strokeWidth={2} vectorEffect="non-scaling-stroke" /> : null}
    </svg>
  );
}

/** Column histogram with rounded bars (search results over time). */
export function Histogram({ points, height = 110, className, label }: { points: { at: string; count: number }[]; height?: number; className?: string; label: string }) {
  const max = Math.max(1, ...points.map((p) => p.count));
  const total = points.reduce((s, p) => s + p.count, 0);
  const w = 100 / Math.max(1, points.length);
  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" className={cn("w-full", className)} style={{ height }} role="img" aria-label={`${label}: ${total} events across ${points.length} intervals, peak ${max}`}>
      {points.map((p, i) => {
        const h = p.count ? Math.max(2, (p.count / max) * (height - 4)) : 0;
        return (
          <g key={i}>
            <rect x={i * w + w * 0.12} y={0} width={w * 0.76} height={height} fill="var(--chart)" opacity={0.05} rx={0.6} />
            {h ? (
              <rect x={i * w + w * 0.12} y={height - h} width={w * 0.76} height={h} fill="var(--chart)" rx={0.6}>
                <title>{`${p.at.slice(11, 16)} UTC — ${p.count}`}</title>
              </rect>
            ) : null}
          </g>
        );
      })}
    </svg>
  );
}

export function Sparkline({ values, className, label, color = "var(--chart)" }: { values: number[]; className?: string; label: string; color?: string }) {
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => `${(i / Math.max(1, values.length - 1)) * 100},${30 - (v / max) * 27}`).join(" ");
  const id = gid(label + "spark");
  return (
    <svg viewBox="0 0 100 32" preserveAspectRatio="none" className={cn("h-9 w-full", className)} role="img" aria-label={`${label}: latest ${values[values.length - 1] ?? 0}, max ${max}`}>
      <defs>
        <linearGradient id={id} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={`0,32 ${pts} 100,32`} fill={`url(#${id})`} />
      <polyline points={pts} fill="none" strokeWidth={1.6} vectorEffect="non-scaling-stroke" stroke={color} />
    </svg>
  );
}

export function Bars({ rows, className, color = "bg-chart" }: { rows: { label: string; value: number; href?: string }[]; className?: string; color?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className={cn("space-y-2.5", className)}>
      {rows.map((r) => (
        <li key={r.label} className="text-sm">
          <div className="mb-1 flex items-baseline justify-between gap-3">
            <span className="min-w-0 truncate" title={r.label}>{r.label}</span>
            <span className="shrink-0 text-xs tabular-nums text-muted-foreground">{r.value.toLocaleString("en-US")}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-surface-2">
            <div className={cn("h-full rounded-full", color)} style={{ width: `${Math.max(2, (r.value / max) * 100)}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

const sevColor: Record<Severity, string> = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)" };

/** Donut of counts by severity with the total in the middle. */
export function SeverityDonut({ counts, label, size = 150 }: { counts: Record<Severity, number>; label: string; size?: number }) {
  const order: Severity[] = ["critical", "high", "medium", "low"];
  const total = order.reduce((s, k) => s + counts[k], 0);
  const r = 42;
  const C = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="flex items-center gap-5">
      <svg viewBox="0 0 100 100" style={{ width: size, height: size }} role="img" aria-label={`${label}: ${order.map((k) => `${counts[k]} ${k}`).join(", ")}`}>
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--surface-2)" strokeWidth="11" />
        {order.map((k) => {
          const len = total ? (counts[k] / total) * C : 0;
          const el = len ? (
            <circle key={k} cx="50" cy="50" r={r} fill="none" stroke={sevColor[k]} strokeWidth="11" strokeDasharray={`${Math.max(0, len - 1.2)} ${C}`} strokeDashoffset={-offset} transform="rotate(-90 50 50)" strokeLinecap="butt" />
          ) : null;
          offset += len;
          return el;
        })}
        <text x="50" y="49" textAnchor="middle" className="fill-foreground" style={{ fontSize: 20, fontWeight: 650 }}>{total}</text>
        <text x="50" y="62" textAnchor="middle" className="fill-muted-foreground" style={{ fontSize: 7.5, letterSpacing: 0.5 }}>OPEN</text>
      </svg>
      <ul className="space-y-1.5 text-sm">
        {order.map((k) => (
          <li key={k} className="flex items-center gap-2">
            <span className="size-2.5 rounded-sm" style={{ background: sevColor[k] }} aria-hidden />
            <span className="w-16 capitalize text-muted-foreground">{k}</span>
            <span className="font-semibold tabular-nums">{counts[k]}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Circular gauge for scores (0-100) or SLA consumption. */
export function Gauge({ value, label, sub, size = 92, tone }: { value: number; label: string; sub?: string; size?: number; tone?: "critical" | "high" | "medium" | "low" | "good" }) {
  const v = Math.max(0, Math.min(100, value));
  const t = tone ?? (v >= 85 ? "critical" : v >= 65 ? "high" : v >= 40 ? "medium" : "low");
  const color = t === "good" ? "var(--good)" : sevColor[t];
  const r = 40;
  const C = 2 * Math.PI * r * 0.75;
  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 100 100" style={{ width: size, height: size }} role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(v)} aria-label={label}>
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--surface-2)" strokeWidth="9" strokeDasharray={`${C} 999`} transform="rotate(135 50 50)" strokeLinecap="round" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="9" strokeDasharray={`${(v / 100) * C} 999`} transform="rotate(135 50 50)" strokeLinecap="round" />
        <text x="50" y="55" textAnchor="middle" className="fill-foreground" style={{ fontSize: 22, fontWeight: 650 }}>{Math.round(v)}</text>
      </svg>
      <p className="-mt-2 text-xs font-medium">{label}</p>
      {sub ? <p className="text-[0.7rem] text-muted-foreground">{sub}</p> : null}
    </div>
  );
}

export function RiskMeter({ value, className }: { value: number; className?: string }) {
  const tone = value >= 80 ? "bg-sev-critical" : value >= 60 ? "bg-sev-high" : value >= 35 ? "bg-sev-medium" : "bg-sev-low";
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-surface-2" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={value} aria-label="Risk score">
        <div className={cn("h-full rounded-full", tone)} style={{ width: `${Math.max(3, value)}%` }} />
      </div>
      <span className="w-7 text-right text-sm font-semibold tabular-nums">{value}</span>
    </div>
  );
}

export type ChainNode = { id: string; kind: "ip" | "user" | "host"; label: string; sub?: string; severity?: Severity };
export type ChainEdge = { from: string; to: string; label: string };

/**
 * Attack-chain diagram: nodes laid out left to right in the order the attack
 * progressed (source → account → hosts), edges labelled with what happened.
 */
export function AttackChain({ columns, edges, label }: { columns: ChainNode[][]; edges: ChainEdge[]; label: string }) {
  const nodeW = 168;
  const nodeH = 50;
  const gap = 118;
  const colW = nodeW + gap;
  const rowH = 74;
  const W = columns.length * colW - gap + 28;
  const H = Math.max(...columns.map((c) => c.length)) * rowH + 10;
  const pos = new Map<string, { x: number; y: number }>();
  columns.forEach((col, ci) => {
    const off = (H - col.length * rowH) / 2;
    col.forEach((n, ri) => pos.set(n.id, { x: ci * colW + 14, y: off + ri * rowH + 8 }));
  });
  const kindColor = { ip: "var(--sev-critical)", user: "var(--sev-high)", host: "var(--chart)" } as const;
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" style={{ minWidth: Math.round(W * 0.82), maxHeight: H * 1.15 }} role="img" aria-label={label}>
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--muted-foreground)" />
          </marker>
        </defs>
        {edges.map((e, i) => {
          const a = pos.get(e.from);
          const b = pos.get(e.to);
          if (!a || !b) return null;
          const x1 = a.x + nodeW;
          const y1 = a.y + nodeH / 2;
          const x2 = b.x - 4;
          const y2 = b.y + nodeH / 2;
          const mx = (x1 + x2) / 2;
          return (
            <g key={i}>
              <path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none" stroke="var(--border-strong)" strokeWidth="1.6" markerEnd="url(#arrow)" />
              {e.label ? (
                <g>
                  <rect x={mx - e.label.length * 2.9 - 6} y={(y1 + y2) / 2 - 20} width={e.label.length * 5.8 + 12} height={15} rx={7.5} fill="var(--surface)" stroke="var(--border-strong)" />
                  <text x={mx} y={(y1 + y2) / 2 - 9.5} textAnchor="middle" className="fill-muted-foreground" style={{ fontSize: 9.5 }}>{e.label}</text>
                </g>
              ) : null}
            </g>
          );
        })}
        {columns.flat().map((n) => {
          const p = pos.get(n.id)!;
          const c = kindColor[n.kind];
          return (
            <g key={n.id}>
              <rect x={p.x} y={p.y} width={nodeW} height={nodeH} rx="10" fill="var(--surface-2)" stroke={c} strokeOpacity="0.55" />
              <rect x={p.x} y={p.y + 8} width="3" height={nodeH - 16} rx="1.5" fill={c} />
              <text x={p.x + 14} y={p.y + 20} className="fill-muted-foreground" style={{ fontSize: 9.5, letterSpacing: 0.8 }}>{n.kind.toUpperCase()}{n.sub ? ` · ${n.sub}` : ""}</text>
              <text x={p.x + 14} y={p.y + 37} className="fill-foreground" style={{ fontSize: 13, fontWeight: 600 }}>{n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
