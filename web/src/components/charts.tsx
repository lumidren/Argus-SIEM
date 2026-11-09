// Small dependency-free SVG charts. Each chart has a text alternative for
// screen readers (role="img" + aria-label summarizing the data).
import { cn } from "@/lib/utils";

export function Histogram({ points, height = 96, className, label }: { points: { at: string; count: number }[]; height?: number; className?: string; label: string }) {
  const max = Math.max(1, ...points.map((p) => p.count));
  const total = points.reduce((s, p) => s + p.count, 0);
  const w = 100 / Math.max(1, points.length);
  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" className={cn("h-24 w-full", className)} role="img" aria-label={`${label}: ${total} events across ${points.length} intervals, peak ${max}`}>
      {points.map((p, i) => {
        const h = (p.count / max) * (height - 4);
        return (
          <rect key={i} x={i * w + w * 0.1} y={height - h} width={w * 0.8} height={h} className="fill-chart">
            <title>{`${p.at.slice(11, 16)} UTC — ${p.count}`}</title>
          </rect>
        );
      })}
    </svg>
  );
}

export function Sparkline({ values, className, label }: { values: number[]; className?: string; label: string }) {
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => `${(i / Math.max(1, values.length - 1)) * 100},${30 - (v / max) * 28}`).join(" ");
  return (
    <svg viewBox="0 0 100 30" preserveAspectRatio="none" className={cn("h-8 w-full", className)} role="img" aria-label={`${label}: latest ${values[values.length - 1] ?? 0}, max ${max}`}>
      <polyline points={pts} fill="none" strokeWidth={1.5} vectorEffect="non-scaling-stroke" className="stroke-chart" />
    </svg>
  );
}

export function Bars({ rows, className }: { rows: { label: string; value: number }[]; className?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className={cn("space-y-1.5", className)}>
      {rows.map((r) => (
        <li key={r.label} className="grid grid-cols-[minmax(0,1fr)_3.5rem] items-center gap-2 text-sm">
          <div className="relative h-6 overflow-hidden rounded bg-muted">
            <div className="absolute inset-y-0 left-0 bg-chart/25" style={{ width: `${(r.value / max) * 100}%` }} />
            <span className="relative block truncate px-2 leading-6" title={r.label}>
              {r.label}
            </span>
          </div>
          <span className="text-right tabular-nums text-muted-foreground">{r.value.toLocaleString("en-US")}</span>
        </li>
      ))}
    </ul>
  );
}

export function RiskMeter({ value, className }: { value: number; className?: string }) {
  const tone = value >= 80 ? "bg-sev-critical" : value >= 60 ? "bg-sev-high" : value >= 35 ? "bg-sev-medium" : "bg-sev-low";
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div className="h-2 w-20 overflow-hidden rounded-full bg-muted" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={value} aria-label="Risk score">
        <div className={cn("h-full", tone)} style={{ width: `${value}%` }} />
      </div>
      <span className="text-sm tabular-nums">{value}</span>
    </div>
  );
}
