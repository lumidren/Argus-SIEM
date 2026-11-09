import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

export const buttonVariants = cva(
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-lg text-[0.85rem] font-medium transition-all active:scale-[0.98] disabled:pointer-events-none disabled:opacity-45 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground shadow-sm shadow-primary/25 hover:brightness-110",
        outline: "border border-border-strong bg-surface hover:bg-accent",
        ghost: "text-muted-foreground hover:bg-accent hover:text-foreground",
        danger: "bg-bad text-white shadow-sm shadow-bad/25 hover:brightness-110",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: { sm: "h-8 px-3", md: "h-9 px-4", lg: "h-10 px-5", icon: "size-9" },
    },
    defaultVariants: { variant: "default", size: "md" },
  },
);

export function Button({ className, variant, size, ...props }: React.ComponentProps<"button"> & VariantProps<typeof buttonVariants>) {
  return <button className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}

export function Card({ className, ...props }: React.ComponentProps<"section">) {
  return (
    <section
      className={cn(
        "relative rounded-xl border bg-surface shadow-[0_1px_0_0_rgb(255_255_255/0.04)_inset,0_8px_24px_-12px_rgb(0_0_0/0.35)]",
        className,
      )}
      {...props}
    />
  );
}

export function CardHeader({ title, description, actions, icon, className }: { title: React.ReactNode; description?: React.ReactNode; actions?: React.ReactNode; icon?: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-wrap items-center justify-between gap-2 px-5 pt-4 pb-3", className)}>
      <div className="flex min-w-0 items-center gap-2.5">
        {icon ? <span className="inline-flex size-7 items-center justify-center rounded-lg bg-accent text-primary [&_svg]:size-4">{icon}</span> : null}
        <div className="min-w-0">
          <h2 className="text-[0.92rem] font-semibold tracking-tight">{title}</h2>
          {description ? <p className="mt-0.5 text-xs text-muted-foreground">{description}</p> : null}
        </div>
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function CardBody({ className, ...props }: React.ComponentProps<"div">) {
  return <div className={cn("px-5 pb-5", className)} {...props} />;
}

const field = "w-full rounded-lg border border-border-strong bg-surface-2/60 text-sm transition-colors placeholder:text-muted-foreground/80 hover:border-ring/60 focus:border-ring focus:bg-surface";

export function Input({ className, ...props }: React.ComponentProps<"input">) {
  return <input className={cn(field, "h-9 px-3", className)} {...props} />;
}

export function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return <textarea className={cn(field, "px-3 py-2", className)} {...props} />;
}

export function Select({ className, ...props }: React.ComponentProps<"select">) {
  return <select className={cn(field, "h-9 w-auto px-2.5", className)} {...props} />;
}

export function Label({ className, ...props }: React.ComponentProps<"label">) {
  return <label className={cn("text-xs font-medium text-muted-foreground", className)} {...props} />;
}

export function Badge({ className, ...props }: React.ComponentProps<"span">) {
  return <span className={cn("inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[0.72rem] font-medium leading-4", className)} {...props} />;
}

export const sevText: Record<Severity, string> = {
  low: "text-sev-low",
  medium: "text-sev-medium",
  high: "text-sev-high",
  critical: "text-sev-critical",
};
export const sevBg: Record<Severity, string> = {
  low: "bg-sev-low",
  medium: "bg-sev-medium",
  high: "bg-sev-high",
  critical: "bg-sev-critical",
};
const sevPill: Record<Severity, string> = {
  low: "bg-sev-low/12 text-sev-low ring-sev-low/30",
  medium: "bg-sev-medium/12 text-sev-medium ring-sev-medium/30",
  high: "bg-sev-high/14 text-sev-high ring-sev-high/35",
  critical: "bg-sev-critical/16 text-sev-critical ring-sev-critical/45",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[0.72rem] font-semibold capitalize ring-1 ring-inset", sevPill[severity], className)}>
      <span aria-hidden className={cn("size-1.5 rounded-full bg-current", severity === "critical" && "animate-live")} />
      {severity}
    </span>
  );
}

/** Coloured bar on the left edge of a row or card. */
export function SeverityStrip({ severity, className }: { severity: Severity; className?: string }) {
  return <span aria-hidden className={cn("absolute inset-y-0 left-0 w-[3px] rounded-l-xl", sevBg[severity], className)} />;
}

const statusTone: Record<string, string> = {
  closed: "bg-good/12 text-good ring-good/30",
  resolved: "bg-good/12 text-good ring-good/30",
  succeeded: "bg-good/12 text-good ring-good/30",
  healthy: "bg-good/12 text-good ring-good/30",
  production: "bg-good/12 text-good ring-good/30",
  ok: "bg-good/12 text-good ring-good/30",
  dry_run: "bg-chart-2/12 text-chart-2 ring-chart-2/30",
  contained: "bg-chart-2/12 text-chart-2 ring-chart-2/30",
  new: "bg-bad/12 text-bad ring-bad/30",
  open: "bg-bad/12 text-bad ring-bad/30",
  silent: "bg-bad/12 text-bad ring-bad/30",
  failed: "bg-bad/12 text-bad ring-bad/30",
  error: "bg-bad/12 text-bad ring-bad/30",
  awaiting_approval: "bg-warn/14 text-warn ring-warn/35",
  pending_approval: "bg-warn/14 text-warn ring-warn/35",
  degraded: "bg-warn/14 text-warn ring-warn/35",
  staging: "bg-warn/14 text-warn ring-warn/35",
  investigating: "bg-primary/12 text-primary ring-primary/30",
  in_progress: "bg-primary/12 text-primary ring-primary/30",
  triage: "bg-primary/12 text-primary ring-primary/30",
  running: "bg-primary/12 text-primary ring-primary/30",
};

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  return (
    <span className={cn("inline-flex items-center rounded-full px-2 py-0.5 text-[0.72rem] font-medium capitalize ring-1 ring-inset", statusTone[status] ?? "bg-surface-2 text-muted-foreground ring-border-strong", className)}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function Table({ className, ...props }: React.ComponentProps<"table">) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={cn("w-full border-collapse text-sm [&_tbody_tr]:transition-colors [&_tbody_tr:hover]:bg-accent/40 [&_tbody_tr:last-child_td]:border-b-0", className)} {...props} />
    </div>
  );
}
export function Th({ className, ...props }: React.ComponentProps<"th">) {
  return <th scope="col" className={cn("whitespace-nowrap border-y bg-surface-2/50 px-4 py-2 text-left text-[0.7rem] font-semibold uppercase tracking-wider text-muted-foreground", className)} {...props} />;
}
export function Td({ className, ...props }: React.ComponentProps<"td">) {
  return <td className={cn("border-b px-4 py-2.5 align-middle", className)} {...props} />;
}

export function PageHeader({ title, description, actions, eyebrow }: { title: React.ReactNode; description?: React.ReactNode; actions?: React.ReactNode; eyebrow?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow ? <p className="mb-1 text-xs font-semibold uppercase tracking-[0.14em] text-primary">{eyebrow}</p> : null}
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description ? <p className="mt-1.5 max-w-3xl text-sm text-muted-foreground">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="px-5 py-12 text-center text-sm text-muted-foreground">{children}</p>;
}

export function Kv({ items }: { items: [React.ReactNode, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(6.5rem,max-content)_1fr] gap-x-4 gap-y-2 text-sm">
      {items.map(([k, v], i) => (
        <React.Fragment key={i}>
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

export function Mono({ className, ...props }: React.ComponentProps<"code">) {
  return <code className={cn("rounded-md bg-surface-2 px-1.5 py-0.5 font-mono text-[0.8em]", className)} {...props} />;
}

/** Segmented control used for filters and tabs. */
export function Segmented({ className, ...props }: React.ComponentProps<"div">) {
  return <div className={cn("inline-flex flex-wrap items-center gap-0.5 rounded-lg border bg-surface-2/60 p-0.5", className)} {...props} />;
}
export function segmentClass(active: boolean) {
  return cn(
    "rounded-md px-3 py-1.5 text-[0.82rem] font-medium capitalize transition-colors",
    active ? "bg-surface text-foreground shadow-sm ring-1 ring-border-strong" : "text-muted-foreground hover:text-foreground",
  );
}

/** Large KPI tile. */
export function Stat({ label, value, sub, tone = "neutral", icon, children }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: "good" | "bad" | "warn" | "neutral"; icon?: React.ReactNode; children?: React.ReactNode }) {
  const color = { good: "text-good", bad: "text-bad", warn: "text-warn", neutral: "text-foreground" }[tone];
  return (
    <Card className="overflow-hidden p-4">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-muted-foreground">{label}</p>
        {icon ? <span className={cn("[&_svg]:size-4", tone === "neutral" ? "text-muted-foreground" : color)}>{icon}</span> : null}
      </div>
      <p className={cn("mt-2 text-[1.75rem] font-semibold leading-none tracking-tight tabular-nums", color)}>{value}</p>
      {sub ? <p className="mt-1.5 text-xs text-muted-foreground">{sub}</p> : null}
      {children ? <div className="mt-3">{children}</div> : null}
    </Card>
  );
}
