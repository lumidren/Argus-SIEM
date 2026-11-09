import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

export const buttonVariants = cva(
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-primary/90",
        outline: "border bg-card hover:bg-accent",
        ghost: "hover:bg-accent",
        danger: "bg-bad text-white hover:bg-bad/90",
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
  return <section className={cn("rounded-lg border bg-card shadow-sm", className)} {...props} />;
}

export function CardHeader({ title, description, actions, className }: { title: React.ReactNode; description?: React.ReactNode; actions?: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-2 border-b px-4 py-3", className)}>
      <div className="min-w-0">
        <h2 className="text-sm font-semibold">{title}</h2>
        {description ? <p className="mt-0.5 text-xs text-muted-foreground">{description}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function CardBody({ className, ...props }: React.ComponentProps<"div">) {
  return <div className={cn("p-4", className)} {...props} />;
}

export function Input({ className, ...props }: React.ComponentProps<"input">) {
  return <input className={cn("h-9 w-full rounded-md border bg-card px-3 text-sm placeholder:text-muted-foreground", className)} {...props} />;
}

export function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return <textarea className={cn("w-full rounded-md border bg-card px-3 py-2 text-sm placeholder:text-muted-foreground", className)} {...props} />;
}

export function Select({ className, ...props }: React.ComponentProps<"select">) {
  return <select className={cn("h-9 rounded-md border bg-card px-2 text-sm", className)} {...props} />;
}

export function Label({ className, ...props }: React.ComponentProps<"label">) {
  return <label className={cn("text-xs font-medium text-muted-foreground", className)} {...props} />;
}

export function Badge({ className, ...props }: React.ComponentProps<"span">) {
  return <span className={cn("inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-xs font-medium", className)} {...props} />;
}

const sevClass: Record<Severity, string> = {
  low: "border-sev-low/40 text-sev-low",
  medium: "border-sev-medium/50 text-sev-medium",
  high: "border-sev-high/50 text-sev-high",
  critical: "border-sev-critical/60 bg-sev-critical/10 text-sev-critical",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <Badge className={cn("capitalize", sevClass[severity], className)}>
      <span aria-hidden className="size-1.5 rounded-full bg-current" />
      {severity}
    </Badge>
  );
}

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  const tone =
    status === "closed" || status === "resolved" || status === "succeeded" || status === "healthy" || status === "production" || status === "ok"
      ? "text-good border-good/40"
      : status === "new" || status === "open" || status === "silent" || status === "failed" || status === "error"
        ? "text-bad border-bad/40"
        : "text-muted-foreground";
  return <Badge className={cn("capitalize", tone, className)}>{status.replace(/_/g, " ")}</Badge>;
}

export function Table({ className, ...props }: React.ComponentProps<"table">) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={cn("w-full border-collapse text-sm", className)} {...props} />
    </div>
  );
}
export function Th({ className, ...props }: React.ComponentProps<"th">) {
  return <th scope="col" className={cn("whitespace-nowrap border-b px-3 py-2 text-left text-xs font-medium text-muted-foreground", className)} {...props} />;
}
export function Td({ className, ...props }: React.ComponentProps<"td">) {
  return <td className={cn("border-b px-3 py-2 align-top", className)} {...props} />;
}

export function PageHeader({ title, description, actions }: { title: string; description?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description ? <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="px-4 py-10 text-center text-sm text-muted-foreground">{children}</p>;
}

export function Kv({ items }: { items: [React.ReactNode, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(7rem,max-content)_1fr] gap-x-4 gap-y-1.5 text-sm">
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
  return <code className={cn("rounded bg-muted px-1 py-0.5 font-mono text-[0.8em]", className)} {...props} />;
}
