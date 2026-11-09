"use client";

import {
  BellRing,
  Briefcase,
  Database,
  Gauge,
  Grid3x3,
  LayoutDashboard,
  Menu,
  Moon,
  Radar,
  Search,
  Settings,
  ShieldAlert,
  Sun,
  Users,
  Workflow,
  X,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";

export type ShellCounts = { alerts: number; incidents: number; eps: string; silent: number };

type Item = { href: string; label: string; icon: typeof Search; count?: keyof ShellCounts };

const nav: { group: string; items: Item[] }[] = [
  { group: "Monitor", items: [
    { href: "/", label: "Overview", icon: Gauge },
    { href: "/dashboards", label: "Dashboards", icon: LayoutDashboard },
    { href: "/search", label: "Search", icon: Search },
  ] },
  { group: "Investigate", items: [
    { href: "/alerts", label: "Alerts", icon: BellRing, count: "alerts" },
    { href: "/incidents", label: "Incidents", icon: Briefcase, count: "incidents" },
    { href: "/entities", label: "Entities", icon: Users },
  ] },
  { group: "Detect & respond", items: [
    { href: "/rules", label: "Rules", icon: ShieldAlert },
    { href: "/coverage", label: "ATT&CK coverage", icon: Grid3x3 },
    { href: "/playbooks", label: "Playbooks", icon: Workflow },
    { href: "/intel", label: "Threat intel", icon: Radar },
  ] },
  { group: "Platform", items: [
    { href: "/sources", label: "Sources", icon: Database, count: "silent" },
    { href: "/admin", label: "Administration", icon: Settings },
  ] },
];

function isActive(path: string, href: string) {
  return href === "/" ? path === "/" : path === href || path.startsWith(href + "/");
}

function Logo() {
  return (
    <span className="relative inline-flex size-8 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-chart-3 shadow-lg shadow-primary/30">
      <svg viewBox="0 0 24 24" className="size-5 text-white" aria-hidden fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z" />
        <circle cx="12" cy="12" r="3" fill="currentColor" />
      </svg>
    </span>
  );
}

function ThemeToggle() {
  const [dark, setDark] = useState<boolean | null>(null);
  useEffect(() => setDark(document.documentElement.classList.contains("dark")), []);
  const toggle = () => {
    const next = !document.documentElement.classList.contains("dark");
    document.documentElement.classList.toggle("dark", next);
    try {
      localStorage.setItem("argus-theme", next ? "dark" : "light");
    } catch {
      // storage unavailable: theme still applies for this page view
    }
    setDark(next);
  };
  return (
    <button type="button" onClick={toggle} className="inline-flex size-9 items-center justify-center rounded-lg text-muted-foreground hover:bg-accent hover:text-foreground" aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}>
      {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
    </button>
  );
}

function QuickSearch() {
  const router = useRouter();
  const [q, setQ] = useState("");
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.key === "k" && (e.metaKey || e.ctrlKey)) || (e.key === "/" && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLTextAreaElement))) {
        e.preventDefault();
        ref.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <form
      role="search"
      className="relative hidden w-full max-w-lg md:block"
      onSubmit={(e) => {
        e.preventDefault();
        router.push(`/search?q=${encodeURIComponent(q)}`);
      }}
    >
      <label htmlFor="quick-search" className="sr-only">Search events</label>
      <Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" aria-hidden />
      <input
        id="quick-search"
        ref={ref}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Search events…  user.name:alice and event.outcome:failure"
        className="h-9 w-full rounded-lg border border-border bg-surface-2/60 pl-9 pr-14 text-sm placeholder:text-muted-foreground/80 hover:border-border-strong focus:border-ring focus:bg-surface"
      />
      <kbd className="pointer-events-none absolute right-2 top-2 rounded border border-border-strong px-1.5 font-mono text-[0.68rem] text-muted-foreground">Ctrl K</kbd>
    </form>
  );
}

export function Shell({ children, counts }: { children: ReactNode; counts: ShellCounts }) {
  const path = usePathname();
  const [open, setOpen] = useState(false);
  useEffect(() => setOpen(false), [path]);
  const sidebar = (
    <nav aria-label="Main" className="flex h-full flex-col gap-6 overflow-y-auto px-3 py-4">
      <Link href="/" className="flex items-center gap-2.5 px-2">
        <Logo />
        <span>
          <span className="block text-[1.05rem] font-semibold leading-tight tracking-tight">Argus</span>
          <span className="block text-[0.68rem] font-medium uppercase tracking-[0.18em] text-muted-foreground">Security analytics</span>
        </span>
      </Link>
      {nav.map((g) => (
        <div key={g.group}>
          <p className="px-2.5 pb-1.5 text-[0.66rem] font-semibold uppercase tracking-[0.16em] text-muted-foreground/80">{g.group}</p>
          <ul className="space-y-0.5">
            {g.items.map((it) => {
              const active = isActive(path, it.href);
              const n = it.count ? counts[it.count] : 0;
              return (
                <li key={it.href}>
                  <Link
                    href={it.href}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "group relative flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[0.88rem] transition-colors",
                      active ? "bg-accent font-medium text-foreground" : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
                    )}
                  >
                    {active ? <span aria-hidden className="absolute -left-3 top-1.5 bottom-1.5 w-[3px] rounded-r bg-primary" /> : null}
                    <it.icon className={cn("size-[1.05rem]", active && "text-primary")} aria-hidden />
                    <span className="flex-1">{it.label}</span>
                    {typeof n === "number" && n > 0 ? (
                      <span className={cn("rounded-full px-1.5 text-[0.7rem] font-semibold tabular-nums", it.count === "silent" ? "bg-bad/15 text-bad" : "bg-primary/15 text-primary")}>{n}</span>
                    ) : null}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
      <div className="mt-auto rounded-xl border bg-surface-2/50 p-3 text-xs">
        <p className="flex items-center gap-2 font-medium">
          <span className="relative flex size-2">
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-good opacity-60" />
            <span className="relative inline-flex size-2 rounded-full bg-good" />
          </span>
          Pipeline healthy
        </p>
        <p className="mt-1 text-muted-foreground">{counts.eps} events/s · demo tenant</p>
      </div>
    </nav>
  );
  return (
    <div className="flex min-h-dvh">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-surface focus:px-3 focus:py-2 focus:shadow">
        Skip to content
      </a>
      <aside className="sticky top-0 hidden h-dvh w-64 shrink-0 border-r bg-surface/70 backdrop-blur lg:block">{sidebar}</aside>
      {open ? (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <button type="button" className="absolute inset-0 bg-black/50" aria-label="Close navigation" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-72 border-r bg-surface">
            <button type="button" onClick={() => setOpen(false)} className="absolute right-2 top-3 inline-flex size-9 items-center justify-center rounded-lg hover:bg-accent" aria-label="Close navigation">
              <X className="size-4" />
            </button>
            {sidebar}
          </aside>
        </div>
      ) : null}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b bg-background/75 px-4 backdrop-blur-md md:px-6">
          <button type="button" className="inline-flex size-9 items-center justify-center rounded-lg hover:bg-accent lg:hidden" aria-label="Open navigation" onClick={() => setOpen(true)}>
            <Menu className="size-4" />
          </button>
          <QuickSearch />
          <div className="ml-auto flex items-center gap-2">
            <span className="hidden items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs text-muted-foreground sm:inline-flex">
              <span className="size-1.5 rounded-full bg-good animate-live" aria-hidden /> Live
            </span>
            <span className="hidden whitespace-nowrap rounded-lg border bg-surface px-2.5 py-1 text-xs font-medium sm:inline">Acme Corp</span>
            <ThemeToggle />
            <span className="flex items-center gap-2 rounded-full border bg-surface p-0.5 xl:pr-3">
              <span className="inline-flex size-7 items-center justify-center rounded-full bg-gradient-to-br from-primary to-chart-3 text-[0.7rem] font-semibold text-white">CS</span>
              <span className="hidden whitespace-nowrap text-xs leading-tight xl:block">
                <span className="block font-medium">Carol Smith</span>
                <span className="block text-muted-foreground">Analyst</span>
              </span>
            </span>
          </div>
        </header>
        <main id="main" className="mx-auto w-full max-w-[1560px] flex-1 px-4 py-7 md:px-8">
          {children}
        </main>
      </div>
    </div>
  );
}
