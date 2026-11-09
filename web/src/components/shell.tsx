"use client";

import {
  Activity,
  BellRing,
  BookOpenCheck,
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
import { useEffect, useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";

const nav: { group: string; items: { href: string; label: string; icon: typeof Search }[] }[] = [
  { group: "Monitor", items: [
    { href: "/", label: "Overview", icon: Gauge },
    { href: "/dashboards", label: "Dashboards", icon: LayoutDashboard },
    { href: "/search", label: "Search", icon: Search },
  ] },
  { group: "Investigate", items: [
    { href: "/alerts", label: "Alerts", icon: BellRing },
    { href: "/incidents", label: "Incidents", icon: Briefcase },
    { href: "/entities", label: "Entities", icon: Users },
  ] },
  { group: "Detect & respond", items: [
    { href: "/rules", label: "Rules", icon: ShieldAlert },
    { href: "/coverage", label: "ATT&CK coverage", icon: Grid3x3 },
    { href: "/playbooks", label: "Playbooks", icon: Workflow },
    { href: "/intel", label: "Threat intel", icon: Radar },
  ] },
  { group: "Platform", items: [
    { href: "/sources", label: "Sources", icon: Database },
    { href: "/admin", label: "Administration", icon: Settings },
  ] },
];

function isActive(path: string, href: string) {
  return href === "/" ? path === "/" : path === href || path.startsWith(href + "/");
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
    <button type="button" onClick={toggle} className="inline-flex size-9 items-center justify-center rounded-md hover:bg-accent" aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}>
      {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
    </button>
  );
}

function QuickSearch() {
  const router = useRouter();
  const [q, setQ] = useState("");
  return (
    <form
      role="search"
      className="relative hidden w-full max-w-md md:block"
      onSubmit={(e) => {
        e.preventDefault();
        router.push(`/search?q=${encodeURIComponent(q)}`);
      }}
    >
      <label htmlFor="quick-search" className="sr-only">
        Search events
      </label>
      <Search className="pointer-events-none absolute left-2.5 top-2.5 size-4 text-muted-foreground" aria-hidden />
      <input id="quick-search" value={q} onChange={(e) => setQ(e.target.value)} placeholder='Search events, e.g. user.name:alice and event.outcome:failure' className="h-9 w-full rounded-md border bg-card pl-8 pr-3 text-sm placeholder:text-muted-foreground" />
    </form>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const [open, setOpen] = useState(false);
  useEffect(() => setOpen(false), [path]);
  const sidebar = (
    <nav aria-label="Main" className="flex h-full flex-col gap-5 overflow-y-auto px-3 py-4">
      <Link href="/" className="flex items-center gap-2 px-2 text-base font-semibold">
        <Activity className="size-5 text-primary" aria-hidden />
        Argus
      </Link>
      {nav.map((g) => (
        <div key={g.group}>
          <p className="px-2 pb-1 text-[0.7rem] font-semibold uppercase tracking-wide text-muted-foreground">{g.group}</p>
          <ul className="space-y-0.5">
            {g.items.map((it) => {
              const active = isActive(path, it.href);
              return (
                <li key={it.href}>
                  <Link href={it.href} aria-current={active ? "page" : undefined} className={cn("flex items-center gap-2 rounded-md px-2 py-1.5 text-sm", active ? "bg-accent font-medium text-foreground" : "text-muted-foreground hover:bg-accent hover:text-foreground")}>
                    <it.icon className="size-4" aria-hidden />
                    {it.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
      <div className="mt-auto flex items-center gap-2 rounded-md border px-2 py-2 text-xs text-muted-foreground">
        <BookOpenCheck className="size-4" aria-hidden />
        Demo data · tenant acme
      </div>
    </nav>
  );
  return (
    <div className="flex min-h-dvh">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-card focus:px-3 focus:py-2 focus:shadow">
        Skip to content
      </a>
      <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 border-r bg-card lg:block">{sidebar}</aside>
      {open ? (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <button type="button" className="absolute inset-0 bg-black/40" aria-label="Close navigation" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-64 border-r bg-card">
            <button type="button" onClick={() => setOpen(false)} className="absolute right-2 top-3 inline-flex size-9 items-center justify-center rounded-md hover:bg-accent" aria-label="Close navigation">
              <X className="size-4" />
            </button>
            {sidebar}
          </aside>
        </div>
      ) : null}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b bg-background/90 px-4 backdrop-blur">
          <button type="button" className="inline-flex size-9 items-center justify-center rounded-md hover:bg-accent lg:hidden" aria-label="Open navigation" onClick={() => setOpen(true)}>
            <Menu className="size-4" />
          </button>
          <QuickSearch />
          <div className="ml-auto flex items-center gap-2">
            <span className="hidden rounded-md border px-2 py-1 text-xs sm:inline">Acme Corp</span>
            <ThemeToggle />
            <span className="inline-flex size-8 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground" title="carol · analyst">
              CS
            </span>
          </div>
        </header>
        <main id="main" className="mx-auto w-full max-w-[1500px] flex-1 px-4 py-6 md:px-6">
          {children}
        </main>
      </div>
    </div>
  );
}
