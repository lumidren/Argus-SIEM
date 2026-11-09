import type { Metadata, Viewport } from "next";
import { Shell } from "@/components/shell";
import { data } from "@/lib/demo/store";
import { compact } from "@/lib/utils";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Argus SIEM", template: "%s · Argus" },
  description: "Search, detection and response for security operations.",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f8fafc" },
    { media: "(prefers-color-scheme: dark)", color: "#0f172a" },
  ],
};

// Applies the saved or system theme before first paint to avoid a flash.
const themeScript = `try{var t=localStorage.getItem("argus-theme");if(t==="dark"||(!t&&matchMedia("(prefers-color-scheme: dark)").matches))document.documentElement.classList.add("dark")}catch(e){}`;

export const dynamic = "force-dynamic";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const d = data();
  const counts = {
    alerts: d.alerts.filter((a) => a.status === "open").length,
    incidents: d.incidents.filter((i) => i.status !== "closed" && i.status !== "resolved").length,
    silent: d.sources.filter((s) => s.status === "silent").length,
    eps: compact(d.sources.reduce((n, s) => n + s.eps, 0)),
  };
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script>{themeScript}</script>
      </head>
      <body className="antialiased">
        <Shell counts={counts}>{children}</Shell>
      </body>
    </html>
  );
}
