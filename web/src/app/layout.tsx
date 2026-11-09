import type { Metadata, Viewport } from "next";
import { Shell } from "@/components/shell";
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

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script>{themeScript}</script>
      </head>
      <body className="antialiased">
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
