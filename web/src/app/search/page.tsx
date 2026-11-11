import type { Metadata } from "next";
import { Suspense } from "react";
import { PageHeader } from "@/components/ui/primitives";
import { SearchClient } from "./search-client";

export const metadata: Metadata = { title: "Search" };

export default function SearchPage() {
  return (
    <>
      <PageHeader eyebrow="Monitor" title="Search" description="Query normalized events with KQL. Click a value to filter for it or exclude it, or open the user, host or IP it belongs to." />
      <Suspense fallback={<p className="text-sm text-muted-foreground">Loading search…</p>}>
        <SearchClient />
      </Suspense>
    </>
  );
}
