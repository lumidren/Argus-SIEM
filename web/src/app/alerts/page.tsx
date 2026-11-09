import type { Metadata } from "next";
import { PageHeader } from "@/components/ui/primitives";
import { data, listAlerts } from "@/lib/demo/store";
import { AlertsClient } from "./alerts-client";

export const metadata: Metadata = { title: "Alerts" };
export const dynamic = "force-dynamic";

export default async function AlertsPage({ searchParams }: { searchParams: Promise<{ focus?: string }> }) {
  const { focus } = await searchParams;
  return (
    <>
      <PageHeader title="Alert queue" description="Deduplicated detections, scored by rule severity, asset criticality and entity risk. Correlated alerts are grouped into incidents." />
      <AlertsClient alerts={listAlerts({ status: "all" })} now={data().now} {...(focus ? { focus } : {})} />
    </>
  );
}
