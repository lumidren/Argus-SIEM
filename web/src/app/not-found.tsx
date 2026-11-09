import Link from "next/link";

export default function NotFound() {
  return (
    <div className="mx-auto max-w-md py-24 text-center">
      <p className="text-sm font-medium text-muted-foreground">404</p>
      <h1 className="mt-1 text-xl font-semibold">Not found</h1>
      <p className="mt-2 text-sm text-muted-foreground">That incident, rule or entity does not exist in this tenant, or you do not have access to it.</p>
      <Link href="/" className="mt-6 inline-block text-sm text-primary hover:underline">Back to overview</Link>
    </div>
  );
}
