import type { Metadata } from "next";
import { Badge, Card, CardBody, CardHeader, Kv, PageHeader, Table, Td, Th } from "@/components/ui/primitives";
import { auditLog, data, tenants, users } from "@/lib/demo/store";
import type { Role } from "@/lib/types";
import { compact, relTime, utc } from "@/lib/utils";

export const metadata: Metadata = { title: "Administration" };
export const dynamic = "force-dynamic";

const PERMISSIONS: [string, Role[]][] = [
  ["Search events, view dashboards", ["admin", "engineer", "analyst", "viewer"]],
  ["Triage alerts, edit incidents, add notes and evidence", ["admin", "engineer", "analyst"]],
  ["Run playbooks (dry run)", ["admin", "engineer", "analyst"]],
  ["Approve destructive playbook steps", ["admin", "engineer"]],
  ["Create and promote rules", ["admin", "engineer"]],
  ["Unmask PII fields", ["admin"]],
  ["Manage sources, feeds and retention", ["admin", "engineer"]],
  ["Manage users, SSO, tenants and legal hold", ["admin"]],
];
const ROLES: Role[] = ["admin", "engineer", "analyst", "viewer"];

export default function AdminPage() {
  const now = data().now;
  return (
    <>
      <PageHeader eyebrow="Platform" title="Administration" description="Tenants, users and roles, single sign-on, and the tamper-evident audit log." />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader title="Tenants" description="Each tenant has isolated indices, row-level security in Postgres and its own retention." />
          <Table>
            <thead>
              <tr><Th>Tenant</Th><Th>Plan</Th><Th>Events/day</Th><Th>Retention</Th><Th>WORM</Th><Th>Users</Th></tr>
            </thead>
            <tbody>
              {tenants().map((t) => (
                <tr key={t.id}>
                  <Td><span className="font-medium">{t.name}</span><div className="font-mono text-xs text-muted-foreground">{t.id}</div></Td>
                  <Td className="capitalize">{t.plan}</Td>
                  <Td className="tabular-nums">{compact(t.eventsPerDay)}</Td>
                  <Td className="tabular-nums">{t.retentionDays} d</Td>
                  <Td>{t.worm ? <Badge className="text-good">on</Badge> : <Badge className="text-muted-foreground">off</Badge>}</Td>
                  <Td className="tabular-nums">{t.users}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
        <Card>
          <CardHeader title="Single sign-on" description="OpenID Connect, authorization code flow with PKCE" />
          <CardBody>
            <Kv
              items={[
                ["Issuer", <code key="i" className="font-mono text-xs">https://login.example.com/oauth2/default</code>],
                ["Client ID", <code key="c" className="font-mono text-xs">argus-web</code>],
                ["Scopes", "openid profile email groups"],
                ["Role mapping", "groups claim: soc-admins → admin, detection-eng → engineer, soc → analyst, auditors → viewer"],
                ["Local accounts", "Break-glass only, MFA required"],
                ["Session", "8 h, SameSite=Strict cookie, idle timeout 30 min"],
              ]}
            />
          </CardBody>
        </Card>
      </div>
      <Card className="mt-4">
        <CardHeader title="Users" description="Acme Corp" />
        <Table>
          <thead>
            <tr><Th>User</Th><Th>Role</Th><Th>Sign-in</Th><Th>MFA</Th><Th>Last login</Th></tr>
          </thead>
          <tbody>
            {users().map((u) => (
              <tr key={u.id}>
                <Td><span className="font-medium">{u.name}</span><div className="text-xs text-muted-foreground">{u.email}</div></Td>
                <Td><Badge className="capitalize">{u.role}</Badge></Td>
                <Td>{u.sso ? "SSO" : "Local (break-glass)"}</Td>
                <Td>{u.mfa ? "Yes" : <span className="text-bad">No</span>}</Td>
                <Td className="whitespace-nowrap text-muted-foreground">{relTime(u.lastLogin, now)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
      <Card className="mt-4">
        <CardHeader title="Role permissions" />
        <Table>
          <thead>
            <tr><Th>Permission</Th>{ROLES.map((r) => <Th key={r} className="text-center capitalize">{r}</Th>)}</tr>
          </thead>
          <tbody>
            {PERMISSIONS.map(([p, roles]) => (
              <tr key={p}>
                <Td>{p}</Td>
                {ROLES.map((r) => (
                  <Td key={r} className="text-center">{roles.includes(r) ? <span aria-label="allowed" className="text-good">✓</span> : <span aria-label="not allowed" className="text-muted-foreground">—</span>}</Td>
                ))}
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
      <Card className="mt-4">
        <CardHeader title="Audit log" description="Append-only and hash-chained: each entry includes the hash of the one before it, and the chain head is anchored to WORM storage daily." />
        <Table>
          <thead>
            <tr><Th>Seq</Th><Th>Time</Th><Th>Actor</Th><Th>Action</Th><Th>Target</Th><Th>Hash</Th></tr>
          </thead>
          <tbody>
            {[...auditLog()].reverse().map((a) => (
              <tr key={a.seq}>
                <Td className="tabular-nums">{a.seq}</Td>
                <Td className="whitespace-nowrap font-mono text-xs">{utc(a.at)}</Td>
                <Td>{a.actor}</Td>
                <Td className="font-mono text-xs">{a.action}</Td>
                <Td>{a.target}</Td>
                <Td className="font-mono text-xs text-muted-foreground" title={`prev ${a.prevHash}`}>{a.hash.slice(0, 12)}…</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </>
  );
}
