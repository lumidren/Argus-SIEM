// Builds the demo tenant: realistic multi-source events over the last 24 hours,
// the brute-force-then-lateral-movement scenario, and the alerts, incidents
// and entity profiles derived from them.
import type {
  Alert,
  AuditEntry,
  EntityProfile,
  EntityRef,
  EventDoc,
  Feed,
  Incident,
  Indicator,
  ParseError,
  PlaybookRun,
  Source,
  Tenant,
  User,
} from "@/lib/types";
import { buildPlaybooks, buildRules } from "./catalog";
import { hexId, rng, type Rng } from "./rng";

const HOUR = 3_600_000;
const MIN = 60_000;

const users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "svc_backup", "svc_deploy"];
const winHosts = ["ws01", "ws02", "ws03", "ws04", "ws05", "fs01", "app01", "app02", "dc01", "dc02"];
const linHosts = ["web01", "web02", "db01", "bastion01", "build01"];
const externalIPs = ["198.51.100.23", "198.51.100.77", "203.0.113.45", "203.0.113.90", "192.0.2.150", "192.0.2.201"];
const countries: [string, string, number, number][] = [
  ["PT", "Lisbon", 38.72, -9.14],
  ["US", "Austin", 30.27, -97.74],
  ["DE", "Berlin", 52.52, 13.4],
  ["SG", "Singapore", 1.35, 103.82],
  ["BR", "São Paulo", -23.55, -46.63],
];
const domains = ["example.com", "intranet.example.org", "cdn.example.net", "updates.example.com", "api.example.io"];

function ip(r: Rng, net = "10.0") {
  return `${net}.${r.int(1, 30)}.${r.int(2, 250)}`;
}

function base(r: Rng, at: number, module: string, dataset: string): EventDoc {
  return {
    id: hexId(r, 24),
    "@timestamp": new Date(at).toISOString(),
    "event.module": module,
    "event.dataset": dataset,
    "event.kind": "event",
    "argus.tenant.id": "acme",
    "argus.pipeline.parse_status": "ok",
  };
}

function noise(r: Rng, now: number, count: number): EventDoc[] {
  const out: EventDoc[] = [];
  for (let i = 0; i < count; i++) {
    // Diurnal shape: more events during working hours.
    let at = now - Math.floor(r.next() * 24 * HOUR);
    const hour = new Date(at).getUTCHours();
    if ((hour < 7 || hour > 19) && r.chance(0.5)) at -= 9 * HOUR * (r.chance(0.5) ? 1 : -1);
    if (at > now) at = now - r.int(1, 60) * MIN;
    const kind = r.weighted([["winlogon", 30], ["sysmon", 18], ["ssh", 10], ["sudo", 4], ["zeek", 16], ["suricata", 4], ["nginx", 10], ["cloudtrail", 4], ["okta", 4], ["fw", 8]] as const);
    const user = r.pick(users);
    switch (kind) {
      case "winlogon": {
        const host = r.pick(winHosts);
        const ok = r.chance(0.94);
        const e = base(r, at, "windows", "windows.security");
        Object.assign(e, {
          "event.code": ok ? "4624" : "4625",
          "event.action": ok ? "logged-in" : "logon-failed",
          "event.category": ["authentication"],
          "event.type": ["start"],
          "event.outcome": ok ? "success" : "failure",
          "user.name": user,
          "user.domain": "CORP",
          "host.name": `${host}.corp.local`,
          "source.ip": ip(r),
          "winlog.logon.type": r.pick([2, 3, 3, 3, 10]),
          "winlog.channel": "Security",
          message: ok ? "An account was successfully logged on." : "An account failed to log on.",
        });
        out.push(e);
        break;
      }
      case "sysmon": {
        const host = r.pick(winHosts);
        const [parent, child, cmd] = r.pick([
          ["explorer.exe", "chrome.exe", '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"'],
          ["explorer.exe", "outlook.exe", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"'],
          ["services.exe", "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p"],
          ["cmd.exe", "ipconfig.exe", "ipconfig /all"],
          ["explorer.exe", "excel.exe", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" report.xlsx'],
          ["svchost.exe", "taskhostw.exe", "taskhostw.exe"],
        ] as const);
        const e = base(r, at, "windows", "windows.sysmon_operational");
        Object.assign(e, {
          "event.code": "1",
          "event.action": "Process Create",
          "event.category": ["process"],
          "event.type": ["start"],
          "host.name": `${host}.corp.local`,
          "user.name": user,
          "process.name": child,
          "process.parent.name": parent,
          "process.command_line": cmd,
          "process.pid": r.int(1000, 30000),
          message: `Process Create: ${child}`,
        });
        out.push(e);
        break;
      }
      case "ssh": {
        const ok = r.chance(0.85);
        const e = base(r, at, "linux", "linux.auth");
        Object.assign(e, {
          "event.action": "ssh_login",
          "event.category": ["authentication"],
          "event.type": ["start"],
          "event.outcome": ok ? "success" : "failure",
          "user.name": r.pick(["deploy", "ubuntu", user]),
          "host.name": r.pick(linHosts),
          "source.ip": ip(r, "10.0"),
          "process.name": "sshd",
          message: ok ? "Accepted publickey for deploy" : "Failed password for deploy",
        });
        out.push(e);
        break;
      }
      case "sudo": {
        const e = base(r, at, "linux", "linux.auth");
        Object.assign(e, {
          "event.action": "sudo_command",
          "event.category": ["process"],
          "event.type": ["start"],
          "event.outcome": "success",
          "user.name": r.pick(["deploy", user]),
          "user.effective.name": "root",
          "host.name": r.pick(linHosts),
          "process.command_line": r.pick(["/usr/bin/systemctl restart nginx", "/usr/bin/apt update", "/usr/bin/journalctl -u app"]),
          message: "sudo command",
        });
        out.push(e);
        break;
      }
      case "zeek": {
        const isDns = r.chance(0.55);
        const e = base(r, at, "zeek", isDns ? "zeek.dns" : "zeek.conn");
        const dom = r.pick(domains);
        Object.assign(e, {
          "event.category": ["network"],
          "event.type": isDns ? ["protocol"] : ["connection", "end"],
          "source.ip": ip(r),
          "destination.ip": isDns ? "10.0.0.53" : r.pick(externalIPs),
          "destination.port": isDns ? 53 : r.pick([443, 443, 443, 80, 22]),
          "network.transport": isDns ? "udp" : "tcp",
          "network.direction": isDns ? "internal" : "outbound",
          ...(isDns ? { "dns.question.name": dom, "dns.response_code": "NOERROR" } : { "source.bytes": r.int(200, 90000), "destination.bytes": r.int(500, 900000), "zeek.conn.state": "SF" }),
          message: isDns ? `DNS query ${dom}` : "connection",
        });
        out.push(e);
        break;
      }
      case "suricata": {
        const e = base(r, at, "suricata", "suricata.eve");
        Object.assign(e, {
          "event.kind": "alert",
          "event.category": ["network", "intrusion_detection"],
          "rule.name": r.pick(["ET POLICY Outdated Browser Version", "ET INFO TLS Handshake Failure", "ET POLICY Possible External IP Lookup"]),
          "suricata.eve.alert.severity": 3,
          "source.ip": ip(r),
          "destination.ip": r.pick(externalIPs),
          "destination.port": 443,
          message: "Suricata alert",
        });
        out.push(e);
        break;
      }
      case "nginx": {
        const status = r.weighted([[200, 80], [304, 8], [404, 9], [500, 3]] as const);
        const e = base(r, at, "nginx", "nginx.access");
        Object.assign(e, {
          "event.category": ["web"],
          "event.type": ["access"],
          "event.outcome": status < 400 ? "success" : "failure",
          "source.ip": r.chance(0.7) ? r.pick(externalIPs) : ip(r),
          "http.request.method": r.pick(["GET", "GET", "GET", "POST"]),
          "url.path": r.pick(["/", "/api/v1/orders", "/login", "/static/app.js", "/healthz"]),
          "http.response.status_code": status,
          "host.name": r.pick(["web01", "web02"]),
          "user_agent.original": "Mozilla/5.0",
          message: `${status} request`,
        });
        out.push(e);
        break;
      }
      case "cloudtrail": {
        const e = base(r, at, "aws", "aws.cloudtrail");
        const action = r.pick(["DescribeInstances", "GetObject", "ListBuckets", "AssumeRole", "PutObject"]);
        Object.assign(e, {
          "event.action": action,
          "event.provider": action === "AssumeRole" ? "sts.amazonaws.com" : action.endsWith("Object") || action === "ListBuckets" ? "s3.amazonaws.com" : "ec2.amazonaws.com",
          "event.category": [action === "AssumeRole" ? "authentication" : "configuration"],
          "event.outcome": "success",
          "user.name": r.pick(["deploy-session", user, "ci-runner"]),
          "cloud.provider": "aws",
          "cloud.region": r.pick(["us-east-1", "eu-west-1"]),
          "source.ip": r.pick(externalIPs),
          message: `${action} on AWS`,
        });
        out.push(e);
        break;
      }
      case "okta": {
        const [cc, city, lat, lon] = r.pick(countries.slice(0, 2));
        const ok = r.chance(0.92);
        const e = base(r, at, "okta", "okta.system");
        Object.assign(e, {
          "event.action": "user.session.start",
          "event.category": ["authentication"],
          "event.outcome": ok ? "success" : "failure",
          "user.name": user,
          "user.email": `${user}@example.com`,
          "source.ip": r.pick(externalIPs),
          "source.geo.country_iso_code": cc,
          "source.geo.city_name": city,
          "source.geo.location": `${lat},${lon}`,
          message: ok ? "User login to Okta" : "User login failed",
        });
        out.push(e);
        break;
      }
      case "fw": {
        const allow = r.chance(0.8);
        const e = base(r, at, "panw", "panw.panos");
        Object.assign(e, {
          "event.category": ["network"],
          "event.type": ["connection", allow ? "allowed" : "denied"],
          "event.action": allow ? "allow" : "deny",
          "event.outcome": allow ? "success" : "failure",
          "source.ip": allow ? ip(r) : r.pick(externalIPs),
          "destination.ip": allow ? r.pick(externalIPs) : ip(r),
          "destination.port": r.pick([443, 80, 22, 3389, 445]),
          "network.application": r.pick(["ssl", "web-browsing", "ssh", "ms-rdp"]),
          "rule.name": allow ? "allow-web" : "default-deny",
          "observer.name": "fw-edge-01",
          message: allow ? "TRAFFIC allow" : "TRAFFIC deny",
        });
        out.push(e);
        break;
      }
    }
  }
  return out;
}

export type Scenario = { events: EventDoc[]; attacker: string; user: string; hosts: string[]; start: number };

/** The README scenario: password guessing against one account from an
 * external address, a successful logon, then the account moving across
 * three servers it never used, ending with a service install. */
function scenario(r: Rng, now: number): Scenario {
  const attacker = "203.0.113.45";
  const user = "svc_backup";
  const hosts = ["app01.corp.local", "fs01.corp.local", "dc01.corp.local"];
  const start = now - 95 * MIN;
  const ev: EventDoc[] = [];
  for (let i = 0; i < 18; i++) {
    const e = base(r, start + i * 9_000, "windows", "windows.security");
    Object.assign(e, {
      "event.code": "4625",
      "event.action": "logon-failed",
      "event.category": ["authentication"],
      "event.type": ["start"],
      "event.outcome": "failure",
      "user.name": user,
      "user.domain": "CORP",
      "host.name": "ws03.corp.local",
      "source.ip": attacker,
      "winlog.logon.type": 3,
      "winlog.logon.failure.reason": "Unknown user name or bad password.",
      "argus.scenario": "bruteforce-lateral",
      message: "An account failed to log on.",
    });
    ev.push(e);
  }
  const ok = base(r, start + 18 * 9_000 + 30_000, "windows", "windows.security");
  Object.assign(ok, {
    "event.code": "4624",
    "event.action": "logged-in",
    "event.category": ["authentication"],
    "event.type": ["start"],
    "event.outcome": "success",
    "user.name": user,
    "user.domain": "CORP",
    "host.name": "ws03.corp.local",
    "source.ip": attacker,
    "winlog.logon.type": 3,
    "argus.scenario": "bruteforce-lateral",
    message: "An account was successfully logged on.",
  });
  ev.push(ok);
  let t = start + 40 * MIN;
  let from = "10.0.3.33";
  for (const [i, h] of hosts.entries()) {
    const logon = base(r, t, "windows", "windows.security");
    Object.assign(logon, {
      "event.code": "4624",
      "event.action": "logged-in",
      "event.category": ["authentication"],
      "event.type": ["start"],
      "event.outcome": "success",
      "user.name": user,
      "user.domain": "CORP",
      "host.name": h,
      "source.ip": from,
      "winlog.logon.type": 3,
      "argus.scenario": "bruteforce-lateral",
      message: "An account was successfully logged on.",
    });
    const share = base(r, t + 20_000, "windows", "windows.security");
    Object.assign(share, {
      "event.code": "5140",
      "event.action": "network-share-accessed",
      "event.category": ["network", "file"],
      "event.type": ["access"],
      "user.name": user,
      "host.name": h,
      "source.ip": from,
      "file.path": "\\\\*\\ADMIN$",
      "argus.scenario": "bruteforce-lateral",
      message: "A network share object was accessed.",
    });
    ev.push(logon, share);
    if (i === hosts.length - 1) {
      const svc = base(r, t + 70_000, "windows", "windows.system");
      Object.assign(svc, {
        "event.code": "7045",
        "event.action": "service-installed",
        "event.category": ["configuration"],
        "event.type": ["creation"],
        "user.name": user,
        "host.name": h,
        "service.name": "UpdaterSvc",
        "process.executable": "C:\\ProgramData\\updater\\updatersvc.exe",
        "argus.scenario": "bruteforce-lateral",
        message: "A service was installed in the system.",
      });
      ev.push(svc);
    }
    from = `10.0.${4 + i}.${20 + i}`;
    t += 12 * MIN;
  }
  return { events: ev, attacker, user, hosts, start };
}

export type DemoData = ReturnType<typeof generate>;

export function generate(now: number) {
  const r = rng(20261109);
  const rules = buildRules(now);
  const playbooks = buildPlaybooks(now);
  const sc = scenario(r, now);
  const events = [...noise(r, now, 3200), ...sc.events].sort((a, b) => (a["@timestamp"] < b["@timestamp"] ? 1 : -1));

  const ruleById = new Map(rules.map((x) => [x.id, x]));
  const alerts: Alert[] = [];
  const mkAlert = (ruleId: string, at: number, entity: EntityRef, entities: EntityRef[], evidence: string[], summary: string, score: number, status: Alert["status"] = "open"): Alert => {
    const rule = ruleById.get(ruleId)!;
    const a: Alert = {
      id: "al-" + hexId(r, 10),
      tenant: "acme",
      ruleId,
      ruleName: rule.name,
      ruleKind: rule.kind,
      severity: rule.severity,
      score,
      status,
      createdAt: new Date(at).toISOString(),
      entity,
      entities,
      tactics: rule.tactics,
      techniques: rule.techniques,
      dataset: rule.logsource,
      evidence,
      latencyMs: r.int(380, 2900),
      summary,
    };
    alerts.push(a);
    return a;
  };

  const scIds = sc.events.map((e) => e.id);
  const userRef: EntityRef = { kind: "user", id: sc.user };
  const ipRef: EntityRef = { kind: "ip", id: sc.attacker };
  const scAlerts = [
    mkAlert("win-001", sc.start + 10 * 9_000, ipRef, [ipRef, userRef, { kind: "host", id: "ws03.corp.local" }], scIds.slice(0, 10), `10 failed logons for ${sc.user} from ${sc.attacker} in 90 seconds`, 58),
    mkAlert("win-002", sc.start + 18 * 9_000 + 31_000, userRef, [userRef, ipRef], scIds.slice(0, 19), `Successful logon for ${sc.user} after 18 failures from ${sc.attacker}`, 81),
    mkAlert("win-003", sc.start + 40 * MIN + 21_000, { kind: "host", id: sc.hosts[0]! }, [userRef, { kind: "host", id: sc.hosts[0]! }], scIds.slice(19, 21), `ADMIN$ accessed on ${sc.hosts[0]} by ${sc.user}`, 64),
    mkAlert("ueba-001", sc.start + 64 * MIN + 25_000, userRef, [userRef, ...sc.hosts.map((h) => ({ kind: "host" as const, id: h }))], scIds.slice(19), `${sc.user} authenticated across ${sc.hosts.length} hosts it never used, within 24 minutes`, 92),
    mkAlert("win-004", sc.start + 64 * MIN + 71_000, { kind: "host", id: sc.hosts[2]! }, [userRef, { kind: "host", id: sc.hosts[2]! }], scIds.slice(-3), `Service UpdaterSvc installed on ${sc.hosts[2]} after share access`, 88),
  ];

  // Background alerts across the catalog.
  const bgRules = rules.filter((x) => x.status !== "deprecated" && !["win-001", "win-002", "ueba-001", "win-004"].includes(x.id));
  for (let i = 0; i < 46; i++) {
    const rule = r.pick(bgRules);
    const at = now - r.int(5, 7 * 24 * 60) * MIN;
    const isUser = r.chance(0.5);
    const ent: EntityRef = isUser ? { kind: "user", id: r.pick(users) } : { kind: "host", id: `${r.pick([...winHosts, ...linHosts])}.corp.local` };
    const st = at < now - 2 * 24 * HOUR ? r.pick(["closed", "closed", "acknowledged"] as const) : r.pick(["open", "open", "acknowledged", "in_progress"] as const);
    const a = mkAlert(rule.id, at, ent, [ent], [r.pick(events).id], `${rule.name} on ${ent.id}`, r.int(15, 75), st);
    if (st === "closed") a.closure = r.pick(["false_positive", "benign_true_positive", "true_positive"] as const);
  }
  alerts.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  for (const a of alerts) {
    const rule = ruleById.get(a.ruleId);
    if (rule && Date.parse(a.createdAt) > now - 7 * 24 * HOUR) rule.alerts7d++;
  }

  const incidents: Incident[] = [];
  const inc: Incident = {
    id: "INC-1042",
    tenant: "acme",
    title: `Password guessing then lateral movement by ${sc.user}`,
    severity: "critical",
    score: 94,
    status: "investigating",
    assignee: "carol",
    createdAt: new Date(sc.start + 18 * 9_000 + 32_000).toISOString(),
    updatedAt: new Date(now - 4 * MIN).toISOString(),
    slaDueAt: new Date(sc.start + 18 * 9_000 + 32_000 + 4 * HOUR).toISOString(),
    alertIds: scAlerts.map((a) => a.id),
    entities: [userRef, ipRef, { kind: "host", id: "ws03.corp.local" }, ...sc.hosts.map((h) => ({ kind: "host" as const, id: h }))],
    tactics: ["TA0006", "TA0001", "TA0008", "TA0002"],
    techniques: ["T1110", "T1078", "T1021.002", "T1569.002", "T1550"],
    timeline: [],
    notes: [
      { id: "n1", at: new Date(sc.start + 70 * MIN).toISOString(), author: "carol", text: "svc_backup is a backup service account; it should only log on to fs01 from the backup server 10.0.10.5. The external source is unexpected." },
      { id: "n2", at: new Date(now - 6 * MIN).toISOString(), author: "argus-playbooks", text: "Enrichment: 203.0.113.45 is listed in 2 feeds (confidence 80). GeoIP: SG, AS64512." },
    ],
    evidence: [
      { id: "ev1", name: "dc01-services.csv", sha256: "9f2c6a2b2e9d4f0f7e2b1c3d4a5b6c7d8e9f00112233445566778899aabbccdd", size: 18342, addedBy: "carol", at: new Date(now - 30 * MIN).toISOString() },
    ],
    tags: ["lateral-movement", "service-account"],
  };
  inc.timeline = [
    ...sc.events.filter((_, i) => i === 0 || i === 17 || i >= 18).map((e) => ({ at: e["@timestamp"], kind: "event" as const, actor: String(e["host.name"] ?? ""), text: String(e.message ?? ""), ref: e.id })),
    ...scAlerts.map((a) => ({ at: a.createdAt, kind: "alert" as const, actor: "argus-detect", text: a.ruleName, ref: a.id })),
    { at: inc.createdAt, kind: "status", actor: "argus", text: "Incident created from correlated alerts" },
    { at: new Date(sc.start + 68 * MIN).toISOString(), kind: "assignment", actor: "argus", text: "Assigned to carol (on-call)" },
    { at: new Date(now - 6 * MIN).toISOString(), kind: "playbook", actor: "argus-playbooks", text: "Playbook \"Enrich incident entities\" completed", ref: "run-1" },
    { at: new Date(now - 30 * MIN).toISOString(), kind: "evidence", actor: "carol", text: "Attached dc01-services.csv" },
    { at: new Date(now - 4 * MIN).toISOString(), kind: "status", actor: "carol", text: "Status changed to investigating" },
  ].sort((a, b) => (a.at < b.at ? -1 : 1));
  for (const a of scAlerts) a.incidentId = inc.id;
  incidents.push(inc);

  const otherTitles = [
    ["Inbox forwarding rule on finance mailbox", "high", "contained", "dave", ["T1114.003"], ["TA0009"]],
    ["Console login without MFA on production account", "medium", "triage", null, ["T1078.004"], ["TA0001"]],
    ["Privileged pod in payments namespace", "high", "new", null, ["T1611"], ["TA0004"]],
    ["SSH password guessing against bastion01", "medium", "resolved", "erin", ["T1110.001"], ["TA0006"]],
    ["Defender protection disabled on ws02", "high", "closed", "carol", ["T1562.001"], ["TA0005"]],
    ["DNS volume spike from build01", "low", "triage", "frank", ["T1071.004"], ["TA0011"]],
  ] as const;
  for (const [i, [title, sev, status, who, techs, tacs]] of otherTitles.entries()) {
    const created = now - (i + 1) * 9 * HOUR - r.int(0, 50) * MIN;
    const linked = alerts.filter((a) => !a.incidentId && a.techniques.some((t) => (techs as readonly string[]).includes(t))).slice(0, 3);
    for (const a of linked) a.incidentId = `INC-${1036 + i}`;
    incidents.push({
      id: `INC-${1036 + i}`,
      tenant: "acme",
      title,
      severity: sev,
      score: { low: 30, medium: 55, high: 76, critical: 92 }[sev],
      status,
      assignee: who,
      createdAt: new Date(created).toISOString(),
      updatedAt: new Date(created + r.int(1, 8) * HOUR).toISOString(),
      slaDueAt: new Date(created + ({ low: 72, medium: 24, high: 8, critical: 4 }[sev] as number) * HOUR).toISOString(),
      alertIds: linked.map((a) => a.id),
      entities: linked.map((a) => a.entity),
      tactics: [...tacs],
      techniques: [...techs],
      timeline: [{ at: new Date(created).toISOString(), kind: "status", actor: "argus", text: "Incident created" }],
      notes: [],
      evidence: [],
      tags: [],
      ...(status === "closed" || status === "resolved" ? { closure: "true_positive" as const } : {}),
    });
  }

  // Entity profiles.
  const profiles = new Map<string, EntityProfile>();
  const touch = (ref: EntityRef, risk: number, attrs: Record<string, string>) => {
    const key = `${ref.kind}:${ref.id}`;
    const hist = Array.from({ length: 24 }, (_, h) => ({ at: new Date(now - (23 - h) * HOUR).toISOString(), value: Math.max(0, Math.round(risk * (h > 21 ? 1 : 0.15 + r.next() * 0.25))) }));
    profiles.set(key, {
      ref,
      displayName: ref.id,
      risk,
      riskHistory: hist,
      firstSeen: new Date(now - r.int(30, 400) * 24 * HOUR).toISOString(),
      lastSeen: new Date(now - r.int(1, 90) * MIN).toISOString(),
      attributes: attrs,
      peers: [],
    });
  };
  for (const u of users) {
    touch({ kind: "user", id: u }, u === sc.user ? 91 : r.int(2, 35), {
      department: u.startsWith("svc_") ? "Service account" : r.pick(["Finance", "Engineering", "Sales", "IT", "Legal"]),
      title: u.startsWith("svc_") ? "Non-interactive" : r.pick(["Analyst", "Engineer", "Manager", "Administrator"]),
      privileged: u === "svc_backup" || u === "carol" ? "yes" : "no",
      mfa: u.startsWith("svc_") ? "n/a" : "enrolled",
      "usual hours": u.startsWith("svc_") ? "01:00–03:00 UTC" : "08:00–18:00 UTC",
    });
  }
  for (const h of [...winHosts, ...linHosts]) {
    const fq = `${h}.corp.local`;
    const risky = sc.hosts.includes(fq) ? 78 : r.int(1, 30);
    touch({ kind: "host", id: fq }, risky, {
      os: winHosts.includes(h) ? r.pick(["Windows 11 23H2", "Windows Server 2022"]) : "Ubuntu 24.04",
      criticality: h.startsWith("dc") ? "critical" : h.startsWith("fs") || h.startsWith("db") ? "high" : "medium",
      owner: h.startsWith("ws") ? "end-user-computing" : "platform",
      ip: ip(r),
    });
  }
  touch(ipRef, 85, { asn: "AS64512 Example Transit", country: "SG", feeds: "2", "first seen in tenant": new Date(sc.start).toISOString() });
  const p = profiles.get(`user:${sc.user}`)!;
  p.peers = [ipRef, ...sc.hosts.map((h) => ({ kind: "host" as const, id: h }))];

  const runs: PlaybookRun[] = [
    { id: "run-1", playbookId: "pb-enrich", incidentId: inc.id, startedAt: new Date(now - 7 * MIN).toISOString(), status: "succeeded", dryRun: false, triggeredBy: "incident.created", steps: [
      { stepId: "s1", status: "ok", output: "7 observables: 1 external IP, 5 hosts, 1 account" },
      { stepId: "s2", status: "ok", output: "203.0.113.45 matched 2 feeds (abuse.ch, internal-misp)" },
      { stepId: "s3", status: "ok", output: "note n2 added" },
    ] },
    { id: "run-2", playbookId: "pb-contain-host", incidentId: inc.id, startedAt: new Date(now - 3 * MIN).toISOString(), status: "awaiting_approval", dryRun: false, triggeredBy: "carol", steps: [
      { stepId: "s1", status: "pending_approval", output: "Isolate dc01.corp.local: waiting for a second approver" },
      { stepId: "s2", status: "skipped", output: "" },
      { stepId: "s3", status: "skipped", output: "" },
    ] },
    { id: "run-3", playbookId: "pb-block-ip", startedAt: new Date(now - 26 * HOUR).toISOString(), status: "dry_run", dryRun: true, triggeredBy: "erin", steps: [
      { stepId: "s1", status: "ok", output: "198.51.100.77 not on the allow-list" },
      { stepId: "s2", status: "ok", output: "dry run: would add 198.51.100.77 to argus-blocklist for 24h" },
    ] },
  ];

  const indicators: Indicator[] = [
    ...externalIPs.map((v, i) => ({ id: `ioc-ip-${i}`, type: "ipv4" as const, value: v, provider: r.pick(["abuse.ch", "internal-misp", "otx"]), confidence: [80, 60, 85, 40, 70, 55][i]!, firstSeen: new Date(now - (i + 3) * 24 * HOUR).toISOString(), lastSeen: new Date(now - i * HOUR).toISOString(), expiresAt: new Date(now + (30 - i) * 24 * HOUR).toISOString(), sightings: v === sc.attacker ? 19 : r.int(0, 6), tags: v === sc.attacker ? ["password-guessing", "scanner"] : ["scanner"], tlp: "green" as const })),
    ...["login-example-support.net", "cdn-update-check.example.info", "files-share-example.top"].map((v, i) => ({ id: `ioc-dom-${i}`, type: "domain" as const, value: v, provider: "otx", confidence: 65 - i * 10, firstSeen: new Date(now - 10 * 24 * HOUR).toISOString(), lastSeen: new Date(now - 2 * 24 * HOUR).toISOString(), expiresAt: new Date(now + 20 * 24 * HOUR).toISOString(), sightings: i === 0 ? 2 : 0, tags: ["phishing"], tlp: "amber" as const })),
    ...[0, 1, 2].map((i) => ({ id: `ioc-hash-${i}`, type: "sha256" as const, value: hexId(r, 64), provider: "internal-misp", confidence: 90, firstSeen: new Date(now - 40 * 24 * HOUR).toISOString(), lastSeen: new Date(now - 5 * 24 * HOUR).toISOString(), expiresAt: new Date(now + 50 * 24 * HOUR).toISOString(), sightings: 0, tags: ["sample"], tlp: "amber" as const })),
  ];
  const feeds: Feed[] = [
    { id: "f1", name: "abuse.ch Feodo Tracker", kind: "abuse_ch", indicators: 412, lastPull: new Date(now - 18 * MIN).toISOString(), status: "ok" },
    { id: "f2", name: "Internal MISP", kind: "misp", indicators: 2290, lastPull: new Date(now - 7 * MIN).toISOString(), status: "ok" },
    { id: "f3", name: "AlienVault OTX pulses", kind: "otx", indicators: 15873, lastPull: new Date(now - 42 * MIN).toISOString(), status: "ok" },
    { id: "f4", name: "Partner TAXII collection", kind: "taxii", indicators: 0, lastPull: new Date(now - 6 * HOUR).toISOString(), status: "error", error: "401 from TAXII server: credentials expired" },
  ];

  const countBy = (ds: string) => events.filter((e) => String(e["event.dataset"]).startsWith(ds)).length;
  const sources: Source[] = [
    ["win-security", "Windows Security (domain)", "windows", "windows.security", "argus-agent"],
    ["win-sysmon", "Sysmon", "windows", "windows.sysmon_operational", "argus-agent"],
    ["linux-auth", "Linux auth", "linux", "linux.auth", "argus-agent"],
    ["zeek", "Zeek sensors", "zeek", "zeek", "vector"],
    ["suricata", "Suricata IDS", "suricata", "suricata.eve", "vector"],
    ["nginx", "Web tier access logs", "nginx", "nginx.access", "fluent-bit"],
    ["cloudtrail", "AWS CloudTrail (org trail)", "aws", "aws.cloudtrail", "puller"],
    ["okta", "Okta System Log", "okta", "okta.system", "puller"],
    ["panos", "PAN-OS edge firewalls", "panw", "panw.panos", "syslog-tls"],
    ["o365", "Microsoft 365 audit", "o365", "o365.audit", "puller"],
  ].map(([id, name, kind, dataset, collector], i) => {
    const n = countBy(dataset!);
    const status = id === "o365" ? "silent" : id === "suricata" ? "degraded" : "healthy";
    return {
      id: id!,
      name: name!,
      kind: kind!,
      dataset: dataset!,
      status: status as Source["status"],
      eps: status === "silent" ? 0 : Math.max(1, Math.round((n / 86400) * 1800)),
      parseFailureRate: status === "degraded" ? 0.034 : [0, 0.0004, 0.0011, 0][i % 4]!,
      lastEventAt: new Date(now - (status === "silent" ? 7 * HOUR : r.int(1, 40) * 1000)).toISOString(),
      lagSeconds: status === "degraded" ? 41 : r.int(0, 3),
      eventsToday: n * 1800,
      collector: collector!,
    };
  });
  const parseErrors: ParseError[] = [
    { at: new Date(now - 4 * MIN).toISOString(), sourceId: "suricata", parser: "suricata", error: "invalid character '}' looking for beginning of object key string", sample: '{"timestamp":"2026-11-09T01:12:09.551+0000","event_type":"flow",,}' },
    { at: new Date(now - 9 * MIN).toISOString(), sourceId: "suricata", parser: "suricata", error: "parsers: record exceeds size limit", sample: '{"timestamp":"…","event_type":"fileinfo","payload":"<1.4 MiB truncated>"}' },
    { at: new Date(now - 51 * MIN).toISOString(), sourceId: "linux-auth", parser: "linux", error: "linux: auth message matched no known pattern", sample: "<38>Nov  9 00:21:44 bastion01 sshd[811]: Timeout before authentication for 10.0.7.12 port 51144" },
  ];

  const tenants: Tenant[] = [
    { id: "acme", name: "Acme Corp", plan: "enterprise", retentionDays: 395, eventsPerDay: 41_000_000, users: 18, worm: true },
    { id: "globex", name: "Globex", plan: "standard", retentionDays: 90, eventsPerDay: 6_200_000, users: 7, worm: false },
    { id: "initech", name: "Initech", plan: "standard", retentionDays: 180, eventsPerDay: 2_900_000, users: 5, worm: false },
  ];
  const people: User[] = [
    ["u1", "Carol Smith", "carol@example.com", "analyst"],
    ["u2", "Dave Jones", "dave@example.com", "analyst"],
    ["u3", "Erin Brooks", "erin@example.com", "engineer"],
    ["u4", "Frank Lee", "frank@example.com", "analyst"],
    ["u5", "Grace Kim", "grace@example.com", "admin"],
    ["u6", "Heidi Novak", "heidi@example.com", "viewer"],
    ["u7", "lumidren", "lumidren@example.com", "admin"],
  ].map(([id, name, email, role], i) => ({ id: id!, name: name!, email: email!, role: role as User["role"], tenant: "acme", lastLogin: new Date(now - (i * 3 + 1) * HOUR).toISOString(), mfa: true, sso: i !== 6 }));
  let prev = "0".repeat(64);
  const audit: AuditEntry[] = [
    ["grace", "rule.promote", "win-009 staging → production"],
    ["erin", "rule.update", "net-002 v3 (tuning: exclude build01)"],
    ["carol", "incident.assign", "INC-1042 → carol"],
    ["argus-playbooks", "playbook.run", "pb-enrich on INC-1042"],
    ["carol", "evidence.add", "INC-1042 dc01-services.csv"],
    ["carol", "playbook.request", "pb-contain-host on INC-1042 (awaiting approval)"],
    ["grace", "legal_hold.set", "tenant acme, index family windows, case INC-1042"],
  ].map(([actor, action, target], i) => {
    const hash = hexId(rng(i + 77), 64);
    const e = { seq: 9_812 + i, at: new Date(now - (7 - i) * 11 * MIN).toISOString(), actor: actor!, action: action!, target: target!, hash, prevHash: prev };
    prev = hash;
    return e;
  });

  return { now, events, alerts, incidents, rules, playbooks, runs, profiles, indicators, feeds, sources, parseErrors, tenants, users: people, audit, scenario: sc };
}
