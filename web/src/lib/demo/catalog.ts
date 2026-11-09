// Curated detection rules and playbooks shipped with the demo tenant. Rule
// definitions use the Argus rule YAML format (docs/adr/0005).
import type { Playbook, Rule, RuleKind, RuleStatus, Severity } from "@/lib/types";

type RuleSeed = [
  id: string,
  name: string,
  kind: RuleKind,
  severity: Severity,
  status: RuleStatus,
  techniques: string[],
  tactics: string[],
  logsource: string,
  condition: string,
  description: string,
  falsePositives: string[],
  response: string,
];

const seeds: RuleSeed[] = [
  ["win-001", "Multiple failed logons from one source", "threshold", "medium", "production", ["T1110"], ["TA0006"], "windows.security", "event.code:4625 | count() by source.ip >= 10 within 5m", "Ten or more failed Windows logons from a single source address within five minutes.", ["Misconfigured service accounts retrying stale passwords", "Vulnerability scanners"], "Identify the source host and the targeted accounts. Check for a subsequent successful logon from the same source."],
  ["win-002", "Failed logons followed by success", "sequence", "high", "production", ["T1110", "T1078"], ["TA0006", "TA0001"], "windows.security", "seq by user.name within 30m: [event.code:4625 | count >= 5] -> [event.code:4624]", "A burst of failed logons followed by a successful logon for the same account.", ["Users who forget and then remember a password"], "Confirm with the user. Review the source address and the sessions opened after the success."],
  ["win-003", "Logon to administrative share from new source", "sigma", "medium", "production", ["T1021.002"], ["TA0008"], "windows.security", "event.code:5140 and file.path:(*ADMIN$ or *C$) and not source.ip:10.0.10.*", "Access to ADMIN$ or C$ from a host outside the management subnet.", ["Software deployment tools", "Backup agents"], "Validate the source host's role. Correlate with service creation on the target."],
  ["win-004", "Service installed on remote host after share access", "sequence", "high", "production", ["T1569.002", "T1021.002"], ["TA0002", "TA0008"], "windows.system", "seq by host.name within 10m: [event.code:5145 and file.name:svcctl] -> [event.code:7045]", "Service control pipe access followed by a new service installation on the same host.", ["Remote administration with management tools"], "Review the service binary path and the account that installed it."],
  ["win-005", "Security event log cleared", "sigma", "high", "production", ["T1070.001"], ["TA0005"], "windows.security", "event.code:1102 or (event.code:104 and winlog.channel:System)", "The Security or System event log was cleared.", ["Planned log maintenance"], "Treat as potential anti-forensics. Recover logs from the SIEM and review activity just before the clear."],
  ["win-006", "Audit policy changed", "sigma", "medium", "production", ["T1562.002"], ["TA0005"], "windows.security", "event.code:4719", "System audit policy was modified.", ["Group Policy updates"], "Compare with change records. Verify auditing coverage is restored."],
  ["win-007", "User added to privileged group", "sigma", "high", "production", ["T1098"], ["TA0003", "TA0004"], "windows.security", "event.code:(4728 or 4732 or 4756) and group.name:(\"Domain Admins\" or \"Enterprise Admins\" or Administrators)", "An account was added to a highly privileged group.", ["Approved access requests"], "Confirm the change ticket. Remove membership if unapproved."],
  ["win-008", "New local account created", "sigma", "medium", "production", ["T1136.001"], ["TA0003"], "windows.security", "event.code:4720 and not user.name:*$", "A local or domain user account was created.", ["Onboarding automation"], "Verify against HR onboarding. Check group memberships of the new account."],
  ["win-009", "Kerberos service ticket with RC4 encryption", "sigma", "medium", "staging", ["T1558.003"], ["TA0006"], "windows.security", "event.code:4769 and winlog.event_data.TicketEncryptionType:0x17 and not winlog.event_data.ServiceName:*$", "Service tickets requested with RC4 for user service accounts.", ["Legacy applications without AES support"], "List requested service names. Rotate service account credentials if unexpected."],
  ["win-010", "Scheduled task created", "sigma", "low", "production", ["T1053.005"], ["TA0002", "TA0003"], "windows.security", "event.code:4698", "A scheduled task was registered.", ["Software installers", "Management agents"], "Review the task action and the creating account."],
  ["win-011", "PowerShell script block with encoded command", "sigma", "medium", "production", ["T1059.001", "T1027"], ["TA0002", "TA0005"], "windows.powershell_operational", "event.code:4104 and powershell.file.script_block_text:*FromBase64String*", "A PowerShell script block decoded Base64 content at runtime.", ["Signed vendor scripts"], "Decode the content and review the parent process."],
  ["win-012", "Defender real-time protection disabled", "sigma", "high", "production", ["T1562.001"], ["TA0005"], "windows.defender", "event.code:5001", "Microsoft Defender real-time protection was turned off.", ["Troubleshooting by IT"], "Re-enable protection. Investigate the host for activity during the gap."],
  ["sys-001", "Rare parent-child process pair", "aggregation", "low", "production", ["T1059"], ["TA0002"], "windows.sysmon_operational", "event.code:1 | rare(process.parent.name, process.name) by host.name over 14d", "A parent/child process pair not seen on this host in the last 14 days.", ["Software updates", "New applications"], "Review the command line and the user context."],
  ["sys-002", "Remote thread created in another process", "sigma", "medium", "staging", ["T1055"], ["TA0005", "TA0004"], "windows.sysmon_operational", "event.code:8 and not process.executable:(\"C:\\\\Windows\\\\System32\\\\*\")", "A process created a thread in another process.", ["Accessibility and debugging tools"], "Identify the source and target images and their signatures."],
  ["sys-003", "Process accessed LSASS memory", "sigma", "high", "production", ["T1003.001"], ["TA0006"], "windows.sysmon_operational", "event.code:10 and winlog.event_data.TargetImage:*\\\\lsass.exe and winlog.event_data.GrantedAccess:(0x1010 or 0x1410 or 0x1fffff)", "A process opened LSASS with memory read access.", ["Endpoint security products"], "Isolate the host if the source process is unknown. Reset credentials of users logged on to it."],
  ["lin-001", "SSH brute force", "threshold", "medium", "production", ["T1110.001"], ["TA0006"], "linux.auth", "event.action:ssh_login and event.outcome:failure | count() by source.ip >= 20 within 5m", "Twenty or more failed SSH logins from one address within five minutes.", ["Monitoring probes using wrong keys"], "Block the source at the perimeter if external. Check for later success."],
  ["lin-002", "Sudo to root by user not seen before", "aggregation", "medium", "production", ["T1548.003"], ["TA0004"], "linux.auth", "event.action:sudo_command and user.effective.name:root | first_seen(user.name) by host.name", "First time a user ran sudo as root on this host.", ["New team members"], "Confirm the user's role on the host."],
  ["lin-003", "Audit daemon stopped", "sigma", "high", "production", ["T1562.012"], ["TA0005"], "linux.auditd", "auditd.log.record_type:(DAEMON_END or SERVICE_STOP) and auditd.log.data.unit:auditd", "The Linux audit daemon was stopped.", ["Package upgrades"], "Restart auditd and review activity since it stopped."],
  ["lin-004", "Kernel module loaded", "sigma", "low", "staging", ["T1547.006"], ["TA0003", "TA0004"], "linux.auditd", "auditd.log.syscall:(init_module or finit_module)", "A kernel module was loaded.", ["Driver installation"], "Verify the module name against the host's baseline."],
  ["net-001", "Outbound connection to threat-intel indicator", "sigma", "high", "production", ["T1071"], ["TA0011"], "network", "tags:ti_match and network.direction:outbound", "Network traffic to an address or domain listed in an active intelligence feed.", ["Stale indicators"], "Review the indicator's source and confidence. Identify the internal process if endpoint data exists."],
  ["net-002", "DNS query volume spike for one host", "aggregation", "medium", "production", ["T1071.004", "T1568"], ["TA0011"], "zeek.dns", "event.dataset:zeek.dns | spike(count()) by source.ip vs 7d baseline > 4 sigma", "A host's DNS query rate rose far above its rolling baseline.", ["Backup jobs", "Software update storms"], "Inspect the queried domains for high-entropy names."],
  ["net-003", "Suricata high-severity alert", "sigma", "high", "production", ["T1190"], ["TA0001"], "suricata.eve", "event.kind:alert and suricata.eve.alert.severity:1", "Suricata raised a severity-1 signature.", ["Signature false positives on test traffic"], "Review the signature, payload and destination service."],
  ["net-004", "Large outbound transfer to new destination", "aggregation", "medium", "staging", ["T1048", "T1567"], ["TA0010"], "zeek.conn", "network.direction:outbound | sum(source.bytes) by source.ip, destination.ip > 500MB and first_seen(destination.ip)", "More than 500 MB sent to a destination not contacted before.", ["Cloud backup onboarding"], "Identify the process and data involved."],
  ["net-005", "Firewall denies from internal host to many ports", "threshold", "low", "production", ["T1046"], ["TA0007"], "network", "event.type:denied | distinct_count(destination.port) by source.ip >= 50 within 10m", "One internal source was denied on fifty or more distinct ports.", ["Network inventory tools"], "Confirm the host is not an approved scanner."],
  ["aws-001", "CloudTrail logging stopped", "sigma", "critical", "production", ["T1562.008"], ["TA0005"], "aws.cloudtrail", "event.provider:cloudtrail.amazonaws.com and event.action:(StopLogging or DeleteTrail)", "A CloudTrail trail was stopped or deleted.", ["Infrastructure-as-code teardown in sandbox accounts"], "Restore logging immediately and review the caller's other actions."],
  ["aws-002", "Console login without MFA", "sigma", "medium", "production", ["T1078.004"], ["TA0001"], "aws.cloudtrail", "event.action:ConsoleLogin and aws.cloudtrail.console_login.additional_eventdata.mfa_used:false and event.outcome:success", "An AWS console login succeeded without multi-factor authentication.", ["Break-glass accounts"], "Enforce MFA for the user."],
  ["aws-003", "Access key created for another user", "sigma", "high", "production", ["T1098.001"], ["TA0003"], "aws.cloudtrail", "event.action:CreateAccessKey and not aws.cloudtrail.flattened.request_parameters.userName:user.name", "An access key was created for a different IAM user.", ["Administrators provisioning service users"], "Confirm with the key owner. Deactivate if unexpected."],
  ["aws-004", "S3 bucket policy made public", "sigma", "high", "production", ["T1530"], ["TA0009"], "aws.cloudtrail", "event.action:PutBucketPolicy and aws.cloudtrail.request_parameters:*\\\"Principal\\\":\\\"*\\\"*", "A bucket policy granting access to any principal was applied.", ["Static website buckets"], "Review the bucket contents and revert the policy."],
  ["az-001", "Sign-ins from two countries within an hour", "ueba", "high", "production", ["T1078"], ["TA0001"], "azure.signinlogs", "impossible_travel(user.name, source.geo.location) speed > 900 km/h", "Successful sign-ins for one user from locations too far apart for the elapsed time.", ["VPN egress changes", "Mobile carriers"], "Contact the user. Revoke sessions if the travel is not explained."],
  ["az-002", "Role assignment at subscription scope", "sigma", "medium", "production", ["T1098"], ["TA0004"], "azure.activitylogs", "event.action:\"MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE\" and azure.activitylogs.identity.authorization.scope:/subscriptions/*", "A role was assigned at subscription scope.", ["Platform team changes"], "Confirm the change and the assigned principal."],
  ["okta-001", "MFA factor reset followed by sign-in", "sequence", "high", "production", ["T1556"], ["TA0006"], "okta.system", "seq by user.name within 1h: [event.action:user.mfa.factor.deactivate] -> [event.action:user.session.start and event.outcome:success]", "A user's MFA factor was removed and the account signed in shortly after.", ["Help-desk factor resets"], "Verify the reset with the help desk and the user."],
  ["okta-002", "Sign-in denied by policy from many IPs", "threshold", "medium", "production", ["T1110.003"], ["TA0006"], "okta.system", "event.action:policy.evaluate_sign_on and event.outcome:failure | distinct_count(source.ip) by user.name >= 10 within 15m", "Many distinct addresses were denied for one user, typical of password spraying.", ["Users roaming between networks"], "Check whether any attempt succeeded and enforce a password reset."],
  ["o365-001", "Inbox rule forwarding to external address", "sigma", "high", "production", ["T1114.003"], ["TA0009"], "o365.audit", "event.action:(New-InboxRule or Set-InboxRule) and o365.audit.parameters.ForwardTo:*", "A mailbox rule that forwards mail was created or changed.", ["Users forwarding to personal accounts with approval"], "Disable the rule and review sign-ins for the mailbox."],
  ["o365-002", "Mass file download from SharePoint", "threshold", "medium", "staging", ["T1530"], ["TA0009"], "o365.audit", "event.action:FileDownloaded | count() by user.name >= 200 within 10m", "A user downloaded two hundred or more files in ten minutes.", ["Sync clients"], "Contact the user and review the sites involved."],
  ["gws-001", "Admin privilege granted in Google Workspace", "sigma", "high", "production", ["T1098"], ["TA0004"], "google_workspace.admin", "event.action:GRANT_ADMIN_PRIVILEGE or event.action:ASSIGN_ROLE", "An administrator role was granted.", ["Approved role changes"], "Confirm the change request."],
  ["k8s-001", "Privileged pod created", "sigma", "high", "production", ["T1611"], ["TA0004"], "kubernetes.audit", "event.action:create and orchestrator.resource.type:pods and kubernetes.audit.pod.privileged:true", "A pod requesting privileged mode was created.", ["Node-level DaemonSets such as CNI or monitoring agents"], "Review the image and the requesting identity."],
  ["k8s-002", "Exec into pod in production namespace", "sigma", "medium", "production", ["T1609"], ["TA0002"], "kubernetes.audit", "kubernetes.audit.object_ref.subresource:exec and orchestrator.namespace:prod*", "An interactive exec session was opened in a production pod.", ["On-call debugging"], "Confirm the session with the on-call engineer."],
  ["ueba-001", "Lateral movement chain across three hosts", "ueba", "critical", "production", ["T1021", "T1550"], ["TA0008"], "windows.security", "chain(user.name, host.name) network logons A->B->C within 60m where hosts new for user", "One account authenticated in a chain across at least three hosts it has not used before.", ["Administrators patching servers"], "Map the chain, isolate the last host reached, and reset the account's credentials."],
  ["ueba-002", "Logon outside the user's normal hours", "ueba", "low", "production", ["T1078"], ["TA0001"], "authentication", "hour_of_day(@timestamp) outside p5..p95 baseline for user.name", "A logon at an hour far from the user's 30-day baseline.", ["Travel", "On-call shifts"], "Low priority on its own; raises the user's risk score."],
  ["ueba-003", "Privilege escalation sequence", "ueba", "high", "experimental", ["T1068", "T1548"], ["TA0004"], "process", "seq by host.name within 15m: [user.id != 0 process start] -> [same session, user.effective.id = 0, unusual parent]", "A non-root session gained root through an unusual parent process.", ["Package managers"], "Review the process tree and the binaries involved."],
];

function yamlFor(s: RuleSeed): string {
  const [id, name, kind, severity, status, techniques, tactics, logsource, condition, description, fps, response] = s;
  return [
    `id: ${id}`,
    `name: ${name}`,
    `kind: ${kind}`,
    `status: ${status}`,
    `severity: ${severity}`,
    `logsource: ${logsource}`,
    `description: >-`,
    `  ${description}`,
    `condition: |`,
    `  ${condition}`,
    `tags:`,
    ...tactics.map((t) => `  - attack.${t.toLowerCase()}`),
    ...techniques.map((t) => `  - attack.${t.toLowerCase()}`),
    `falsepositives:`,
    ...fps.map((f) => `  - ${f}`),
    `response: >-`,
    `  ${response}`,
  ].join("\n");
}

export function buildRules(now: number): Rule[] {
  return seeds.map((s, i) => {
    const [id, name, kind, severity, status, techniques, tactics, logsource, , description, falsePositives, response] = s;
    const tests = [
      { name: "matches positive sample", kind: "true_positive" as const, passed: true },
      { name: "ignores benign sample", kind: "true_negative" as const, passed: true },
    ];
    if (status === "experimental") tests.push({ name: "ignores package manager", kind: "true_negative", passed: false });
    return {
      id,
      name,
      kind,
      status,
      severity,
      version: 1 + (i % 4),
      description,
      tactics,
      techniques,
      logsource,
      definition: yamlFor(s),
      falsePositives,
      response,
      tests,
      alerts7d: 0,
      fpRate: [0.02, 0.08, 0.15, 0.31, 0.05][i % 5]!,
      updatedAt: new Date(now - (i + 2) * 86_400_000).toISOString(),
      author: ["detection-eng", "lumidren", "soc-tier3"][i % 3]!,
    };
  });
}

export function buildPlaybooks(now: number): Playbook[] {
  const pbs: Omit<Playbook, "yaml">[] = [
    {
      id: "pb-enrich",
      name: "Enrich incident entities",
      description: "Look up every IP, domain and hash on the incident in threat intel and GeoIP, attach results as notes.",
      version: 3,
      enabled: true,
      trigger: "incident.created",
      steps: [
        { id: "s1", name: "Collect observables", action: "collect_observables", adapter: "argus", destructive: false, requiresApproval: false, params: { from: "incident.alerts" } },
        { id: "s2", name: "Threat-intel lookup", action: "enrich_ioc", adapter: "argus-ti", destructive: false, requiresApproval: false, params: { feeds: "all" } },
        { id: "s3", name: "Add findings note", action: "add_note", adapter: "argus", destructive: false, requiresApproval: false, params: { template: "enrichment" } },
      ],
      updatedAt: new Date(now - 6 * 86_400_000).toISOString(),
    },
    {
      id: "pb-contain-host",
      name: "Contain compromised host",
      description: "Isolate the host through the EDR, notify the on-call channel and open a ticket.",
      version: 5,
      enabled: true,
      trigger: "manual",
      steps: [
        { id: "s1", name: "Isolate host", action: "isolate_host", adapter: "defender-for-endpoint", destructive: true, requiresApproval: true, params: { host: "{{ incident.primary_host }}", comment: "Argus incident {{ incident.id }}" } },
        { id: "s2", name: "Notify on-call", action: "notify", adapter: "slack", destructive: false, requiresApproval: false, params: { channel: "#soc-oncall" } },
        { id: "s3", name: "Open ticket", action: "create_ticket", adapter: "webhook", destructive: false, requiresApproval: false, params: { url: "https://tickets.example.com/api/issues" } },
      ],
      updatedAt: new Date(now - 12 * 86_400_000).toISOString(),
    },
    {
      id: "pb-disable-user",
      name: "Disable account and revoke sessions",
      description: "Suspend the identity-provider account and revoke active sessions.",
      version: 2,
      enabled: true,
      trigger: "manual",
      steps: [
        { id: "s1", name: "Suspend user", action: "disable_user", adapter: "okta", destructive: true, requiresApproval: true, params: { user: "{{ incident.primary_user }}" } },
        { id: "s2", name: "Revoke sessions", action: "revoke_sessions", adapter: "okta", destructive: true, requiresApproval: true, params: { user: "{{ incident.primary_user }}" } },
        { id: "s3", name: "Notify user's manager", action: "notify", adapter: "email", destructive: false, requiresApproval: false, params: { to: "{{ identity.manager }}" } },
      ],
      updatedAt: new Date(now - 20 * 86_400_000).toISOString(),
    },
    {
      id: "pb-block-ip",
      name: "Block external address at the firewall",
      description: "Add the source address to the perimeter block list for 24 hours.",
      version: 4,
      enabled: true,
      trigger: "alert.rule:lin-001",
      steps: [
        { id: "s1", name: "Check allow-list", action: "check_allowlist", adapter: "argus", destructive: false, requiresApproval: false, params: { value: "{{ alert.source.ip }}" } },
        { id: "s2", name: "Block address", action: "block_ip", adapter: "pan-os", destructive: true, requiresApproval: true, params: { address: "{{ alert.source.ip }}", group: "argus-blocklist", ttl: "24h" } },
      ],
      updatedAt: new Date(now - 3 * 86_400_000).toISOString(),
    },
  ];
  return pbs.map((p) => ({
    ...p,
    yaml: [
      `id: ${p.id}`,
      `name: ${p.name}`,
      `version: ${p.version}`,
      `trigger: ${p.trigger}`,
      `steps:`,
      ...p.steps.flatMap((s) => [
        `  - id: ${s.id}`,
        `    name: ${s.name}`,
        `    action: ${s.action}`,
        `    adapter: ${s.adapter}`,
        ...(s.requiresApproval ? [`    approval: required`] : []),
        `    with:`,
        ...Object.entries(s.params).map(([k, v]) => `      ${k}: "${v}"`),
      ]),
    ].join("\n"),
  }));
}
