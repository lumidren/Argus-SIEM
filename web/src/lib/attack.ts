// MITRE ATT&CK Enterprise tactics and a representative technique set used by
// the coverage heat-map. IDs and names follow the public ATT&CK matrix.

export type Tactic = { id: string; name: string; shortName: string };

export const TACTICS: Tactic[] = [
  { id: "TA0043", name: "Reconnaissance", shortName: "reconnaissance" },
  { id: "TA0042", name: "Resource Development", shortName: "resource-development" },
  { id: "TA0001", name: "Initial Access", shortName: "initial-access" },
  { id: "TA0002", name: "Execution", shortName: "execution" },
  { id: "TA0003", name: "Persistence", shortName: "persistence" },
  { id: "TA0004", name: "Privilege Escalation", shortName: "privilege-escalation" },
  { id: "TA0005", name: "Defense Evasion", shortName: "defense-evasion" },
  { id: "TA0006", name: "Credential Access", shortName: "credential-access" },
  { id: "TA0007", name: "Discovery", shortName: "discovery" },
  { id: "TA0008", name: "Lateral Movement", shortName: "lateral-movement" },
  { id: "TA0009", name: "Collection", shortName: "collection" },
  { id: "TA0011", name: "Command and Control", shortName: "command-and-control" },
  { id: "TA0010", name: "Exfiltration", shortName: "exfiltration" },
  { id: "TA0040", name: "Impact", shortName: "impact" },
];

export type Technique = { id: string; name: string; tactics: string[] };

export const TECHNIQUES: Technique[] = [
  { id: "T1595", name: "Active Scanning", tactics: ["TA0043"] },
  { id: "T1589", name: "Gather Victim Identity Information", tactics: ["TA0043"] },
  { id: "T1583", name: "Acquire Infrastructure", tactics: ["TA0042"] },
  { id: "T1588", name: "Obtain Capabilities", tactics: ["TA0042"] },
  { id: "T1566", name: "Phishing", tactics: ["TA0001"] },
  { id: "T1078", name: "Valid Accounts", tactics: ["TA0001", "TA0003", "TA0004", "TA0005"] },
  { id: "T1133", name: "External Remote Services", tactics: ["TA0001", "TA0003"] },
  { id: "T1190", name: "Exploit Public-Facing Application", tactics: ["TA0001"] },
  { id: "T1059", name: "Command and Scripting Interpreter", tactics: ["TA0002"] },
  { id: "T1053", name: "Scheduled Task/Job", tactics: ["TA0002", "TA0003", "TA0004"] },
  { id: "T1047", name: "Windows Management Instrumentation", tactics: ["TA0002"] },
  { id: "T1569", name: "System Services", tactics: ["TA0002"] },
  { id: "T1136", name: "Create Account", tactics: ["TA0003"] },
  { id: "T1543", name: "Create or Modify System Process", tactics: ["TA0003", "TA0004"] },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tactics: ["TA0003", "TA0004"] },
  { id: "T1098", name: "Account Manipulation", tactics: ["TA0003", "TA0004"] },
  { id: "T1068", name: "Exploitation for Privilege Escalation", tactics: ["TA0004"] },
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tactics: ["TA0004", "TA0005"] },
  { id: "T1070", name: "Indicator Removal", tactics: ["TA0005"] },
  { id: "T1562", name: "Impair Defenses", tactics: ["TA0005"] },
  { id: "T1027", name: "Obfuscated Files or Information", tactics: ["TA0005"] },
  { id: "T1218", name: "System Binary Proxy Execution", tactics: ["TA0005"] },
  { id: "T1055", name: "Process Injection", tactics: ["TA0005", "TA0004"] },
  { id: "T1611", name: "Escape to Host", tactics: ["TA0004"] },
  { id: "T1609", name: "Container Administration Command", tactics: ["TA0002"] },
  { id: "T1556", name: "Modify Authentication Process", tactics: ["TA0006", "TA0005", "TA0003"] },
  { id: "T1530", name: "Data from Cloud Storage", tactics: ["TA0009"] },
  { id: "T1110", name: "Brute Force", tactics: ["TA0006"] },
  { id: "T1003", name: "OS Credential Dumping", tactics: ["TA0006"] },
  { id: "T1558", name: "Steal or Forge Kerberos Tickets", tactics: ["TA0006"] },
  { id: "T1552", name: "Unsecured Credentials", tactics: ["TA0006"] },
  { id: "T1087", name: "Account Discovery", tactics: ["TA0007"] },
  { id: "T1082", name: "System Information Discovery", tactics: ["TA0007"] },
  { id: "T1018", name: "Remote System Discovery", tactics: ["TA0007"] },
  { id: "T1046", name: "Network Service Discovery", tactics: ["TA0007"] },
  { id: "T1021", name: "Remote Services", tactics: ["TA0008"] },
  { id: "T1570", name: "Lateral Tool Transfer", tactics: ["TA0008"] },
  { id: "T1550", name: "Use Alternate Authentication Material", tactics: ["TA0005", "TA0008"] },
  { id: "T1005", name: "Data from Local System", tactics: ["TA0009"] },
  { id: "T1114", name: "Email Collection", tactics: ["TA0009"] },
  { id: "T1560", name: "Archive Collected Data", tactics: ["TA0009"] },
  { id: "T1071", name: "Application Layer Protocol", tactics: ["TA0011"] },
  { id: "T1105", name: "Ingress Tool Transfer", tactics: ["TA0011"] },
  { id: "T1572", name: "Protocol Tunneling", tactics: ["TA0011"] },
  { id: "T1568", name: "Dynamic Resolution", tactics: ["TA0011"] },
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactics: ["TA0010"] },
  { id: "T1567", name: "Exfiltration Over Web Service", tactics: ["TA0010"] },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactics: ["TA0010"] },
  { id: "T1486", name: "Data Encrypted for Impact", tactics: ["TA0040"] },
  { id: "T1490", name: "Inhibit System Recovery", tactics: ["TA0040"] },
  { id: "T1489", name: "Service Stop", tactics: ["TA0040"] },
  { id: "T1531", name: "Account Access Removal", tactics: ["TA0040"] },
];

export const techniqueById = new Map(TECHNIQUES.map((t) => [t.id, t]));
export const tacticById = new Map(TACTICS.map((t) => [t.id, t]));

/** Rule counts per technique, for the heat-map. */
export function coverage(rules: { techniques: string[]; status: string }[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const r of rules) {
    if (r.status === "deprecated") continue;
    for (const t of r.techniques) {
      const base = t.split(".")[0] ?? t;
      out.set(base, (out.get(base) ?? 0) + 1);
    }
  }
  return out;
}
