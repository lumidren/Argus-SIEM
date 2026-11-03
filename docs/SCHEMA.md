# Argus Event Schema (ECS 8.11 + `argus.*`)

Schema version: **1** (`argus.schema.version`). See [ADR-0001](adr/0001-common-schema-ecs.md) for
why ECS. This document is the contract between parsers, the index templates in
`deploy/opensearch/templates/`, the Sigma processing pipelines in `tools/sigma/pipelines/`, and
the UI field explorer. Parser tests assert every field named here for their source.

## 1. Representation

Inside the pipeline an event is a flat map of dotted ECS paths to values
(`internal/schema.Event`). Arrays are allowed as values (`related.ip`, `event.category`). The
OpenSearch sink converts the flat map to nested JSON; the API converts back. Keys that are not
in the mapping for a source are written under `<module>.raw.<key>` and indexed as `flat_object`.

Timestamps are RFC 3339 UTC with millisecond precision. Durations are nanoseconds
(`event.duration`). IPs are strings; the index maps them as `ip`. Ports are integers. Byte
counts are `long`. Hashes are lower-case hex.

## 2. Fields populated for every event

| Field | Type | Source |
|---|---|---|
| `@timestamp` | date | event time from the source; falls back to receive time with `argus.pipeline.time_source=processing` |
| `event.kind` | keyword | `event` (default), `alert` (IDS/firewall threat, Argus alerts), `metric`, `state` |
| `event.category` | keyword[] | ECS allowed values only |
| `event.type` | keyword[] | ECS allowed values only |
| `event.action` | keyword | source-native action name |
| `event.outcome` | keyword | `success` / `failure` / `unknown` |
| `event.module` | keyword | parser family (`windows`, `linux`, `zeek`, `suricata`, `nginx`, `apache`, `aws`, `azure`, `gcp`, `okta`, `o365`, `google_workspace`, `panw`, `fortinet`, `osquery`, `kubernetes`, `generic`) |
| `event.dataset` | keyword | `<module>.<stream>` (see per-source sections) |
| `event.original` | keyword (not indexed) | raw payload as received |
| `event.hash` | keyword | content hash, also the OpenSearch `_id` (ADR-0004) |
| `event.ingested` | date | time the processor finished normalizing |
| `event.severity` | long | 0–100 when the source provides one; Argus alerts use 1 low … 4 critical × 25 |
| `message` | text | human-readable summary; the raw line for syslog-type sources |
| `host.name` | keyword | lower-cased; from the event when present, else from the collector |
| `ecs.version` | keyword | `8.11.0` |
| `agent.type` / `agent.version` / `agent.id` | keyword | collector identity |
| `related.ip` / `related.user` / `related.hosts` / `related.hash` | keyword[] | populated by the normalizer from all IP/user/host/hash fields present |
| `tags` | keyword[] | source tags plus pipeline tags (`unparsed`, `pii_masked`, `ti_match`) |
| `argus.tenant.id` | keyword | assigned by the receiving component, never trusted from the payload |
| `argus.source.id` / `argus.source.kind` | keyword | registered data-source id and its parser kind |
| `argus.schema.version` | long | `1` |
| `argus.pipeline.parser` / `argus.pipeline.parser_version` | keyword | parser name and semantic version |
| `argus.pipeline.parse_status` | keyword | `ok`, `partial` (parsed with unmapped keys), `failed` (raw only), `sink_rejected` |
| `argus.pipeline.parse_error` | keyword | present when `partial`/`failed` |
| `argus.pipeline.received_at` | date | first-touch time, used for detection latency |
| `argus.pipeline.processor_id` | keyword | processor pod/instance |
| `argus.pipeline.time_source` | keyword | `event` or `processing` |
| `argus.entity.key` | keyword | `tenant|user:<name>` or `tenant|host:<name>`; Kafka partition key for `argus.events` |

## 3. Enrichment fields

| Field | Filled by |
|---|---|
| `source.geo.*`, `destination.geo.*`, `client.geo.*`, `server.geo.*` (`country_iso_code`, `country_name`, `region_name`, `city_name`, `location{lat,lon}`) | GeoIP (MaxMind GeoLite2-City or DB-IP, mmdb) on public IPs only |
| `source.as.number`, `source.as.organization.name` (and destination/client/server) | ASN mmdb |
| `threat.indicator.*`, `threat.enrichments[]` (`indicator.type`, `indicator.ip/url/file.hash.*/domain`, `indicator.provider`, `indicator.confidence`, `indicator.first_seen`, `matched.field`, `matched.atomic`, `feed.name`) | in-stream IOC matcher; also sets `tags: ti_match` and `event.risk_score` boost |
| `threat.technique.id/name`, `threat.tactic.id/name`, `threat.framework` | detection engine on alerts |
| `host.criticality` → `argus.asset.criticality` (`low`/`medium`/`high`/`critical`), `argus.asset.owner`, `argus.asset.tags`, `argus.asset.environment` | asset inventory lookup (Postgres `assets` table, CSV/CMDB import) |
| `argus.identity.department`, `argus.identity.title`, `argus.identity.manager`, `argus.identity.privileged` | identity directory (SCIM/CSV import) |
| `argus.entity.user.risk`, `argus.entity.host.risk` | UEBA risk at ingest time (0–100, decayed) |
| `argus.pii.masked_fields[]` | PII masker; masked values are replaced with `***<hmac8>` tokens |

## 4. Windows (`event.module: windows`)

Input: XML from `argus-agent` (wevtapi `EvtRender`) or Winlogbeat-style JSON. Datasets:
`windows.security`, `windows.system`, `windows.application`, `windows.sysmon_operational`,
`windows.powershell`, `windows.powershell_operational`, `windows.defender`, `windows.taskscheduler`,
`windows.wmi_activity`, `windows.bits_client`, `windows.terminalservices`, `windows.ntlm`,
`windows.ldap_debug`, `windows.dns_server`, `windows.firewall`, `windows.other` (any other channel).

### 4.1 Common `winlog.*` fields (all channels)

| Field | From XML |
|---|---|
| `winlog.channel` | `System/Channel` |
| `winlog.event_id` (long) and `event.code` (keyword) | `System/EventID` |
| `winlog.provider_name`, `event.provider` | `System/Provider/@Name` |
| `winlog.provider_guid` | `System/Provider/@Guid` |
| `winlog.record_id` | `System/EventRecordID` |
| `winlog.computer_name`, `host.name` | `System/Computer` |
| `winlog.task`, `winlog.opcode`, `winlog.keywords[]`, `winlog.version`, `winlog.level` | `System/*` |
| `winlog.process.pid`, `winlog.process.thread.id` | `System/Execution` |
| `winlog.user.identifier` | `System/Security/@UserID` |
| `winlog.activity_id` | `System/Correlation/@ActivityID` |
| `winlog.event_data.<Name>` | every `EventData/Data[@Name]`; unnamed Data as `winlog.event_data.param1..n` |
| `winlog.user_data.*` | `UserData/*` recursively |
| `@timestamp` | `System/TimeCreated/@SystemTime` |
| `message` | rendered message when available, else `"<Provider>: EventID <id>"` |

The full `winlog.event_data.*` map is always retained because SigmaHQ Windows rules compiled with
the `ecs_windows` pipeline reference it for any field without an ECS equivalent.

### 4.2 Security channel event-id mappings

| Event ID | `event.category` / `event.type` / `event.action` | ECS fields |
|---|---|---|
| 4624 | authentication / start / `logged-in` | `user.name`←TargetUserName, `user.domain`←TargetDomainName, `user.id`←TargetUserSid, `source.ip`←IpAddress (`-`, `::1`, `127.0.0.1` dropped), `source.port`←IpPort, `source.domain`←WorkstationName, `winlog.logon.type` (numeric) and `winlog.logon.type_name` (Interactive, Network, Batch, Service, Unlock, NetworkCleartext, NewCredentials, RemoteInteractive, CachedInteractive), `winlog.logon.id`←TargetLogonId, `process.executable`←ProcessName, `process.pid`←ProcessId (hex→int), `winlog.event_data.LogonProcessName`, `winlog.event_data.AuthenticationPackageName`, `winlog.event_data.ElevatedToken`; `event.outcome: success` |
| 4625 | authentication / start / `logon-failed` | same identity/source fields from Target*, `winlog.logon.failure.reason`←FailureReason, `winlog.logon.failure.status`←Status, `winlog.logon.failure.sub_status`←SubStatus; `event.outcome: failure` |
| 4634, 4647 | authentication / end / `logged-out` | `user.name`←TargetUserName, `winlog.logon.id`, `winlog.logon.type` |
| 4648 | authentication / start / `logon-with-explicit-credentials` | `user.name`←SubjectUserName, `user.target.name`←TargetUserName, `user.target.domain`←TargetDomainName, `destination.domain`←TargetServerName, `source.ip`←IpAddress, `process.executable`←ProcessName |
| 4672 | iam / admin / `special-privileges-assigned` | `user.name`←SubjectUserName, `user.domain`, `user.id`, `winlog.logon.id`, `winlog.event_data.PrivilegeList` |
| 4688 | process / start / `process-created` | `process.pid`←NewProcessId, `process.executable`←NewProcessName, `process.name`, `process.command_line`←CommandLine, `process.parent.pid`←ProcessId, `process.parent.executable`←ParentProcessName, `process.parent.name`, `user.name`←SubjectUserName, `user.domain`←SubjectDomainName, `user.id`←SubjectUserSid, `winlog.event_data.TokenElevationType`, `winlog.event_data.MandatoryLabel` |
| 4689 | process / end / `process-exited` | `process.pid`, `process.executable`, `process.exit_code`←Status |
| 4697 | configuration / creation / `service-installed` | `service.name`←ServiceName, `process.executable`←ServiceFileName (when a path), `service.type`←ServiceType, `winlog.event_data.ServiceStartType`, `user.name`←SubjectUserName |
| 4698, 4699, 4700, 4701, 4702 | configuration / creation,deletion,change / `scheduled-task-*` | `winlog.event_data.TaskName`, `winlog.event_data.TaskContent`, `user.name`←SubjectUserName |
| 4719 | configuration / change / `audit-policy-changed` | `winlog.event_data.SubcategoryGuid`, `winlog.event_data.AuditPolicyChanges`, `user.name` |
| 4720 | iam / user, creation / `added-user-account` | `user.name`←SubjectUserName (actor), `user.target.name`←TargetUserName, `user.target.id`←TargetSid, `user.target.domain` |
| 4722, 4725, 4726 | iam / user, change,deletion / `enabled-user-account`, `disabled-user-account`, `deleted-user-account` | as 4720 |
| 4723, 4724 | iam / user, change / `changed-password`, `reset-password` | as 4720 |
| 4728, 4732, 4756, 4729, 4733, 4757 | iam / group, change / `added-member-to-group`, `removed-member-from-group` | `group.name`←TargetUserName, `group.domain`←TargetDomainName, `group.id`←TargetSid, `user.target.name`←MemberName (CN parsed) , `user.target.id`←MemberSid, `user.name`←SubjectUserName |
| 4738 | iam / user, change / `modified-user-account` | as 4720 plus every changed attribute in `winlog.event_data.*` |
| 4740 | authentication / info / `locked-out-user-account` | `user.target.name`←TargetUserName, `source.domain`←TargetDomainName |
| 4768 | authentication / start / `kerberos-authentication-ticket-requested` | `user.name`←TargetUserName, `user.domain`←TargetDomainName, `source.ip`←IpAddress (`::ffff:` stripped), `source.port`←IpPort, `winlog.event_data.TicketOptions`, `winlog.event_data.TicketEncryptionType`, `winlog.event_data.Status`, `winlog.event_data.PreAuthType`, `winlog.event_data.ServiceName`; outcome by Status (`0x0` success) |
| 4769 | authentication / start / `kerberos-service-ticket-requested` | as 4768 plus `winlog.event_data.ServiceName` (service account) and `winlog.event_data.ServiceSid` |
| 4771 | authentication / start / `kerberos-preauth-failed` | as 4768, outcome failure |
| 4776 | authentication / start / `credential-validated` | `user.name`←TargetUserName, `source.domain`←Workstation, `winlog.event_data.Status`, `winlog.event_data.PackageName`; outcome by Status |
| 4778, 4779 | session / start,end / `session-reconnected`, `session-disconnected` | `user.name`←AccountName, `user.domain`←AccountDomain, `source.ip`←ClientAddress, `source.domain`←ClientName, `winlog.event_data.SessionName` |
| 4794 | iam / user, change / `dsrm-password-set` | `user.name`←SubjectUserName |
| 5136, 5137, 5141 | iam / change,creation,deletion / `directory-service-object-*` | `winlog.event_data.ObjectDN`, `winlog.event_data.ObjectClass`, `winlog.event_data.AttributeLDAPDisplayName`, `winlog.event_data.AttributeValue` |
| 5140, 5145 | network, file / access / `network-share-accessed`, `network-share-object-checked` | `file.path`←ShareName (+ RelativeTargetName for 5145), `file.name`, `source.ip`←IpAddress, `source.port`←IpPort, `user.name`←SubjectUserName, `winlog.event_data.AccessMask`, `winlog.event_data.ShareLocalPath` |
| 5156, 5157, 5158 | network / connection, allowed,denied / `windows-firewall-connection-*` | `source.ip`←SourceAddress, `source.port`←SourcePort, `destination.ip`←DestAddress, `destination.port`←DestPort, `network.transport`←Protocol (iana→name), `network.direction`←Direction (`%%14592` inbound, `%%14593` outbound), `process.executable`←Application, `process.pid`←ProcessID |
| 4657 | registry / change / `registry-value-modified` | `registry.path`←ObjectName + ObjectValueName, `registry.key`, `registry.value`, `registry.data.strings`←NewValue, `process.executable`←ProcessName, `user.name` |
| 4663, 4656, 4660, 4670 | file (or registry when ObjectType=Key) / access,deletion,change | `file.path`←ObjectName, `winlog.event_data.ObjectType`, `winlog.event_data.AccessMask`, `winlog.event_data.AccessList`, `process.executable`, `process.pid`, `user.name` |
| 1102 | process / change / `audit-log-cleared` (Sigma: `security` logsource) | `user.name`←SubjectUserName (UserData), `event.kind: event`, tag `log_cleared` |
| 1100, 1104, 1105 | process / info / event-log-service-* | — |
| 4100, 4103, 4104 (PowerShell channels) | process / info / `powershell-*` | `powershell.file.script_block_text`←ScriptBlockText, `powershell.file.script_block_id`←ScriptBlockId, `powershell.sequence`←MessageNumber, `powershell.total`←MessageTotal, `file.path`←Path, `powershell.command.value`←Payload, `powershell.command.name`, `powershell.engine.version`, `powershell.runspace_id`, `user.name`←UserId / User |
| 7045 (System) | configuration / creation / `service-installed` | `service.name`←ServiceName, `process.executable`←ImagePath, `winlog.event_data.ServiceType`, `winlog.event_data.StartType`, `winlog.event_data.AccountName` |
| 7036, 7040, 7034 (System) | configuration / change / service state | `service.name`, `winlog.event_data.param1..n` |
| 104 (System, Eventlog) | process / change / `event-log-cleared` | `winlog.user_data.Channel`, `winlog.user_data.SubjectUserName` |
| 106, 140, 141, 200, 201 (TaskScheduler/Operational) | configuration / creation,change,deletion | `winlog.event_data.TaskName`, `winlog.event_data.ActionName`, `user.name`←UserContext |
| 1116, 1117, 1118, 1119, 5001, 5007 (Defender) | malware / info / Defender actions | `rule.name`←Threat Name, `file.path`←Path, `event.severity`←Severity ID, `winlog.event_data.Action Name`, `winlog.event_data.Detection User` |
| 5857, 5858, 5859, 5860, 5861 (WMI-Activity) | process / info / wmi-* | `winlog.user_data.Operation`, `winlog.user_data.User`, `winlog.user_data.ClientProcessId`, `winlog.user_data.Consumer`, `winlog.user_data.PossibleCause` |
| 1149, 21, 22, 23, 24, 25 (TerminalServices) | authentication, session / start,end / rdp-* | `user.name`←User / Param1, `user.domain`←Domain, `source.ip`←Address / Param3 |
| 8001, 8002, 8003, 8004 (NTLM) | authentication / info | `user.name`←UserName, `source.domain`←WorkstationName, `destination.domain`←TargetName |
| 59, 60 (Bits-Client) | process / info / bits-* | `url.original`←url, `process.executable`←processPath, `winlog.event_data.name` |
| 2004, 2005, 2006, 2033 (Firewall) | configuration / change / firewall-rule-* | `rule.name`←RuleName, `process.executable`←ApplicationPath, `winlog.event_data.Direction`, `winlog.event_data.Action` |
| 2889 (Directory Service), 1644 (LDAP), 30 (NTDS) | network / info | `source.ip`←IPAddress / Client, `user.name`←User, `winlog.event_data.Query` |
| 256, 257, 260, 261 (DNS-Server audit) | network / info / dns-server-* | `dns.question.name`←QNAME, `dns.question.type`←QTYPE, `source.ip`←Source, `destination.ip`←Destination |
| 4100 — 7000 generic | — | `winlog.event_data.*` only, `argus.pipeline.parse_status: ok` |

### 4.3 Sysmon (`windows.sysmon_operational`)

`user.name` and `user.domain` are split from `User` (`DOMAIN\user`); `process.hash.{md5,sha1,sha256,imphash}`
are parsed from `Hashes` (`SHA256=…,MD5=…`), `process.entity_id`←ProcessGuid, `process.parent.entity_id`←ParentProcessGuid.

| Event ID | `event.category` / `event.type` / `event.action` | ECS fields |
|---|---|---|
| 1 | process / start / `Process Create` | `process.pid`←ProcessId, `process.executable`←Image, `process.name`, `process.command_line`←CommandLine, `process.working_directory`←CurrentDirectory, `process.parent.pid`←ParentProcessId, `process.parent.executable`←ParentImage, `process.parent.name`, `process.parent.command_line`←ParentCommandLine, `process.pe.original_file_name`←OriginalFileName, `process.pe.company`←Company, `process.pe.description`←Description, `process.pe.product`←Product, `process.pe.file_version`←FileVersion, `process.hash.*`, `winlog.event_data.IntegrityLevel`, `winlog.event_data.LogonId`, `winlog.event_data.LogonGuid`, `winlog.event_data.TerminalSessionId`, `winlog.event_data.RuleName` |
| 2 | file / change / `File creation time changed` | `file.path`←TargetFilename, `file.name`, `file.extension`, `winlog.event_data.CreationUtcTime`, `winlog.event_data.PreviousCreationUtcTime`, `process.*`←Image/ProcessId/ProcessGuid |
| 3 | network / connection, start / `Network connection detected` | `source.ip`←SourceIp, `source.port`←SourcePort, `source.domain`←SourceHostname, `destination.ip`←DestinationIp, `destination.port`←DestinationPort, `destination.domain`←DestinationHostname, `network.transport`←Protocol, `network.type`←ipv4/ipv6 (SourceIsIpv6), `network.direction`←Initiated (`true`→egress, `false`→ingress), `process.*`, `user.name`, `winlog.event_data.SourcePortName`, `winlog.event_data.DestinationPortName` |
| 4 | process / change / `Sysmon service state changed` | `winlog.event_data.State`, `winlog.event_data.Version`, `winlog.event_data.SchemaVersion` |
| 5 | process / end / `Process terminated` | `process.pid`, `process.executable`, `process.entity_id` |
| 6 | driver / start / `Driver loaded` | `file.path`←ImageLoaded, `file.name`, `file.hash.*`←Hashes, `file.code_signature.subject_name`←Signature, `file.code_signature.status`←SignatureStatus, `file.code_signature.signed`←Signed |
| 7 | process / change / `Image loaded` | `file.path`←ImageLoaded, `file.name`, `file.hash.*`, `file.pe.original_file_name`, `file.pe.company`, `file.pe.description`, `file.pe.product`, `file.code_signature.*`, `process.executable`←Image, `process.pid`, `process.entity_id` |
| 8 | process / change / `CreateRemoteThread detected` | `process.pid`←SourceProcessId, `process.executable`←SourceImage, `process.entity_id`←SourceProcessGuid, `winlog.event_data.TargetProcessId`, `winlog.event_data.TargetImage`, `winlog.event_data.TargetProcessGuid`, `winlog.event_data.NewThreadId`, `winlog.event_data.StartAddress`, `winlog.event_data.StartModule`, `winlog.event_data.StartFunction` |
| 9 | driver / access / `RawAccessRead detected` | `process.*`, `winlog.event_data.Device` |
| 10 | process / access / `Process accessed` | `process.pid`←SourceProcessId, `process.executable`←SourceImage, `process.thread.id`←SourceThreadId, `winlog.event_data.TargetProcessId`, `winlog.event_data.TargetImage`, `winlog.event_data.GrantedAccess`, `winlog.event_data.CallTrace`, `winlog.event_data.SourceUser`, `winlog.event_data.TargetUser` |
| 11 | file / creation / `File created` | `file.path`←TargetFilename, `file.name`, `file.extension`, `file.directory`, `winlog.event_data.CreationUtcTime`, `process.*`, `user.name` |
| 12, 13, 14 | registry / creation,deletion,change / `Registry object added or deleted`, `Registry value set`, `Registry object renamed` | `registry.path`←TargetObject, `registry.hive`, `registry.key`, `registry.value`, `registry.data.strings`←Details, `winlog.event_data.EventType` (CreateKey, DeleteKey, SetValue, …), `winlog.event_data.NewName`, `process.*` |
| 15 | file / access / `File stream created` | `file.path`←TargetFilename, `file.hash.*`←Hash, `winlog.event_data.Contents`, `process.*` |
| 16 | configuration / change / `Sysmon config state changed` | `winlog.event_data.Configuration`, `winlog.event_data.ConfigurationFileHash` |
| 17, 18 | file / creation,access / `Pipe Created`, `Pipe Connected` | `file.name`←PipeName, `process.*` |
| 19, 20, 21 | process / creation / `WmiEventFilter activity detected`, `WmiEventConsumer …`, `WmiEventConsumerToFilter …` | `winlog.event_data.Operation`, `winlog.event_data.EventNamespace`, `winlog.event_data.Name`, `winlog.event_data.Query`, `winlog.event_data.Type`, `winlog.event_data.Destination`, `winlog.event_data.Consumer`, `winlog.event_data.Filter`, `user.name`←User |
| 22 | network / protocol, info / `Dns query` | `dns.question.name`←QueryName, `dns.answers.data[]`←QueryResults (parsed `type:` prefixes removed), `dns.response_code`←QueryStatus (numeric Windows status → name), `process.*`, `user.name` |
| 23, 26 | file / deletion / `File Delete archived`, `File Delete logged` | `file.path`←TargetFilename, `file.hash.*`, `winlog.event_data.IsExecutable`, `winlog.event_data.Archived`, `process.*`, `user.name` |
| 24 | process / change / `Clipboard changed` | `winlog.event_data.Session`, `winlog.event_data.ClientInfo`, `file.hash.*` |
| 25 | process / change / `Process Tampering` | `process.*`, `winlog.event_data.Type` |
| 27, 28 | file / deletion / `File Block Executable`, `File Block Shredding` | `file.path`, `file.hash.*`, `process.*` |
| 29 | file / creation / `File Executable Detected` | `file.path`, `file.hash.*`, `process.*` |
| 255 | error / info / `Error report` | `winlog.event_data.ID`, `winlog.event_data.Description` |

## 5. Linux

### 5.1 `linux.auth` (syslog from sshd, sudo, su, pam, useradd/usermod/groupadd, cron, systemd-logind)

| Message pattern | `event.category`/`type`/`action`/`outcome` | Fields |
|---|---|---|
| `Accepted <method> for <user> from <ip> port <port> ssh2[: <key type> <fingerprint>]` | authentication / start / `ssh_login` / success | `user.name`, `source.ip`, `source.port`, `linux.auth.ssh.method`, `linux.auth.ssh.signature`, `process.name: sshd`, `process.pid` |
| `Failed <method> for [invalid user ]<user> from <ip> port <port>` | authentication / start / `ssh_login` / failure | same; `linux.auth.ssh.invalid_user: true` when present |
| `Invalid user <user> from <ip> port <port>` | authentication / info / `ssh_login` / failure | `user.name`, `source.ip`, `source.port` |
| `Connection closed by [invalid user <user> ]<ip> port <port> [preauth]` | network / end / `ssh_disconnect` | `source.ip`, `source.port` |
| `Disconnected from [authenticating ]user <user> <ip> port <port>` | network / end / `ssh_disconnect` | `user.name`, `source.ip`, `source.port` |
| `Received disconnect from <ip> port <port>:<code>: <text>` | network / end | `source.ip`, `source.port`, `linux.auth.ssh.disconnect_code` |
| `pam_unix(<svc>:session): session opened for user <user>[(uid=N)] by [<by>](uid=M)` | session / start / `session_opened` | `user.name`, `user.id`, `linux.auth.pam.service`, `linux.auth.pam.by_user`, `linux.auth.pam.by_uid` |
| `pam_unix(<svc>:session): session closed for user <user>` | session / end / `session_closed` | `user.name` |
| `pam_unix(<svc>:auth): authentication failure; logname=… uid=… euid=… tty=… ruser=… rhost=…  user=<user>` | authentication / start / `pam_auth` / failure | `user.name`, `source.ip`←rhost (if IP) or `source.domain`, `linux.auth.pam.tty`, `linux.auth.pam.ruser`, `linux.auth.pam.logname` |
| sudo `<user> : TTY=<tty> ; PWD=<pwd> ; USER=<target> ; [GROUP=…;] COMMAND=<cmd>` | process / start / `sudo_command` / success | `user.name`, `user.effective.name`←USER, `process.command_line`←COMMAND, `process.executable` (first token), `process.name`, `process.working_directory`←PWD, `linux.auth.sudo.tty` |
| sudo `<user> : <n> incorrect password attempt(s) ; TTY=… ; PWD=… ; USER=… ; COMMAND=…` | authentication / start / `sudo_command` / failure | as above, `linux.auth.sudo.attempts` |
| sudo `<user> : user NOT in sudoers ; …` or `command not allowed` | process / denied / `sudo_denied` / failure | as above, `linux.auth.sudo.error` |
| su `(to <target>) <user> on <tty>` / `pam_unix(su:session): session opened for user root by alice(uid=1000)` | authentication / start / `su` / success | `user.name`, `user.effective.name`, `linux.auth.su.tty` |
| su `FAILED SU (to <target>) <user> on <tty>` | authentication / start / `su` / failure | as above |
| useradd `new user: name=<n>, UID=<u>, GID=<g>, home=<h>, shell=<s>[, from=<ip>]` | iam / user, creation / `user_added` | `user.target.name`, `user.target.id`, `user.target.group.id`, `linux.auth.useradd.home`, `linux.auth.useradd.shell` |
| useradd `new group: name=<n>, GID=<g>` / groupadd | iam / group, creation / `group_added` | `group.name`, `group.id` |
| userdel `delete user '<n>'` / `removed group '<n>'` | iam / user, deletion / `user_deleted` | `user.target.name` |
| usermod `add '<user>' to group '<group>'` / `to shadow group` | iam / group, change / `user_added_to_group` | `user.target.name`, `group.name` |
| passwd `pam_unix(passwd:chauthtok): password changed for <user>` | iam / user, change / `password_changed` | `user.target.name` |
| chage / `changed password expiry for <user>` | iam / user, change | `user.target.name` |
| systemd-logind `New session <id> of user <user>.` | session / start / `session_opened` | `user.name`, `linux.auth.session.id` |
| CRON `pam_unix(cron:session): session opened for user <user>` | session / start / `cron_session` | `user.name` |
| sshd `error: maximum authentication attempts exceeded for <user> from <ip> port <port>` | authentication / info / `ssh_max_auth_exceeded` / failure | `user.name`, `source.ip` |
| sshd `error: PAM: Authentication failure for [illegal user ]<user> from <host>` | authentication / start / `ssh_login` / failure | `user.name`, `source.address` |
| sshd `Server listening on <ip> port <port>` / `Received SIGHUP` | process / info | — |
| anything else from these programs | — / info | `message` only, `argus.pipeline.parse_status: partial` |

Common: `host.name`←syslog hostname, `process.name`←app-name, `process.pid`←procid,
`log.syslog.facility.code/name`, `log.syslog.severity.code/name`, `log.syslog.priority`,
`log.source.address` (sending collector/relay).

### 5.2 `linux.auditd` (raw `/var/log/audit/audit.log`, `ausearch -i` text, or `go-audit` JSON)

Records are grouped by the `audit(<ts>:<serial>)` key: SYSCALL + EXECVE + PATH + CWD + PROCTITLE
records with the same serial are merged into one event (configurable `coalesce_window`, default
2 s). A late record that misses the window is emitted alone with `auditd.log.coalesced: false`.

| Field | From |
|---|---|
| `@timestamp` | `audit(<epoch.millis>:…)` |
| `auditd.log.sequence` | serial |
| `auditd.log.record_type` (and `auditd.log.record_types[]` when merged) | `type=` |
| `event.category` / `event.type` | SYSCALL execve → process/start; USER_LOGIN, USER_AUTH, USER_ACCT, CRED_ACQ, CRED_DISP, LOGIN → authentication; ADD_USER, DEL_USER, ADD_GROUP, USER_CHAUTHTOK, USER_MGMT, GRP_MGMT → iam; CONFIG_CHANGE, SERVICE_START, SERVICE_STOP, SYSTEM_BOOT, SYSTEM_SHUTDOWN, DAEMON_* → configuration; AVC, SELINUX_ERR, ANOM_*, MAC_* → intrusion_detection; PATH-only / SYSCALL open/unlink/rename → file; SOCKADDR/connect → network; everything else → process |
| `event.action` | `auditd.log.key` when set (admin-defined rule key) else lower-case record type |
| `event.outcome` | `success=yes/no`, `res=success/failed` |
| `process.pid`, `process.parent.pid` | `pid=`, `ppid=` |
| `process.name`, `process.executable`, `process.title` | `comm=`, `exe=`, `proctitle=` (hex-decoded) |
| `process.args[]`, `process.command_line`, `process.args_count` | EXECVE `a0..aN` (hex-decoded, quotes stripped), joined |
| `process.working_directory` | CWD `cwd=` |
| `user.id`, `user.name` (resolved by agent when available), `user.group.id` | `uid=`, `gid=` |
| `user.effective.id`, `user.saved.id`, `user.filesystem.id` | `euid=`, `suid=`, `fsuid=` |
| `user.audit.id` (loginuid) | `auid=` (4294967295 → absent) |
| `auditd.log.ses`, `auditd.log.tty`, `auditd.log.terminal`, `auditd.log.subj`, `auditd.log.arch`, `auditd.log.syscall` (number and name via arch table), `auditd.log.exit`, `auditd.log.items`, `auditd.log.key` | SYSCALL fields |
| `file.path`, `file.inode`, `file.device`, `file.mode`, `file.uid`, `file.gid`, `auditd.paths[]` (nametype, name, inode, mode, ouid, ogid, rdev, objtype) | PATH records (first `nametype=NORMAL` or `CREATE` path becomes `file.path`) |
| `source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.transport` | SOCKADDR `saddr=` decoded (AF_INET/AF_INET6) + syscall connect/accept/bind |
| `user.name`, `source.ip`, `source.address`, `auditd.log.op`, `auditd.log.acct`, `auditd.log.hostname`, `auditd.log.terminal` | USER_* records: `acct=`, `addr=`, `hostname=`, `terminal=`, `op=`, `exe=` |
| `auditd.log.a0..a3` | syscall arguments (raw hex) |
| `auditd.log.data.<key>` | any key not mapped above |

Field names follow Filebeat's `auditd` module and the fields SigmaHQ Linux auditd rules use
(`type`, `a0`, `exe`, `key`, `syscall`, `comm`, `name`, `nametype`, `uid`, `auid`), which the
Argus Sigma pipeline `linux_auditd.yml` maps to the paths above.

### 5.3 `linux.journald` (journal export / `journalctl -o json`)

`@timestamp`←`__REALTIME_TIMESTAMP`, `message`←`MESSAGE`, `process.name`←`_COMM`, `process.executable`←`_EXE`,
`process.command_line`←`_CMDLINE`, `process.pid`←`_PID`, `user.id`←`_UID`, `host.name`←`_HOSTNAME`,
`log.syslog.identifier`←`SYSLOG_IDENTIFIER`, `log.syslog.facility.code`←`SYSLOG_FACILITY`,
`log.level`←`PRIORITY` (name), `journald.unit`←`_SYSTEMD_UNIT`, `journald.boot_id`←`_BOOT_ID`,
`journald.machine_id`←`_MACHINE_ID`, `journald.cap_effective`, `journald.transport`←`_TRANSPORT`,
`journald.code.file/line/func`. Messages from sshd/sudo/su/pam are then passed through the
`linux.auth` matcher so the same fields appear whether the source is syslog or journald.

## 6. Zeek (`event.module: zeek`, dataset `zeek.<log>`)

JSON lines (`-o json`) or TSV with `#fields` header. Common for every log: `@timestamp`←`ts`,
`zeek.session_id`←`uid`, `source.ip`←`id.orig_h`, `source.port`←`id.orig_p`,
`destination.ip`←`id.resp_h`, `destination.port`←`id.resp_p`, `network.community_id`←`community_id`,
`observer.hostname`←`_system_name`, `event.category: [network]`, `network.type` from IP family.

| Log | Fields |
|---|---|
| `conn` | `network.transport`←proto, `network.protocol`←service, `event.duration`←duration, `source.bytes`←orig_bytes, `destination.bytes`←resp_bytes, `source.packets`←orig_pkts, `destination.packets`←resp_pkts, `network.bytes`, `network.packets`, `zeek.conn.state`←conn_state, `zeek.conn.state_message` (S0 … OTH decoded), `zeek.conn.history`←history, `zeek.conn.local_orig`, `zeek.conn.local_resp`, `zeek.conn.missed_bytes`, `zeek.conn.vlan`, `zeek.conn.inner_vlan`, `network.direction` (`inbound`/`outbound`/`internal`/`external` from local_orig/local_resp), `event.type: [connection, start|end|info]` |
| `dns` | `dns.id`←trans_id, `dns.question.name`←query, `dns.question.class`←qclass_name, `dns.question.type`←qtype_name, `dns.response_code`←rcode_name, `dns.answers[].data`←answers, `dns.answers[].ttl`←TTLs, `dns.resolved_ip[]` (IP answers), `zeek.dns.AA/TC/RD/RA/Z/rejected/rtt`, `network.transport`←proto, `event.type: [protocol, info]` |
| `http` | `http.request.method`←method, `url.domain`←host, `url.path` + `url.query`←uri (split), `url.original`←`host`+`uri`, `http.request.referrer`←referrer, `http.version`←version, `user_agent.original`←user_agent, `http.request.body.bytes`←request_body_len, `http.response.body.bytes`←response_body_len, `http.response.status_code`←status_code, `zeek.http.status_msg`, `zeek.http.trans_depth`, `zeek.http.tags[]`, `url.username`←username, `zeek.http.proxied[]`, `zeek.http.orig_fuids[]`, `zeek.http.resp_fuids[]`, `http.request.mime_type`←orig_mime_types[0], `http.response.mime_type`←resp_mime_types[0], `event.category: [network, web]` |
| `ssl` | `tls.version`←version (`TLSv12`→`1.2`), `tls.version_protocol`, `tls.cipher`←cipher, `tls.curve`←curve, `tls.client.server_name`←server_name, `tls.resumed`←resumed, `tls.established`←established, `tls.next_protocol`←next_protocol, `tls.client.ja3`←ja3, `tls.server.ja3s`←ja3s, `tls.server.subject`←subject, `tls.server.issuer`←issuer, `tls.client.subject`←client_subject, `tls.client.issuer`←client_issuer, `zeek.ssl.validation_status`, `zeek.ssl.cert_chain_fuids[]`, `zeek.ssl.last_alert`, `zeek.ssl.sni_matches_cert` |
| `files` | `zeek.files.fuid`←fuid, `client.ip`←rx_hosts[0], `server.ip`←tx_hosts[0], `zeek.files.session_ids[]`←conn_uids, `zeek.files.source`←source, `zeek.files.depth`, `zeek.files.analyzers[]`, `file.mime_type`←mime_type, `file.name`←filename, `event.duration`←duration, `zeek.files.local_orig`, `zeek.files.is_orig`, `file.size`←total_bytes, `zeek.files.seen_bytes`, `zeek.files.missing_bytes`, `zeek.files.overflow_bytes`, `zeek.files.timedout`, `file.hash.md5/sha1/sha256`, `zeek.files.extracted`, `zeek.files.extracted_cutoff`, `event.category: [file, network]` |
| `notice` | `rule.name`←note, `message`←msg, `zeek.notice.sub`←sub, `source.ip`←src (also id.orig_h), `destination.ip`←dst, `destination.port`←p, `zeek.notice.n`, `zeek.notice.peer_descr`, `zeek.notice.actions[]`, `zeek.notice.suppress_for`, `zeek.notice.dropped`, `zeek.notice.file_mime_type`, `zeek.notice.file_desc`, `event.kind: alert`, `event.category: [intrusion_detection, network]` |
| `weird` | `zeek.weird.name`←name, `zeek.weird.additional_info`←addl, `zeek.weird.notice`←notice, `zeek.weird.peer`←peer, `zeek.weird.source`←source |
| `ssh` | `zeek.ssh.version`, `zeek.ssh.auth.success`←auth_success, `zeek.ssh.auth.attempts`←auth_attempts, `zeek.ssh.direction`, `zeek.ssh.client`←client, `zeek.ssh.server`←server, `zeek.ssh.algorithm.{cipher,mac,compression,key_exchange,host_key}`, `zeek.ssh.host_key`, `zeek.ssh.hassh`, `zeek.ssh.hasshServer`, `event.category: [network, authentication]`, `event.outcome` from auth_success |
| `kerberos` | `zeek.kerberos.request_type`, `user.name`←client (realm stripped into `user.domain`), `zeek.kerberos.service`←service, `zeek.kerberos.success`, `zeek.kerberos.error.code/msg`, `zeek.kerberos.valid.from/until/days`, `zeek.kerberos.cipher`, `zeek.kerberos.forwardable`, `zeek.kerberos.renewable`, `zeek.kerberos.ticket.auth/new`, `zeek.kerberos.cert.client/server.*`, `event.category: [network, authentication]` |
| `smb_files` | `zeek.smb_files.action`←action, `file.path`←path + name, `file.name`←name, `file.size`←size, `zeek.smb_files.prev_name`, `zeek.smb_files.times.{accessed,changed,created,modified}`, `zeek.smb_files.fuid`, `event.category: [network, file]` |
| `smb_mapping` | `zeek.smb_mapping.path`←path, `zeek.smb_mapping.service`, `zeek.smb_mapping.native_file_system`, `zeek.smb_mapping.share_type` |
| `dce_rpc` | `zeek.dce_rpc.rtt`, `zeek.dce_rpc.named_pipe`, `zeek.dce_rpc.endpoint`, `zeek.dce_rpc.operation` |
| `ntlm` | `user.name`←username, `user.domain`←domain, `source.domain`←hostname, `destination.domain`←server_nb_computer_name, `zeek.ntlm.server.{dns,nb,tree}.name`, `zeek.ntlm.success`, `event.category: [network, authentication]` |
| `rdp` | `zeek.rdp.cookie`←cookie, `zeek.rdp.result`, `zeek.rdp.security_protocol`, `zeek.rdp.client.{build,client_name,product_id}`, `zeek.rdp.desktop.{width,height,color_depth}`, `zeek.rdp.keyboard_layout`, `zeek.rdp.encryption.{level,method}`, `zeek.rdp.cert.{type,count,permanent}` |
| `ftp`, `smtp`, `sip`, `snmp`, `tunnel`, `x509`, `software`, `pe`, `dhcp`, `radius`, `irc`, `mysql`, `socks`, `dpd`, `intel`, `signatures`, `capture_loss`, `stats` | all fields under `zeek.<log>.<field>` (snake_case); ids/ips mapped as above when present; `intel` → `threat.indicator.*` + `event.kind: alert` |

## 7. Suricata EVE (`event.module: suricata`, dataset `suricata.eve`)

Common: `@timestamp`←timestamp, `suricata.eve.event_type`←event_type, `suricata.eve.flow_id`←flow_id,
`suricata.eve.in_iface`←in_iface, `suricata.eve.pcap_cnt`, `suricata.eve.tx_id`,
`source.ip`←src_ip, `source.port`←src_port, `destination.ip`←dest_ip, `destination.port`←dest_port,
`network.transport`←proto (lower), `network.protocol`←app_proto, `network.community_id`←community_id,
`network.direction`←direction (when present), `source.bytes/packets` + `destination.bytes/packets` from embedded `flow`,
`event.category: [network]`, `observer.product: Suricata`, `observer.type: ids`, `observer.hostname`←host.

| `event_type` | Fields |
|---|---|
| `alert` | `event.kind: alert`, `event.category: [network, intrusion_detection]`, `event.type: [allowed|denied]`←alert.action, `event.action`←alert.action, `rule.id`←alert.signature_id, `rule.name`←alert.signature, `rule.category`←alert.category, `rule.version`←alert.rev, `rule.ruleset`←alert.metadata.ruleset, `suricata.eve.alert.gid`, `suricata.eve.alert.severity` and `event.severity` (1→75, 2→50, 3→25, 4→10), `suricata.eve.alert.metadata.*` (flattened arrays), `suricata.eve.alert.signature_severity`, `suricata.eve.alert.affected_product`, `suricata.eve.alert.attack_target`, `suricata.eve.alert.created_at`, `suricata.eve.alert.updated_at`, `suricata.eve.alert.mitre_technique_id` → `threat.technique.id`, `suricata.eve.alert.mitre_tactic_id` → `threat.tactic.id`, `suricata.eve.payload`, `suricata.eve.payload_printable`, `suricata.eve.packet`, `suricata.eve.stream`, embedded `http`/`dns`/`tls`/`fileinfo` mapped as below |
| `dns` | `dns.type`←dns.type, `dns.id`←dns.id, `dns.question.name`←dns.rrname, `dns.question.type`←dns.rrtype, `dns.response_code`←dns.rcode, `dns.answers[].{name,type,ttl,data}`←dns.answers / dns.grouped, `dns.resolved_ip[]`, `suricata.eve.dns.version`, `suricata.eve.dns.flags`, `suricata.eve.dns.qr/aa/tc/rd/ra`, `event.category: [network]`, `event.type: [protocol]` |
| `http` | `url.domain`←http.hostname, `url.path` + `url.query`←http.url, `url.original`, `http.request.method`←http.http_method, `http.response.status_code`←http.status, `http.response.body.bytes`←http.length, `http.request.referrer`←http.http_refer, `user_agent.original`←http.http_user_agent, `http.version`←http.protocol, `http.response.mime_type`←http.http_content_type, `suricata.eve.http.redirect`←http.redirect, `suricata.eve.http.http_port`, `suricata.eve.http.request_headers[]`, `suricata.eve.http.response_headers[]`, `event.category: [network, web]` |
| `tls` | `tls.client.server_name`←tls.sni, `tls.version`←tls.version (`TLS 1.2`→`1.2`), `tls.version_protocol: tls`, `tls.server.subject`←tls.subject, `tls.server.issuer`←tls.issuerdn, `tls.server.hash.sha1`←tls.fingerprint (colons removed), `tls.server.not_before`←tls.notbefore, `tls.server.not_after`←tls.notafter, `tls.client.ja3`←tls.ja3.hash, `suricata.eve.tls.ja3.string`, `tls.server.ja3s`←tls.ja3s.hash, `suricata.eve.tls.serial`, `suricata.eve.tls.session_resumed`, `suricata.eve.tls.certificate` |
| `flow` / `netflow` | `event.start`←flow.start, `event.end`←flow.end, `event.duration` (end−start), `source.bytes`←flow.bytes_toserver, `destination.bytes`←flow.bytes_toclient, `source.packets`←flow.pkts_toserver, `destination.packets`←flow.pkts_toclient, `network.bytes`, `network.packets`, `suricata.eve.flow.state`, `suricata.eve.flow.reason`, `suricata.eve.flow.alerted`, `suricata.eve.flow.age`, `suricata.eve.tcp.{tcp_flags,tcp_flags_ts,tcp_flags_tc,syn,ack,psh,fin,rst,state}`, `event.type: [connection, end]` |
| `fileinfo` | `file.path`←fileinfo.filename, `file.name`, `file.extension`, `file.size`←fileinfo.size, `file.hash.md5/sha1/sha256`←fileinfo.md5/sha1/sha256, `suricata.eve.fileinfo.magic`, `suricata.eve.fileinfo.state`, `suricata.eve.fileinfo.stored`, `suricata.eve.fileinfo.gaps`, `suricata.eve.fileinfo.tx_id`, `suricata.eve.fileinfo.file_id`, embedded `http` as above, `event.category: [network, file]` |
| `ssh` | `suricata.eve.ssh.client.{proto_version,software_version,hassh.hash,hassh.string}`, `suricata.eve.ssh.server.{…}`, `event.category: [network]` |
| `smb`, `dcerpc`, `krb5`, `ftp`, `smtp`, `rdp`, `dhcp`, `nfs`, `tftp`, `ikev2`, `snmp`, `sip`, `rfb`, `mqtt`, `http2` | `suricata.eve.<type>.*` (snake_case keys); for `krb5`: `user.name`←krb5.cname, `user.domain`←krb5.realm, `event.category: [network, authentication]`; for `smb`: `file.path`←smb.filename, `user.name`←smb.ntlmssp.user, `user.domain`←smb.ntlmssp.domain |
| `anomaly` | `suricata.eve.anomaly.{type,event,layer,code}`, `event.kind: alert`, `event.category: [network]` |
| `stats` | `event.kind: metric`, `suricata.eve.stats.*` flattened (uptime, capture.*, decoder.*, flow.*, tcp.*, detect.*, app_layer.*) |
| `drop` | `event.type: [connection, denied]`, `suricata.eve.drop.*` |

## 8. Web servers

### 8.1 `nginx.access` / `apache.access`

Formats: NCSA combined (default), combined + `$request_time $upstream_response_time`
(nginx `main_ext`), Apache `vhost_combined` (`vhost:port` prefix), and nginx JSON access logs
(`log_format json escape=json {...}` with keys `time_local|time_iso8601, remote_addr, remote_user,
request|request_method+request_uri+server_protocol, status, body_bytes_sent, http_referer,
http_user_agent, request_time, upstream_response_time, http_x_forwarded_for, host, server_name`).

| Field | From |
|---|---|
| `@timestamp` | `[dd/MMM/yyyy:HH:mm:ss Z]` or ISO 8601 |
| `source.address`, `source.ip` (when an IP) | remote address; when `X-Forwarded-For` is present the first public hop becomes `client.ip` and the remote address `source.ip`; `network.forwarded_ip`←XFF chain |
| `user.name` | remote user (`-` → absent) |
| `http.request.method`, `url.original`, `url.path`, `url.query`, `url.fragment`, `http.version` | request line |
| `http.response.status_code`, `http.response.body.bytes` | status, bytes (`-` → 0) |
| `http.request.referrer`, `user_agent.original` | referrer, UA |
| `url.domain` (vhost), `destination.port` (vhost port) | `vhost_combined` / `host` |
| `event.duration` | `request_time` (seconds → ns) |
| `nginx.access.upstream_response_time`, `nginx.access.upstream_addr`, `nginx.access.server_name` / `apache.access.server_name` | extended fields |
| `event.category: [web]`, `event.type: [access]`, `event.outcome` | status < 400 → success, ≥ 400 → failure |
| `http.request.bytes` | `%I` when present (Apache logio) |

Parsed user agents are **not** expanded at ingest (cost); `user_agent.original` only. The UI
and rules match on the raw string, as SigmaHQ webserver rules do (`cs-method`, `cs-uri-query`,
`sc-status`, `c-useragent`, `cs-referer` → mapped by pipeline `webserver.yml`).

### 8.2 `nginx.error` / `apache.error`

`@timestamp`, `log.level`←severity (`error`, `crit`, `notice`, …), `process.pid`, `process.thread.id`
(nginx `pid#tid`), `nginx.error.connection_id`, `message`, `source.ip`←`client:`, `destination.domain`←`server:`,
`url.original`←`request:` request line path, `url.domain`←`host:`, `http.request.referrer`←`referrer:`,
`apache.error.module`, `file.path` (Apache `[client ip]` + file not found path), `event.category: [web]`, `event.type: [error]`.

## 9. AWS CloudTrail (`aws.cloudtrail`)

Delivered as gzipped JSON objects in S3 (`{"Records":[…]}`) announced through SQS, or as single
records from EventBridge/Kinesis. One ECS event per record.

| Field | From |
|---|---|
| `@timestamp` | eventTime |
| `event.id` | eventID |
| `event.action` | eventName |
| `event.provider` | eventSource |
| `cloud.provider: aws`, `cloud.region`←awsRegion, `cloud.account.id`←recipientAccountId, `cloud.service.name`←eventSource minus `.amazonaws.com` |
| `event.outcome` | `failure` when errorCode/errorMessage present (including `AccessDenied`, `UnauthorizedOperation`), else `success` |
| `event.category` / `event.type` | ConsoleLogin, AssumeRole*, GetSessionToken, GetFederationToken → authentication/start; iam.amazonaws.com and sts.amazonaws.com → iam (type by verb: Create→creation, Delete→deletion, Attach/Put/Update/Add/Remove→change, Get/List→access); Put*/Delete*/Modify*/Update*/Create*/Authorize*/Revoke* on ec2, s3, kms, cloudtrail, config, guardduty, securityhub, lambda, logs → configuration; `readOnly: true` → `event.type: [access]`; GetObject/PutObject/DeleteObject → file |
| `source.ip` (IP) or `source.address` (service principal like `cloudtrail.amazonaws.com`, `AWS Internal`) | sourceIPAddress |
| `user_agent.original` | userAgent |
| `user.name` | userIdentity.userName, else last segment of userIdentity.arn or sessionIssuer.userName, else `Root` for type Root |
| `user.id` | userIdentity.principalId |
| `aws.cloudtrail.user_identity.type` | IAMUser, AssumedRole, Root, FederatedUser, AWSAccount, AWSService, SAMLUser, WebIdentityUser, Unknown |
| `aws.cloudtrail.user_identity.arn`, `.account_id`, `.access_key_id`, `.invoked_by`, `.identity_provider` | userIdentity |
| `aws.cloudtrail.user_identity.session_context.mfa_authenticated` (bool), `.creation_date`, `.session_issuer.{type,principal_id,arn,account_id,user_name}`, `.web_id_federation_data.*` | userIdentity.sessionContext |
| `aws.cloudtrail.flattened.request_parameters.*`, `aws.cloudtrail.flattened.response_elements.*`, `aws.cloudtrail.flattened.additional_eventdata.*`, `aws.cloudtrail.flattened.service_event_details.*` | the JSON objects, flattened with dotted keys (mapped `flat_object`) |
| `aws.cloudtrail.request_parameters`, `aws.cloudtrail.response_elements` | the same objects serialized as compact JSON strings (for `contains` searches) |
| `aws.cloudtrail.error_code`, `aws.cloudtrail.error_message` | errorCode, errorMessage |
| `aws.cloudtrail.read_only`, `aws.cloudtrail.management_event`, `aws.cloudtrail.event_type`, `aws.cloudtrail.event_version`, `aws.cloudtrail.event_category`, `aws.cloudtrail.api_version`, `aws.cloudtrail.shared_event_id`, `aws.cloudtrail.vpc_endpoint_id`, `aws.cloudtrail.recipient_account_id` | top-level |
| `aws.cloudtrail.resources[].{arn,account_id,type}` | resources |
| `aws.cloudtrail.tls_details.{tls_version,cipher_suite,client_provided_host_header}` | tlsDetails |
| `aws.cloudtrail.console_login.additional_eventdata.{mfa_used,mobile_version,login_to}` | additionalEventData for ConsoleLogin (`MFAUsed: Yes/No` → bool) |
| `aws.cloudtrail.insight_details.*` | insightDetails |
| `related.user`, `related.ip` | — |

SigmaHQ `aws` rules reference `eventSource`, `eventName`, `errorCode`, `errorMessage`,
`userIdentity.type`, `userIdentity.arn`, `userIdentity.sessionContext.sessionIssuer.type`,
`requestParameters.*`, `responseElements.*`, `sourceIPAddress`, `userAgent`,
`additionalEventData.*`; pipeline `aws_cloudtrail.yml` maps them to the fields above.

## 10. Azure (`azure.signinlogs`, `azure.auditlogs`, `azure.activitylogs`)

Input: Event Hub JSON (`{"records":[…]}`) or Graph API objects. One event per record.

| Field | signinlogs (Entra sign-in) | auditlogs (Entra directory audit) | activitylogs (ARM activity) |
|---|---|---|---|
| `@timestamp` | time | time | time |
| `event.id` | properties.id | properties.id | correlationId + operationName |
| `event.action` | operationName (`Sign-in activity`) | properties.activityDisplayName | operationName (`MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE`) |
| `event.outcome` | resultType `0` → success, else failure | properties.result (`success`/`failure`) | resultType (`Success`/`Failure`/`Start`→unknown) |
| `event.category` / `event.type` | authentication / start (interactive) or info | iam (user/group/application/policy by category) / creation,change,deletion by activityDisplayName verb | configuration (iam for `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/*`) / type by last URI segment (WRITE→change, DELETE→deletion, ACTION→info) |
| `user.name` | properties.userPrincipalName | properties.initiatedBy.user.userPrincipalName (or `.app.displayName` into `user.name` + `azure.auditlogs.initiated_by.app.*`) | identity.claims.`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` / `…/upn` / `appid` |
| `user.id` | properties.userId | properties.initiatedBy.user.id | identity.claims.`http://schemas.microsoft.com/identity/claims/objectidentifier` |
| `user.full_name` | properties.userDisplayName | — | — |
| `source.ip` | properties.ipAddress / callerIpAddress | properties.initiatedBy.user.ipAddress | callerIpAddress |
| `source.geo.{city_name,region_name,country_iso_code,location}` | properties.location | — | — |
| `user_agent.original` | properties.userAgent | — | — |
| `azure.tenant_id`, `cloud.account.id` | tenantId | tenantId | tenantId |
| `azure.correlation_id` | correlationId | correlationId | correlationId |
| `azure.resource.id` | resourceId | resourceId | resourceId (+ parsed `azure.subscription_id`, `azure.resource.group`, `azure.resource.provider`, `azure.resource.name`) |
| `cloud.provider: azure` | ✓ | ✓ | ✓ |
| Module-specific | `azure.signinlogs.result_type`, `.result_signature`, `.result_description`, `.category` (SignInLogs / NonInteractiveUserSignInLogs / ServicePrincipalSignInLogs / ManagedIdentitySignInLogs), `.properties.{app_id, app_display_name, client_app_used, conditional_access_status, is_interactive, risk_detail, risk_level_aggregated, risk_level_during_signin, risk_state, risk_event_types[], resource_display_name, resource_id, authentication_requirement, authentication_protocol, token_issuer_type, user_type, status.error_code, status.failure_reason, status.additional_details, device_detail.{device_id, display_name, operating_system, browser, is_compliant, is_managed, trust_type}, mfa_detail.{auth_method, auth_detail}, authentication_details[].*, applied_conditional_access_policies[].*, network_location_details[].*, service_principal_id, service_principal_name, cross_tenant_access_type, home_tenant_id, incoming_token_type, original_request_id, session_id, correlation_id, authentication_processing_details[].*}` | `azure.auditlogs.category`, `.operation_name`, `.operation_version`, `.result_signature`, `.properties.{activity_datetime, activity_display_name, category, logged_by_service, operation_type, result, result_reason, initiated_by.user.*, initiated_by.app.*, target_resources[].{id, display_name, type, user_principal_name, modified_properties[].{display_name, old_value, new_value}}, additional_details[].{key,value}}` | `azure.activitylogs.operation_name`, `.category` (Administrative, Security, Policy, Alert, …), `.result_type`, `.result_signature`, `.event_category`, `.level`, `.identity.authorization.{scope, action, evidence.{role, role_assignment_scope, role_assignment_id, role_definition_id, principal_id, principal_type}}`, `.identity.claims.*` (flattened), `.identity.claims_initiated_by_user.{name, givenname, surname, fullname, schema}`, `.properties.*` (flattened: statusCode, serviceRequestId, eventCategory, entity, message, hierarchy) |

Sigma `azure` rules use `ResultType`, `ResultDescription`, `AppDisplayName`, `UserPrincipalName`,
`IPAddress`, `Status`, `RiskState`, `RiskLevelAggregated`, `ConditionalAccessStatus`,
`AuthenticationRequirement`, `DeviceDetail.*`, `Category`, `OperationName`, `ActivityDisplayName`,
`LoggedByService`, `properties.message`, `TargetResources.*`, `InitiatedBy.*`, `Operation`,
`ResourceId`, `Level`; pipeline `azure.yml` maps them.

## 11. GCP Audit (`gcp.audit`)

Input: Pub/Sub message or Cloud Logging export JSON (`LogEntry`).

| Field | From |
|---|---|
| `@timestamp` | timestamp |
| `event.id` | insertId |
| `event.action` | protoPayload.methodName |
| `event.provider` | protoPayload.serviceName |
| `event.outcome` | protoPayload.status.code absent/0 → success; else failure |
| `event.category` / `event.type` | iam.googleapis.com, SetIamPolicy, *.serviceAccounts.*, *.roles.* → iam; google.login.LoginService.loginSuccess/Failure → authentication; `logName` ends `/data_access` → access; `/system_event` → info; else configuration with type by method verb (create/insert → creation, delete → deletion, update/patch/set → change, get/list → access) |
| `cloud.provider: gcp`, `cloud.project.id`←resource.labels.project_id, `cloud.region`←resource.labels.region/location, `cloud.availability_zone`←resource.labels.zone, `cloud.instance.id`←resource.labels.instance_id |
| `user.email`, `user.name` | protoPayload.authenticationInfo.principalEmail (name = local part) |
| `user.id` | protoPayload.authenticationInfo.principalSubject |
| `source.ip` | protoPayload.requestMetadata.callerIp (`gce-internal-ip`, `private` → `source.address`) |
| `user_agent.original` | protoPayload.requestMetadata.callerSuppliedUserAgent |
| `gcp.audit.type` | protoPayload.@type |
| `gcp.audit.method_name`, `.service_name`, `.resource_name`, `.resource_location.current_locations[]`, `.num_response_items` | protoPayload |
| `gcp.audit.authentication_info.{principal_email, principal_subject, authority_selector, service_account_key_name, service_account_delegation_info[].*}` | protoPayload.authenticationInfo |
| `gcp.audit.authorization_info[].{permission, granted, resource, resource_attributes.*}` | protoPayload.authorizationInfo |
| `gcp.audit.status.{code,message}` | protoPayload.status |
| `gcp.audit.request.*`, `gcp.audit.response.*`, `gcp.audit.metadata.*`, `gcp.audit.service_data.*` | flattened (`flat_object`) |
| `gcp.audit.request_metadata.{caller_ip, caller_supplied_user_agent, caller_network, request_attributes.*, destination_attributes.*}` | protoPayload.requestMetadata |
| `gcp.audit.log_name`, `gcp.audit.severity`, `log.level`, `gcp.audit.operation.{id, producer, first, last}`, `gcp.audit.receive_timestamp`, `gcp.resource.type`, `gcp.resource.labels.*` | LogEntry |

SigmaHQ `gcp` rules already use `gcp.audit.method_name` and `gcp.audit.authorization_info.permission`
style names; pipeline `gcp_audit.yml` only normalizes case and the few older `data.protoPayload.*` forms.

## 12. Okta System Log (`okta.system`)

| Field | From |
|---|---|
| `@timestamp` | published |
| `event.id` | uuid |
| `event.action` | eventType |
| `event.outcome` | outcome.result: SUCCESS → success; FAILURE, DENY → failure; ALLOW → success; SKIPPED, CHALLENGE, UNKNOWN → unknown |
| `event.category` / `event.type` | `user.session.start`, `user.authentication.*`, `user.mfa.*`, `policy.evaluate_sign_on` → authentication/start|info; `user.lifecycle.*`, `user.account.*`, `group.user_membership.*`, `group.lifecycle.*`, `application.user_membership.*`, `application.lifecycle.*`, `system.api_token.*`, `user.mfa.factor.*` → iam (type by verb: create/activate → creation, deactivate/delete/suspend → deletion, update/reset/unlock → change); `policy.*`, `system.*`, `security.*`, `app.*` → configuration; `user.session.end` → authentication/end |
| `okta.event_type`, `okta.severity`, `okta.display_message`, `okta.legacy_event_type`, `okta.version` | top-level |
| `okta.outcome.result`, `okta.outcome.reason` | outcome |
| `user.name` (email local part when actor is a User — `alternateId` is the login), `user.email`, `user.full_name`, `user.id` | actor.alternateId, actor.displayName, actor.id |
| `okta.actor.{id,type,alternate_id,display_name}` | actor |
| `source.ip` | client.ipAddress |
| `source.geo.{city_name,region_name,country_name,postal_code,location}` (Okta supplies the country name, not the ISO code) | client.geographicalContext |
| `source.as.number`, `source.as.organization.name`, `okta.security_context.{isp,domain,is_proxy}` | securityContext |
| `user_agent.original`, `user_agent.os.full`←client.userAgent.os, `user_agent.name`←client.userAgent.browser | client.userAgent |
| `okta.client.{zone,device,id}` | client |
| `okta.authentication_context.{authentication_provider,credential_provider,credential_type,issuer.{id,type},interface,authentication_step,external_session_id}` | authenticationContext |
| `okta.target[].{id,type,alternate_id,display_name,detail_entry.*}` | target; the first target of type `User` also fills `user.target.name`/`user.target.id`; `AppInstance` → `okta.target.app.display_name` |
| `okta.transaction.{type,id}`, `okta.transaction.detail.*` | transaction |
| `okta.debug_context.debug_data.*` (dotted keys preserved as snake_case: `request_uri`, `request_id`, `url`, `threat_suspected`, `risk_level`, `risk_reasons`, `risk_behaviors`, `device_fingerprint`, `dt_hash`, `logon_type`, `factor`, `origin`, `behaviors`, `authn_request_id`) | debugContext.debugData |
| `okta.request.ip_chain[].{ip, version, source, geographical_context.*}` | request.ipChain |

Pipeline `okta.yml` maps SigmaHQ names (`eventtype`, `displaymessage`, `outcome.result`,
`outcome.reason`, `actor.alternateid`, `client.ipaddress`, `client.useragent.rawuseragent`,
`debugcontext.debugdata.*`, `target.type`, `target.displayname`, `securitycontext.*`).

## 13. Office 365 Management Activity (`o365.audit`)

| Field | From |
|---|---|
| `@timestamp` | CreationTime |
| `event.id` | Id |
| `event.action` | Operation |
| `event.provider` | Workload (AzureActiveDirectory, Exchange, SharePoint, OneDrive, MicrosoftTeams, SecurityComplianceCenter, PowerBI, …) |
| `event.code` | RecordType (numeric → `o365.audit.record_type_name` via the published table) |
| `event.outcome` | ResultStatus: Succeeded, Success, True, PartiallySucceeded→success; Failed, Failure, False→failure; UserLoginFailed Operation → failure |
| `event.category` / `event.type` | UserLoggedIn, UserLoginFailed → authentication/start; Add user, Update user, Delete user, Add member to role, Add member to group, Reset user password, Change user password, Set-Mailbox*, Add-MailboxPermission, Consent to application, Add service principal* → iam; New-InboxRule, Set-InboxRule, Set-TransportRule, New-TransportRule, Set-OrganizationConfig, Set-CASMailbox, Remove-UnifiedAuditLogRetentionPolicy → configuration; FileAccessed, FileDownloaded, FileUploaded, FileDeleted, FileModified, FileSyncDownloadedFull, SharingSet, AnonymousLinkCreated, SharingInvitationCreated → file; MailItemsAccessed, Send, SendAs, SendOnBehalf, MoveToDeletedItems, HardDelete, SoftDelete → email; TeamsSessionStarted, MemberAdded → session/iam |
| `user.name`, `user.email`, `user.id` | UserId (UPN; `user.name` = UPN local part), UserKey |
| `o365.audit.user_type` (0 Regular, 2 Admin, 3 DcAdmin, 4 System, 5 Application, 6 ServicePrincipal, 7 CustomPolicy, 8 SystemPolicy) and `.user_type_name` | UserType |
| `source.ip` | ClientIP / ClientIPAddress / ActorIpAddress (brackets and `:port` suffix removed) |
| `user_agent.original` | UserAgent, else ExtendedProperties[UserAgent], else ClientInfoString |
| `cloud.provider: azure`, `cloud.account.id`, `organization.id` | OrganizationId |
| `o365.audit.{record_type, workload, result_status, object_id, scope, intra_system_id, inter_systems_id, support_ticket_id, version, application_id, azure_active_directory_event_type, logon_error, error_number, client_info_string, client_app_id, external_access, originating_server, organization_name, mailbox_guid, mailbox_owner_upn, mailbox_owner_sid, logon_type, logon_user_sid, item_type, site_url, source_file_name, source_file_extension, source_relative_url, object_id, user_sharing_action, target_user_or_group_name, target_user_or_group_type, event_source, list_item_unique_id, machine_domain_info, machine_id, correlation_id, device_properties.*}` | respective properties |
| `o365.audit.extended_properties.<Name>` = Value | ExtendedProperties[] |
| `o365.audit.modified_properties.<Name>.{new_value,old_value}` | ModifiedProperties[] (when Name is a valid key; otherwise array under `o365.audit.modified_properties_raw`) |
| `o365.audit.parameters.<Name>` = Value | Parameters[] (Exchange cmdlet parameters; also serialized into `o365.audit.parameters_text` for `contains` search) |
| `o365.audit.actor[].{id,type}`, `o365.audit.target[].{id,type}`, `o365.audit.actor_context_id`, `o365.audit.target_context_id` | Actor, Target |
| `o365.audit.affected_items[]`, `o365.audit.folder.*`, `o365.audit.operation_properties.*` | Exchange mailbox audit |
| `file.name`←SourceFileName, `file.extension`←SourceFileExtension, `url.original`←ObjectId (when URL), `file.path`←SourceRelativeUrl + SourceFileName | SharePoint/OneDrive |
| `email.*` (`email.from.address`, `email.to.address[]`, `email.subject`, `email.message_id`, `email.direction`) | Exchange Send/SendAs, Defender for O365 events (P1Sender, Recipients, Subject, NetworkMessageId) |

Pipeline `o365.yml` maps SigmaHQ `m365` fields (`eventSource`, `eventName`, `status`,
`Operation`, `Workload`, `ResultStatus`, `UserId`, `ClientIP`, `Parameters`, `ModifiedProperties`).

## 14. Google Workspace Reports (`google_workspace.<application>`)

One `activity` may carry several `events[]`; Argus emits one event per entry.

| Field | From |
|---|---|
| `@timestamp` | id.time |
| `event.id` | id.uniqueQualifier + `-` + event index |
| `event.provider`, `event.dataset` | id.applicationName (admin, login, drive, token, groups, calendar, mobile, saml, user_accounts, access_transparency, chat, meet, rules, context_aware_access, data_studio, gcp, chrome, keep, vault, jamboard) |
| `event.action` | events[].name |
| `google_workspace.event.type` | events[].type |
| `event.category` / `event.type` / `event.outcome` | login: `login_success`→authentication/start/success, `login_failure`→authentication/start/failure, `logout`→authentication/end, `login_challenge`, `login_verification`, `suspicious_login`, `suspicious_login_less_secure_app`, `account_disabled_*`, `password_edit` → authentication|iam; admin: `CREATE_USER`, `DELETE_USER`, `SUSPEND_USER`, `CHANGE_PASSWORD`, `GRANT_ADMIN_PRIVILEGE`, `ASSIGN_ROLE`, `ADD_GROUP_MEMBER`, `CREATE_ROLE`, `CHANGE_APPLICATION_SETTING`, `ADD_DOMAIN_ALIAS`, `CREATE_DATA_TRANSFER_REQUEST`, `AUTHORIZE_API_CLIENT_ACCESS`, `TOGGLE_SSO_ENABLED` → iam|configuration; drive: `view`, `download`, `edit`, `create`, `delete`, `trash`, `move`, `rename`, `change_acl_editors`, `change_document_visibility`, `change_user_access`, `shared_drive_membership_change` → file/access|change|…; token: `authorize`, `revoke`, `request` → iam; saml: `login_success`/`login_failure` → authentication; groups: `add_member`, `remove_member`, `change_group_setting` → iam |
| `user.name` (local part), `user.email`, `user.id` | actor.email, actor.profileId |
| `google_workspace.actor.{type (USER, ADMIN, KEY, …), key}` | actor |
| `source.ip` | ipAddress |
| `organization.id`, `google_workspace.organization.domain` | id.customerId, ownerDomain |
| `google_workspace.<application>.<parameter_name>` (snake_case) | events[].parameters[] — `value`, `intValue` (long), `boolValue` (bool), `multiValue[]`, `multiIntValue[]`, `messageValue.parameter[]` (nested flattened) |
| Promoted: login `login_type`→`google_workspace.login.type`, `is_suspicious`, `is_second_factor`, `login_challenge_method[]`, `login_failure_type`, `affected_email_address`→`user.target.email`; admin `USER_EMAIL`→`user.target.email`/`user.target.name`, `GROUP_EMAIL`→`group.name`, `ROLE_NAME`→`google_workspace.admin.role.name`, `PRIVILEGE_NAME`→`google_workspace.admin.privilege.name`, `SETTING_NAME`/`NEW_VALUE`/`OLD_VALUE`→`google_workspace.admin.setting.{name,new_value,old_value}`, `DOMAIN_NAME`, `APPLICATION_NAME`→`google_workspace.admin.application.name`, `API_CLIENT_NAME`, `OAUTH2_SERVICE_NAME`; drive `doc_id`→`google_workspace.drive.file.id`, `doc_title`→`file.name`, `doc_type`→`google_workspace.drive.file.type`, `owner`→`google_workspace.drive.owner`, `visibility`→`google_workspace.drive.visibility`, `target_user`→`user.target.email`, `shared_drive_id`, `originating_app_id`; token `client_id`→`google_workspace.token.client.id`, `app_name`→`google_workspace.token.app_name`, `scope[]`→`google_workspace.token.scope.data[]`, `client_type`, `api_name`, `method_name`, `num_response_bytes`; saml `application_name`, `failure_type`, `initiated_by`, `orgunit_path`, `response_status`, `second_level_status` | — |

## 15. Palo Alto PAN-OS syslog (`panw.panos`)

CSV body after the syslog header (RFC 3164 or 5424). Log types TRAFFIC, THREAT, SYSTEM, CONFIG,
USERID, HIPMATCH, GLOBALPROTECT, DECRYPTION, AUTHENTICATION, CORRELATION, GTP, TUNNEL, SCTP,
IPTAG, URL (THREAT subtype `url`), DATA, WILDFIRE, VULNERABILITY, VIRUS, SPYWARE, FILE, FLOOD,
PACKET, SCAN. Column indices are from the PAN-OS 10.x/11.x syslog field order; fields beyond the
known column count are kept under `panw.panos.extra[]`.

| Field | TRAFFIC | THREAT | SYSTEM / CONFIG | AUTHENTICATION / GLOBALPROTECT / USERID |
|---|---|---|---|---|
| `@timestamp` | generated_time (col 7) | generated_time | generated_time | generated_time |
| `observer.vendor: Palo Alto Networks`, `observer.product: PAN-OS`, `observer.type: firewall`, `observer.serial_number`←serial, `observer.hostname`←syslog host, `observer.name`←device_name (col 60ish) | ✓ | ✓ | ✓ | ✓ |
| `panw.panos.type`, `panw.panos.sub_type` | TRAFFIC / start, end, drop, deny | THREAT / url, virus, spyware, vulnerability, file, wildfire, data, flood, scan, packet, ml-virus, wildfire-virus | SYSTEM subtypes, CONFIG | — |
| `source.ip`, `destination.ip`, `source.nat.ip`, `destination.nat.ip` | src, dst, natsrc, natdst | same | — | ip |
| `source.port`, `destination.port`, `source.nat.port`, `destination.nat.port` | sport, dport, natsport, natdport | same | — | — |
| `rule.name`, `rule.uuid` | rule, rule_uuid | rule | — | authpolicy |
| `source.user.name`, `destination.user.name`, `user.name` (= source.user.name) | srcuser, dstuser | same | admin (SYSTEM/CONFIG) | user |
| `network.application` | app | app | — | — |
| `observer.ingress.zone`, `observer.egress.zone`, `observer.ingress.interface.name`, `observer.egress.interface.name` | from, to, inbound_if, outbound_if | same | — | — |
| `panw.panos.flow_id` | sessionid | sessionid | — | — |
| `panw.panos.repeat_count` | repeatcnt | repeatcnt | — | — |
| `network.transport` | proto | proto | — | — |
| `event.action`, `panw.panos.action` | action (allow, deny, drop, reset-client, reset-server, reset-both, block-url, block-ip, random-drop, sinkhole, …) | action | — | event (auth-success, auth-fail) |
| `event.outcome` | allow→success; deny/drop/reset-*→failure | alert→unknown; block-*/drop/reset→failure; allow→success | — | from event |
| `network.bytes`, `source.bytes`, `destination.bytes`, `network.packets`, `source.packets`, `destination.packets` | bytes, bytes_sent, bytes_received, packets, pkts_sent, pkts_received | — | — | — |
| `event.start`, `event.duration` | start, elapsed (s → ns) | — | — | — |
| `panw.panos.url.category` | category | category (URL category / threat category) | — | — |
| `panw.panos.sequence_number`, `panw.panos.action_flags` | seqno, actionflags | same | seqno | seqno |
| `source.geo.country_name`/`destination.geo.country_name` (or `panw.panos.source.zone_location` when not a country) | srcloc, dstloc | same | — | — |
| `panw.panos.session_end_reason` | session_end_reason | — | — | — |
| `panw.panos.device_group_hierarchy.{level_1..4}`, `panw.panos.virtual_system`, `panw.panos.vsys_name`, `panw.panos.device_name`, `panw.panos.action_source` | ✓ | ✓ | ✓ | ✓ |
| `panw.panos.threat.id` (numeric id parsed from `name(id)`), `panw.panos.threat.name`, `rule.name` stays the policy; `event.kind: alert`, `event.category: [network, intrusion_detection]`, `event.severity` (informational 10, low 25, medium 50, high 75, critical 100), `panw.panos.direction`←direction (raw `client-to-server` / `server-to-client`), `network.direction` set to `inbound`/`outbound` when the source zone is tagged trusted/untrusted in the source configuration, `url.original`←misc (url/file subtype), `file.name`←misc (file/virus/wildfire), `file.hash.sha256`←filedigest, `panw.panos.content_type`, `panw.panos.pcap_id`, `panw.panos.cloud`, `panw.panos.url_index`, `user_agent.original`←user_agent, `panw.panos.file_type`, `network.forwarded_ip`←xff, `http.request.referrer`←referer, `email.from.address`←sender, `email.subject`←subject, `email.to.address`←recipient, `panw.panos.report_id`, `panw.panos.threat_category`, `panw.panos.content_version`, `panw.panos.sig_flags`, `http.request.method`←http_method, `panw.panos.tunnel_id`, `panw.panos.http_headers`, `panw.panos.url_category_list`, `panw.panos.rule_uuid`, `panw.panos.http2_connection`, `panw.panos.dynusergroup_name`, `panw.panos.xff_ip`←xff_ip, `panw.panos.src_device_category/profile/model/vendor/os/osv/hostname/mac`, `panw.panos.dst_device_*`, `panw.panos.partial_hash` | — | THREAT | — | — |
| SYSTEM / CONFIG: `event.category: [configuration]` for CONFIG and `[process]` for SYSTEM; `panw.panos.event_id`←eventid, `panw.panos.object`, `panw.panos.module`, `log.level`←severity, `message`←opaque/description, `panw.panos.cmd`←cmd, `panw.panos.result`, `panw.panos.config_path`, `panw.panos.before_change_detail`, `panw.panos.after_change_detail`, `source.ip`←host (CONFIG admin host) | — | — | ✓ | — |
| AUTHENTICATION / GLOBALPROTECT: `event.category: [authentication]`, `panw.panos.auth.{server_profile, description, client_type, event, factor_no, authproto, user_agent, region, vendor, repeat_count}`, `source.ip`←ip, `panw.panos.gp.{stage, auth_method, tunnel_type, source_region, machine_name, public_ip, private_ip, host_id, serial, client_version, client_os, error_code, status, gateway, portal, login_duration, connect_method, selection_type, priority, attempted_gateways}` | — | — | — | ✓ |

Sigma has few PAN-OS rules; pipeline `paloalto.yml` maps `src`, `dst`, `sport`, `dport`,
`rule`, `app`, `action`, `category`, `threatid`, `srcuser`, `misc`, `subtype`, `type`.

## 16. Fortinet FortiGate syslog (`fortinet.firewall`)

Key=value body (values may be quoted). Common: `@timestamp` ← `eventtime` (ns epoch) else
`date`+`time`+`tz`; `observer.vendor: Fortinet`, `observer.product: FortiGate`, `observer.type: firewall`,
`observer.name`←devname, `observer.serial_number`←devid, `fortinet.firewall.type` (traffic, utm,
event, anomaly), `fortinet.firewall.subtype` (forward, local, multicast, sniffer, app-ctrl, ips,
virus, webfilter, dns, ssl, waf, emailfilter, dlp, system, vpn, user, router, wireless, …),
`fortinet.firewall.logid`, `event.code`←logid, `fortinet.firewall.vd`, `log.level`←level,
`fortinet.firewall.eventtype`, `fortinet.firewall.logdesc`, `message`←msg.

| Fields | From |
|---|---|
| `source.ip`, `source.port`, `destination.ip`, `destination.port` | srcip, srcport, dstip, dstport |
| `source.nat.ip`, `source.nat.port` | transip, transport (trandisp=snat) |
| `destination.nat.ip`, `destination.nat.port` | tranip, tranport (trandisp=dnat) |
| `source.mac`, `destination.mac` | srcmac, dstmac |
| `source.domain`/`destination.domain` | srcname, dstname (or hostname for utm) |
| `observer.ingress.interface.name`, `observer.egress.interface.name`, `fortinet.firewall.srcintfrole`, `fortinet.firewall.dstintfrole` | srcintf, dstintf, srcintfrole, dstintfrole |
| `network.iana_number`, `network.transport` | proto (6 tcp, 17 udp, 1 icmp, 58 ipv6-icmp, 47 gre, 50 esp) |
| `network.application`, `fortinet.firewall.service` | app / service |
| `fortinet.firewall.appcat`, `fortinet.firewall.apprisk`, `fortinet.firewall.appid`, `fortinet.firewall.applist`, `fortinet.firewall.appact` | app-ctrl |
| `rule.id`, `rule.uuid`, `rule.name`, `fortinet.firewall.policytype`, `fortinet.firewall.policymode` | policyid, poluuid, policyname, policytype, policymode |
| `fortinet.firewall.sessionid` | sessionid |
| `event.action`, `fortinet.firewall.action`, `fortinet.firewall.utmaction` | action, utmaction |
| `event.outcome` | accept/pass/allow/close/timeout/server-rst/client-rst → success; deny/block/blocked/drop/dropped/reset → failure |
| `event.category` / `event.type` / `event.kind` | traffic → network / connection,allowed|denied; utm ips/virus/anomaly → `event.kind: alert`, [network, intrusion_detection|malware] ; webfilter/dns/app-ctrl → network / allowed|denied; event.system/user/vpn → authentication (logdesc contains `login`, action in login/logout/auth) or configuration |
| `event.duration` | duration (s → ns) |
| `source.bytes`, `destination.bytes`, `source.packets`, `destination.packets`, `network.bytes`, `network.packets` | sentbyte, rcvdbyte, sentpkt, rcvdpkt |
| `source.geo.country_name`, `destination.geo.country_name` | srccountry, dstcountry (`Reserved` dropped) |
| `user.name`, `user.group.name`, `fortinet.firewall.authserver`, `fortinet.firewall.authproto`, `fortinet.firewall.unauthuser` | user, group, authserver, authproto, unauthuser |
| `rule.name`←attack, `rule.id`←attackid, `fortinet.firewall.attack`, `fortinet.firewall.attackid`, `fortinet.firewall.ref`←ref, `event.severity`←severity (info 10, low 25, medium 50, high 75, critical 100), `fortinet.firewall.crscore`, `fortinet.firewall.craction`, `fortinet.firewall.crlevel`, `fortinet.firewall.incidentserialno`, `fortinet.firewall.profile`, `fortinet.firewall.direction`→`network.direction` (incoming→inbound, outgoing→outbound) | utm ips |
| `url.original`←url, `url.domain`←hostname, `url.path`, `http.request.method`←method, `http.request.referrer`←referralurl, `user_agent.original`←agent, `fortinet.firewall.catdesc`, `fortinet.firewall.cat`, `fortinet.firewall.reqtype`, `fortinet.firewall.urlfilteridx`, `fortinet.firewall.urlfilterlist`, `fortinet.firewall.urlsource` | utm webfilter |
| `file.name`←filename, `fortinet.firewall.checksum`←checksum, `fortinet.firewall.virus`, `fortinet.firewall.virusid`, `fortinet.firewall.dtype`, `fortinet.firewall.analyticscksum`, `fortinet.firewall.analyticssubmit`, `fortinet.firewall.quarskip`, `fortinet.firewall.filetype`, `file.size`←filesize | utm virus / file-filter |
| `dns.question.name`←qname, `dns.question.type`←qtype, `fortinet.firewall.error`←error, `dns.resolved_ip[]`←ipaddr (space separated), `fortinet.firewall.qtypeval`, `fortinet.firewall.xid`→`dns.id`, `fortinet.firewall.domainfilteridx`, `fortinet.firewall.botnetip`, `fortinet.firewall.botnetdomain` | utm dns |
| `fortinet.firewall.{tunnelid, tunneltype, tunnelip, remip, locip, remport, locport, outintf, cookies, xauthuser, xauthgroup, assignip, vpntunnel, status, reason, init, mode, stage, role, result, version, peer_notif, esptransform, espauth, dir, spi, phase2_name}`, `source.ip`←remip, `user.name`←xauthuser | event vpn |
| `fortinet.firewall.{ui, method, sn, cfgpath, cfgattr, cfgobj, cfgtid, user_interface, dstuser, profiletype, profile, interface, state, policy, old_state, new_state, msg, trigger}`, `source.ip`←srcip or ui `ssh(ip)`/`https(ip)` parsed, `user.name`←user, `event.category: [authentication]` for logid 0100032001–0100032003 (admin login success/failed/logout), 0100032006 (admin lockout), 0100032301 (SSL VPN user login) | event system / user |
| `fortinet.firewall.<key>` | every remaining key |

## 17. osquery (`osquery.result`)

Event format (`{"name","hostIdentifier","calendarTime","unixTime","epoch","counter","numerics","decorations":{},"columns":{},"action"}`)
and snapshot format (`"snapshot":[…]`, one event per row). Batch format (`"diffResults":{"added":[…],"removed":[…]}`) is expanded likewise.

| Field | From |
|---|---|
| `@timestamp` | unixTime (s) else calendarTime |
| `host.name`, `host.hostname` | decorations.hostname, else hostIdentifier |
| `host.id` | decorations.host_uuid |
| `osquery.result.{name, action (added, removed, snapshot), calendar_time, unix_time, epoch, counter, numerics, host_identifier}` | top-level |
| `osquery.result.decorations.*` | decorations |
| `osquery.result.columns.*` | columns (`flat_object`); numeric strings stay strings |
| `event.category: [host]`, `event.type: [info]` default; `event.action`←`osquery.result.name` | — |
| Promotions by query table (detected from `name` suffix or column set) | `process_events` / `processes`: `process.pid`←pid, `process.executable`←path, `process.command_line`←cmdline, `process.name`←path basename, `process.parent.pid`←parent, `process.working_directory`←cwd, `user.id`←uid, `user.group.id`←gid, `user.effective.id`←euid, `process.start`←time, `process.hash.sha256`←sha256 (if joined with hash), `event.category: [process]`, `event.type: [start|end]`←action (added → start, removed → end); `socket_events` / `process_open_sockets`: `source.ip`←local_address, `source.port`←local_port, `destination.ip`←remote_address, `destination.port`←remote_port, `network.transport`←protocol (iana), `process.pid`←pid, `process.executable`←path, `event.category: [network]`; `listening_ports`: `destination.port`←port, `destination.ip`←address, `process.pid`; `logged_in_users`: `user.name`←user, `source.ip`/`source.address`←host, `osquery.result.columns.tty`, `event.category: [session]`; `users`: `user.name`←username, `user.id`←uid, `user.group.id`←gid, `user.home`←directory, `osquery.result.columns.shell`, `event.category: [iam]`; `file_events`: `file.path`←target_path, `file.hash.{md5,sha1,sha256}`, `file.size`, `file.mode`, `file.uid`, `file.gid`, `event.category: [file]`, `event.type`←action (CREATED→creation, DELETED→deletion, UPDATED/ATTRIBUTES_MODIFIED→change); `shell_history`: `user.id`←uid, `process.command_line`←command, `file.path`←history_file; `crontab`: `process.command_line`←command, `file.path`←path; `services` / `startup_items` / `launchd` / `scheduled_tasks`: `service.name`←name, `process.executable`←path, `osquery.result.columns.*`; `dns_resolvers`, `etc_hosts`, `arp_cache`, `interface_addresses`, `kernel_modules`, `chrome_extensions`, `authorized_keys`, `sudoers`, `suid_bin`, `windows_eventlog`, `registry`: columns only (plus `registry.path`←path for `registry`) |

SigmaHQ has no osquery-specific logsource; Argus rules target `osquery.result.columns.*` and the
promoted ECS fields.

## 18. Kubernetes audit (`kubernetes.audit`)

Input: audit webhook `EventList` or `Event` JSON, `audit.k8s.io/v1`.

| Field | From |
|---|---|
| `@timestamp` | requestReceivedTimestamp (stageTimestamp for `Panic`) |
| `event.id` | auditID + `-` + stage (ResponseComplete only is kept by default; `RequestReceived` dropped unless `keep_all_stages`) |
| `event.action` | verb (get, list, watch, create, update, patch, delete, deletecollection, proxy, impersonate, …) |
| `event.outcome` | responseStatus.code < 400 → success, ≥ 400 → failure; annotation `authorization.k8s.io/decision: forbid` → failure |
| `event.category` / `event.type` | objectRef.resource in {roles, rolebindings, clusterroles, clusterrolebindings, serviceaccounts, tokenreviews, subjectaccessreviews, certificatesigningrequests} → iam; {secrets, configmaps} → configuration (type access for get/list/watch); {pods (exec/attach/portforward subresources), pods/exec} → process (type start); anything else → configuration; type by verb: create → creation; delete, deletecollection → deletion; update, patch → change; get, list, watch, proxy → access |
| `kubernetes.audit.{level (Metadata, Request, RequestResponse), stage, verb, request_uri, audit_id, kind, api_version}` | top-level |
| `url.original`, `url.path`, `url.query` | requestURI |
| `user.name`, `user.id`, `user.group.name[]`, `kubernetes.audit.user.extra.*` | user.username, user.uid, user.groups, user.extra |
| `kubernetes.audit.impersonated_user.{username, uid, groups[], extra.*}`, `user.effective.name`←impersonatedUser.username | impersonatedUser |
| `source.ip`, `related.ip[]`, `source.address` | sourceIPs[0], sourceIPs |
| `user_agent.original` | userAgent |
| `kubernetes.audit.object_ref.{resource, namespace, name, uid, api_group, api_version, resource_version, subresource}` | objectRef |
| `orchestrator.type: kubernetes`, `orchestrator.namespace`←objectRef.namespace, `orchestrator.resource.type`←objectRef.resource, `orchestrator.resource.name`←objectRef.name, `orchestrator.api_version`←objectRef.apiVersion, `orchestrator.cluster.name`←annotation `cluster` or source config | — |
| `kubernetes.audit.response_status.{code, status, reason, message}` | responseStatus |
| `kubernetes.audit.request_object.*`, `kubernetes.audit.response_object.*` | flattened (`flat_object`); `kubernetes.audit.request_object_text` compact JSON (bounded 32 KiB) for `contains` |
| `kubernetes.audit.annotations.authorization_k8s_io/decision`, `…/reason`, `kubernetes.audit.annotations.pod-security_kubernetes_io/*`, other annotations with `.`→`_` | annotations |
| `container.image.name`←requestObject.spec.containers[].image (first), `kubernetes.audit.request_object.spec.host_pid`, `.host_network`, `.host_ipc`, `.security_context.privileged`, `.volumes[].host_path.path` are promoted to `kubernetes.audit.pod.{image, host_pid, host_network, host_ipc, privileged, host_path[]}` for pod creation | requestObject |

SigmaHQ `kubernetes` rules (compiled with pySigma's `ecs_kubernetes`) reference
`kubernetes.audit.verb`, `kubernetes.audit.objectRef.*`, `kubernetes.audit.user.*`,
`kubernetes.audit.requestObject.*`, `kubernetes.audit.annotations.*`; pipeline `kubernetes.yml`
converts camelCase to the snake_case paths above.

## 19. Generic fallbacks (`event.module: generic`)

| Dataset | Rules |
|---|---|
| `generic.json` | Parse as JSON; keys that are valid ECS paths (validated against the bundled ECS field list) are kept; `@timestamp`, `timestamp`, `time`, `ts`, `eventTime`, `event_time`, `date` tried in order for the time (RFC 3339, epoch s/ms/µs/ns, common layouts); `message`/`msg`/`log`/`text` for message; `host`/`hostname`/`host.name` for host; all other keys under `generic.json.<key>` (flattened, dotted) |
| `generic.cef` | `CEF:<v>|<vendor>|<product>|<version>|<sigid>|<name>|<severity>|<ext>` → `observer.vendor`, `observer.product`, `observer.version`, `event.code`←sigid, `event.action`/`rule.name`←name, `event.severity` (0–10 → ×10; Low 25, Medium 50, High 75, Very-High 100), `cef.version`, extensions: `rt`→@timestamp, `src`→source.ip, `spt`→source.port, `smac`→source.mac, `shost`→source.domain, `suser`→source.user.name (and user.name), `suid`→source.user.id, `sntdom`→source.user.domain, `dst`→destination.ip, `dpt`→destination.port, `dmac`→destination.mac, `dhost`→destination.domain, `duser`→destination.user.name (user.target.name), `duid`, `dntdom`, `proto`→network.transport, `app`→network.protocol, `act`→event.action, `msg`→message, `in`→source.bytes, `out`→destination.bytes, `fname`→file.name, `fsize`→file.size, `filePath`→file.path, `fileHash`→file.hash.sha256|sha1|md5 by length, `fileType`→file.type, `request`→url.original, `requestMethod`→http.request.method, `requestClientApplication`→user_agent.original, `requestContext`→http.request.referrer, `dvc`→observer.ip, `dvchost`→observer.hostname, `dvcpid`→process.pid, `deviceExternalId`→observer.serial_number, `deviceInboundInterface`→observer.ingress.interface.name, `deviceOutboundInterface`→observer.egress.interface.name, `deviceDirection`→network.direction (0 inbound, 1 outbound), `sproc`→process.name, `dproc`→process.name, `spriv`→source.user.group.name, `dpriv`→destination.user.group.name, `outcome`→event.outcome, `reason`→event.reason, `cat`→cef.extensions.device_event_category, `cnt`→cef.extensions.base_event_count, `start`→event.start, `end`→event.end, `externalId`→event.id, `cs1..cs6` with `cs1Label..` → `cef.extensions.<label>` (also raw `cef.extensions.custom_string_1`), `cn1..cn3` likewise, `flexString1/2`, `flexDate1`; everything else `cef.extensions.<key>`. Escapes `\|`, `\\`, `\=`, `\n`, `\r` handled |
| `generic.leef` | `LEEF:<v>|<vendor>|<product>|<version>|<event_id>|[<delim>|]<attrs>` → `observer.*`, `event.code`←event_id, `leef.version`, attribute mapping: `devTime`+`devTimeFormat`→@timestamp, `src`, `dst`, `srcPort`, `dstPort`, `srcMAC`, `dstMAC`, `proto`, `usrName`→user.name, `srcPreNAT`→source.nat.ip, `dstPreNAT`, `srcPostNAT`, `dstPostNAT`, `sev`→event.severity (0–10 ×10), `cat`→leef.attributes.cat, `identSrc`, `identHostName`→source.domain, `url`→url.original, `domain`→user.domain, `role`, `realm`, `policy`→rule.name, `resource`, `accountName`→user.name, `calCountryOrRegion`, `calLanguage`, `vSrc`, `vSrcName`, `totalPackets`→network.packets, `srcBytes`, `dstBytes`, `srcPackets`, `dstPackets`; others `leef.attributes.<key>`; delimiter from header (tab default, `x09`/`0x09` forms) |
| `generic.syslog` | RFC 5424 (`<PRI>1 TS HOST APP PROCID MSGID [SD] MSG`) and RFC 3164 (`<PRI>Mmm dd hh:mm:ss HOST APP[PID]: MSG`, with optional year, ISO timestamps, no-hostname and no-PRI variants, Cisco sequence/`%FAC-SEV-MNEMONIC:` prefixes) → `log.syslog.priority`, `log.syslog.facility.{code,name}`, `log.syslog.severity.{code,name}`, `log.level`, `log.syslog.hostname`→`host.name`, `log.syslog.appname`→`process.name`, `log.syslog.procid`→`process.pid` (when numeric), `log.syslog.msgid`, `log.syslog.structured_data.<sd-id>.<param>`, `log.syslog.version`, `message` (MSG part), `event.original`; the MSG part is then offered to the structured sub-parsers (CEF, LEEF, JSON, key=value, PAN-OS CSV, FortiGate kv, linux auth) via the registry's sniffing order so a syslog-wrapped payload always lands in the most specific dataset. `log.source.address` is the sender's IP:port |

## 20. Argus alert documents (`argus-{tenant}-alerts-*`)

Alerts are written both to Postgres (for workflow) and to OpenSearch (for search). The
OpenSearch document is an ECS event with `event.kind: alert`, `event.module: argus`,
`event.dataset: argus.alert`, plus:

| Field | Meaning |
|---|---|
| `rule.id`, `rule.name`, `rule.version`, `rule.category` (sigma, threshold, sequence, aggregation, scheduled, ueba), `rule.ruleset` (sigmahq, argus), `rule.reference[]`, `rule.description`, `rule.license` | rule identity |
| `event.severity` (25/50/75/100), `argus.alert.severity` (low/medium/high/critical), `argus.alert.score` (0–100 combined score), `argus.alert.score_inputs.{rule, asset, entity_risk}` | severity scoring |
| `threat.framework: MITRE ATT&CK`, `threat.tactic.{id,name}[]`, `threat.technique.{id,name,subtechnique.id}[]` | ATT&CK |
| `argus.alert.id`, `argus.alert.dedupe_key`, `argus.alert.status` (open, acknowledged, in_progress, closed), `argus.alert.suppressed` (staging rules), `argus.alert.incident_id` | workflow |
| `argus.alert.entity.{kind,id}`, `argus.alert.entities[]` | primary and related entities |
| `argus.alert.evidence[].{event_hash,index,timestamp,summary}` | contributing events (bounded, default 50) |
| `argus.detection.latency_ms`, `argus.detection.engine_instance`, `argus.detection.window.{start,end}` | measurement |
| `argus.alert.false_positive_notes`, `argus.alert.response_guidance` | copied from the rule for the analyst |

## 21. Versioning and evolution

- `argus.schema.version` increments on breaking renames. Parsers declare the schema version they
  emit; the processor refuses to start if a parser's version is newer than the index templates.
- Additive fields need no version bump; the index templates use `dynamic: false` at the root and
  `flat_object` for the per-module `raw`/flattened subtrees, so an unmapped field is still stored
  and searchable via the flattened path and does not explode the mapping.
- `tools/schema/ecs_fields.json` (generated from the ECS 8.11 flat field list) is used by
  `internal/schema` tests to assert that every top-level ECS field a parser writes exists in ECS
  with the right type, and by the generic JSON parser to decide what to pass through.
