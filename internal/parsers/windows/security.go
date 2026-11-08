package windows

import (
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

var logonTypeNames = map[string]string{
	"2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock",
	"8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive", "11": "CachedInteractive",
	"12": "CachedRemoteInteractive", "13": "CachedUnlock", "0": "System",
}

var failureReasons = map[string]string{
	"%%2304": "An Error occurred during Logon.",
	"%%2305": "The specified user account has expired.",
	"%%2306": "The NetLogon component is not active.",
	"%%2307": "Account locked out.",
	"%%2308": "The user has not been granted the requested logon type at this machine.",
	"%%2309": "The specified account's password has expired.",
	"%%2310": "Account currently disabled.",
	"%%2311": "Account logon time restriction violation.",
	"%%2312": "User not allowed to logon at this computer.",
	"%%2313": "Unknown user name or bad password.",
}

type securityHandler func(e *schema.Event, r *record)

var securityHandlers = map[int64]securityHandler{
	4624: logon(schema.OutcomeSuccess, "logged-in"),
	4625: logon(schema.OutcomeFailure, "logon-failed"),
	4634: logoff, 4647: logoff,
	4648: explicitCreds,
	4672: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeAdmin)
		e.Set(schema.FieldEventAction, "special-privileges-assigned")
		setSubject(e, r)
		e.Set("winlog.logon.id", r.get("SubjectLogonId"))
	},
	4688: processCreated,
	4689: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeEnd)
		e.Set(schema.FieldEventAction, "process-exited")
		setProcess(e, "process", r.get("ProcessName"), r.get("ProcessId"))
		parsers.SetInt(e, "process.exit_code", r.get("Status"))
		setSubject(e, r)
	},
	4697: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeCreation)
		e.Set(schema.FieldEventAction, "service-installed")
		e.Set("service.name", r.get("ServiceName"))
		e.Set("service.type", r.get("ServiceType"))
		setServiceExecutable(e, r.get("ServiceFileName"))
		setSubject(e, r)
	},
	4698: scheduledTask(schema.TypeCreation, "scheduled-task-created"),
	4699: scheduledTask(schema.TypeDeletion, "scheduled-task-deleted"),
	4700: scheduledTask(schema.TypeChange, "scheduled-task-enabled"),
	4701: scheduledTask(schema.TypeChange, "scheduled-task-disabled"),
	4702: scheduledTask(schema.TypeChange, "scheduled-task-updated"),
	4719: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "audit-policy-changed")
		setSubject(e, r)
	},
	4720: accountMgmt(schema.TypeCreation, "added-user-account"),
	4722: accountMgmt(schema.TypeChange, "enabled-user-account"),
	4723: accountMgmt(schema.TypeChange, "changed-password"),
	4724: accountMgmt(schema.TypeChange, "reset-password"),
	4725: accountMgmt(schema.TypeChange, "disabled-user-account"),
	4726: accountMgmt(schema.TypeDeletion, "deleted-user-account"),
	4738: accountMgmt(schema.TypeChange, "modified-user-account"),
	4781: accountMgmt(schema.TypeChange, "renamed-user-account"),
	4794: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeUser, schema.TypeChange)
		e.Set(schema.FieldEventAction, "dsrm-password-set")
		setSubject(e, r)
	},
	4727: groupMgmt(schema.TypeCreation, "added-group-account"),
	4730: groupMgmt(schema.TypeDeletion, "deleted-group-account"),
	4731: groupMgmt(schema.TypeCreation, "added-group-account"),
	4734: groupMgmt(schema.TypeDeletion, "deleted-group-account"),
	4735: groupMgmt(schema.TypeChange, "modified-group-account"),
	4737: groupMgmt(schema.TypeChange, "modified-group-account"),
	4754: groupMgmt(schema.TypeCreation, "added-group-account"),
	4758: groupMgmt(schema.TypeDeletion, "deleted-group-account"),
	4728: groupMember("added-member-to-group"),
	4732: groupMember("added-member-to-group"),
	4756: groupMember("added-member-to-group"),
	4729: groupMember("removed-member-from-group"),
	4733: groupMember("removed-member-from-group"),
	4757: groupMember("removed-member-from-group"),
	4740: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeInfo)
		e.Set(schema.FieldEventAction, "locked-out-user-account")
		e.Set("user.target.name", r.get("TargetUserName"))
		e.Set("user.target.id", r.get("TargetSid"))
		e.Set("source.domain", r.get("TargetDomainName"))
		setSubject(e, r)
	},
	4767: accountMgmt(schema.TypeChange, "unlocked-user-account"),
	4768: kerberos("kerberos-authentication-ticket-requested"),
	4769: kerberos("kerberos-service-ticket-requested"),
	4770: kerberos("kerberos-service-ticket-renewed"),
	4771: func(e *schema.Event, r *record) {
		kerberos("kerberos-preauth-failed")(e, r)
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	},
	4776: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventAction, "credential-validated")
		if u := r.get("TargetUserName"); u != "" {
			name, dom := splitUPN(u)
			e.Set("user.name", name)
			e.Set("user.domain", dom)
		}
		if w := r.get("Workstation"); w != "" {
			e.Set("source.domain", strings.TrimPrefix(w, `\\`))
		}
		if oc := kerberosOutcome(r.get("Status")); oc != "" {
			e.Set(schema.FieldEventOutcome, oc)
		}
	},
	4778: rdpSession(schema.TypeStart, "session-reconnected"),
	4779: rdpSession(schema.TypeEnd, "session-disconnected"),
	5136: dsObject(schema.TypeChange, "directory-service-object-modified"),
	5137: dsObject(schema.TypeCreation, "directory-service-object-created"),
	5139: dsObject(schema.TypeChange, "directory-service-object-moved"),
	5141: dsObject(schema.TypeDeletion, "directory-service-object-deleted"),
	5140: share("network-share-accessed"),
	5145: share("network-share-object-checked"),
	5156: wfp(schema.TypeAllowed, "windows-firewall-connection-allowed"),
	5157: wfp(schema.TypeDenied, "windows-firewall-connection-blocked"),
	5158: wfp(schema.TypeAllowed, "windows-firewall-bind-allowed"),
	5152: wfp(schema.TypeDenied, "windows-firewall-packet-blocked"),
	4657: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryRegistry)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "registry-value-modified")
		key := normalizeRegistryKey(r.get("ObjectName"))
		val := r.get("ObjectValueName")
		e.Set("registry.key", key)
		e.Set("registry.value", val)
		if key != "" && val != "" {
			e.Set("registry.path", key+`\`+val)
		} else {
			e.Set("registry.path", key)
		}
		e.Set("registry.hive", registryHive(key))
		if nv := r.get("NewValue"); nv != "" {
			e.Set("registry.data.strings", []string{nv})
		}
		e.Set("registry.data.type", r.get("NewValueType"))
		setProcess(e, "process", r.get("ProcessName"), r.get("ProcessId"))
		setSubject(e, r)
	},
	4656: objectAccess(schema.TypeAccess, "handle-requested"),
	4658: objectAccess(schema.TypeAccess, "handle-closed"),
	4660: objectAccess(schema.TypeDeletion, "object-deleted"),
	4663: objectAccess("", "object-accessed"),
	4670: objectAccess(schema.TypeChange, "permissions-changed"),
	1102: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "audit-log-cleared")
		e.Set("user.name", r.UserData["SubjectUserName"])
		e.Set("user.domain", r.UserData["SubjectDomainName"])
		e.Set("user.id", r.UserData["SubjectUserSid"])
		e.Set("winlog.logon.id", r.UserData["SubjectLogonId"])
		e.AddTag("log_cleared")
	},
	1100: eventLogService("event-log-service-shutdown"),
	1104: eventLogService("event-log-full"),
	1105: eventLogService("event-log-archived"),
	4608: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryHost)
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventAction, "windows-starting-up")
	},
	4616: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "system-time-changed")
		setSubject(e, r)
		setProcess(e, "process", r.get("ProcessName"), r.get("ProcessId"))
	},
	4673:          privilegedService("privileged-service-called"),
	4674:          privilegedService("privileged-object-operation"),
	4720 + 100000: nil, // sentinel to keep gofmt alignment stable
	4798: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeUser, schema.TypeInfo)
		e.Set(schema.FieldEventAction, "user-local-group-membership-enumerated")
		setSubject(e, r)
		setTargetAsTarget(e, r)
		setProcess(e, "process", r.get("CallerProcessName"), r.get("CallerProcessId"))
	},
	4799: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeGroup, schema.TypeInfo)
		e.Set(schema.FieldEventAction, "security-local-group-membership-enumerated")
		setSubject(e, r)
		e.Set("group.name", r.get("TargetUserName"))
		e.Set("group.domain", r.get("TargetDomainName"))
		e.Set("group.id", r.get("TargetSid"))
		setProcess(e, "process", r.get("CallerProcessName"), r.get("CallerProcessId"))
	},
	4886: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeInfo)
		e.Set(schema.FieldEventAction, "certificate-services-request-received")
		e.Set("user.name", cnFromDN(r.get("Requester")))
	},
	4887: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeCreation)
		e.Set(schema.FieldEventAction, "certificate-services-certificate-issued")
		e.Set("user.name", cnFromDN(r.get("Requester")))
	},
	5024: eventLogService("windows-firewall-service-started"),
	5025: eventLogService("windows-firewall-service-stopped"),
	5379: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeAccess)
		e.Set(schema.FieldEventAction, "credential-manager-credentials-read")
		setSubject(e, r)
		e.Set("winlog.logon.id", r.get("SubjectLogonId"))
	},
	4697 + 100000: nil,
}

func init() {
	// Remove the alignment sentinels.
	delete(securityHandlers, 4720+100000)
	delete(securityHandlers, 4697+100000)
}

func applySecurity(e *schema.Event, r *record) {
	if h, ok := securityHandlers[r.EventID]; ok && h != nil {
		h(e, r)
	}
}

func logon(outcome, action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventAction, action)
		e.Set(schema.FieldEventOutcome, outcome)
		setTargetUser(e, r)
		setSourceIP(e, "source.ip", r.get("IpAddress"))
		parsers.SetPort(e, "source.port", r.get("IpPort"))
		if w := r.get("WorkstationName"); w != "" {
			e.Set("source.domain", strings.TrimPrefix(w, `\\`))
		}
		if lt := r.get("LogonType"); lt != "" {
			parsers.SetInt(e, "winlog.logon.type", lt)
			e.Set("winlog.logon.type_name", logonTypeNames[lt])
		}
		setProcess(e, "process", r.get("ProcessName"), r.get("ProcessId"))
		if outcome == schema.OutcomeFailure {
			if fr := r.get("FailureReason"); fr != "" {
				if text, ok := failureReasons[fr]; ok {
					e.Set("winlog.logon.failure.reason", text)
				} else {
					e.Set("winlog.logon.failure.reason", fr)
				}
			}
			e.Set("winlog.logon.failure.status", r.get("Status"))
			e.Set("winlog.logon.failure.sub_status", r.get("SubStatus"))
		}
	}
}

func logoff(e *schema.Event, r *record) {
	e.SetCategory(schema.CategoryAuthentication)
	e.SetTypes(schema.TypeEnd)
	e.Set(schema.FieldEventAction, "logged-out")
	setTargetUser(e, r)
	if lt := r.get("LogonType"); lt != "" {
		parsers.SetInt(e, "winlog.logon.type", lt)
		e.Set("winlog.logon.type_name", logonTypeNames[lt])
	}
}

func explicitCreds(e *schema.Event, r *record) {
	e.SetCategory(schema.CategoryAuthentication)
	e.SetTypes(schema.TypeStart)
	e.Set(schema.FieldEventAction, "logon-with-explicit-credentials")
	setSubject(e, r)
	setTargetAsTarget(e, r)
	if ts := r.get("TargetServerName"); ts != "" && !strings.EqualFold(ts, "localhost") {
		e.Set("destination.domain", ts)
	}
	setSourceIP(e, "source.ip", r.get("IpAddress"))
	parsers.SetPort(e, "source.port", r.get("IpPort"))
	setProcess(e, "process", r.get("ProcessName"), r.get("ProcessId"))
}

func processCreated(e *schema.Event, r *record) {
	e.SetCategory(schema.CategoryProcess)
	e.SetTypes(schema.TypeStart)
	e.Set(schema.FieldEventAction, "process-created")
	setProcess(e, "process", r.get("NewProcessName"), r.get("NewProcessId"))
	e.Set("process.command_line", r.get("CommandLine"))
	setProcess(e, "process.parent", r.get("ParentProcessName"), r.get("ProcessId"))
	setSubject(e, r)
	// 4688 may carry a different target identity when the token differs.
	if tu := r.get("TargetUserName"); tu != "" && tu != r.get("SubjectUserName") {
		e.Set("user.effective.name", tu)
		e.Set("user.effective.domain", r.get("TargetDomainName"))
	}
}

func setServiceExecutable(e *schema.Event, fileName string) {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		return
	}
	// "C:\path\svc.exe" -k args  or  "\??\C:\x.sys" or  cmd.exe /c ...
	exe := fileName
	if strings.HasPrefix(exe, `"`) {
		if end := strings.IndexByte(exe[1:], '"'); end >= 0 {
			exe = exe[1 : end+1]
		}
	} else if i := strings.Index(strings.ToLower(exe), ".exe "); i > 0 {
		exe = exe[:i+4]
	}
	exe = strings.TrimPrefix(exe, `\??\`)
	e.Set("process.executable", exe)
	e.Set("process.name", parsers.BaseName(exe))
	if exe != fileName {
		e.Set("process.command_line", fileName)
	}
}

func scheduledTask(typ, action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(typ)
		e.Set(schema.FieldEventAction, action)
		setSubject(e, r)
	}
}

func accountMgmt(typ, action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeUser, typ)
		e.Set(schema.FieldEventAction, action)
		setSubject(e, r)
		setTargetAsTarget(e, r)
		if nn := r.get("NewTargetUserName"); nn != "" {
			e.Set("user.changes.name", nn)
		}
	}
}

func groupMgmt(typ, action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeGroup, typ)
		e.Set(schema.FieldEventAction, action)
		setSubject(e, r)
		e.Set("group.name", r.get("TargetUserName"))
		e.Set("group.domain", r.get("TargetDomainName"))
		e.Set("group.id", r.get("TargetSid"))
	}
}

func groupMember(action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeGroup, schema.TypeChange)
		e.Set(schema.FieldEventAction, action)
		setSubject(e, r)
		e.Set("group.name", r.get("TargetUserName"))
		e.Set("group.domain", r.get("TargetDomainName"))
		e.Set("group.id", r.get("TargetSid"))
		if m := r.get("MemberName"); m != "" {
			e.Set("user.target.name", cnFromDN(m))
		}
		e.Set("user.target.id", r.get("MemberSid"))
	}
}

func kerberos(action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventAction, action)
		if u := r.get("TargetUserName"); u != "" {
			name, dom := splitUPN(u)
			e.Set("user.name", name)
			if dom != "" {
				e.Set("user.domain", dom)
			}
		}
		if d := r.get("TargetDomainName"); d != "" {
			e.Set("user.domain", d)
		}
		e.Set("user.id", r.get("TargetSid"))
		setSourceIP(e, "source.ip", r.get("IpAddress"))
		parsers.SetPort(e, "source.port", r.get("IpPort"))
		if oc := kerberosOutcome(r.get("Status")); oc != "" {
			e.Set(schema.FieldEventOutcome, oc)
		}
	}
}

func rdpSession(typ, action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategorySession)
		e.SetTypes(typ)
		e.Set(schema.FieldEventAction, action)
		e.Set("user.name", r.get("AccountName"))
		e.Set("user.domain", r.get("AccountDomain"))
		e.Set("winlog.logon.id", r.get("LogonID"))
		setSourceIP(e, "source.ip", r.get("ClientAddress"))
		if c := r.get("ClientName"); c != "" && c != "Unknown" {
			e.Set("source.domain", c)
		}
	}
}

func dsObject(typ, action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(typ)
		e.Set(schema.FieldEventAction, action)
		setSubject(e, r)
	}
}

func share(action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryNetwork, schema.CategoryFile)
		e.SetTypes(schema.TypeAccess)
		e.Set(schema.FieldEventAction, action)
		setSubject(e, r)
		setSourceIP(e, "source.ip", r.get("IpAddress"))
		parsers.SetPort(e, "source.port", r.get("IpPort"))
		path := r.get("ShareName")
		if rel := r.get("RelativeTargetName"); rel != "" {
			path = strings.TrimRight(path, `\`) + `\` + rel
			e.Set("file.name", parsers.BaseName(rel))
		}
		e.Set("file.path", path)
	}
}

func wfp(typ, action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeConnection, typ)
		e.Set(schema.FieldEventAction, action)
		parsers.SetIP(e, "source.ip", r.get("SourceAddress"))
		parsers.SetPort(e, "source.port", r.get("SourcePort"))
		parsers.SetIP(e, "destination.ip", r.get("DestAddress"))
		parsers.SetPort(e, "destination.port", r.get("DestPort"))
		parsers.SetTransport(e, r.get("Protocol"))
		switch r.get("Direction") {
		case "%%14592":
			e.Set("network.direction", "inbound")
		case "%%14593":
			e.Set("network.direction", "outbound")
		}
		setProcess(e, "process", r.get("Application"), r.get("ProcessID"))
		if typ == schema.TypeDenied {
			e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		}
	}
}

func objectAccess(typ, action string) securityHandler {
	return func(e *schema.Event, r *record) {
		objType := r.get("ObjectType")
		if strings.EqualFold(objType, "Key") {
			e.SetCategory(schema.CategoryRegistry)
			key := normalizeRegistryKey(r.get("ObjectName"))
			e.Set("registry.key", key)
			e.Set("registry.path", key)
			e.Set("registry.hive", registryHive(key))
		} else {
			e.SetCategory(schema.CategoryFile)
			parsers.SetFile(e, strings.TrimPrefix(r.get("ObjectName"), `\??\`))
		}
		t := typ
		if t == "" {
			t = schema.TypeAccess
			if mask, ok := parsers.ParseInt(r.get("AccessMask")); ok {
				switch {
				case mask&0x10000 != 0:
					t = schema.TypeDeletion
				case mask&0x2 != 0 || mask&0x4 != 0:
					t = schema.TypeChange
				}
			}
		}
		e.SetTypes(t)
		e.Set(schema.FieldEventAction, action)
		setProcess(e, "process", r.get("ProcessName"), r.get("ProcessId"))
		setSubject(e, r)
	}
}

func eventLogService(action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeInfo)
		e.Set(schema.FieldEventAction, action)
	}
}

func privilegedService(action string) securityHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeAdmin)
		e.Set(schema.FieldEventAction, action)
		setSubject(e, r)
		setProcess(e, "process", r.get("ProcessName"), r.get("ProcessId"))
	}
}

// normalizeRegistryKey converts kernel object paths to the HK* form used by
// Sysmon and Sigma rules.
func normalizeRegistryKey(k string) string {
	k = strings.TrimSpace(k)
	up := strings.ToUpper(k)
	switch {
	case strings.HasPrefix(up, `\REGISTRY\MACHINE`):
		return "HKLM" + k[len(`\REGISTRY\MACHINE`):]
	case strings.HasPrefix(up, `\REGISTRY\USER`):
		return "HKU" + k[len(`\REGISTRY\USER`):]
	}
	return k
}

func registryHive(key string) string {
	if key == "" {
		return ""
	}
	first := key
	if i := strings.IndexByte(key, '\\'); i > 0 {
		first = key[:i]
	}
	switch strings.ToUpper(first) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return "HKLM"
	case "HKU", "HKEY_USERS":
		return "HKU"
	case "HKCU", "HKEY_CURRENT_USER":
		return "HKCU"
	case "HKCR", "HKEY_CLASSES_ROOT":
		return "HKCR"
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return "HKCC"
	}
	return ""
}
