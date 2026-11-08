package windows

import (
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// applyOtherChannel maps the non-Security, non-Sysmon channels.
func applyOtherChannel(e *schema.Event, r *record, dataset string) {
	switch dataset {
	case "windows.system":
		applySystem(e, r)
	case "windows.powershell", "windows.powershell_operational":
		applyPowerShell(e, r)
	case "windows.taskscheduler":
		applyTaskScheduler(e, r)
	case "windows.defender":
		applyDefender(e, r)
	case "windows.wmi_activity":
		applyWMI(e, r)
	case "windows.terminalservices":
		applyTerminalServices(e, r)
	case "windows.ntlm":
		applyNTLM(e, r)
	case "windows.bits_client":
		applyBits(e, r)
	case "windows.firewall":
		applyFirewall(e, r)
	case "windows.dns_server":
		applyDNSServer(e, r)
	case "windows.ldap_debug":
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeInfo)
		e.Set(schema.FieldEventAction, "ldap-client-debug")
	case "windows.other":
		applyDirectoryService(e, r)
	}
}

func applySystem(e *schema.Event, r *record) {
	switch r.EventID {
	case 7045:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeCreation)
		e.Set(schema.FieldEventAction, "service-installed")
		e.Set("service.name", r.get("ServiceName"))
		setServiceExecutable(e, r.get("ImagePath"))
		if acct := r.get("AccountName"); acct != "" {
			parsers.SetUser(e, "user", acct)
		}
	case 7036:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "service-state-changed")
		e.Set("service.name", r.get("param1"))
		e.Set("service.state", r.get("param2"))
	case 7040:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "service-start-type-changed")
		e.Set("service.name", r.get("param1"))
	case 7034:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "service-crashed")
		e.Set("service.name", r.get("param1"))
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	case 7035:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "service-control-sent")
		e.Set("service.name", r.get("param1"))
	case 104:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "event-log-cleared")
		e.Set("user.name", r.UserData["SubjectUserName"])
		e.Set("user.domain", r.UserData["SubjectDomainName"])
		e.Set("winlog.user_data.Channel", r.UserData["Channel"])
		e.AddTag("log_cleared")
	case 1074:
		e.SetCategory(schema.CategoryHost)
		e.SetTypes(schema.TypeEnd)
		e.Set(schema.FieldEventAction, "system-shutdown-initiated")
		if u := r.get("param7"); u != "" {
			parsers.SetUser(e, "user", u)
		}
		e.Set("process.executable", trimQuotes(r.get("param1")))
	case 6005:
		e.SetCategory(schema.CategoryHost)
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventAction, "event-log-service-started")
	case 6006:
		e.SetCategory(schema.CategoryHost)
		e.SetTypes(schema.TypeEnd)
		e.Set(schema.FieldEventAction, "event-log-service-stopped")
	case 6008:
		e.SetCategory(schema.CategoryHost)
		e.SetTypes(schema.TypeError)
		e.Set(schema.FieldEventAction, "unexpected-shutdown")
	case 1:
		if r.Provider == "Microsoft-Windows-Kernel-General" {
			e.SetCategory(schema.CategoryConfiguration)
			e.SetTypes(schema.TypeChange)
			e.Set(schema.FieldEventAction, "system-time-changed")
		}
	case 12, 13:
		if r.Provider == "Microsoft-Windows-Kernel-General" {
			e.SetCategory(schema.CategoryHost)
			if r.EventID == 12 {
				e.SetTypes(schema.TypeStart)
				e.Set(schema.FieldEventAction, "system-started")
			} else {
				e.SetTypes(schema.TypeEnd)
				e.Set(schema.FieldEventAction, "system-shutdown")
			}
		}
	}
}

func applyPowerShell(e *schema.Event, r *record) {
	e.SetCategory(schema.CategoryProcess)
	e.SetTypes(schema.TypeInfo)
	switch r.EventID {
	case 4104:
		e.Set(schema.FieldEventAction, "powershell-script-block-logged")
		e.Set("powershell.file.script_block_text", r.get("ScriptBlockText"))
		e.Set("powershell.file.script_block_id", r.get("ScriptBlockId"))
		parsers.SetInt(e, "powershell.sequence", r.get("MessageNumber"))
		parsers.SetInt(e, "powershell.total", r.get("MessageTotal"))
		if p := r.get("Path"); p != "" {
			parsers.SetFile(e, p)
		}
	case 4103:
		e.Set(schema.FieldEventAction, "powershell-module-logging")
		e.Set("powershell.command.value", r.get("Payload"))
		parseContextInfo(e, r.get("ContextInfo"))
	case 4100:
		e.Set(schema.FieldEventAction, "powershell-error")
		e.SetTypes(schema.TypeError)
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		parseContextInfo(e, r.get("ContextInfo"))
	case 400, 403:
		if r.EventID == 400 {
			e.Set(schema.FieldEventAction, "powershell-engine-started")
			e.SetTypes(schema.TypeStart)
		} else {
			e.Set(schema.FieldEventAction, "powershell-engine-stopped")
			e.SetTypes(schema.TypeEnd)
		}
		parseEngineLifecycle(e, r.get("param3"))
	case 600:
		e.Set(schema.FieldEventAction, "powershell-provider-started")
		parseEngineLifecycle(e, r.get("param3"))
	case 800:
		e.Set(schema.FieldEventAction, "powershell-pipeline-execution")
		parseEngineLifecycle(e, r.get("param2"))
		e.Set("powershell.command.value", r.get("param2"))
	case 53504:
		e.Set(schema.FieldEventAction, "powershell-named-pipe-listener")
	default:
		e.Set(schema.FieldEventAction, "powershell-event")
	}
	if u := r.get("UserId"); u != "" {
		parsers.SetUser(e, "user", u)
	} else if u := r.get("User"); u != "" {
		parsers.SetUser(e, "user", u)
	}
}

// parseContextInfo extracts the key/value lines of ContextInfo
// ("        Host Application = powershell.exe -nop\n        Command Name = Invoke-Expression\n        User = CORP\alice").
func parseContextInfo(e *schema.Event, ctx string) {
	if ctx == "" {
		return
	}
	for _, line := range strings.Split(ctx, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch k {
		case "Host Application":
			e.Set("powershell.process.executable", v)
		case "Command Name":
			e.Set("powershell.command.name", v)
		case "Command Type":
			e.Set("powershell.command.type", v)
		case "Script Name":
			parsers.SetFile(e, v)
		case "Command Path":
			e.Set("powershell.command.path", v)
		case "Sequence Number":
			parsers.SetInt(e, "powershell.sequence", v)
		case "User":
			parsers.SetUser(e, "user", v)
		case "Connected User":
			parsers.SetUser(e, "user.effective", v)
		case "Engine Version":
			e.Set("powershell.engine.version", v)
		case "Runspace ID":
			e.Set("powershell.runspace_id", v)
		case "Pipeline ID":
			parsers.SetInt(e, "powershell.pipeline_id", v)
		case "Host Name":
			e.Set("powershell.process.host.name", v)
		case "Host Version":
			e.Set("powershell.process.host.version", v)
		case "Host ID":
			e.Set("powershell.process.host.id", v)
		case "Shell ID":
			e.Set("powershell.shell_id", v)
		}
	}
}

// parseEngineLifecycle handles the classic "NewEngineState=Available\n\tPreviousEngineState=None\n\tHostApplication=..." block.
func parseEngineLifecycle(e *schema.Event, block string) {
	if block == "" {
		return
	}
	for _, line := range strings.Split(block, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch strings.TrimSpace(k) {
		case "HostApplication":
			e.Set("powershell.process.executable", v)
		case "NewEngineState":
			e.Set("powershell.engine.new_state", v)
		case "PreviousEngineState":
			e.Set("powershell.engine.previous_state", v)
		case "EngineVersion":
			e.Set("powershell.engine.version", v)
		case "RunspaceId":
			e.Set("powershell.runspace_id", v)
		case "HostName":
			e.Set("powershell.process.host.name", v)
		case "HostVersion":
			e.Set("powershell.process.host.version", v)
		case "CommandLine":
			e.Set("powershell.command.value", v)
		case "ScriptName":
			parsers.SetFile(e, v)
		case "UserId":
			parsers.SetUser(e, "user", v)
		}
	}
}

func applyTaskScheduler(e *schema.Event, r *record) {
	e.SetCategory(schema.CategoryConfiguration)
	switch r.EventID {
	case 106:
		e.SetTypes(schema.TypeCreation)
		e.Set(schema.FieldEventAction, "scheduled-task-registered")
	case 140:
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "scheduled-task-updated")
	case 141:
		e.SetTypes(schema.TypeDeletion)
		e.Set(schema.FieldEventAction, "scheduled-task-deleted")
	case 200:
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventAction, "scheduled-task-action-started")
	case 201:
		e.SetTypes(schema.TypeEnd)
		e.Set(schema.FieldEventAction, "scheduled-task-action-completed")
	case 100, 102, 107, 108, 110, 118, 119, 129:
		e.SetTypes(schema.TypeInfo)
		e.Set(schema.FieldEventAction, "scheduled-task-event")
	default:
		e.SetTypes(schema.TypeInfo)
	}
	if u := r.get("UserContext"); u != "" {
		parsers.SetUser(e, "user", u)
	} else if u := r.get("UserName"); u != "" {
		parsers.SetUser(e, "user", u)
	}
	if a := r.get("ActionName"); a != "" {
		parsers.SetProcessExecutable(e, "process", trimQuotes(a))
	}
	if p := r.get("Path"); p != "" {
		parsers.SetProcessExecutable(e, "process", trimQuotes(p))
	}
	parsers.SetInt(e, "process.pid", r.get("ProcessID"))
}

func applyDefender(e *schema.Event, r *record) {
	switch r.EventID {
	case 1116, 1117, 1118, 1119, 1006, 1007, 1008, 1015:
		e.SetCategory(schema.CategoryMalware)
		e.SetTypes(schema.TypeInfo)
		switch r.EventID {
		case 1116, 1006:
			e.Set(schema.FieldEventAction, "malware-detected")
		case 1117, 1007:
			e.Set(schema.FieldEventAction, "malware-action-taken")
		case 1118, 1008:
			e.Set(schema.FieldEventAction, "malware-action-failed")
			e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		case 1119:
			e.Set(schema.FieldEventAction, "malware-action-critically-failed")
			e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		case 1015:
			e.Set(schema.FieldEventAction, "suspicious-behavior-detected")
		}
		e.Set("rule.name", r.get("Threat Name"))
		e.Set("rule.id", r.get("Threat ID"))
		if p := r.get("Path"); p != "" {
			parsers.SetFile(e, strings.TrimPrefix(strings.TrimPrefix(p, "file:_"), "file:"))
		}
		if sev, ok := parsers.ParseInt(r.get("Severity ID")); ok {
			e.Set(schema.FieldEventSeverity, defenderSeverity(sev))
		}
		if u := r.get("Detection User"); u != "" {
			parsers.SetUser(e, "user", u)
		}
		if pn := r.get("Process Name"); pn != "" && pn != "Unknown" {
			parsers.SetProcessExecutable(e, "process", pn)
		}
	case 5001:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "real-time-protection-disabled")
	case 5004:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "real-time-protection-configuration-changed")
	case 5007:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "configuration-changed")
	case 5010, 5012:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "scanning-disabled")
	case 2000, 2001, 2002:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "definitions-updated")
	default:
		e.SetCategory(schema.CategoryHost)
		e.SetTypes(schema.TypeInfo)
	}
}

func defenderSeverity(id int64) int64 {
	switch id {
	case 1:
		return 10
	case 2:
		return 25
	case 3:
		return 50
	case 4:
		return 75
	case 5:
		return 100
	}
	return 0
}

func applyWMI(e *schema.Event, r *record) {
	e.SetCategory(schema.CategoryProcess)
	e.SetTypes(schema.TypeInfo)
	switch r.EventID {
	case 5857:
		e.Set(schema.FieldEventAction, "wmi-provider-started")
	case 5858:
		e.Set(schema.FieldEventAction, "wmi-operation-failed")
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	case 5859:
		e.Set(schema.FieldEventAction, "wmi-permanent-event-subscription-activated")
	case 5860:
		e.Set(schema.FieldEventAction, "wmi-temporary-event-subscription")
	case 5861:
		e.Set(schema.FieldEventAction, "wmi-permanent-consumer-registered")
		e.SetTypes(schema.TypeCreation)
	default:
		e.Set(schema.FieldEventAction, "wmi-activity")
	}
	if u := r.UserData["User"]; u != "" {
		parsers.SetUser(e, "user", u)
	}
	parsers.SetInt(e, "process.pid", r.UserData["ClientProcessId"])
	if m := r.UserData["ClientMachine"]; m != "" {
		e.Set("source.domain", m)
	}
}

func applyTerminalServices(e *schema.Event, r *record) {
	switch r.EventID {
	case 1149:
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventAction, "rdp-connection-authenticated")
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
		e.Set("user.name", r.UserData["Param1"])
		e.Set("user.domain", r.UserData["Param2"])
		setSourceIP(e, "source.ip", r.UserData["Param3"])
		if r.UserData["Param1"] == "" {
			e.Set("user.name", r.get("Param1"))
			e.Set("user.domain", r.get("Param2"))
			setSourceIP(e, "source.ip", r.get("Param3"))
		}
	case 21, 22, 25:
		e.SetCategory(schema.CategorySession)
		e.SetTypes(schema.TypeStart)
		switch r.EventID {
		case 21:
			e.Set(schema.FieldEventAction, "rdp-session-logon")
		case 22:
			e.Set(schema.FieldEventAction, "rdp-shell-start")
		case 25:
			e.Set(schema.FieldEventAction, "rdp-session-reconnected")
		}
		tsSession(e, r)
	case 23, 24, 39, 40:
		e.SetCategory(schema.CategorySession)
		e.SetTypes(schema.TypeEnd)
		switch r.EventID {
		case 23:
			e.Set(schema.FieldEventAction, "rdp-session-logoff")
		case 24:
			e.Set(schema.FieldEventAction, "rdp-session-disconnected")
		case 39:
			e.Set(schema.FieldEventAction, "rdp-session-disconnected-by-other-session")
		case 40:
			e.Set(schema.FieldEventAction, "rdp-session-disconnected-reason")
		}
		tsSession(e, r)
	case 131:
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeConnection, schema.TypeStart)
		e.Set(schema.FieldEventAction, "rdp-connection-accepted")
		if v := r.UserData["ClientIP"]; v != "" {
			host, _, _ := strings.Cut(v, ":")
			setSourceIP(e, "source.ip", host)
		}
	case 140:
		e.SetCategory(schema.CategoryAuthentication)
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventAction, "rdp-connection-failed")
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		setSourceIP(e, "source.ip", r.UserData["IPString"])
	default:
		e.SetCategory(schema.CategorySession)
		e.SetTypes(schema.TypeInfo)
	}
}

func tsSession(e *schema.Event, r *record) {
	if u := r.UserData["User"]; u != "" {
		parsers.SetUser(e, "user", u)
	}
	setSourceIP(e, "source.ip", r.UserData["Address"])
	e.Set("winlog.user_data.SessionID", r.UserData["SessionID"])
}

func applyNTLM(e *schema.Event, r *record) {
	e.SetCategory(schema.CategoryAuthentication)
	e.SetTypes(schema.TypeInfo)
	switch r.EventID {
	case 8001:
		e.Set(schema.FieldEventAction, "ntlm-client-authentication")
	case 8002:
		e.Set(schema.FieldEventAction, "ntlm-server-authentication")
	case 8003:
		e.Set(schema.FieldEventAction, "ntlm-domain-authentication")
	case 8004:
		e.Set(schema.FieldEventAction, "ntlm-audit-blocked")
	default:
		e.Set(schema.FieldEventAction, "ntlm-event")
	}
	e.Set("user.name", r.get("UserName"))
	e.Set("user.domain", r.get("DomainName"))
	if w := r.get("WorkstationName"); w != "" {
		e.Set("source.domain", strings.TrimPrefix(w, `\\`))
	}
	if t := r.get("TargetName"); t != "" {
		e.Set("destination.domain", t)
	}
	if s := r.get("SChannelName"); s != "" {
		e.Set("destination.domain", s)
	}
	setProcess(e, "process", r.get("ProcessName"), r.get("ProcessId"))
}

func applyBits(e *schema.Event, r *record) {
	e.SetCategory(schema.CategoryProcess)
	e.SetTypes(schema.TypeInfo)
	switch r.EventID {
	case 59:
		e.Set(schema.FieldEventAction, "bits-job-started")
		e.SetTypes(schema.TypeStart)
	case 60:
		e.Set(schema.FieldEventAction, "bits-job-stopped")
		e.SetTypes(schema.TypeEnd)
	case 61:
		e.Set(schema.FieldEventAction, "bits-job-error")
		e.SetTypes(schema.TypeError)
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	case 3:
		e.Set(schema.FieldEventAction, "bits-job-created")
		e.SetTypes(schema.TypeCreation)
	case 4:
		e.Set(schema.FieldEventAction, "bits-job-completed")
		e.SetTypes(schema.TypeEnd)
	case 16403:
		e.Set(schema.FieldEventAction, "bits-job-modified")
		e.SetTypes(schema.TypeChange)
	default:
		e.Set(schema.FieldEventAction, "bits-event")
	}
	if u := r.get("url"); u != "" {
		parsers.SetURL(e, u)
	} else if u := r.get("fileUrl"); u != "" {
		parsers.SetURL(e, u)
	}
	if p := r.get("processPath"); p != "" {
		parsers.SetProcessExecutable(e, "process", p)
	}
	parsers.SetInt(e, "process.pid", r.get("processId"))
	if u := r.get("User"); u != "" {
		parsers.SetUser(e, "user", u)
	}
	if n := r.get("name"); n != "" {
		e.Set("winlog.event_data.jobTitle", n)
	}
	if n := r.get("fileLocal"); n != "" {
		parsers.SetFile(e, n)
	}
}

func applyFirewall(e *schema.Event, r *record) {
	e.SetCategory(schema.CategoryConfiguration)
	switch r.EventID {
	case 2004:
		e.SetTypes(schema.TypeCreation)
		e.Set(schema.FieldEventAction, "firewall-rule-added")
	case 2005:
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "firewall-rule-modified")
	case 2006:
		e.SetTypes(schema.TypeDeletion)
		e.Set(schema.FieldEventAction, "firewall-rule-deleted")
	case 2033:
		e.SetTypes(schema.TypeDeletion)
		e.Set(schema.FieldEventAction, "firewall-rules-deleted-all")
	case 2003, 2008, 2009, 2010, 2011:
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "firewall-setting-changed")
	default:
		e.SetTypes(schema.TypeInfo)
		e.Set(schema.FieldEventAction, "firewall-event")
	}
	e.Set("rule.name", r.get("RuleName"))
	e.Set("rule.id", r.get("RuleId"))
	if ap := r.get("ApplicationPath"); ap != "" {
		parsers.SetProcessExecutable(e, "process", ap)
	}
	if ma := r.get("ModifyingApplication"); ma != "" {
		parsers.SetProcessExecutable(e, "process.parent", ma)
	}
	if u := r.get("ModifyingUser"); u != "" {
		e.Set("user.id", u)
	}
	switch r.get("Direction") {
	case "1":
		e.Set("network.direction", "inbound")
	case "2":
		e.Set("network.direction", "outbound")
	}
	if port := r.get("LocalPorts"); port != "" {
		parsers.SetPort(e, "destination.port", port)
	}
	parsers.SetTransport(e, r.get("Protocol"))
}

func applyDNSServer(e *schema.Event, r *record) {
	e.SetCategory(schema.CategoryNetwork)
	e.SetTypes(schema.TypeProtocol, schema.TypeInfo)
	e.Set("network.protocol", "dns")
	switch r.EventID {
	case 256:
		e.Set(schema.FieldEventAction, "dns-server-query-received")
	case 257:
		e.Set(schema.FieldEventAction, "dns-server-response-sent")
	case 258:
		e.Set(schema.FieldEventAction, "dns-server-recursive-query-timeout")
	case 259:
		e.Set(schema.FieldEventAction, "dns-server-recursive-query-out")
	case 260:
		e.Set(schema.FieldEventAction, "dns-server-recursive-response-in")
	case 261:
		e.Set(schema.FieldEventAction, "dns-server-response-failure")
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	case 262:
		e.Set(schema.FieldEventAction, "dns-server-ignored-query")
	case 263, 264, 265, 266:
		e.Set(schema.FieldEventAction, "dns-server-update")
	case 541:
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "dns-server-plugin-dll-loaded")
	default:
		e.Set(schema.FieldEventAction, "dns-server-event")
	}
	e.Set("dns.question.name", strings.TrimSuffix(r.get("QNAME"), "."))
	e.Set("dns.question.type", dnsTypeName(r.get("QTYPE")))
	if rc := r.get("RCODE"); rc != "" {
		e.Set("dns.response_code", rc)
	}
	parsers.SetIP(e, "source.ip", r.get("Source"))
	parsers.SetIP(e, "destination.ip", r.get("Destination"))
	parsers.SetPort(e, "source.port", r.get("Port"))
	if p := r.get("ServerDllPath"); p != "" {
		parsers.SetFile(e, p)
	}
}

func dnsTypeName(t string) string {
	switch t {
	case "1":
		return "A"
	case "2":
		return "NS"
	case "5":
		return "CNAME"
	case "6":
		return "SOA"
	case "12":
		return "PTR"
	case "15":
		return "MX"
	case "16":
		return "TXT"
	case "28":
		return "AAAA"
	case "33":
		return "SRV"
	case "255":
		return "ANY"
	}
	return t
}

func applyDirectoryService(e *schema.Event, r *record) {
	switch {
	case r.Provider == "Microsoft-Windows-ActiveDirectory_DomainService" && r.EventID == 2889:
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeInfo)
		e.Set(schema.FieldEventAction, "ldap-unsigned-bind")
		if v := r.get("param1"); v != "" {
			host, port, found := strings.Cut(v, ":")
			parsers.SetIP(e, "source.ip", host)
			if found {
				parsers.SetPort(e, "source.port", port)
			}
		}
		if u := r.get("param2"); u != "" {
			parsers.SetUser(e, "user", u)
		}
	case r.Provider == "Microsoft-Windows-ActiveDirectory_DomainService" && r.EventID == 1644:
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeInfo)
		e.Set(schema.FieldEventAction, "ldap-expensive-query")
		if v := r.get("param2"); v != "" {
			host, port, found := strings.Cut(v, ":")
			parsers.SetIP(e, "source.ip", host)
			if found {
				parsers.SetPort(e, "source.port", port)
			}
		}
	case r.Provider == "NTDS ISAM" || r.Provider == "ESENT":
		e.SetCategory(schema.CategoryDatabase)
		e.SetTypes(schema.TypeInfo)
		e.Set(schema.FieldEventAction, "ntds-database-event")
		if r.EventID == 325 || r.EventID == 327 || r.EventID == 216 {
			e.AddTag("ntds_copy")
		}
	}
}
