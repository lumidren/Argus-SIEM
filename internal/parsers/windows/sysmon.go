package windows

import (
	"regexp"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

var dnsStatusNames = map[string]string{
	"0": "NOERROR", "9001": "FORMERR", "9002": "SERVFAIL", "9003": "NXDOMAIN", "9004": "NOTIMP",
	"9005": "REFUSED", "9501": "NO_RECORDS", "9701": "RECORD_DOES_NOT_EXIST", "1460": "TIMEOUT",
	"87": "INVALID_PARAMETER", "123": "INVALID_NAME",
}

var dnsTypePrefix = regexp.MustCompile(`^type:\s*\d+\s*`)

type sysmonHandler func(e *schema.Event, r *record)

var sysmonHandlers = map[int64]sysmonHandler{
	1: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventAction, "Process Create")
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		e.Set("process.command_line", r.get("CommandLine"))
		e.Set("process.working_directory", r.get("CurrentDirectory"))
		sysmonProcess(e, r, "process.parent", "ParentImage", "ParentProcessId", "ParentProcessGuid")
		e.Set("process.parent.command_line", r.get("ParentCommandLine"))
		e.Set("process.pe.original_file_name", r.get("OriginalFileName"))
		e.Set("process.pe.company", r.get("Company"))
		e.Set("process.pe.description", r.get("Description"))
		e.Set("process.pe.product", r.get("Product"))
		e.Set("process.pe.file_version", r.get("FileVersion"))
		parsers.SetHashes(e, "process.hash", r.get("Hashes"))
		sysmonUser(e, r)
	},
	2: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryFile)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "File creation time changed")
		parsers.SetFile(e, r.get("TargetFilename"))
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	},
	3: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeConnection, schema.TypeStart)
		e.Set(schema.FieldEventAction, "Network connection detected")
		parsers.SetIP(e, "source.ip", r.get("SourceIp"))
		parsers.SetPort(e, "source.port", r.get("SourcePort"))
		e.Set("source.domain", r.get("SourceHostname"))
		parsers.SetIP(e, "destination.ip", r.get("DestinationIp"))
		parsers.SetPort(e, "destination.port", r.get("DestinationPort"))
		e.Set("destination.domain", r.get("DestinationHostname"))
		parsers.SetTransport(e, r.get("Protocol"))
		if v6, ok := boolOf(r.get("SourceIsIpv6")); ok {
			if v6 {
				e.Set("network.type", "ipv6")
			} else {
				e.Set("network.type", "ipv4")
			}
		}
		if init, ok := boolOf(r.get("Initiated")); ok {
			if init {
				e.Set("network.direction", "egress")
			} else {
				e.Set("network.direction", "ingress")
			}
		}
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	},
	4: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "Sysmon service state changed")
	},
	5: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeEnd)
		e.Set(schema.FieldEventAction, "Process terminated")
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	},
	6: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryDriver)
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventAction, "Driver loaded")
		parsers.SetFile(e, r.get("ImageLoaded"))
		parsers.SetHashes(e, "file.hash", r.get("Hashes"))
		sysmonSignature(e, r)
	},
	7: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "Image loaded")
		parsers.SetFile(e, r.get("ImageLoaded"))
		parsers.SetHashes(e, "file.hash", r.get("Hashes"))
		e.Set("file.pe.original_file_name", r.get("OriginalFileName"))
		e.Set("file.pe.company", r.get("Company"))
		e.Set("file.pe.description", r.get("Description"))
		e.Set("file.pe.product", r.get("Product"))
		e.Set("file.pe.file_version", r.get("FileVersion"))
		sysmonSignature(e, r)
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	},
	8: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "CreateRemoteThread detected")
		sysmonProcess(e, r, "process", "SourceImage", "SourceProcessId", "SourceProcessGuid")
		sysmonUser(e, r)
	},
	9: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryDriver)
		e.SetTypes(schema.TypeAccess)
		e.Set(schema.FieldEventAction, "RawAccessRead detected")
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	},
	10: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeAccess)
		e.Set(schema.FieldEventAction, "Process accessed")
		sysmonProcess(e, r, "process", "SourceImage", "SourceProcessId", "SourceProcessGUID")
		if !e.Has("process.entity_id") {
			e.Set("process.entity_id", r.get("SourceProcessGuid"))
		}
		parsers.SetInt(e, "process.thread.id", r.get("SourceThreadId"))
		if su := r.get("SourceUser"); su != "" {
			parsers.SetUser(e, "user", su)
		}
	},
	11: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryFile)
		e.SetTypes(schema.TypeCreation)
		e.Set(schema.FieldEventAction, "File created")
		parsers.SetFile(e, r.get("TargetFilename"))
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	},
	12: registry(schema.TypeCreation, "Registry object added or deleted"),
	13: registry(schema.TypeChange, "Registry value set"),
	14: registry(schema.TypeChange, "Registry object renamed"),
	15: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryFile)
		e.SetTypes(schema.TypeAccess)
		e.Set(schema.FieldEventAction, "File stream created")
		parsers.SetFile(e, r.get("TargetFilename"))
		parsers.SetHashes(e, "file.hash", r.get("Hash"))
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	},
	16: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryConfiguration)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "Sysmon config state changed")
	},
	17: pipe(schema.TypeCreation, "Pipe Created"),
	18: pipe(schema.TypeAccess, "Pipe Connected"),
	19: wmi("WmiEventFilter activity detected"),
	20: wmi("WmiEventConsumer activity detected"),
	21: wmi("WmiEventConsumerToFilter activity detected"),
	22: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeProtocol, schema.TypeInfo)
		e.Set(schema.FieldEventAction, "Dns query")
		e.Set("network.protocol", "dns")
		e.Set("dns.question.name", r.get("QueryName"))
		if qs := r.get("QueryStatus"); qs != "" {
			if name, ok := dnsStatusNames[qs]; ok {
				e.Set("dns.response_code", name)
			} else {
				e.Set("dns.response_code", qs)
			}
		}
		var answers []string
		var resolved []string
		for _, part := range strings.Split(r.get("QueryResults"), ";") {
			part = strings.TrimSpace(dnsTypePrefix.ReplaceAllString(strings.TrimSpace(part), ""))
			if part == "" {
				continue
			}
			if ip := parsers.NormalizeIP(part); ip != "" {
				part = ip
				resolved = append(resolved, ip)
			}
			answers = append(answers, part)
		}
		if len(answers) > 0 {
			e.Set("dns.answers.data", answers)
		}
		if len(resolved) > 0 {
			e.Set("dns.resolved_ip", resolved)
		}
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	},
	23: fileDelete("File Delete archived"),
	24: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "Clipboard changed")
		parsers.SetHashes(e, "file.hash", r.get("Hashes"))
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	},
	25: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeChange)
		e.Set(schema.FieldEventAction, "Process Tampering")
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	},
	26: fileDelete("File Delete logged"),
	27: fileBlock(schema.TypeDeletion, "File Block Executable"),
	28: fileBlock(schema.TypeDeletion, "File Block Shredding"),
	29: fileBlock(schema.TypeCreation, "File Executable Detected"),
	255: func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeError)
		e.Set(schema.FieldEventAction, "Error report")
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
	},
}

func applySysmon(e *schema.Event, r *record) {
	if h, ok := sysmonHandlers[r.EventID]; ok {
		h(e, r)
	}
	if rn := r.get("RuleName"); rn != "" && rn != "-" {
		e.Set("rule.name", rn)
	}
}

func sysmonProcess(e *schema.Event, r *record, prefix, imageKey, pidKey, guidKey string) {
	setProcess(e, prefix, r.get(imageKey), r.get(pidKey))
	if g := r.get(guidKey); g != "" {
		e.Set(prefix+".entity_id", g)
	}
}

func sysmonUser(e *schema.Event, r *record) {
	if u := r.get("User"); u != "" {
		parsers.SetUser(e, "user", u)
	}
}

func sysmonSignature(e *schema.Event, r *record) {
	e.Set("file.code_signature.subject_name", r.get("Signature"))
	e.Set("file.code_signature.status", r.get("SignatureStatus"))
	if signed, ok := boolOf(r.get("Signed")); ok {
		e.Set("file.code_signature.signed", signed)
	}
}

func boolOf(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	}
	return false, false
}

func registry(defaultType, action string) sysmonHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryRegistry)
		typ := defaultType
		switch r.get("EventType") {
		case "CreateKey", "CreateValue":
			typ = schema.TypeCreation
		case "DeleteKey", "DeleteValue":
			typ = schema.TypeDeletion
		case "SetValue", "RenameKey":
			typ = schema.TypeChange
		}
		e.SetTypes(typ)
		e.Set(schema.FieldEventAction, action)
		target := r.get("TargetObject")
		e.Set("registry.path", target)
		e.Set("registry.hive", registryHive(target))
		if r.EventID == 13 || r.get("EventType") == "SetValue" || r.get("EventType") == "DeleteValue" {
			e.Set("registry.key", parsers.DirName(target))
			e.Set("registry.value", parsers.BaseName(target))
		} else {
			e.Set("registry.key", target)
		}
		if d := r.get("Details"); d != "" {
			e.Set("registry.data.strings", []string{d})
			switch {
			case strings.HasPrefix(d, "DWORD"):
				e.Set("registry.data.type", "REG_DWORD")
			case strings.HasPrefix(d, "QWORD"):
				e.Set("registry.data.type", "REG_QWORD")
			case strings.HasPrefix(d, "Binary Data"):
				e.Set("registry.data.type", "REG_BINARY")
			default:
				e.Set("registry.data.type", "REG_SZ")
			}
		}
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	}
}

func pipe(typ, action string) sysmonHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryFile)
		e.SetTypes(typ)
		e.Set(schema.FieldEventAction, action)
		e.Set("file.name", r.get("PipeName"))
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	}
}

func wmi(action string) sysmonHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeCreation)
		if r.get("Operation") == "Deleted" {
			e.SetTypes(schema.TypeDeletion)
		}
		e.Set(schema.FieldEventAction, action)
		sysmonUser(e, r)
	}
}

func fileDelete(action string) sysmonHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryFile)
		e.SetTypes(schema.TypeDeletion)
		e.Set(schema.FieldEventAction, action)
		parsers.SetFile(e, r.get("TargetFilename"))
		parsers.SetHashes(e, "file.hash", r.get("Hashes"))
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	}
}

func fileBlock(typ, action string) sysmonHandler {
	return func(e *schema.Event, r *record) {
		e.SetCategory(schema.CategoryFile)
		e.SetTypes(typ)
		e.Set(schema.FieldEventAction, action)
		parsers.SetFile(e, r.get("TargetFilename"))
		parsers.SetHashes(e, "file.hash", r.get("Hashes"))
		sysmonProcess(e, r, "process", "Image", "ProcessId", "ProcessGuid")
		sysmonUser(e, r)
	}
}
