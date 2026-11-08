package windows

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

var errNoEventID = errors.New("windows: json record has no event id")

// nxlogSystemKeys are the NXLog top-level keys that describe the record
// rather than carrying event data.
var nxlogSystemKeys = map[string]bool{
	"EventTime": true, "EventTimeWritten": true, "Hostname": true, "Keywords": true,
	"EventType": true, "SeverityValue": true, "Severity": true, "EventID": true,
	"SourceName": true, "ProviderGuid": true, "Version": true, "Task": true,
	"OpcodeValue": true, "Opcode": true, "RecordNumber": true, "ProcessID": true,
	"ThreadID": true, "Channel": true, "Domain": true, "AccountName": true,
	"UserID": true, "AccountType": true, "Message": true, "Category": true,
	"EventReceivedTime": true, "SourceModuleName": true, "SourceModuleType": true,
	"ActivityID": true, "RelatedActivityID": true, "ExecutionProcessID": true,
	"ExecutionThreadID": true, "EventXML": true,
}

func parseJSON(b []byte) (*record, error) {
	obj, err := parsers.DecodeJSON(b)
	if err != nil {
		return nil, err
	}
	if wl := parsers.GetMap(obj, "winlog"); wl != nil {
		return fromWinlogbeat(obj, wl)
	}
	if _, ok := obj["EventID"]; ok {
		return fromNXLog(obj)
	}
	return nil, errNoEventID
}

func fromWinlogbeat(obj, wl map[string]any) (*record, error) {
	r := &record{Data: make(map[string]string)}
	r.Channel = parsers.GetString(wl, "channel")
	r.Provider = parsers.GetString(wl, "provider_name")
	r.ProviderGUID = parsers.GetString(wl, "provider_guid")
	r.RecordID = parsers.GetString(wl, "record_id")
	r.Computer = parsers.GetString(wl, "computer_name")
	r.Task = parsers.GetString(wl, "task")
	r.Opcode = parsers.GetString(wl, "opcode")
	r.Version = parsers.GetString(wl, "version")
	r.Level = parsers.GetString(wl, "level")
	r.ActivityID = parsers.GetString(wl, "activity_id")
	r.ProcessID = parsers.GetString(wl, "process.pid")
	r.ThreadID = parsers.GetString(wl, "process.thread.id")
	r.UserID = parsers.GetString(wl, "user.identifier")
	r.Keywords = parsers.GetStrings(wl, "keywords")
	id := parsers.GetString(wl, "event_id")
	if id == "" {
		id = parsers.GetString(obj, "event.code")
	}
	n, ok := parsers.ParseInt(id)
	if !ok {
		return nil, errNoEventID
	}
	r.EventID = n
	r.TimeCreated = parsers.GetString(obj, "@timestamp")
	if r.TimeCreated == "" {
		r.TimeCreated = parsers.GetString(obj, "event.created")
	}
	r.Message = parsers.GetString(obj, "message")
	if r.Computer == "" {
		r.Computer = parsers.GetString(obj, "host.name")
	}
	// Level in Winlogbeat JSON is already a name ("information").
	if r.Level != "" {
		if _, numeric := levelNames[r.Level]; !numeric {
			r.LevelName = r.Level
			r.Level = ""
		}
	}
	if ed := parsers.GetMap(wl, "event_data"); ed != nil {
		keys := make([]string, 0, len(ed))
		for k := range ed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			r.DataOrder = append(r.DataOrder, k)
			r.Data[k] = stringify(ed[k])
		}
	}
	if ud := parsers.GetMap(wl, "user_data"); ud != nil {
		flat := make(map[string]any)
		schema.Flatten("", ud, flat)
		r.UserData = make(map[string]string, len(flat))
		for k, v := range flat {
			r.UserData[k] = stringify(v)
		}
	}
	return r, nil
}

func fromNXLog(obj map[string]any) (*record, error) {
	r := &record{Data: make(map[string]string)}
	n, ok := parsers.GetInt(obj, "EventID")
	if !ok {
		return nil, errNoEventID
	}
	r.EventID = n
	r.Channel = parsers.GetString(obj, "Channel")
	r.Provider = parsers.GetString(obj, "SourceName")
	r.ProviderGUID = parsers.GetString(obj, "ProviderGuid")
	r.Computer = parsers.GetString(obj, "Hostname")
	r.RecordID = parsers.GetString(obj, "RecordNumber")
	r.Version = parsers.GetString(obj, "Version")
	r.Task = parsers.GetString(obj, "Task")
	r.Opcode = parsers.GetString(obj, "OpcodeValue")
	r.OpcodeName = parsers.GetString(obj, "Opcode")
	r.ActivityID = parsers.GetString(obj, "ActivityID")
	r.ProcessID = parsers.GetString(obj, "ExecutionProcessID")
	if r.ProcessID == "" {
		r.ProcessID = parsers.GetString(obj, "ProcessID")
	}
	r.ThreadID = parsers.GetString(obj, "ExecutionThreadID")
	if r.ThreadID == "" {
		r.ThreadID = parsers.GetString(obj, "ThreadID")
	}
	r.UserID = parsers.GetString(obj, "UserID")
	r.Message = parsers.GetString(obj, "Message")
	r.TimeCreated = parsers.GetString(obj, "EventTime")
	if sev := strings.ToLower(parsers.GetString(obj, "Severity")); sev != "" {
		switch sev {
		case "info":
			r.LevelName = "information"
		default:
			r.LevelName = sev
		}
	}
	switch parsers.GetString(obj, "EventType") {
	case "AUDIT_SUCCESS":
		r.Keywords = []string{"Audit Success"}
	case "AUDIT_FAILURE":
		r.Keywords = []string{"Audit Failure"}
	default:
		if kw := parsers.GetString(obj, "Keywords"); kw != "" {
			if kn, err := strconv.ParseUint(kw, 10, 64); err == nil {
				r.Keywords = keywordNames("0x" + strconv.FormatUint(kn, 16))
			}
		}
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		if nxlogSystemKeys[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r.DataOrder = append(r.DataOrder, k)
		r.Data[k] = stringify(obj[k])
	}
	return r, nil
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, x := range t {
			parts = append(parts, stringify(x))
		}
		return strings.Join(parts, ", ")
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}
