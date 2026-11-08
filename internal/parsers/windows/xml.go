package windows

import (
	"bytes"
	"encoding/xml"
	"errors"
	"strconv"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
)

// MaxXMLBytes caps a single rendered event (THREAT_MODEL T2.2).
const MaxXMLBytes = 1 << 20

var (
	errDTD      = errors.New("windows: DTD/entity declarations are not allowed")
	errTooLarge = errors.New("windows: event exceeds size limit")
	errNoSystem = errors.New("windows: event has no System section")
)

type xmlEvent struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		Provider struct {
			Name            string `xml:"Name,attr"`
			Guid            string `xml:"Guid,attr"`
			EventSourceName string `xml:"EventSourceName,attr"`
		} `xml:"Provider"`
		EventID struct {
			Value      string `xml:",chardata"`
			Qualifiers string `xml:"Qualifiers,attr"`
		} `xml:"EventID"`
		Version     string `xml:"Version"`
		Level       string `xml:"Level"`
		Task        string `xml:"Task"`
		Opcode      string `xml:"Opcode"`
		Keywords    string `xml:"Keywords"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID string `xml:"EventRecordID"`
		Correlation   struct {
			ActivityID string `xml:"ActivityID,attr"`
		} `xml:"Correlation"`
		Execution struct {
			ProcessID string `xml:"ProcessID,attr"`
			ThreadID  string `xml:"ThreadID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data   []xmlData `xml:"Data"`
		Binary string    `xml:"Binary"`
	} `xml:"EventData"`
	UserData      xmlNode `xml:"UserData"`
	RenderingInfo struct {
		Message  string `xml:"Message"`
		Level    string `xml:"Level"`
		Task     string `xml:"Task"`
		Opcode   string `xml:"Opcode"`
		Channel  string `xml:"Channel"`
		Provider string `xml:"Provider"`
		Keywords struct {
			Keyword []string `xml:"Keyword"`
		} `xml:"Keywords"`
	} `xml:"RenderingInfo"`
}

type xmlData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// xmlNode captures an arbitrary element tree (used for UserData).
type xmlNode struct {
	XMLName xml.Name
	Content string    `xml:",chardata"`
	Nodes   []xmlNode `xml:",any"`
}

func parseXML(b []byte) (*record, error) {
	if len(b) > MaxXMLBytes {
		return nil, errTooLarge
	}
	if bytes.Contains(b, []byte("<!DOCTYPE")) || bytes.Contains(b, []byte("<!ENTITY")) {
		return nil, errDTD
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	dec.Entity = map[string]string{}
	var ev xmlEvent
	if err := dec.Decode(&ev); err != nil {
		return nil, err
	}
	if ev.System.Channel == "" && ev.System.Provider.Name == "" && ev.System.EventID.Value == "" {
		return nil, errNoSystem
	}
	r := &record{
		Provider:     ev.System.Provider.Name,
		ProviderGUID: ev.System.Provider.Guid,
		Qualifiers:   ev.System.EventID.Qualifiers,
		Version:      ev.System.Version,
		Level:        ev.System.Level,
		Task:         ev.System.Task,
		Opcode:       ev.System.Opcode,
		TimeCreated:  ev.System.TimeCreated.SystemTime,
		RecordID:     strings.TrimSpace(ev.System.EventRecordID),
		ActivityID:   ev.System.Correlation.ActivityID,
		ProcessID:    ev.System.Execution.ProcessID,
		ThreadID:     ev.System.Execution.ThreadID,
		Channel:      strings.TrimSpace(ev.System.Channel),
		Computer:     strings.TrimSpace(ev.System.Computer),
		UserID:       ev.System.Security.UserID,
		Message:      strings.TrimSpace(ev.RenderingInfo.Message),
		LevelName:    strings.TrimSpace(ev.RenderingInfo.Level),
		TaskName:     strings.TrimSpace(ev.RenderingInfo.Task),
		OpcodeName:   strings.TrimSpace(ev.RenderingInfo.Opcode),
		Data:         make(map[string]string, len(ev.EventData.Data)),
	}
	if r.Provider == "" {
		r.Provider = ev.System.Provider.EventSourceName
	}
	if id, ok := parsers.ParseInt(strings.TrimSpace(ev.System.EventID.Value)); ok {
		r.EventID = id
	} else {
		return nil, errors.New("windows: missing or invalid EventID")
	}
	if len(ev.RenderingInfo.Keywords.Keyword) > 0 {
		for _, k := range ev.RenderingInfo.Keywords.Keyword {
			if k = strings.TrimSpace(k); k != "" {
				r.Keywords = append(r.Keywords, k)
			}
		}
	} else if kw := strings.TrimSpace(ev.System.Keywords); kw != "" {
		r.Keywords = keywordNames(kw)
		if len(r.Keywords) == 0 {
			r.Keywords = []string{kw}
		}
	}
	unnamed := 0
	for _, d := range ev.EventData.Data {
		name := strings.TrimSpace(d.Name)
		if name == "" {
			unnamed++
			name = "param" + strconv.Itoa(unnamed)
		}
		if _, dup := r.Data[name]; !dup {
			r.DataOrder = append(r.DataOrder, name)
		}
		r.Data[name] = strings.TrimSpace(d.Value)
	}
	if ev.EventData.Binary != "" {
		r.DataOrder = append(r.DataOrder, "Binary")
		r.Data["Binary"] = strings.TrimSpace(ev.EventData.Binary)
	}
	if len(ev.UserData.Nodes) > 0 {
		r.UserData = make(map[string]string)
		// UserData wraps a single provider-specific element; flatten its children.
		for _, wrapper := range ev.UserData.Nodes {
			if len(wrapper.Nodes) == 0 {
				if v := strings.TrimSpace(wrapper.Content); v != "" {
					r.UserData[wrapper.XMLName.Local] = v
				}
				continue
			}
			flattenNodes("", wrapper.Nodes, r.UserData)
		}
	}
	return r, nil
}

func flattenNodes(prefix string, nodes []xmlNode, out map[string]string) {
	for _, n := range nodes {
		key := n.XMLName.Local
		if prefix != "" {
			key = prefix + "." + key
		}
		if len(n.Nodes) == 0 {
			out[key] = strings.TrimSpace(n.Content)
			continue
		}
		flattenNodes(key, n.Nodes, out)
	}
}
