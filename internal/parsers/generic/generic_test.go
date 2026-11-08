package generic

import (
	"strings"
	"testing"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/parsers/parsertest"
	"github.com/lumidren/argus/internal/schema"
)

func TestDetect(t *testing.T) {
	p := New()
	if !p.Detect([]byte("anything"), nil) {
		t.Fatal("non-empty must be detected")
	}
	if p.Detect([]byte("  \n "), nil) {
		t.Fatal("blank must not be detected")
	}
}

func TestJSON(t *testing.T) {
	raw := `{"@timestamp":"2024-06-01T09:15:32Z","source":{"ip":"10.0.0.5","port":443},"msg":"user signed in","hostname":"app01","level":"INFO","app":{"name":"billing","version":"2.1"},"tags":["prod"],"argus.tenant.id":"spoof","items":[{"id":1},{"id":2}]}`
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp":               "2024-06-01T09:15:32.000Z",
		"event.module":             "generic",
		"event.dataset":            "generic.json",
		"source.ip":                "10.0.0.5",
		"source.port":              int64(443),
		"message":                  "user signed in",
		"host.name":                "app01",
		"log.level":                "info",
		"generic.json.app.name":    "billing",
		"generic.json.app.version": "2.1",
		"tags":                     []string{"prod"},
	})
	parsertest.ExpectAbsent(t, e, "argus.tenant.id", "generic.json.argus.tenant.id")
	if !e.Has("generic.json.items") {
		t.Fatal("array of objects should be kept")
	}
}

func TestJSONEpochMillis(t *testing.T) {
	e := parsertest.ParseOne(t, New(), `{"ts":1717233332000,"text":"hello"}`)
	parsertest.Expect(t, e, map[string]any{"@timestamp": "2024-06-01T09:15:32.000Z", "message": "hello"})
}

func TestSyslogWrappedJSON(t *testing.T) {
	e := parsertest.ParseOne(t, New(), `<134>Jun  1 09:15:32 relay01 app[42]: {"event":{"action":"export"},"user":{"name":"carol"}}`)
	parsertest.Expect(t, e, map[string]any{
		"event.dataset": "generic.json", "event.action": "export", "user.name": "carol",
		"host.name": "relay01", "process.name": "app", "process.pid": int64(42), "log.syslog.priority": int64(134),
	})
}

func TestCEF(t *testing.T) {
	raw := `CEF:0|Acme|Gateway|5.1|100|Connection allowed|3|rt=1717233332000 src=10.0.0.5 spt=50000 dst=192.0.2.10 dpt=443 proto=TCP suser=dave act=allow msg=Session opened for app cs1Label=Policy Name cs1=Default\=Allow cn1Label=Bytes cn1=2048 request=https://example.com/a?b=1 outcome=success deviceDirection=1 custom=a\|b`
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"event.dataset":                  "generic.cef",
		"cef.version":                    int64(0),
		"observer.vendor":                "Acme",
		"observer.product":               "Gateway",
		"observer.version":               "5.1",
		"event.code":                     "100",
		"rule.name":                      "Connection allowed",
		"event.severity":                 int64(30),
		"@timestamp":                     "2024-06-01T09:15:32.000Z",
		"source.ip":                      "10.0.0.5",
		"source.port":                    int64(50000),
		"destination.ip":                 "192.0.2.10",
		"destination.port":               int64(443),
		"network.transport":              "tcp",
		"user.name":                      "dave",
		"event.action":                   "allow",
		"message":                        "Session opened for app",
		"cef.extensions.custom_string_1": "Default=Allow",
		"cef.extensions.policy_name":     "Default=Allow",
		"cef.extensions.custom_number_1": int64(2048),
		"cef.extensions.bytes":           "2048",
		"url.domain":                     "example.com",
		"event.outcome":                  "success",
		"network.direction":              "outbound",
		"cef.extensions.custom":          "a|b",
		"event.category":                 []string{"network"},
	})
}

func TestCEFTextSeverityAndEscapedHeader(t *testing.T) {
	e := parsertest.ParseOne(t, New(), `<13>1 2024-06-01T09:15:32Z fw01 cef - - - CEF:0|Ven\|dor|Prod|1|7|Name|High|rt=Jun 01 2024 09:15:32 msg=x`)
	parsertest.Expect(t, e, map[string]any{
		"observer.vendor": "Ven|dor", "event.severity": int64(75), "@timestamp": "2024-06-01T09:15:32.000Z", "host.name": "fw01",
	})
}

func TestLEEF(t *testing.T) {
	e := parsertest.ParseOne(t, New(), "LEEF:1.0|Acme|Proxy|2.0|login|devTime=Jun 01 2024 09:15:32\tdevTimeFormat=MMM dd yyyy HH:mm:ss\tsrc=10.0.0.5\tdst=192.0.2.1\tdstPort=443\tusrName=erin\tsev=4\tcat=Auth\tsrcBytes=100")
	parsertest.Expect(t, e, map[string]any{
		"event.dataset": "generic.leef", "leef.version": "1.0", "event.code": "login", "@timestamp": "2024-06-01T09:15:32.000Z",
		"source.ip": "10.0.0.5", "destination.port": int64(443), "user.name": "erin", "event.severity": int64(40),
		"leef.attributes.cat": "Auth", "source.bytes": int64(100),
	})
	e = parsertest.ParseOne(t, New(), "LEEF:2.0|Acme|Proxy|2.0|evt|^|src=10.0.0.6^usrName=frank^customKey=v")
	parsertest.Expect(t, e, map[string]any{"source.ip": "10.0.0.6", "user.name": "frank", "leef.attributes.custom_key": "v"})
	e = parsertest.ParseOne(t, New(), "LEEF:2.0|Acme|Proxy|2.0|evt|x09|src=10.0.0.7\tusrName=gina")
	parsertest.Expect(t, e, map[string]any{"source.ip": "10.0.0.7", "user.name": "gina"})
}

func TestSyslogAndCisco(t *testing.T) {
	e := parsertest.ParseOne(t, New(), `<165>1 2024-06-01T09:15:32.003Z host1 app 99 ID1 [meta seq="7"] service restarted`)
	parsertest.Expect(t, e, map[string]any{
		"event.dataset": "generic.syslog", "message": "service restarted", "host.name": "host1",
		"log.syslog.structured_data.meta.seq": "7", "log.syslog.msgid": "ID1",
	})
	e = parsertest.ParseOne(t, New(), `<190>Jun  1 09:15:32 10.1.1.1 : %LINK-3-UPDOWN: Interface Gi0/1, changed state to up`)
	parsertest.Expect(t, e, map[string]any{
		"generic.syslog.cisco.facility": "LINK", "generic.syslog.cisco.severity": int64(3),
		"event.code": "UPDOWN", "message": "Interface Gi0/1, changed state to up", "log.level": "error",
	})
}

func TestPlainTextViaRegistry(t *testing.T) {
	r := parsers.NewRegistry()
	r.Register(New())
	res := r.Parse(parsertest.Input("just some text", nil))
	if res.Status != schema.ParseStatusOK {
		t.Fatalf("status %s", res.Status)
	}
	e := res.Events[0]
	parsertest.Expect(t, e, map[string]any{"event.dataset": "generic.text", "message": "just some text", "argus.pipeline.time_source": "processing"})
}

func TestErrors(t *testing.T) {
	if _, err := New().Parse(parsertest.Input("   ", nil)); err == nil {
		t.Fatal("blank should error")
	}
	big := `{"a":"` + strings.Repeat("x", parsers.MaxJSONBytes) + `"}`
	if _, err := New().Parse(parsertest.Input(big, nil)); err == nil {
		t.Fatal("oversize JSON should error")
	}
	if _, err := New().Parse(parsertest.Input("CEF:0|a|b", nil)); err == nil {
		t.Fatal("short CEF header should error")
	}
}
