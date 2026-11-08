package all

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

func TestEveryParserRegistered(t *testing.T) {
	r := Registry()
	if got := len(r.Names()); got != len(SniffOrder) {
		t.Fatalf("registered %d parsers, sniff order lists %d", got, len(SniffOrder))
	}
	for _, n := range SniffOrder {
		if _, ok := r.Get(n); !ok {
			t.Errorf("sniff order names unknown parser %q", n)
		}
	}
}

// TestSniffRouting checks that records without an explicit kind reach the
// right parser when every parser competes.
func TestSniffRouting(t *testing.T) {
	cases := map[string]string{
		`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4634</EventID><Channel>Security</Channel><Computer>WS01</Computer></System><EventData><Data Name='TargetUserName'>alice</Data></EventData></Event>`: "windows",
		`{"timestamp":"2024-06-01T09:15:32.000000+0000","flow_id":1,"event_type":"dns","src_ip":"10.0.0.5","dest_ip":"10.0.0.53","proto":"UDP","dns":{"type":"query","rrname":"example.org"}}`:                                                                                                           "suricata",
		`{"_path":"conn","ts":1717233332.1,"uid":"C1","id.orig_h":"10.0.0.5","id.orig_p":1,"id.resp_h":"10.0.0.6","id.resp_p":2,"proto":"tcp"}`:                                                                                                                                                          "zeek",
		`{"eventVersion":"1.08","eventTime":"2024-06-01T09:15:32Z","eventSource":"s3.amazonaws.com","eventName":"ListBuckets","sourceIPAddress":"198.51.100.1"}`:                                                                                                                                         "aws",
		`{"insertId":"i","logName":"projects/p/logs/cloudaudit.googleapis.com%2Factivity","protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","methodName":"x"}}`:                                                                                                                  "gcp",
		`{"CreationTime":"2024-06-01T09:15:32","Id":"1","Operation":"UserLoggedIn","RecordType":15,"UserId":"a@example.com"}`:                                                                                                                                                                            "o365",
		`{"eventType":"user.session.start","published":"2024-06-01T09:15:32Z","uuid":"u","actor":{"alternateId":"a@example.com"}}`:                                                                                                                                                                       "okta",
		`{"kind":"admin#reports#activity","id":{"time":"2024-06-01T09:15:32Z","uniqueQualifier":"q","applicationName":"login"},"events":[{"name":"logout"}]}`:                                                                                                                                            "google_workspace",
		`{"time":"2024-06-01T09:15:32Z","operationName":"MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE","resourceId":"/SUBSCRIPTIONS/s","category":"Administrative","resultType":"Success"}`:                                                                                                                   "azure",
		`{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"a","stage":"ResponseComplete","requestURI":"/api/v1/pods","verb":"list","objectRef":{"resource":"pods"}}`:                                                                                                                             "kubernetes",
		`{"name":"processes","hostIdentifier":"h","unixTime":1717233332,"columns":{"pid":"1","path":"/sbin/init","cmdline":"init"},"action":"added"}`:                                                                                                                                                    "osquery",
		`<14>Jun  1 09:15:33 fw 1,2024/06/01 09:15:33,012801000001,SYSTEM,general,,2024/06/01 09:15:32,,general`:                                                                                                                                                                                         "panw",
		`<189>date=2024-06-01 time=09:15:32 devname="FGT" logid="0000000013" type="traffic" subtype="forward" srcip=10.0.0.5 action="accept"`:                                                                                                                                                            "fortinet",
		`<38>Jun  1 09:00:01 web01 sshd[2001]: Accepted publickey for alice from 10.0.0.5 port 51234 ssh2`:                                                                                                                                                                                               "linux",
		`type=CWD msg=audit(1717233332.123:4567): cwd="/home/alice"`:                                                                                                                                                                                                                                     "linux",
		`[Sat Jun 01 09:15:32.123456 2024] [core:error] [pid 1:tid 2] AH00128: File does not exist: /x`:                                                                                                                                                                                                  "apache",
		`10.0.0.1 - - [01/Jun/2024:09:15:32 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`:                                                                                                                                                                                                                       "nginx",
		`CEF:0|Acme|Gateway|5.1|100|Connection allowed|3|src=10.0.0.5`:                                                                                                                                                                                                                                   "generic",
		`{"service":"billing","msg":"invoice generated"}`:                                                                                                                                                                                                                                                "generic",
		`plain text line`: "generic",
	}
	r := Registry()
	for raw, want := range cases {
		res := r.Parse(&parsers.Input{Raw: []byte(raw), ReceivedAt: time.Now(), Source: parsers.Source{TenantID: "t"}})
		if res.Parser == nil || res.Parser.Name() != want {
			got := "<none>"
			if res.Parser != nil {
				got = res.Parser.Name()
			}
			t.Errorf("routed to %s, want %s: %.80s", got, want, raw)
			continue
		}
		if res.Status == schema.ParseStatusFailed {
			t.Errorf("%s failed to parse: %v", want, res.Err)
		}
	}
}

// TestCorpusNeverFails runs every committed fuzz corpus file through the
// default registry: no file may produce a failed parse or a panic.
func TestCorpusNeverFails(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "..", "test", "fuzz", "corpus")
	r := Registry()
	n := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		n++
		res := r.Parse(&parsers.Input{Raw: b, ReceivedAt: time.Now(), Source: parsers.Source{TenantID: "t"}})
		if res.Panic || res.Status == schema.ParseStatusFailed {
			t.Errorf("%s: status %s err %v", path, res.Status, res.Err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 20 {
		t.Fatalf("expected at least 20 corpus files, found %d", n)
	}
}
