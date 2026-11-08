package osquery

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func TestEventFormat(t *testing.T) {
	raw := `{"name":"pack_monitoring_process_events","hostIdentifier":"web01","calendarTime":"Sat Jun  1 09:15:32 2024 UTC","unixTime":1717233332,"epoch":0,"counter":3,"numerics":false,"decorations":{"host_uuid":"h-1","hostname":"web01.example.com"},"columns":{"pid":"4242","path":"/usr/bin/python3","cmdline":"python3 /opt/app/report.py","parent":"1","cwd":"/opt/app","uid":"1000","gid":"1000","euid":"1000","time":"1717233332"},"action":"added"}`
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.000Z", "event.dataset": "osquery.result", "event.category": []string{"process"},
		"event.type": []string{"start"}, "event.action": "pack_monitoring_process_events", "host.name": "web01.example.com",
		"host.id": "h-1", "process.pid": int64(4242), "process.executable": "/usr/bin/python3", "process.name": "python3",
		"process.command_line": "python3 /opt/app/report.py", "process.parent.pid": int64(1), "user.id": "1000",
		"osquery.result.columns.cwd": "/opt/app", "osquery.result.counter": int64(3), "osquery.result.action": "added",
	})
	e = parsertest.ParseOne(t, New(), `{"name":"file_events","hostIdentifier":"web01","unixTime":"1717233332","columns":{"target_path":"/etc/app/config.yaml","action":"UPDATED","md5":"0123456789abcdef0123456789abcdef","size":"512"},"action":"added"}`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"file"}, "event.type": []string{"change"}, "file.path": "/etc/app/config.yaml", "file.extension": "yaml", "file.size": int64(512)})
}

func TestSnapshotAndDiff(t *testing.T) {
	raw := `{"name":"listening_ports","hostIdentifier":"web01","unixTime":1717233332,"action":"snapshot","snapshot":[{"pid":"700","port":"22","protocol":"6","address":"0.0.0.0"},{"pid":"800","port":"443","protocol":"6","address":"0.0.0.0"}]}`
	evs, err := New().Parse(parsertest.Input(raw, nil))
	if err != nil || len(evs) != 2 {
		t.Fatalf("snapshot rows: %d %v", len(evs), err)
	}
	parsertest.Expect(t, evs[1], map[string]any{"event.category": []string{"network"}, "destination.port": int64(443), "network.transport": "tcp", "osquery.result.action": "snapshot"})
	raw = `{"name":"logged_in_users","hostIdentifier":"web01","unixTime":1717233332,"diffResults":{"added":[{"user":"alice","tty":"pts/0","host":"10.0.0.5"}],"removed":[{"user":"bob","tty":"pts/1","host":"laptop.example.org"}]}}`
	evs, err = New().Parse(parsertest.Input(raw, nil))
	if err != nil || len(evs) != 2 {
		t.Fatalf("diff rows: %d %v", len(evs), err)
	}
	parsertest.Expect(t, evs[0], map[string]any{"event.category": []string{"session"}, "user.name": "alice", "source.ip": "10.0.0.5", "osquery.result.action": "added"})
	parsertest.Expect(t, evs[1], map[string]any{"user.name": "bob", "source.address": "laptop.example.org", "osquery.result.action": "removed"})
	e := parsertest.ParseOne(t, New(), `{"name":"custom_users","hostIdentifier":"web01","unixTime":1717233332,"columns":{"username":"deploy","uid":"1001","gid":"1001","directory":"/home/deploy"},"action":"added"}`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"iam"}, "user.name": "deploy", "user.home": "/home/deploy"})
}

func TestDetect(t *testing.T) {
	for _, s := range []string{`{"a":1}`, `{"name":"x","columns":{}}`, `x`} {
		if New().Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := New().Parse(parsertest.Input(`{"name":"x","hostIdentifier":"h"}`, nil)); err == nil {
		t.Fatal("no rows should error")
	}
}
