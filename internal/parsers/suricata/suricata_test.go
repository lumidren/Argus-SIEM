package suricata

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

const base = `"timestamp":"2024-06-01T09:15:32.123456+0000","flow_id":1234567890,"in_iface":"eth0","src_ip":"10.0.0.5","src_port":51234,"dest_ip":"192.0.2.10","dest_port":80,"proto":"TCP","community_id":"1:xyz=","host":"sensor01"`

func TestAlert(t *testing.T) {
	raw := `{` + base + `,"event_type":"alert","app_proto":"http","alert":{"action":"allowed","gid":1,"signature_id":2100498,"rev":7,"signature":"Example policy rule matched","category":"Potentially Bad Traffic","severity":2,"metadata":{"mitre_technique_id":["T1071"],"mitre_tactic_id":["TA0011"],"signature_severity":["Major"],"created_at":["2020_01_01"]}},"http":{"hostname":"www.example.com","url":"/index.html","http_user_agent":"curl/8.0","http_method":"GET","protocol":"HTTP/1.1","status":200,"length":512},"payload_printable":"GET /","flow":{"pkts_toserver":3,"pkts_toclient":2,"bytes_toserver":300,"bytes_toclient":900,"start":"2024-06-01T09:15:31.000000+0000"}}`
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.123Z", "event.dataset": "suricata.eve", "event.kind": "alert",
		"event.category": []string{"network", "intrusion_detection"}, "event.type": []string{"allowed"}, "event.outcome": "success",
		"rule.id": "2100498", "rule.name": "Example policy rule matched", "rule.category": "Potentially Bad Traffic", "rule.version": "7",
		"event.severity": int64(50), "suricata.eve.alert.severity": int64(2), "threat.technique.id": []string{"T1071"},
		"threat.tactic.id": []string{"TA0011"}, "source.ip": "10.0.0.5", "destination.port": int64(80), "network.transport": "tcp",
		"network.protocol": "http", "url.domain": "www.example.com", "url.path": "/index.html", "url.original": "www.example.com/index.html",
		"http.response.status_code": int64(200), "source.bytes": int64(300), "network.bytes": int64(1200), "observer.hostname": "sensor01",
		"suricata.eve.payload_printable": "GET /", "message": "Example policy rule matched",
	})
	raw = `{` + base + `,"event_type":"alert","alert":{"action":"blocked","signature_id":1,"signature":"x","severity":1}}`
	e = parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{"event.type": []string{"denied"}, "event.outcome": "failure", "event.severity": int64(75)})
}

func TestProtocols(t *testing.T) {
	e := parsertest.ParseOne(t, New(), `{`+base+`,"event_type":"dns","dns":{"type":"answer","id":4242,"rrname":"www.example.com","rrtype":"A","rcode":"NOERROR","ttl":300,"rdata":"93.184.216.34"}}`)
	parsertest.Expect(t, e, map[string]any{"dns.type": "answer", "dns.question.name": "www.example.com", "dns.resolved_ip": []string{"93.184.216.34"}, "dns.response_code": "NOERROR"})
	e = parsertest.ParseOne(t, New(), `{`+base+`,"event_type":"dns","dns":{"version":2,"type":"answer","id":1,"rrname":"example.org","rrtype":"AAAA","rcode":"NOERROR","grouped":{"AAAA":["2001:db8::1"]}}}`)
	parsertest.Expect(t, e, map[string]any{"dns.resolved_ip": []string{"2001:db8::1"}, "suricata.eve.dns.version": "2"})
	e = parsertest.ParseOne(t, New(), `{`+base+`,"event_type":"tls","tls":{"subject":"CN=www.example.com","issuerdn":"CN=Example CA","fingerprint":"AA:BB:CC","sni":"www.example.com","version":"TLS 1.2","notbefore":"2024-01-01T00:00:00","notafter":"2025-01-01T00:00:00","ja3":{"hash":"j3","string":"771,..."},"ja3s":{"hash":"j3s"}}}`)
	parsertest.Expect(t, e, map[string]any{"tls.version": "1.2", "tls.server.hash.sha1": "aabbcc", "tls.client.ja3": "j3", "tls.server.ja3s": "j3s", "tls.server.not_after": "2025-01-01T00:00:00Z"})
	e = parsertest.ParseOne(t, New(), `{`+base+`,"event_type":"flow","app_proto":"failed","flow":{"pkts_toserver":5,"pkts_toclient":4,"bytes_toserver":500,"bytes_toclient":400,"start":"2024-06-01T09:15:30.000000+0000","end":"2024-06-01T09:15:32.000000+0000","age":2,"state":"closed","reason":"timeout","alerted":false},"tcp":{"tcp_flags":"1b","syn":true}}`)
	parsertest.Expect(t, e, map[string]any{"event.type": []string{"connection", "end"}, "event.duration": int64(2000000000), "network.packets": int64(9), "suricata.eve.flow.state": "closed", "suricata.eve.tcp.syn": true})
	parsertest.ExpectAbsent(t, e, "network.protocol")
	e = parsertest.ParseOne(t, New(), `{`+base+`,"event_type":"fileinfo","http":{"hostname":"files.example.org","url":"/a/report.pdf"},"fileinfo":{"filename":"/a/report.pdf","magic":"PDF document","state":"CLOSED","md5":"0123456789abcdef0123456789abcdef","stored":false,"size":4096,"tx_id":0}}`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"network", "file"}, "file.name": "report.pdf", "file.size": int64(4096), "suricata.eve.fileinfo.magic": "PDF document"})
	e = parsertest.ParseOne(t, New(), `{`+base+`,"event_type":"krb5","krb5":{"msg_type":"KRB_AS_REQ","cname":"alice","realm":"CORP.LOCAL","sname":"krbtgt/CORP.LOCAL"}}`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"network", "authentication"}, "user.name": "alice", "user.domain": "CORP.LOCAL", "suricata.eve.krb5.sname": "krbtgt/CORP.LOCAL"})
	e = parsertest.ParseOne(t, New(), `{"timestamp":"2024-06-01T09:15:32.000000+0000","event_type":"stats","stats":{"uptime":3600,"capture":{"kernel_packets":1000}}}`)
	parsertest.Expect(t, e, map[string]any{"event.kind": "metric", "suricata.eve.stats.uptime": int64(3600), "suricata.eve.stats.capture.kernel_packets": int64(1000)})
	e = parsertest.ParseOne(t, New(), `{`+base+`,"event_type":"anomaly","anomaly":{"type":"stream","event":"STREAM_PKT_INVALID_TIMESTAMP"}}`)
	parsertest.Expect(t, e, map[string]any{"event.kind": "alert", "suricata.eve.anomaly.event": "STREAM_PKT_INVALID_TIMESTAMP"})
	e = parsertest.ParseOne(t, New(), `{`+base+`,"event_type":"mqtt","mqtt":{"connect":{"client_id":"sensor-7"}}}`)
	parsertest.Expect(t, e, map[string]any{"suricata.eve.mqtt.connect.client_id": "sensor-7", "event.action": "mqtt"})
}

func TestDetect(t *testing.T) {
	p := New()
	if !p.Detect([]byte(`{"event_type":"dns","src_ip":"1.2.3.4"}`), nil) {
		t.Fatal("eve not detected")
	}
	for _, s := range []string{`{"_path":"conn","id.orig_h":"x"}`, `{"a":1}`, `x`, ``} {
		if p.Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := p.Parse(parsertest.Input(`{"src_ip":"1.2.3.4"}`, nil)); err == nil {
		t.Fatal("missing event_type should error")
	}
}
