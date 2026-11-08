package paloalto

import (
	"strings"
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

// line builds a CSV body from a column table and named values.
func line(tbl []string, vals map[string]string) string {
	cols := make([]string, len(tbl))
	for i, n := range tbl {
		cols[i] = vals[n]
		if strings.ContainsAny(cols[i], ", ") {
			cols[i] = `"` + cols[i] + `"`
		}
	}
	return strings.Join(cols, ",")
}

func base(typ, sub string) map[string]string {
	return map[string]string{"_0": "1", "receive_time": "2024/06/01 09:15:33", "serial": "012801000001", "type": typ, "subtype": sub, "generated_time": "2024/06/01 09:15:32", "device_name": "fw-edge-01", "vsys": "vsys1", "seqno": "1001"}
}

func with(m map[string]string, kv ...string) map[string]string {
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func TestTraffic(t *testing.T) {
	v := with(base("TRAFFIC", "end"), "src", "10.0.0.5", "dst", "192.0.2.10", "natsrc", "203.0.113.5", "natdst", "0.0.0.0",
		"rule", "allow-web", "srcuser", `corp\alice`, "app", "web-browsing", "from", "trust", "to", "untrust", "inbound_if", "ethernet1/2",
		"outbound_if", "ethernet1/1", "sessionid", "33760", "repeatcnt", "1", "sport", "51234", "dport", "443", "natsport", "40000",
		"natdport", "0", "proto", "tcp", "action", "allow", "bytes", "6600", "bytes_sent", "1200", "bytes_received", "5400",
		"packets", "22", "start", "2024/06/01 09:15:30", "elapsed", "2", "category", "computer-and-internet-info", "srcloc", "10.0.0.0-10.255.255.255",
		"dstloc", "US", "pkts_sent", "12", "pkts_received", "10", "session_end_reason", "tcp-fin", "rule_uuid", "uuid-1")
	raw := "<14>Jun  1 09:15:33 fw-edge-01 1," + line(trafficCols, v)[2:]
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.000Z", "event.dataset": "panw.panos", "event.category": []string{"network"},
		"event.type": []string{"connection", "allowed"}, "event.outcome": "success", "event.action": "allow",
		"source.ip": "10.0.0.5", "destination.ip": "192.0.2.10", "source.nat.ip": "203.0.113.5", "source.port": int64(51234),
		"destination.port": int64(443), "source.nat.port": int64(40000), "rule.name": "allow-web", "user.name": "alice",
		"source.user.domain": "corp", "network.application": "web-browsing", "observer.ingress.zone": "trust",
		"observer.egress.interface.name": "ethernet1/1", "network.transport": "tcp", "network.bytes": int64(6600),
		"source.bytes": int64(1200), "destination.packets": int64(10), "event.duration": int64(2000000000),
		"destination.geo.country_iso_code": "US", "panw.panos.source.zone_location": "10.0.0.0-10.255.255.255",
		"panw.panos.session_end_reason": "tcp-fin", "observer.serial_number": "012801000001", "observer.name": "fw-edge-01",
		"observer.hostname": "fw-edge-01", "panw.panos.flow_id": "33760",
	})
	parsertest.ExpectAbsent(t, e, "destination.nat.ip", "destination.nat.port", "host.name")

	v = with(base("TRAFFIC", "deny"), "src", "10.0.0.6", "dst", "192.0.2.11", "sport", "50000", "dport", "23", "proto", "tcp", "action", "deny", "rule", "default-deny", "high_res_timestamp", "2024-06-01T09:15:32.456Z")
	e = parsertest.ParseOne(t, New(), line(trafficCols, v))
	parsertest.Expect(t, e, map[string]any{"event.type": []string{"connection", "denied"}, "event.outcome": "failure", "@timestamp": "2024-06-01T09:15:32.456Z"})
}

func TestThreat(t *testing.T) {
	v := with(base("THREAT", "url"), "src", "10.0.0.5", "dst", "192.0.2.12", "rule", "web-filter", "app", "web-browsing", "proto", "tcp",
		"action", "block-url", "misc", "media.example.net/videos/clip", "threatid", "(9999)", "category", "streaming-media", "severity", "informational",
		"direction", "client-to-server", "user_agent", "Mozilla/5.0", "http_method", "get")
	e := parsertest.ParseOne(t, New(), line(threatCols, v))
	parsertest.Expect(t, e, map[string]any{
		"event.kind": "alert", "event.category": []string{"network", "intrusion_detection"}, "event.type": []string{"denied"},
		"event.outcome": "failure", "url.original": "media.example.net/videos/clip", "panw.panos.url.category": "streaming-media",
		"event.severity": int64(10), "user_agent.original": "Mozilla/5.0", "panw.panos.threat.id": "9999",
	})
	v = with(base("THREAT", "vulnerability"), "src", "198.51.100.90", "dst", "10.0.0.20", "proto", "tcp", "action", "alert",
		"threatid", "Example test signature(10001)", "severity", "high", "filedigest", strings.Repeat("ab", 32))
	e = parsertest.ParseOne(t, New(), line(threatCols, v))
	parsertest.Expect(t, e, map[string]any{"panw.panos.threat.name": "Example test signature", "panw.panos.threat.id": "10001", "event.severity": int64(75), "event.outcome": "unknown", "file.hash.sha256": strings.Repeat("ab", 32)})
	v = with(base("THREAT", "file"), "src", "10.0.0.5", "dst", "192.0.2.13", "proto", "tcp", "action", "allow", "misc", "report.pdf", "threatid", "PDF File(52020)", "severity", "low")
	e = parsertest.ParseOne(t, New(), line(threatCols, v))
	parsertest.Expect(t, e, map[string]any{"file.name": "report.pdf", "event.type": []string{"allowed"}})
}

func TestSystemConfigAuthGP(t *testing.T) {
	v := with(base("SYSTEM", "general"), "eventid", "general", "module", "general", "severity", "informational", "opaque", "Configuration committed by admin")
	e := parsertest.ParseOne(t, New(), line(systemCols, v))
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"process"}, "message": "Configuration committed by admin", "log.level": "informational"})
	v = with(base("CONFIG", "0"), "host", "10.0.0.100", "cmd", "set", "admin", "netadmin", "client", "Web", "result", "Succeeded", "path", "deviceconfig system hostname")
	e = parsertest.ParseOne(t, New(), line(configCols, v))
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"configuration"}, "user.name": "netadmin", "source.ip": "10.0.0.100", "event.outcome": "success", "panw.panos.config_path": "deviceconfig system hostname"})
	v = with(base("AUTHENTICATION", "0"), "ip", "10.0.0.5", "user", "alice", "authpolicy", "mfa-policy", "event", "auth-fail", "serverprofile", "corp-ldap", "desc", "Invalid credentials")
	e = parsertest.ParseOne(t, New(), line(authCols, v))
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"authentication"}, "event.outcome": "failure", "user.name": "alice", "panw.panos.auth.serverprofile": "corp-ldap"})
	v = with(base("GLOBALPROTECT", "0"), "eventid", "gateway-auth", "stage", "login", "auth_method", "LDAP", "srcuser", "bob", "public_ip", "198.51.100.91", "status", "success", "portal", "gp-portal", "opaque", "Login succeeded")
	e = parsertest.ParseOne(t, New(), line(gpCols, v))
	parsertest.Expect(t, e, map[string]any{"user.name": "bob", "source.ip": "198.51.100.91", "event.outcome": "success", "panw.panos.gp.stage": "login"})
}

func TestDetectAndErrors(t *testing.T) {
	p := New()
	for _, s := range []string{`date=2024-06-01 time=09:15:32 devname="fw" logid="0000000013" type="traffic"`, `CEF:0|a|b|c|d|e|1|`, `{"a":1}`, `1,2,3`} {
		if p.Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := p.Parse(parsertest.Input("1,2024/06/01 09:15:33,012801000001", nil)); err == nil {
		t.Fatal("short line should error")
	}
	e := parsertest.ParseOne(t, p, "1,2024/06/01 09:15:33,012801000001,USERID,login,,2024/06/01 09:15:32,vsys1,10.0.0.5,alice")
	parsertest.Expect(t, e, map[string]any{"panw.panos.type": "USERID", "panw.panos.userid.col_8": "10.0.0.5"})
}
