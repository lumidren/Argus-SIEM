package zeek

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func TestConn(t *testing.T) {
	e := parsertest.ParseOne(t, New(), `{"_path":"conn","ts":1717233332.123456,"uid":"CAbc123","id.orig_h":"10.0.0.5","id.orig_p":51234,"id.resp_h":"192.0.2.10","id.resp_p":443,"proto":"tcp","service":"ssl","duration":2.5,"orig_bytes":1200,"resp_bytes":5400,"conn_state":"SF","local_orig":true,"local_resp":false,"missed_bytes":0,"history":"ShADadFf","orig_pkts":12,"resp_pkts":10,"community_id":"1:abc=","extra_field":"kept"}`)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.123Z", "event.dataset": "zeek.conn", "zeek.session_id": "CAbc123",
		"source.ip": "10.0.0.5", "source.port": int64(51234), "destination.ip": "192.0.2.10", "destination.port": int64(443),
		"network.transport": "tcp", "network.protocol": "ssl", "event.duration": int64(2500000000),
		"source.bytes": int64(1200), "destination.bytes": int64(5400), "network.bytes": int64(6600), "network.packets": int64(22),
		"zeek.conn.state": "SF", "zeek.conn.state_message": "Normal SYN/FIN completion", "network.direction": "outbound",
		"network.community_id": "1:abc=", "network.type": "ipv4", "event.category": []string{"network"},
		"event.type": []string{"connection", "end"}, "zeek.conn.extra_field": "kept",
	})
	e = parsertest.ParseOne(t, New(), `{"ts":1717233332.0,"uid":"C2","id.orig_h":"2001:db8::5","id.orig_p":5000,"id.resp_h":"2001:db8::9","id.resp_p":22,"proto":"tcp","conn_state":"REJ","local_orig":true,"local_resp":true}`)
	parsertest.Expect(t, e, map[string]any{"event.dataset": "zeek.conn", "network.type": "ipv6", "network.direction": "internal", "event.type": []string{"connection", "denied"}})
}

func TestDNSHTTPSSLFiles(t *testing.T) {
	e := parsertest.ParseOne(t, New(), `{"_path":"dns","ts":1717233332.0,"uid":"C3","id.orig_h":"10.0.0.5","id.orig_p":53000,"id.resp_h":"10.0.0.53","id.resp_p":53,"proto":"udp","trans_id":4242,"query":"www.example.com","qclass_name":"C_INTERNET","qtype_name":"A","rcode_name":"NOERROR","AA":false,"RD":true,"RA":true,"answers":["www.example.com.cdn.test","93.184.216.34"],"TTLs":[300.0,60.0]}`)
	parsertest.Expect(t, e, map[string]any{
		"dns.id": "4242", "dns.question.name": "www.example.com", "dns.question.type": "A", "dns.response_code": "NOERROR",
		"dns.resolved_ip": []string{"93.184.216.34"}, "network.transport": "udp", "event.outcome": "success", "zeek.dns.RD": true,
	})
	e = parsertest.ParseOne(t, New(), `{"_path":"http","ts":1717233332.0,"uid":"C4","id.orig_h":"10.0.0.5","id.orig_p":50000,"id.resp_h":"192.0.2.20","id.resp_p":8080,"trans_depth":1,"method":"GET","host":"intranet.example.org:8080","uri":"/reports/q2.pdf?dl=1","referrer":"https://intranet.example.org/","version":"1.1","user_agent":"Mozilla/5.0","request_body_len":0,"response_body_len":20480,"status_code":200,"status_msg":"OK","tags":[],"resp_mime_types":["application/pdf"],"resp_fuids":["F1"]}`)
	parsertest.Expect(t, e, map[string]any{
		"event.category": []string{"network", "web"}, "url.domain": "intranet.example.org", "url.path": "/reports/q2.pdf",
		"url.query": "dl=1", "url.original": "intranet.example.org:8080/reports/q2.pdf?dl=1", "http.request.method": "GET",
		"http.response.status_code": int64(200), "http.response.body.bytes": int64(20480), "http.response.mime_type": "application/pdf",
		"user_agent.original": "Mozilla/5.0", "event.outcome": "success", "zeek.http.resp_fuids": []string{"F1"},
	})
	e = parsertest.ParseOne(t, New(), `{"_path":"ssl","ts":1717233332.0,"uid":"C5","id.orig_h":"10.0.0.5","id.orig_p":50001,"id.resp_h":"192.0.2.10","id.resp_p":443,"version":"TLSv12","cipher":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","curve":"x25519","server_name":"www.example.com","resumed":false,"established":true,"ja3":"aaa","ja3s":"bbb","subject":"CN=www.example.com","issuer":"CN=Example CA","validation_status":"ok"}`)
	parsertest.Expect(t, e, map[string]any{
		"tls.version": "1.2", "tls.version_protocol": "tls", "tls.cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"tls.client.server_name": "www.example.com", "tls.established": true, "tls.client.ja3": "aaa", "tls.server.ja3s": "bbb",
		"zeek.ssl.validation_status": "ok",
	})
	e = parsertest.ParseOne(t, New(), `{"_path":"files","ts":1717233332.0,"fuid":"F1","tx_hosts":["192.0.2.20"],"rx_hosts":["10.0.0.5"],"conn_uids":["C4"],"source":"HTTP","depth":0,"analyzers":["MD5","SHA1"],"mime_type":"application/pdf","filename":"q2.pdf","duration":0.01,"is_orig":false,"seen_bytes":20480,"total_bytes":20480,"missing_bytes":0,"timedout":false,"md5":"0123456789abcdef0123456789abcdef","sha1":"0123456789abcdef0123456789abcdef01234567"}`)
	parsertest.Expect(t, e, map[string]any{
		"event.dataset": "zeek.files", "server.ip": "192.0.2.20", "client.ip": "10.0.0.5", "file.mime_type": "application/pdf",
		"file.name": "q2.pdf", "file.size": int64(20480), "file.hash.md5": "0123456789abcdef0123456789abcdef", "zeek.files.session_ids": []string{"C4"},
	})
}

func TestOtherLogs(t *testing.T) {
	e := parsertest.ParseOne(t, New(), `{"_path":"notice","ts":1717233332.0,"uid":"C6","id.orig_h":"10.0.0.5","note":"SSL::Invalid_Server_Cert","msg":"certificate expired","sub":"CN=old.example.org","src":"10.0.0.5","dst":"192.0.2.30","p":443,"actions":["Notice::ACTION_LOG"],"suppress_for":3600.0}`)
	parsertest.Expect(t, e, map[string]any{"event.kind": "alert", "rule.name": "SSL::Invalid_Server_Cert", "message": "certificate expired", "destination.port": int64(443), "zeek.notice.actions": []string{"Notice::ACTION_LOG"}})
	e = parsertest.ParseOne(t, New(), `{"_path":"weird","ts":1717233332.0,"uid":"C7","id.orig_h":"10.0.0.5","name":"truncated_header","addl":"","notice":false,"peer":"zeek"}`)
	parsertest.Expect(t, e, map[string]any{"zeek.weird.name": "truncated_header", "zeek.weird.notice": false})
	e = parsertest.ParseOne(t, New(), `{"_path":"ssh","ts":1717233332.0,"uid":"C8","id.orig_h":"10.0.0.5","id.resp_h":"10.0.0.22","id.resp_p":22,"version":2,"auth_success":true,"auth_attempts":1,"direction":"INBOUND","client":"SSH-2.0-OpenSSH_9.6","server":"SSH-2.0-OpenSSH_9.6"}`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"network", "authentication"}, "event.outcome": "success", "zeek.ssh.auth.attempts": int64(1)})
	e = parsertest.ParseOne(t, New(), `{"_path":"kerberos","ts":1717233332.0,"uid":"C9","id.orig_h":"10.0.0.5","request_type":"TGS","client":"alice/CORP.LOCAL","service":"host/fs01.corp.local","success":true,"cipher":"aes256-cts-hmac-sha1-96","forwardable":true}`)
	parsertest.Expect(t, e, map[string]any{"user.name": "alice", "user.domain": "CORP.LOCAL", "zeek.kerberos.service": "host/fs01.corp.local", "event.outcome": "success"})
	e = parsertest.ParseOne(t, New(), `{"_path":"smb_files","ts":1717233332.0,"uid":"C10","id.orig_h":"10.0.0.5","fuid":"F2","action":"SMB::FILE_OPEN","path":"\\\\fs01\\share","name":"report.docx","size":1024}`)
	parsertest.Expect(t, e, map[string]any{"file.name": "report.docx", "file.path": `\\fs01\share\report.docx`, "event.action": "SMB::FILE_OPEN"})
	e = parsertest.ParseOne(t, New(), `{"_path":"ntlm","ts":1717233332.0,"uid":"C11","id.orig_h":"10.0.0.5","username":"alice","domainname":"CORP","hostname":"WS01","server_nb_computer_name":"FS01","success":true}`)
	parsertest.Expect(t, e, map[string]any{"user.name": "alice", "source.domain": "WS01", "destination.domain": "FS01", "zeek.ntlm.server.nb.name": "FS01"})
	e = parsertest.ParseOne(t, New(), `{"_path":"intel","ts":1717233332.0,"uid":"C12","id.orig_h":"10.0.0.5","seen.indicator":"bad.example.net","seen.indicator_type":"Intel::DOMAIN","seen.where":"DNS::IN_REQUEST","matched":["Intel::DOMAIN"],"sources":["feed-a"]}`)
	parsertest.Expect(t, e, map[string]any{"event.kind": "alert", "threat.indicator.domain": "bad.example.net", "threat.indicator.provider": "feed-a", "zeek.intel.seen.where": "DNS::IN_REQUEST"})
	e = parsertest.ParseOne(t, New(), `{"_path":"software","ts":1717233332.0,"host":"10.0.0.5","software_type":"HTTP::BROWSER","name":"Firefox","version.major":126}`)
	parsertest.Expect(t, e, map[string]any{"event.dataset": "zeek.software", "zeek.software.software_type": "HTTP::BROWSER", "zeek.software.version.major": int64(126)})
}

func TestTSVAndHints(t *testing.T) {
	fields := "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state"
	hints := map[string]string{"zeek_fields": fields, "zeek_path": "conn"}
	e := parsertest.ParseOneHints(t, New(), "1717233332.000000\tCt1\t10.0.0.5\t51000\t192.0.2.10\t80\ttcp\thttp\t0.5\t100\t-\tSF", hints)
	parsertest.Expect(t, e, map[string]any{"event.dataset": "zeek.conn", "destination.port": int64(80), "source.bytes": int64(100), "network.protocol": "http"})
	parsertest.ExpectAbsent(t, e, "destination.bytes")
	evs, err := New().Parse(parsertest.Input("#fields\tts\tuid", hints))
	if err != nil || evs != nil {
		t.Fatalf("header should be dropped: %v %v", evs, err)
	}
	e = parsertest.ParseOneHints(t, New(), `{"ts":1717233332.0,"uid":"C1","id.orig_h":"10.0.0.5"}`, map[string]string{"path": "/opt/zeek/logs/current/dhcp.log"})
	parsertest.Expect(t, e, map[string]any{"event.dataset": "zeek.dhcp"})
	e = parsertest.ParseOne(t, New(), `{"ts":1717233332.0,"uid":"C1","id.orig_h":"10.0.0.5","mystery":1}`)
	parsertest.Expect(t, e, map[string]any{"event.dataset": "zeek.unknown", "zeek.unknown.mystery": int64(1)})
}

func TestDetect(t *testing.T) {
	p := New()
	if !p.Detect([]byte(`{"_path":"conn","ts":1}`), nil) || !p.Detect([]byte(`{"ts":1,"id.orig_h":"1.2.3.4"}`), nil) {
		t.Fatal("zeek not detected")
	}
	for _, s := range []string{`{"event_type":"alert","src_ip":"1.2.3.4","id.orig_h":"x"}`, `{"a":1}`, `203.0.113.7 - - [01/Jun/2024:09:15:32 +0000] "GET / HTTP/1.1" 200 1`, ``} {
		if p.Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := p.Parse(parsertest.Input(`not json`, nil)); err == nil {
		t.Fatal("garbage should error")
	}
}
