package fortinet

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func TestTraffic(t *testing.T) {
	raw := `<189>date=2024-06-01 time=09:15:32 devname="FGT-HQ" devid="FGT60E0000000001" eventtime=1717233332123456789 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.0.0.5 srcport=51234 srcintf="internal" srcintfrole="lan" dstip=192.0.2.10 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=12345 proto=6 action="accept" policyid=3 policytype="policy" poluuid="uuid-3" policyname="LAN-to-WAN" service="HTTPS" trandisp="snat" transip=203.0.113.5 transport=40000 appcat="unscanned" duration=2 sentbyte=1200 rcvdbyte=5400 sentpkt=12 rcvdpkt=10`
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.123Z", "event.dataset": "fortinet.firewall", "event.code": "0000000013",
		"event.category": []string{"network"}, "event.type": []string{"connection", "allowed"}, "event.outcome": "success",
		"event.action": "accept", "observer.name": "FGT-HQ", "observer.serial_number": "FGT60E0000000001",
		"source.ip": "10.0.0.5", "source.port": int64(51234), "destination.ip": "192.0.2.10", "destination.port": int64(443),
		"network.transport": "tcp", "network.iana_number": "6", "source.nat.ip": "203.0.113.5", "source.nat.port": int64(40000),
		"rule.id": "3", "rule.name": "LAN-to-WAN", "rule.uuid": "uuid-3", "destination.geo.country_name": "United States",
		"event.duration": int64(2000000000), "network.bytes": int64(6600), "network.packets": int64(22),
		"observer.ingress.interface.name": "internal", "fortinet.firewall.service": "HTTPS", "fortinet.firewall.srcintfrole": "lan",
		"log.level": "notice", "fortinet.firewall.sessionid": "12345",
	})
	parsertest.ExpectAbsent(t, e, "source.geo.country_name")
	e = parsertest.ParseOne(t, New(), `date=2024-06-01 time=09:15:32 tz="+0200" devname="FGT-HQ" logid="0000000013" type="traffic" subtype="forward" srcip=10.0.0.6 dstip=192.0.2.11 dstport=23 proto=6 action="deny" policyid=0 policyname="implicit-deny"`)
	parsertest.Expect(t, e, map[string]any{"@timestamp": "2024-06-01T07:15:32.000Z", "event.type": []string{"connection", "denied"}, "event.outcome": "failure"})
}

func TestUTMAndEvents(t *testing.T) {
	e := parsertest.ParseOne(t, New(), `date=2024-06-01 time=09:16:00 devname="FGT-HQ" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" srcip=10.0.0.5 dstip=192.0.2.20 dstport=80 proto=6 action="blocked" hostname="games.example.com" url="http://games.example.com/play" method="domain" catdesc="Games" cat=8 agent="Mozilla/5.0"`)
	parsertest.Expect(t, e, map[string]any{"event.type": []string{"denied"}, "url.domain": "games.example.com", "url.path": "/play", "fortinet.firewall.catdesc": "Games", "user_agent.original": "Mozilla/5.0"})
	e = parsertest.ParseOne(t, New(), `date=2024-06-01 time=09:16:01 devname="FGT-HQ" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="medium" srcip=198.51.100.90 dstip=10.0.0.20 dstport=8080 proto=6 action="dropped" attack="Example.Test.Signature" attackid=10001 direction="incoming" ref="http://www.fortinet.com/ids/VID10001"`)
	parsertest.Expect(t, e, map[string]any{"event.kind": "alert", "event.category": []string{"network", "intrusion_detection"}, "rule.name": "Example.Test.Signature", "rule.id": "10001", "event.severity": int64(50), "network.direction": "inbound", "event.outcome": "failure"})
	e = parsertest.ParseOne(t, New(), `date=2024-06-01 time=09:16:02 devname="FGT-HQ" logid="1501054802" type="utm" subtype="dns" srcip=10.0.0.5 dstip=10.0.0.53 qname="www.example.com" qtype="A" xid=4242 ipaddr="93.184.216.34, 93.184.216.35" action="pass"`)
	parsertest.Expect(t, e, map[string]any{"dns.question.name": "www.example.com", "dns.id": "4242", "dns.resolved_ip": []string{"93.184.216.34", "93.184.216.35"}})
	e = parsertest.ParseOne(t, New(), `date=2024-06-01 time=09:16:03 devname="FGT-HQ" logid="0100032001" type="event" subtype="system" level="information" logdesc="Admin login successful" user="netadmin" ui="ssh(10.0.0.100)" method="ssh" action="login" status="success" msg="Administrator netadmin logged in successfully from ssh(10.0.0.100)"`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"authentication"}, "event.type": []string{"start"}, "event.outcome": "success", "user.name": "netadmin", "source.ip": "10.0.0.100", "fortinet.firewall.ui": "ssh(10.0.0.100)"})
	e = parsertest.ParseOne(t, New(), `date=2024-06-01 time=09:16:04 devname="FGT-HQ" logid="0100032002" type="event" subtype="system" logdesc="Admin login failed" user="netadmin" ui="https(10.0.0.101)" action="login" status="failed"`)
	parsertest.Expect(t, e, map[string]any{"event.outcome": "failure", "source.ip": "10.0.0.101"})
	e = parsertest.ParseOne(t, New(), `date=2024-06-01 time=09:16:05 devname="FGT-HQ" logid="0101037138" type="event" subtype="vpn" logdesc="IPsec connection status changed" action="tunnel-up" remip=198.51.100.92 locip=203.0.113.1 xauthuser="bob" vpntunnel="branch"`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"network"}, "source.ip": "198.51.100.92", "user.name": "bob", "fortinet.firewall.vpntunnel": "branch"})
}

func TestDetect(t *testing.T) {
	p := New()
	for _, s := range []string{`1,2024/06/01 09:15:33,012801000001,TRAFFIC,end`, `CEF:0|a|b|c|d|e|1|`, `{"a":1}`, `type=SYSCALL msg=audit(1.0:1):`} {
		if p.Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := p.Parse(parsertest.Input("nothing", nil)); err == nil {
		t.Fatal("garbage should error")
	}
}
