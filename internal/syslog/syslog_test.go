package syslog

import (
	"testing"
	"time"
)

var ref = time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

func TestParse5424(t *testing.T) {
	raw := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][other@1 a="x\"y"] ` + "\xef\xbb\xbf" + `An application event log entry...`
	h, err := Parse([]byte(raw), ref)
	if err != nil {
		t.Fatal(err)
	}
	if h.Format != "rfc5424" || h.Priority != 165 || h.Facility != 20 || h.Severity != 5 {
		t.Fatalf("header %+v", h)
	}
	if h.Hostname != "mymachine.example.com" || h.AppName != "evntslog" || h.ProcID != "1234" || h.MsgID != "ID47" {
		t.Fatalf("fields %+v", h)
	}
	if h.StructuredData["exampleSDID@32473"]["eventID"] != "1011" || h.StructuredData["other@1"]["a"] != `x"y` {
		t.Fatalf("sd %+v", h.StructuredData)
	}
	if h.Message != "An application event log entry..." {
		t.Fatalf("msg %q", h.Message)
	}
	if h.Timestamp.Format(time.RFC3339Nano) != "2003-10-11T22:14:15.003Z" {
		t.Fatalf("ts %v", h.Timestamp)
	}
	// nil values
	h, err = Parse([]byte(`<34>1 - - - - - - plain`), ref)
	if err != nil || h.Message != "plain" || h.Hostname != "" {
		t.Fatalf("nil fields: %+v %v", h, err)
	}
}

func TestParse3164Variants(t *testing.T) {
	cases := []struct {
		in                     string
		host, app, pid, msg    string
		year, month, day, hour int
	}{
		{`<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8`, "mymachine", "su", "", "'su root' failed for lonvick on /dev/pts/8", 2023, 10, 11, 22},
		{`<86>Jun  1 09:00:01 web01 sshd[12345]: Accepted publickey for alice from 10.0.0.5 port 51234 ssh2`, "web01", "sshd", "12345", "Accepted publickey for alice from 10.0.0.5 port 51234 ssh2", 2024, 6, 1, 9},
		{`Jun  1 09:00:01 web01 sshd[12345]: no pri`, "web01", "sshd", "12345", "no pri", 2024, 6, 1, 9},
		{`<13>Jun  1 09:00:01 CRON[1]: no host`, "", "CRON", "1", "no host", 2024, 6, 1, 9},
		{`<13>2024-06-01T09:00:01.123456+02:00 host2 app: iso timestamp`, "host2", "app", "", "iso timestamp", 2024, 6, 1, 7},
		{`<13>Jun 1 2024 09:00:01 host3 app[7]: with year`, "host3", "app", "7", "with year", 2024, 6, 1, 9},
		{`<134>Jun  1 09:00:01 fw01 message without tag`, "fw01", "", "", "message without tag", 2024, 6, 1, 9},
		{`<189>Jun  1 09:00:01 10.0.0.1 %ASA-6-302013: Built inbound TCP connection`, "10.0.0.1", "%ASA-6-302013", "", "Built inbound TCP connection", 2024, 6, 1, 9},
	}
	for _, c := range cases {
		h, err := Parse([]byte(c.in), ref)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if h.Hostname != c.host || h.AppName != c.app || h.ProcID != c.pid || h.Message != c.msg {
			t.Errorf("%q:\n got host=%q app=%q pid=%q msg=%q\nwant host=%q app=%q pid=%q msg=%q", c.in, h.Hostname, h.AppName, h.ProcID, h.Message, c.host, c.app, c.pid, c.msg)
		}
		if h.Timestamp.Year() != c.year || int(h.Timestamp.Month()) != c.month || h.Timestamp.Day() != c.day || h.Timestamp.Hour() != c.hour {
			t.Errorf("%q: time %v", c.in, h.Timestamp)
		}
	}
}

func TestParseBareAndPriOnly(t *testing.T) {
	h, err := Parse([]byte(`just a line`), ref)
	if err != ErrNoHeader || h.Message != "just a line" || h.Format != "bare" {
		t.Fatalf("bare: %+v %v", h, err)
	}
	h, err = Parse([]byte(`<134>CEF:0|Vendor|Product|1.0|100|Name|5|src=1.2.3.4`), ref)
	if err != nil || h.Priority != 134 || h.Message != `CEF:0|Vendor|Product|1.0|100|Name|5|src=1.2.3.4` {
		t.Fatalf("pri-only: %+v %v", h, err)
	}
	// leading octet count not stripped by framer
	h, err = Parse([]byte(`25 <34>1 - - - - - - octet`), ref)
	if err != nil || h.Message != "octet" {
		t.Fatalf("octet prefix: %+v %v", h, err)
	}
}

func TestFrame(t *testing.T) {
	buf := []byte("11 <34>1 hello\n<34>second line\r\n13 <34>partial")
	msg, n, ok, err := Frame(buf)
	if err != nil || !ok || string(msg) != "<34>1 hello" || n != 14 {
		t.Fatalf("octet frame: %q %d %v %v", msg, n, ok, err)
	}
	buf = buf[n:]
	// the octet-counted message consumed exactly 11 bytes; the "\n" that
	// follows is leftover and must be skipped as an empty newline frame
	msg, n, ok, _ = Frame(buf)
	if !ok || len(msg) != 0 || n != 1 {
		t.Fatalf("empty frame: %q %d %v", msg, n, ok)
	}
	buf = buf[n:]
	msg, n, ok, _ = Frame(buf)
	if !ok || string(msg) != "<34>second line" {
		t.Fatalf("newline frame: %q %v", msg, ok)
	}
	buf = buf[n:]
	_, _, ok, err = Frame(buf)
	if ok || err != nil {
		t.Fatalf("partial should need more data: %v %v", ok, err)
	}
	_, _, _, err = Frame([]byte("99999999 x"))
	if err != ErrFrameTooLarge {
		t.Fatalf("size guard: %v", err)
	}
}

func TestApply(t *testing.T) {
	h, _ := Parse([]byte(`<86>1 2024-06-01T09:00:01Z web01 sshd 12345 - [meta seq="1"] msg`), ref)
	e := newEvent()
	Apply(e, h)
	if e.String("host.name") != "web01" || e.String("process.name") != "sshd" || e.String("log.level") != "informational" {
		t.Fatalf("apply %v", e.Flat())
	}
	if pid, _ := e.Int64("process.pid"); pid != 12345 {
		t.Fatal("pid")
	}
	if e.String("log.syslog.structured_data.meta.seq") != "1" {
		t.Fatal("sd")
	}
	if e.String("log.syslog.facility.name") != "security/authorization" {
		t.Fatalf("facility %s", e.String("log.syslog.facility.name"))
	}
}
