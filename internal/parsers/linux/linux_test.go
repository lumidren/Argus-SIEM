package linux

import (
	"errors"
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func TestAuthSSH(t *testing.T) {
	p := New()
	cases := []struct {
		raw  string
		want map[string]any
	}{
		{`<38>Jun  1 09:00:01 web01 sshd[2001]: Accepted publickey for alice from 10.0.0.5 port 51234 ssh2: ED25519 SHA256:abc123`, map[string]any{
			"event.dataset": "linux.auth", "event.category": []string{"authentication"}, "event.type": []string{"start"},
			"event.action": "ssh_login", "event.outcome": "success", "user.name": "alice", "source.ip": "10.0.0.5",
			"source.port": int64(51234), "linux.auth.ssh.method": "publickey", "linux.auth.ssh.signature": "ED25519 SHA256:abc123",
			"host.name": "web01", "process.name": "sshd", "process.pid": int64(2001),
		}},
		{`<38>Jun  1 09:00:02 web01 sshd[2002]: Failed password for bob from 2001:db8::7 port 40022 ssh2`, map[string]any{
			"event.outcome": "failure", "user.name": "bob", "source.ip": "2001:db8::7", "linux.auth.ssh.method": "password",
		}},
		{`<38>Jun  1 09:00:03 web01 sshd[2003]: Failed password for invalid user guest from 10.0.0.9 port 40023 ssh2`, map[string]any{
			"event.outcome": "failure", "user.name": "guest", "linux.auth.ssh.invalid_user": true,
		}},
		{`<38>Jun  1 09:00:04 web01 sshd[2004]: Invalid user test from 10.0.0.9 port 40024`, map[string]any{
			"event.type": []string{"info"}, "user.name": "test", "linux.auth.ssh.invalid_user": true, "source.port": int64(40024),
		}},
		{`<38>Jun  1 09:00:05 web01 sshd[2005]: Connection closed by authenticating user carol 10.0.0.6 port 40025 [preauth]`, map[string]any{
			"event.category": []string{"network"}, "event.type": []string{"end"}, "user.name": "carol", "source.ip": "10.0.0.6",
		}},
		{`<38>Jun  1 09:00:06 web01 sshd[2006]: Disconnected from user alice 10.0.0.5 port 51234`, map[string]any{
			"event.action": "ssh_disconnect", "user.name": "alice",
		}},
		{`<38>Jun  1 09:00:07 web01 sshd[2007]: Received disconnect from 10.0.0.5 port 51234:11: disconnected by user`, map[string]any{
			"linux.auth.ssh.disconnect_code": "11",
		}},
		{`<38>Jun  1 09:00:08 web01 sshd[2008]: error: maximum authentication attempts exceeded for dave from 10.0.0.8 port 40026 ssh2 [preauth]`, map[string]any{
			"event.action": "ssh_max_auth_exceeded", "user.name": "dave", "event.outcome": "failure",
		}},
		{`<38>Jun  1 09:00:09 web01 sshd[2009]: pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)`, map[string]any{
			"event.category": []string{"session"}, "event.action": "session_opened", "user.name": "alice", "user.id": "1000",
			"linux.auth.pam.service": "sshd", "linux.auth.pam.by_uid": "0",
		}},
		{`<38>Jun  1 09:00:10 web01 sshd[2010]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=client.example.org  user=erin`, map[string]any{
			"event.action": "pam_auth", "event.outcome": "failure", "user.name": "erin", "source.domain": "client.example.org", "linux.auth.pam.tty": "ssh",
		}},
	}
	for _, c := range cases {
		parsertest.Expect(t, parsertest.ParseOne(t, p, c.raw), c.want)
	}
}

func TestAuthSudoSuAccounts(t *testing.T) {
	p := New()
	e := parsertest.ParseOne(t, p, `<85>Jun  1 09:10:00 web01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update`)
	parsertest.Expect(t, e, map[string]any{
		"event.category": []string{"process"}, "event.action": "sudo_command", "event.outcome": "success", "user.name": "alice",
		"user.effective.name": "root", "process.command_line": "/usr/bin/apt update", "process.executable": "/usr/bin/apt",
		"process.name": "apt", "process.working_directory": "/home/alice", "linux.auth.sudo.tty": "pts/0",
	})
	e = parsertest.ParseOne(t, p, `<85>Jun  1 09:10:01 web01 sudo: bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"authentication"}, "event.outcome": "failure", "linux.auth.sudo.attempts": int64(3)})
	e = parsertest.ParseOne(t, p, `<85>Jun  1 09:10:02 web01 sudo: carol : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/carol ; USER=root ; COMMAND=/usr/bin/id`)
	parsertest.Expect(t, e, map[string]any{"event.action": "sudo_denied", "event.type": []string{"denied"}, "linux.auth.sudo.error": "user NOT in sudoers"})

	e = parsertest.ParseOne(t, p, `<86>Jun  1 09:10:03 web01 su[3000]: (to root) alice on pts/0`)
	parsertest.Expect(t, e, map[string]any{"event.action": "su", "event.outcome": "success", "user.name": "alice", "user.effective.name": "root", "linux.auth.su.tty": "pts/0"})
	e = parsertest.ParseOne(t, p, `<86>Jun  1 09:10:04 web01 su[3001]: FAILED SU (to root) bob on pts/1`)
	parsertest.Expect(t, e, map[string]any{"event.outcome": "failure", "user.name": "bob"})
	e = parsertest.ParseOne(t, p, `<86>Jun  1 09:10:05 web01 su[3002]: pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)`)
	parsertest.Expect(t, e, map[string]any{"event.action": "su", "user.name": "alice", "user.effective.name": "root", "linux.auth.pam.by_uid": "1000"})

	e = parsertest.ParseOne(t, p, `<86>Jun  1 09:20:00 web01 useradd[4000]: new user: name=deploy, UID=1001, GID=1001, home=/home/deploy, shell=/bin/bash, from=/dev/pts/0`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"iam"}, "event.type": []string{"user", "creation"}, "user.target.name": "deploy", "user.target.id": "1001", "linux.auth.useradd.shell": "/bin/bash"})
	e = parsertest.ParseOne(t, p, `<86>Jun  1 09:20:01 web01 groupadd[4001]: new group: name=deploy, GID=1001`)
	parsertest.Expect(t, e, map[string]any{"event.action": "group_added", "group.name": "deploy", "group.id": "1001"})
	e = parsertest.ParseOne(t, p, `<86>Jun  1 09:20:02 web01 usermod[4002]: add 'deploy' to group 'docker'`)
	parsertest.Expect(t, e, map[string]any{"event.action": "user_added_to_group", "user.target.name": "deploy", "group.name": "docker"})
	e = parsertest.ParseOne(t, p, `<86>Jun  1 09:20:03 web01 userdel[4003]: delete user 'deploy'`)
	parsertest.Expect(t, e, map[string]any{"event.action": "user_deleted", "user.target.name": "deploy"})
	e = parsertest.ParseOne(t, p, `<86>Jun  1 09:20:04 web01 passwd[4004]: pam_unix(passwd:chauthtok): password changed for alice`)
	parsertest.Expect(t, e, map[string]any{"event.action": "password_changed", "user.target.name": "alice"})
	e = parsertest.ParseOne(t, p, `<38>Jun  1 09:20:05 web01 systemd-logind[700]: New session 42 of user alice.`)
	parsertest.Expect(t, e, map[string]any{"event.action": "session_opened", "user.name": "alice", "linux.auth.session.id": "42"})
	e = parsertest.ParseOne(t, p, `<78>Jun  1 09:20:06 web01 CRON[5000]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)`)
	parsertest.Expect(t, e, map[string]any{"event.action": "cron_session", "user.name": "root"})
}

func TestAuthUnmatchedIsPartial(t *testing.T) {
	evs, err := New().Parse(parsertest.Input(`<38>Jun  1 09:00:01 web01 sshd[1]: Server listening on 0.0.0.0 port 22.`, nil))
	if !errors.Is(err, ErrUnmatchedAuth) || len(evs) != 1 || evs[0].String("message") != "Server listening on 0.0.0.0 port 22." {
		t.Fatalf("unmatched handling: %v %d", err, len(evs))
	}
}

func TestAuditdExecveGroup(t *testing.T) {
	raw := "type=SYSCALL msg=audit(1717233332.123:4567): arch=c000003e syscall=59 success=yes exit=0 a0=55d4 a1=55d5 a2=55d6 a3=0 items=2 ppid=1234 pid=1235 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm=\"ls\" exe=\"/usr/bin/ls\" subj=unconfined key=\"exec\"\n" +
		"type=EXECVE msg=audit(1717233332.123:4567): argc=3 a0=\"ls\" a1=\"-la\" a2=2F746D702F6D7920646972\n" +
		"type=CWD msg=audit(1717233332.123:4567): cwd=\"/home/alice\"\n" +
		"type=PATH msg=audit(1717233332.123:4567): item=0 name=\"/usr/bin/ls\" inode=1311 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL\n" +
		"type=PROCTITLE msg=audit(1717233332.123:4567): proctitle=6C73002D6C61"
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.123Z", "event.dataset": "linux.auditd", "event.category": []string{"process"},
		"event.type": []string{"start"}, "event.action": "exec", "event.outcome": "success",
		"auditd.log.sequence": int64(4567), "auditd.log.record_type": "SYSCALL",
		"auditd.log.record_types": []string{"SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"},
		"auditd.log.syscall":      "execve", "auditd.log.arch": "x86_64", "process.pid": int64(1235), "process.parent.pid": int64(1234),
		"process.name": "ls", "process.executable": "/usr/bin/ls", "user.id": "0", "user.audit.id": "1000",
		"process.args": []string{"ls", "-la", "/tmp/my dir"}, "process.args_count": int64(3),
		"process.command_line": "ls -la /tmp/my dir", "process.working_directory": "/home/alice",
		"process.title": "ls -la", "file.path": "/usr/bin/ls", "file.inode": "1311", "auditd.log.key": "exec",
	})
}

func TestAuditdUserLoginAndSockaddr(t *testing.T) {
	raw := `type=USER_LOGIN msg=audit(1717233332.500:4600): pid=900 uid=0 auid=1000 ses=4 subj=unconfined msg='op=login acct="alice" exe="/usr/sbin/sshd" hostname=? addr=10.0.0.5 terminal=ssh res=success'`
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"event.category": []string{"authentication"}, "event.type": []string{"start"}, "event.outcome": "success",
		"user.name": "alice", "source.ip": "10.0.0.5", "process.name": "sshd", "auditd.log.op": "login", "auditd.log.terminal": "ssh",
		"event.action": "user_login",
	})
	raw = "type=SYSCALL msg=audit(1717233333.000:4601): arch=c00000b7 syscall=203 success=yes exit=0 items=0 ppid=1 pid=77 auid=4294967295 uid=33 gid=33 comm=\"curl\" exe=\"/usr/bin/curl\" key=(null)\n" +
		"type=SOCKADDR msg=audit(1717233333.000:4601): saddr=020001BBC0000201000000000000000000"
	e = parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"auditd.log.syscall": "connect", "auditd.log.arch": "aarch64", "event.category": []string{"network"},
		"destination.ip": "192.0.2.1", "destination.port": int64(443), "event.action": "syscall",
	})
	parsertest.ExpectAbsent(t, e, "user.audit.id", "auditd.log.key")
	raw = "type=SOCKADDR msg=audit(1717233333.000:4602): saddr=0A0001BB0000000020010DB800000000000000000000000100000000"
	e = parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{"destination.ip": "2001:db8::1", "destination.port": int64(443), "event.category": []string{"network"}})
}

func TestAuditdMultipleSerialsAndGoAudit(t *testing.T) {
	raw := "type=SERVICE_START msg=audit(1717233334.000:10): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=nginx comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" hostname=? addr=? terminal=? res=success'\n" +
		"type=ADD_USER msg=audit(1717233335.000:11): pid=4000 uid=0 auid=1000 ses=3 msg='op=add-user id=1001 exe=\"/usr/sbin/useradd\" hostname=web01 addr=? terminal=pts/0 res=success'"
	evs, err := New().Parse(parsertest.Input(raw, nil))
	if err != nil || len(evs) != 2 {
		t.Fatalf("want 2 events, got %d (%v)", len(evs), err)
	}
	parsertest.Expect(t, evs[0], map[string]any{"event.category": []string{"configuration"}, "event.type": []string{"start"}, "auditd.log.data.unit": "nginx"})
	parsertest.Expect(t, evs[1], map[string]any{"event.category": []string{"iam"}, "event.type": []string{"creation"}, "user.target.id": "1001"})

	goaudit := `{"sequence":4567,"timestamp":"1717233332.123","messages":[{"type":1300,"data":"arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=2 auid=1000 uid=1000 comm=\"id\" exe=\"/usr/bin/id\""},{"type":1309,"data":"argc=1 a0=\"id\""}],"uid_map":{"1000":"alice"}}`
	if !New().Detect([]byte(goaudit), nil) {
		t.Fatal("go-audit not detected")
	}
	e := parsertest.ParseOne(t, New(), goaudit)
	parsertest.Expect(t, e, map[string]any{"auditd.log.syscall": "execve", "process.command_line": "id", "user.name": "alice", "@timestamp": "2024-06-01T09:15:32.123Z"})
}

func TestJournald(t *testing.T) {
	p := New()
	e := parsertest.ParseOne(t, p, `{"__REALTIME_TIMESTAMP":"1717233332123456","MESSAGE":"Started Daily apt download activities.","_COMM":"systemd","_PID":"1","_UID":"0","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"systemd","PRIORITY":"6","_SYSTEMD_UNIT":"init.scope","_BOOT_ID":"b1","_TRANSPORT":"journal"}`)
	parsertest.Expect(t, e, map[string]any{
		"event.dataset": "linux.journald", "@timestamp": "2024-06-01T09:15:32.123Z", "message": "Started Daily apt download activities.",
		"process.name": "systemd", "process.pid": int64(1), "host.name": "web01", "log.level": "informational", "journald.unit": "init.scope",
	})
	e = parsertest.ParseOne(t, p, `{"__REALTIME_TIMESTAMP":"1717233332123456","MESSAGE":"Accepted password for alice from 10.0.0.5 port 2222 ssh2","_COMM":"sshd","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"6","_HOSTNAME":"web01"}`)
	parsertest.Expect(t, e, map[string]any{"event.dataset": "linux.journald", "event.action": "ssh_login", "user.name": "alice", "source.port": int64(2222)})
	e = parsertest.ParseOne(t, p, `{"__REALTIME_TIMESTAMP":"1717233332123456","_TRANSPORT":"audit","_AUDIT_TYPE":"1112","MESSAGE":"type=USER_LOGIN msg=audit(1717233332.500:4600): pid=900 uid=0 msg='op=login acct=\"alice\" res=success'"}`)
	parsertest.Expect(t, e, map[string]any{"event.dataset": "linux.auditd", "user.name": "alice"})
	e = parsertest.ParseOne(t, p, `{"__REALTIME_TIMESTAMP":"1717233332123456","MESSAGE":"disk almost full","PRIORITY":"3"}`)
	parsertest.Expect(t, e, map[string]any{"log.level": "error"})
}

func TestDetect(t *testing.T) {
	p := New()
	for _, s := range []string{
		`<38>Jun  1 09:00:01 web01 sshd[1]: Accepted publickey for alice from 10.0.0.5 port 1 ssh2`,
		`type=SYSCALL msg=audit(1717233332.123:1): arch=c000003e`,
		`{"__REALTIME_TIMESTAMP":"1","MESSAGE":"x"}`,
	} {
		if !p.Detect([]byte(s), nil) {
			t.Errorf("should detect %q", s)
		}
	}
	for _, s := range []string{
		`203.0.113.7 - - [01/Jun/2024:09:15:32 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`,
		`{"a":1}`, `{"event_type":"alert"}`, `<Event><System></System></Event>`, ``,
		`<134>Jun  1 09:15:32 app01 billing: invoice generated`,
	} {
		if p.Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := p.Parse(parsertest.Input(`type=SYSCALL no header`, nil)); err == nil {
		t.Fatal("bad audit should error")
	}
}
