package linux

import (
	"regexp"
	"strings"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

type authRule struct {
	re    *regexp.Regexp
	apply func(e *schema.Event, m map[string]string)
}

func named(re *regexp.Regexp, s string) map[string]string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for i, n := range re.SubexpNames() {
		if n != "" && i < len(m) {
			out[n] = m[i]
		}
	}
	return out
}

func setAddr(e *schema.Event, ipKey, domainKey, v string) {
	if v == "" {
		return
	}
	if !parsers.SetIP(e, ipKey, v) {
		e.Set(domainKey, v)
	}
}

func auth(e *schema.Event, action, outcome string, types ...string) {
	e.SetCategory(schema.CategoryAuthentication)
	if len(types) == 0 {
		types = []string{schema.TypeStart}
	}
	e.SetTypes(types...)
	e.Set(schema.FieldEventAction, action)
	if outcome != "" {
		e.Set(schema.FieldEventOutcome, outcome)
	}
}

var sshRules = []authRule{
	{regexp.MustCompile(`^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?(?:: (?P<sig>.+))?$`), func(e *schema.Event, m map[string]string) {
		auth(e, "ssh_login", schema.OutcomeSuccess)
		e.Set("user.name", m["user"])
		setAddr(e, "source.ip", "source.address", m["ip"])
		parsers.SetPort(e, "source.port", m["port"])
		e.Set("linux.auth.ssh.method", m["method"])
		e.Set("linux.auth.ssh.signature", m["sig"])
	}},
	{regexp.MustCompile(`^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)`), func(e *schema.Event, m map[string]string) {
		auth(e, "ssh_login", schema.OutcomeFailure)
		e.Set("user.name", m["user"])
		setAddr(e, "source.ip", "source.address", m["ip"])
		parsers.SetPort(e, "source.port", m["port"])
		e.Set("linux.auth.ssh.method", m["method"])
		if m["invalid"] != "" {
			e.Set("linux.auth.ssh.invalid_user", true)
		}
	}},
	{regexp.MustCompile(`^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?$`), func(e *schema.Event, m map[string]string) {
		auth(e, "ssh_login", schema.OutcomeFailure, schema.TypeInfo)
		e.Set("user.name", m["user"])
		setAddr(e, "source.ip", "source.address", m["ip"])
		parsers.SetPort(e, "source.port", m["port"])
		e.Set("linux.auth.ssh.invalid_user", true)
	}},
	{regexp.MustCompile(`^Connection closed by (?:(?:invalid|authenticating) user (?P<user>\S+) )?(?P<ip>\S+) port (?P<port>\d+)`), func(e *schema.Event, m map[string]string) {
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeEnd)
		e.Set(schema.FieldEventAction, "ssh_disconnect")
		e.Set("user.name", m["user"])
		setAddr(e, "source.ip", "source.address", m["ip"])
		parsers.SetPort(e, "source.port", m["port"])
	}},
	{regexp.MustCompile(`^Disconnected from (?:(?:invalid|authenticating) )?(?:user (?P<user>\S+) )?(?P<ip>\S+) port (?P<port>\d+)`), func(e *schema.Event, m map[string]string) {
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeEnd)
		e.Set(schema.FieldEventAction, "ssh_disconnect")
		e.Set("user.name", m["user"])
		setAddr(e, "source.ip", "source.address", m["ip"])
		parsers.SetPort(e, "source.port", m["port"])
	}},
	{regexp.MustCompile(`^Received disconnect from (?P<ip>\S+) port (?P<port>\d+):(?P<code>\d+): (?P<text>.*)$`), func(e *schema.Event, m map[string]string) {
		e.SetCategory(schema.CategoryNetwork)
		e.SetTypes(schema.TypeEnd)
		e.Set(schema.FieldEventAction, "ssh_disconnect")
		setAddr(e, "source.ip", "source.address", m["ip"])
		parsers.SetPort(e, "source.port", m["port"])
		e.Set("linux.auth.ssh.disconnect_code", m["code"])
	}},
	{regexp.MustCompile(`^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)`), func(e *schema.Event, m map[string]string) {
		auth(e, "ssh_max_auth_exceeded", schema.OutcomeFailure, schema.TypeInfo)
		e.Set("user.name", m["user"])
		setAddr(e, "source.ip", "source.address", m["ip"])
		parsers.SetPort(e, "source.port", m["port"])
	}},
	{regexp.MustCompile(`^error: PAM: Authentication failure for (?:illegal user )?(?P<user>\S+) from (?P<host>\S+)`), func(e *schema.Event, m map[string]string) {
		auth(e, "ssh_login", schema.OutcomeFailure)
		e.Set("user.name", m["user"])
		e.Set("source.address", m["host"])
		parsers.SetIP(e, "source.ip", m["host"])
	}},
}

var (
	pamSessionOpen  = regexp.MustCompile(`^pam_unix\((?P<svc>[^:]+):session\): session opened for user (?P<user>[^\s(]+)(?:\(uid=(?P<uid>\d+)\))? by (?P<by>[^\s(]*)\(uid=(?P<byuid>\d+)\)`)
	pamSessionClose = regexp.MustCompile(`^pam_unix\((?P<svc>[^:]+):session\): session closed for user (?P<user>\S+)`)
	pamAuthFail     = regexp.MustCompile(`^pam_unix\((?P<svc>[^:]+):auth\): authentication failure; (?P<kv>.*)$`)
	sudoCmd         = regexp.MustCompile(`^\s*(?P<user>\S+) : (?:(?P<fail>\d+) incorrect password attempts? ; |(?P<err>user NOT in sudoers|command not allowed|user NOT authorized on host) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; USER=(?P<target>\S+) ;(?: GROUP=\S+ ;)?(?: ENV=.*? ;)? COMMAND=(?P<cmd>.*)$`)
	suTo            = regexp.MustCompile(`^(?P<fail>FAILED SU )?\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)`)
	useraddUser     = regexp.MustCompile(`^new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), home=(?P<home>[^,]+), shell=(?P<shell>[^,]+)`)
	useraddGroup    = regexp.MustCompile(`^new group: name=(?P<name>[^,]+), GID=(?P<gid>\d+)`)
	userdelUser     = regexp.MustCompile(`^delete user '(?P<name>[^']+)'`)
	userdelGroup    = regexp.MustCompile(`^(?:removed group|group) '(?P<name>[^']+)'(?: removed)?`)
	usermodAdd      = regexp.MustCompile(`^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'`)
	passwdChanged   = regexp.MustCompile(`^pam_unix\(passwd:chauthtok\): password changed for (?P<user>\S+)`)
	chageChanged    = regexp.MustCompile(`^changed password expiry for (?P<user>\S+)`)
	logindNew       = regexp.MustCompile(`^New session (?P<id>\S+) of user (?P<user>[^\s.]+)\.?`)
	logindRemoved   = regexp.MustCompile(`^Removed session (?P<id>\S+)\.?`)
)

func matchAuth(e *schema.Event, app, msg string) bool {
	switch app {
	case "sshd":
		for _, r := range sshRules {
			if m := named(r.re, msg); m != nil {
				r.apply(e, m)
				return true
			}
		}
	case "sudo":
		if m := named(sudoCmd, msg); m != nil {
			applySudo(e, m)
			return true
		}
	case "su":
		if m := named(suTo, msg); m != nil {
			outcome := schema.OutcomeSuccess
			if m["fail"] != "" {
				outcome = schema.OutcomeFailure
			}
			auth(e, "su", outcome)
			e.Set("user.name", m["user"])
			e.Set("user.effective.name", m["target"])
			e.Set("linux.auth.su.tty", m["tty"])
			return true
		}
	case "useradd", "groupadd":
		if m := named(useraddUser, msg); m != nil {
			e.SetCategory(schema.CategoryIAM)
			e.SetTypes(schema.TypeUser, schema.TypeCreation)
			e.Set(schema.FieldEventAction, "user_added")
			e.Set("user.target.name", m["name"])
			e.Set("user.target.id", m["uid"])
			e.Set("user.target.group.id", m["gid"])
			e.Set("linux.auth.useradd.home", m["home"])
			e.Set("linux.auth.useradd.shell", m["shell"])
			return true
		}
		if m := named(useraddGroup, msg); m != nil {
			e.SetCategory(schema.CategoryIAM)
			e.SetTypes(schema.TypeGroup, schema.TypeCreation)
			e.Set(schema.FieldEventAction, "group_added")
			e.Set("group.name", m["name"])
			e.Set("group.id", m["gid"])
			return true
		}
	case "userdel", "groupdel":
		if m := named(userdelUser, msg); m != nil {
			e.SetCategory(schema.CategoryIAM)
			e.SetTypes(schema.TypeUser, schema.TypeDeletion)
			e.Set(schema.FieldEventAction, "user_deleted")
			e.Set("user.target.name", m["name"])
			return true
		}
		if m := named(userdelGroup, msg); m != nil {
			e.SetCategory(schema.CategoryIAM)
			e.SetTypes(schema.TypeGroup, schema.TypeDeletion)
			e.Set(schema.FieldEventAction, "group_deleted")
			e.Set("group.name", m["name"])
			return true
		}
	case "usermod", "gpasswd":
		if m := named(usermodAdd, msg); m != nil {
			e.SetCategory(schema.CategoryIAM)
			e.SetTypes(schema.TypeGroup, schema.TypeChange)
			e.Set(schema.FieldEventAction, "user_added_to_group")
			e.Set("user.target.name", m["user"])
			e.Set("group.name", m["group"])
			return true
		}
	case "chage":
		if m := named(chageChanged, msg); m != nil {
			e.SetCategory(schema.CategoryIAM)
			e.SetTypes(schema.TypeUser, schema.TypeChange)
			e.Set(schema.FieldEventAction, "password_expiry_changed")
			e.Set("user.target.name", m["user"])
			return true
		}
	case "systemd-logind":
		if m := named(logindNew, msg); m != nil {
			e.SetCategory(schema.CategorySession)
			e.SetTypes(schema.TypeStart)
			e.Set(schema.FieldEventAction, "session_opened")
			e.Set("user.name", m["user"])
			e.Set("linux.auth.session.id", m["id"])
			return true
		}
		if m := named(logindRemoved, msg); m != nil {
			e.SetCategory(schema.CategorySession)
			e.SetTypes(schema.TypeEnd)
			e.Set(schema.FieldEventAction, "session_closed")
			e.Set("linux.auth.session.id", m["id"])
			return true
		}
	}
	// PAM lines can come from any program (sshd, sudo, cron, login, ...).
	if m := named(passwdChanged, msg); m != nil {
		e.SetCategory(schema.CategoryIAM)
		e.SetTypes(schema.TypeUser, schema.TypeChange)
		e.Set(schema.FieldEventAction, "password_changed")
		e.Set("user.target.name", m["user"])
		return true
	}
	if m := named(pamSessionOpen, msg); m != nil {
		e.SetCategory(schema.CategorySession)
		e.SetTypes(schema.TypeStart)
		action := "session_opened"
		if strings.EqualFold(m["svc"], "cron") {
			action = "cron_session"
		}
		e.Set(schema.FieldEventAction, action)
		e.Set("user.name", m["user"])
		e.Set("user.id", m["uid"])
		e.Set("linux.auth.pam.service", m["svc"])
		e.Set("linux.auth.pam.by_user", m["by"])
		e.Set("linux.auth.pam.by_uid", m["byuid"])
		if m["svc"] == "su" || m["svc"] == "su-l" {
			auth(e, "su", schema.OutcomeSuccess)
			e.Set("user.name", m["by"])
			e.Set("user.effective.name", m["user"])
		}
		return true
	}
	if m := named(pamSessionClose, msg); m != nil {
		e.SetCategory(schema.CategorySession)
		e.SetTypes(schema.TypeEnd)
		e.Set(schema.FieldEventAction, "session_closed")
		e.Set("user.name", m["user"])
		e.Set("linux.auth.pam.service", m["svc"])
		return true
	}
	if m := named(pamAuthFail, msg); m != nil {
		auth(e, "pam_auth", schema.OutcomeFailure)
		e.Set("linux.auth.pam.service", m["svc"])
		_, kv := parsers.ParseKV(m["kv"])
		e.Set("user.name", kv["user"])
		setAddr(e, "source.ip", "source.domain", kv["rhost"])
		e.Set("linux.auth.pam.tty", kv["tty"])
		e.Set("linux.auth.pam.ruser", kv["ruser"])
		e.Set("linux.auth.pam.logname", kv["logname"])
		return true
	}
	return false
}

func applySudo(e *schema.Event, m map[string]string) {
	cmd := strings.TrimSpace(m["cmd"])
	e.Set("user.name", m["user"])
	e.Set("user.effective.name", m["target"])
	e.Set("process.command_line", cmd)
	exe := cmd
	if i := strings.IndexByte(cmd, ' '); i > 0 {
		exe = cmd[:i]
	}
	parsers.SetProcessExecutable(e, "process", exe)
	e.Set("process.working_directory", m["pwd"])
	e.Set("linux.auth.sudo.tty", m["tty"])
	switch {
	case m["fail"] != "":
		auth(e, "sudo_command", schema.OutcomeFailure)
		parsers.SetInt(e, "linux.auth.sudo.attempts", m["fail"])
	case m["err"] != "":
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeDenied)
		e.Set(schema.FieldEventAction, "sudo_denied")
		e.Set(schema.FieldEventOutcome, schema.OutcomeFailure)
		e.Set("linux.auth.sudo.error", m["err"])
	default:
		e.SetCategory(schema.CategoryProcess)
		e.SetTypes(schema.TypeStart)
		e.Set(schema.FieldEventAction, "sudo_command")
		e.Set(schema.FieldEventOutcome, schema.OutcomeSuccess)
	}
}
