package googleworkspace

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func act(app, events string) string {
	return `{"kind":"admin#reports#activity","id":{"time":"2024-06-01T09:15:32.123Z","uniqueQualifier":"q1","applicationName":"` + app + `","customerId":"C01"},"etag":"x","actor":{"callerType":"USER","email":"alice@example.com","profileId":"p1"},"ownerDomain":"example.com","ipAddress":"198.51.100.80","events":[` + events + `]}`
}

func TestLogin(t *testing.T) {
	e := parsertest.ParseOne(t, New(), act("login", `{"type":"login","name":"login_success","parameters":[{"name":"login_type","value":"google_password"},{"name":"is_suspicious","boolValue":false},{"name":"login_challenge_method","multiValue":["password","totp"]}]}`))
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.123Z", "event.dataset": "google_workspace.login", "event.id": "q1-0", "event.action": "login_success",
		"event.category": []string{"authentication"}, "event.type": []string{"start"}, "event.outcome": "success",
		"user.email": "alice@example.com", "user.name": "alice", "user.id": "p1", "source.ip": "198.51.100.80", "organization.id": "C01",
		"google_workspace.login.type": "google_password", "google_workspace.login.is_suspicious": false,
		"google_workspace.login.challenge_method": []string{"password", "totp"}, "google_workspace.event.type": "login",
	})
	e = parsertest.ParseOne(t, New(), act("login", `{"type":"login","name":"login_failure","parameters":[{"name":"login_failure_type","value":"login_failure_invalid_password"}]}`))
	parsertest.Expect(t, e, map[string]any{"event.outcome": "failure", "google_workspace.login.failure_type": "login_failure_invalid_password"})
}

func TestAdminDriveToken(t *testing.T) {
	evs, err := New().Parse(parsertest.Input(act("admin", `{"type":"USER_SETTINGS","name":"CREATE_USER","parameters":[{"name":"USER_EMAIL","value":"bob@example.com"}]},{"type":"APPLICATION_SETTINGS","name":"CHANGE_APPLICATION_SETTING","parameters":[{"name":"APPLICATION_NAME","value":"Drive and Docs"},{"name":"SETTING_NAME","value":"Sharing outside"},{"name":"NEW_VALUE","value":"ON"},{"name":"OLD_VALUE","value":"OFF"}]}`), nil))
	if err != nil || len(evs) != 2 {
		t.Fatalf("two events: %d %v", len(evs), err)
	}
	parsertest.Expect(t, evs[0], map[string]any{"event.category": []string{"iam"}, "event.type": []string{"creation"}, "user.target.email": "bob@example.com", "user.target.name": "bob", "event.id": "q1-0"})
	parsertest.Expect(t, evs[1], map[string]any{"event.category": []string{"configuration"}, "event.type": []string{"change"}, "google_workspace.admin.setting.new_value": "ON", "event.id": "q1-1"})
	e := parsertest.ParseOne(t, New(), act("drive", `{"type":"access","name":"download","parameters":[{"name":"doc_id","value":"d1"},{"name":"doc_title","value":"Budget"},{"name":"doc_type","value":"spreadsheet"},{"name":"owner","value":"carol@example.com"},{"name":"visibility","value":"private"},{"name":"primary_event","boolValue":true}]}`))
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"file"}, "event.type": []string{"access"}, "file.name": "Budget", "google_workspace.drive.visibility": "private", "google_workspace.drive.primary_event": true})
	e = parsertest.ParseOne(t, New(), act("token", `{"type":"auth","name":"authorize","parameters":[{"name":"client_id","value":"c-1"},{"name":"app_name","value":"Calendar Sync"},{"name":"scope","multiValue":["https://www.googleapis.com/auth/calendar"]},{"name":"num_response_bytes","intValue":"512"}]}`))
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"iam"}, "event.type": []string{"creation"}, "google_workspace.token.app_name": "Calendar Sync", "google_workspace.token.num_response_bytes": int64(512)})
	e = parsertest.ParseOne(t, New(), `{"items":[`+act("groups", `{"type":"acl_change","name":"add_member","parameters":[{"name":"group_email","value":"eng@example.com"},{"name":"member_email","value":"dave@example.com"}]}`)+`]}`)
	parsertest.Expect(t, e, map[string]any{"group.name": "eng@example.com", "user.target.email": "dave@example.com", "event.type": []string{"group", "change"}})
}

func TestDetectNegative(t *testing.T) {
	for _, s := range []string{`{"a":1}`, `{"eventType":"x","published":"y","actor":{}}`, `x`} {
		if New().Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := New().Parse(parsertest.Input(`{"items":[]}`, nil)); err == nil {
		t.Fatal("empty items should error")
	}
}
