package o365

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func TestLogin(t *testing.T) {
	raw := `{"CreationTime":"2024-06-01T09:15:32","Id":"id-1","Operation":"UserLoggedIn","OrganizationId":"org-1","RecordType":15,"ResultStatus":"Success","UserKey":"uk-1","UserType":0,"Version":1,"Workload":"AzureActiveDirectory","ClientIP":"198.51.100.70","ObjectId":"00000002-0000-0ff1-ce00-000000000000","UserId":"alice@example.com","ExtendedProperties":[{"Name":"UserAgent","Value":"Mozilla/5.0"},{"Name":"RequestType","Value":"OAuth2:Authorize"}],"ApplicationId":"app-1"}`
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.000Z", "event.dataset": "o365.audit", "event.action": "UserLoggedIn", "event.code": "15",
		"event.category": []string{"authentication"}, "event.type": []string{"start"}, "event.outcome": "success",
		"o365.audit.record_type_name": "AzureActiveDirectoryStsLogon", "user.name": "alice", "user.email": "alice@example.com",
		"user.id": "uk-1", "o365.audit.user_type_name": "Regular", "source.ip": "198.51.100.70", "user_agent.original": "Mozilla/5.0",
		"o365.audit.extended_properties.RequestType": "OAuth2:Authorize", "o365.audit.application_id": "app-1", "organization.id": "org-1",
	})
	e = parsertest.ParseOne(t, New(), `{"CreationTime":"2024-06-01T09:16:00","Id":"id-2","Operation":"UserLoginFailed","RecordType":15,"ResultStatus":"Failed","UserId":"bob@example.com","ClientIP":"[2001:db8::7]:443","LogonError":"InvalidUserNameOrPassword"}`)
	parsertest.Expect(t, e, map[string]any{"event.outcome": "failure", "source.ip": "2001:db8::7", "o365.audit.logon_error": "InvalidUserNameOrPassword"})
}

func TestAdminAndExchange(t *testing.T) {
	raw := `[{"CreationTime":"2024-06-01T09:20:00","Id":"id-3","Operation":"Add member to role.","RecordType":8,"ResultStatus":"Success","UserId":"admin@example.com","ModifiedProperties":[{"Name":"Role.DisplayName","NewValue":"Reports Reader","OldValue":""}],"Target":[{"ID":"carol@example.com","Type":5}],"Actor":[{"ID":"admin@example.com","Type":5}]},` +
		`{"CreationTime":"2024-06-01T09:21:00","Id":"id-4","Operation":"New-InboxRule","RecordType":1,"ResultStatus":"True","UserId":"dave@example.com","ClientIP":"198.51.100.71:51234","Parameters":[{"Name":"Name","Value":"Archive newsletters"},{"Name":"MoveToFolder","Value":"Newsletters"}]},` +
		`{"CreationTime":"2024-06-01T09:22:00","Id":"id-5","Operation":"FileDownloaded","RecordType":6,"Workload":"SharePoint","UserId":"erin@example.com","ObjectId":"https://example.sharepoint.com/sites/team/Shared Documents/plan.docx","SourceFileName":"plan.docx","SourceFileExtension":"docx","SourceRelativeUrl":"Shared Documents","SiteUrl":"https://example.sharepoint.com/sites/team/"}]`
	evs, err := New().Parse(parsertest.Input(raw, nil))
	if err != nil || len(evs) != 3 {
		t.Fatalf("array: %d %v", len(evs), err)
	}
	parsertest.Expect(t, evs[0], map[string]any{
		"event.category": []string{"iam"}, "event.type": []string{"change"},
		"o365.audit.modified_properties.Role_DisplayName.new_value": "Reports Reader",
	})
	if !evs[0].Has("o365.audit.target") || !evs[0].Has("o365.audit.actor") {
		t.Fatal("actor/target arrays")
	}
	parsertest.Expect(t, evs[1], map[string]any{
		"event.category": []string{"configuration"}, "event.type": []string{"creation"}, "event.outcome": "success",
		"o365.audit.parameters.MoveToFolder": "Newsletters", "source.ip": "198.51.100.71",
		"o365.audit.parameters_text": `[{"Name":"Name","Value":"Archive newsletters"},{"Name":"MoveToFolder","Value":"Newsletters"}]`,
	})
	parsertest.Expect(t, evs[2], map[string]any{
		"event.category": []string{"file"}, "file.name": "plan.docx", "file.extension": "docx", "file.path": "Shared Documents/plan.docx",
		"url.domain": "example.sharepoint.com", "o365.audit.site_url": "https://example.sharepoint.com/sites/team/",
	})
	e := parsertest.ParseOne(t, New(), `{"content":[{"CreationTime":"2024-06-01T09:23:00","Id":"id-6","Operation":"MemberAdded","RecordType":25,"Workload":"MicrosoftTeams","UserId":"frank@example.com","TeamName":"Project X"}]}`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"iam"}, "o365.audit.team_name": "Project X", "o365.audit.record_type_name": "MicrosoftTeams"})
}

func TestDetectNegative(t *testing.T) {
	for _, s := range []string{`{"a":1}`, `{"eventType":"x","published":"y","actor":{}}`, `x`} {
		if New().Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := New().Parse(parsertest.Input(`[{"x":1}]`, nil)); err == nil {
		t.Fatal("no records should error")
	}
}
