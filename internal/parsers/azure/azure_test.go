package azure

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func TestSignIn(t *testing.T) {
	raw := `{"records":[{"time":"2024-06-01T09:15:32.0000000Z","resourceId":"/tenants/t-1/providers/Microsoft.aadiam","operationName":"Sign-in activity","category":"SignInLogs","tenantId":"t-1","resultType":"0","resultSignature":"None","callerIpAddress":"198.51.100.40","correlationId":"c-1","properties":{"id":"s-1","userPrincipalName":"alice@example.com","userId":"u-1","userDisplayName":"Alice Example","appId":"a-1","appDisplayName":"Office 365","ipAddress":"198.51.100.40","clientAppUsed":"Browser","conditionalAccessStatus":"success","isInteractive":true,"riskLevelDuringSignIn":"none","location":{"city":"Lisbon","state":"Lisboa","countryOrRegion":"PT","geoCoordinates":{"latitude":38.72,"longitude":-9.14}},"deviceDetail":{"operatingSystem":"Windows 10","browser":"Edge 125","isCompliant":true},"status":{"errorCode":0},"appliedConditionalAccessPolicies":[{"displayName":"Require MFA","result":"success"}]}}]}`
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.000Z", "event.dataset": "azure.signinlogs", "event.category": []string{"authentication"},
		"event.type": []string{"start"}, "event.outcome": "success", "user.name": "alice@example.com", "user.email": "alice@example.com",
		"user.id": "u-1", "user.full_name": "Alice Example", "source.ip": "198.51.100.40", "source.geo.city_name": "Lisbon",
		"source.geo.country_iso_code": "PT", "azure.tenant_id": "t-1", "cloud.provider": "azure", "event.id": "s-1",
		"azure.signinlogs.properties.app_display_name": "Office 365", "azure.signinlogs.properties.device_detail.is_compliant": true,
		"azure.signinlogs.properties.status.error_code": int64(0), "azure.signinlogs.category": "SignInLogs",
	})
	if !e.Has("azure.signinlogs.properties.applied_conditional_access_policies") {
		t.Fatal("CA policies missing")
	}
	raw = `{"time":"2024-06-01T09:16:00Z","operationName":"Sign-in activity","category":"NonInteractiveUserSignInLogs","tenantId":"t-1","resultType":"50126","resultDescription":"Invalid username or password","properties":{"userPrincipalName":"bob@example.com","ipAddress":"198.51.100.41","isInteractive":false,"status":{"errorCode":50126,"failureReason":"Invalid username or password."}}}`
	e = parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{"event.outcome": "failure", "event.type": []string{"info"}, "azure.signinlogs.result_type": "50126", "azure.signinlogs.properties.status.failure_reason": "Invalid username or password."})
	raw = `{"id":"g-1","createdDateTime":"2024-06-01T09:17:00Z","userPrincipalName":"carol@example.com","appDisplayName":"Azure Portal","ipAddress":"198.51.100.42","status":{"errorCode":0},"isInteractive":true}`
	e = parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{"event.outcome": "success", "user.name": "carol@example.com", "event.id": "g-1"})
}

func TestAuditAndActivity(t *testing.T) {
	raw := `{"time":"2024-06-01T09:20:00Z","category":"AuditLogs","operationName":"Add member to role","tenantId":"t-1","properties":{"id":"d-1","activityDisplayName":"Add member to role","category":"RoleManagement","result":"success","loggedByService":"Core Directory","initiatedBy":{"user":{"id":"u-1","userPrincipalName":"alice@example.com","ipAddress":"198.51.100.40"}},"targetResources":[{"id":"u-2","type":"User","userPrincipalName":"dave@example.com","modifiedProperties":[{"displayName":"Role.DisplayName","oldValue":"\"\"","newValue":"\"Reports Reader\""}]}]}}`
	e := parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"event.dataset": "azure.auditlogs", "event.category": []string{"iam"}, "event.type": []string{"creation"}, "event.outcome": "success",
		"user.name": "alice@example.com", "source.ip": "198.51.100.40", "user.target.name": "dave@example.com", "user.target.id": "u-2",
		"azure.auditlogs.properties.logged_by_service": "Core Directory",
	})
	raw = `{"time":"2024-06-01T09:21:00Z","category":"AuditLogs","properties":{"activityDisplayName":"Update application","category":"ApplicationManagement","result":"success","initiatedBy":{"app":{"displayName":"Provisioning Service","servicePrincipalId":"sp-1"}}}}`
	e = parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{"user.name": "Provisioning Service", "event.type": []string{"change"}})

	raw = `{"time":"2024-06-01T09:22:00Z","resourceId":"/SUBSCRIPTIONS/sub-1/RESOURCEGROUPS/rg-app/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/vm-01","operationName":"MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE","category":"Administrative","resultType":"Success","callerIpAddress":"198.51.100.43","correlationId":"c-2","level":"Information","identity":{"claims":{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":"alice@example.com","http://schemas.microsoft.com/identity/claims/objectidentifier":"u-1"},"authorization":{"scope":"/subscriptions/sub-1","action":"Microsoft.Compute/virtualMachines/write"}},"properties":{"statusCode":"Created","eventCategory":"Administrative"}}`
	e = parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{
		"event.dataset": "azure.activitylogs", "event.category": []string{"configuration"}, "event.type": []string{"change"},
		"event.outcome": "success", "user.name": "alice@example.com", "user.id": "u-1", "azure.subscription_id": "sub-1",
		"azure.resource.group": "rg-app", "azure.resource.provider": "MICROSOFT.COMPUTE/VIRTUALMACHINES", "azure.resource.name": "vm-01",
		"azure.activitylogs.properties.status_code": "Created", "azure.activitylogs.identity.authorization.action": "Microsoft.Compute/virtualMachines/write",
	})
	raw = `{"time":"2024-06-01T09:23:00Z","operationName":"MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/DELETE","category":"Administrative","resultType":"Failure","tenantId":"t-1"}`
	e = parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"iam"}, "event.type": []string{"deletion"}, "event.outcome": "failure"})
}

func TestDetect(t *testing.T) {
	p := New()
	for _, s := range []string{`{"a":1}`, `{"eventVersion":"1","eventSource":"x","eventName":"y","operationName":"z","resourceId":"r"}`, `x`} {
		if p.Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := p.Parse(parsertest.Input(`{"records":[{"foo":1}]}`, nil)); err == nil {
		t.Fatal("unclassifiable should error")
	}
}
