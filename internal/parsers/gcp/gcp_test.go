package gcp

import (
	"encoding/base64"
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

const setIAM = `{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","status":{},"authenticationInfo":{"principalEmail":"alice@example.com"},"requestMetadata":{"callerIp":"198.51.100.50","callerSuppliedUserAgent":"google-cloud-sdk"},"serviceName":"cloudresourcemanager.googleapis.com","methodName":"SetIamPolicy","authorizationInfo":[{"resource":"projects/demo-proj","permission":"resourcemanager.projects.setIamPolicy","granted":true}],"resourceName":"projects/demo-proj","request":{"policy":{"bindings":[{"role":"roles/viewer"}]}}},"insertId":"i-1","resource":{"type":"project","labels":{"project_id":"demo-proj"}},"timestamp":"2024-06-01T09:15:32.123Z","severity":"NOTICE","logName":"projects/demo-proj/logs/cloudaudit.googleapis.com%2Factivity","receiveTimestamp":"2024-06-01T09:15:33Z"}`

func TestAudit(t *testing.T) {
	e := parsertest.ParseOne(t, New(), setIAM)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.123Z", "event.dataset": "gcp.audit", "event.id": "i-1", "event.action": "SetIamPolicy",
		"event.provider": "cloudresourcemanager.googleapis.com", "event.category": []string{"iam"}, "event.type": []string{"change"},
		"event.outcome": "success", "user.email": "alice@example.com", "user.name": "alice", "source.ip": "198.51.100.50",
		"user_agent.original": "google-cloud-sdk", "cloud.project.id": "demo-proj", "log.level": "notice",
		"gcp.audit.resource_name": "projects/demo-proj", "gcp.resource.type": "project",
	})
	if !e.Has("gcp.audit.authorization_info") || !e.Has("gcp.audit.request.policy.bindings") {
		t.Fatalf("missing nested fields")
	}
	e = parsertest.ParseOne(t, New(), `{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","status":{"code":7,"message":"PERMISSION_DENIED"},"authenticationInfo":{"principalEmail":"bob@example.com"},"requestMetadata":{"callerIp":"gce-internal-ip"},"serviceName":"compute.googleapis.com","methodName":"v1.compute.instances.insert"},"insertId":"i-2","resource":{"type":"gce_instance","labels":{"project_id":"demo-proj","zone":"europe-west1-b","instance_id":"123"}},"timestamp":"2024-06-01T09:16:00Z","logName":"projects/demo-proj/logs/cloudaudit.googleapis.com%2Factivity"}`)
	parsertest.Expect(t, e, map[string]any{"event.outcome": "failure", "event.type": []string{"creation"}, "source.address": "gce-internal-ip", "cloud.availability_zone": "europe-west1-b", "gcp.audit.status.code": int64(7)})
	e = parsertest.ParseOne(t, New(), `{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","authenticationInfo":{"principalEmail":"carol@example.com"},"serviceName":"storage.googleapis.com","methodName":"storage.objects.get"},"insertId":"i-3","resource":{"type":"gcs_bucket","labels":{"project_id":"demo-proj"}},"timestamp":"2024-06-01T09:17:00Z","logName":"projects/demo-proj/logs/cloudaudit.googleapis.com%2Fdata_access"}`)
	parsertest.Expect(t, e, map[string]any{"event.type": []string{"access"}, "event.category": []string{"configuration"}})
	e = parsertest.ParseOne(t, New(), `{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","authenticationInfo":{"principalEmail":"dave@example.com"},"serviceName":"login.googleapis.com","methodName":"google.login.LoginService.loginFailure"},"insertId":"i-4","timestamp":"2024-06-01T09:18:00Z","logName":"organizations/1/logs/cloudaudit.googleapis.com%2Fdata_access"}`)
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"authentication"}, "event.outcome": "failure"})
}

func TestEnvelopesAndPlainLogs(t *testing.T) {
	push := `{"message":{"data":"` + base64.StdEncoding.EncodeToString([]byte(setIAM)) + `","messageId":"m-1","attributes":{}},"subscription":"projects/demo-proj/subscriptions/argus"}`
	if !New().Detect([]byte(push), nil) {
		t.Fatal("pubsub not detected")
	}
	e := parsertest.ParseOne(t, New(), push)
	parsertest.Expect(t, e, map[string]any{"event.action": "SetIamPolicy"})
	evs, err := New().Parse(parsertest.Input(`{"entries":[`+setIAM+`,{"insertId":"i-5","logName":"projects/demo-proj/logs/app","textPayload":"job finished","severity":"INFO","timestamp":"2024-06-01T09:19:00Z"}]}`, nil))
	if err != nil || len(evs) != 2 {
		t.Fatalf("entries envelope %d %v", len(evs), err)
	}
	parsertest.Expect(t, evs[1], map[string]any{"event.dataset": "gcp.log", "message": "job finished", "gcp.log.text_payload": "job finished", "log.level": "info"})
}

func TestDetect(t *testing.T) {
	for _, s := range []string{`{"a":1}`, `{"eventVersion":"1"}`, `x`} {
		if New().Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := New().Parse(parsertest.Input(`{"entries":[{"a":1}]}`, nil)); err == nil {
		t.Fatal("no entries should error")
	}
}
