package okta

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

const sessionStart = `{"actor":{"id":"00u1","type":"User","alternateId":"alice@example.com","displayName":"Alice Example"},"client":{"userAgent":{"rawUserAgent":"Mozilla/5.0","os":"Mac OS X","browser":"CHROME"},"zone":"null","device":"Computer","ipAddress":"198.51.100.60","geographicalContext":{"city":"Austin","state":"Texas","country":"United States","postalCode":"78701","geolocation":{"lat":30.27,"lon":-97.74}}},"authenticationContext":{"authenticationStep":0,"externalSessionId":"x1"},"displayMessage":"User login to Okta","eventType":"user.session.start","outcome":{"result":"SUCCESS"},"published":"2024-06-01T09:15:32.123Z","securityContext":{"asNumber":64500,"asOrg":"example isp","isp":"example isp","domain":"example.net","isProxy":false},"severity":"INFO","debugContext":{"debugData":{"requestUri":"/api/v1/authn","requestId":"r1","threatSuspected":"false"}},"legacyEventType":"core.user_auth.login_success","transaction":{"type":"WEB","id":"t1"},"uuid":"ev-1","version":"0","request":{"ipChain":[{"ip":"198.51.100.60","version":"V4","source":null}]},"target":[]}`

func TestSessionStart(t *testing.T) {
	p := New()
	if !p.Detect([]byte(sessionStart), nil) {
		t.Fatal("detect")
	}
	e := parsertest.ParseOne(t, p, sessionStart)
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.123Z", "event.dataset": "okta.system", "event.id": "ev-1", "event.action": "user.session.start",
		"event.category": []string{"authentication"}, "event.type": []string{"start"}, "event.outcome": "success", "event.severity": int64(10),
		"user.name": "alice", "user.email": "alice@example.com", "user.full_name": "Alice Example", "user.id": "00u1",
		"source.ip": "198.51.100.60", "source.geo.city_name": "Austin", "source.geo.country_name": "United States",
		"source.as.number": int64(64500), "okta.security_context.is_proxy": false, "user_agent.original": "Mozilla/5.0",
		"user_agent.name": "CHROME", "okta.debug_context.debug_data.request_uri": "/api/v1/authn", "okta.transaction.type": "WEB",
		"okta.authentication_context.external_session_id": "x1", "message": "User login to Okta",
	})
	if !e.Has("okta.request.ip_chain") {
		t.Fatal("ip chain")
	}
}

func TestLifecycleAndArrays(t *testing.T) {
	raw := `[{"actor":{"id":"00u9","type":"User","alternateId":"admin@example.com"},"eventType":"group.user_membership.add","outcome":{"result":"SUCCESS"},"published":"2024-06-01T09:20:00Z","uuid":"ev-2","target":[{"id":"00u2","type":"User","alternateId":"bob@example.com","displayName":"Bob"},{"id":"00g1","type":"UserGroup","alternateId":"unknown","displayName":"Engineering"}]},` +
		`{"actor":{"id":"00u9","type":"User","alternateId":"admin@example.com"},"eventType":"user.lifecycle.deactivate","outcome":{"result":"SUCCESS"},"published":"2024-06-01T09:21:00Z","uuid":"ev-3","target":[{"id":"00u3","type":"User","alternateId":"carol@example.com"}]},` +
		`{"actor":{"id":"00u4","type":"User","alternateId":"dave@example.com"},"eventType":"user.session.start","outcome":{"result":"FAILURE","reason":"INVALID_CREDENTIALS"},"published":"2024-06-01T09:22:00Z","uuid":"ev-4","severity":"WARN"},` +
		`{"actor":{"id":"00u5","type":"User","alternateId":"erin@example.com"},"eventType":"application.user_membership.add","outcome":{"result":"SUCCESS"},"published":"2024-06-01T09:23:00Z","uuid":"ev-5","target":[{"id":"0oa1","type":"AppInstance","displayName":"Payroll"}]},` +
		`{"actor":{"id":"00u5","type":"User","alternateId":"erin@example.com"},"eventType":"policy.evaluate_sign_on","outcome":{"result":"DENY"},"published":"2024-06-01T09:24:00Z","uuid":"ev-6"}]`
	evs, err := New().Parse(parsertest.Input(raw, nil))
	if err != nil || len(evs) != 5 {
		t.Fatalf("array: %d %v", len(evs), err)
	}
	parsertest.Expect(t, evs[0], map[string]any{"event.category": []string{"iam"}, "event.type": []string{"creation"}, "user.target.name": "bob", "group.name": "Engineering"})
	parsertest.Expect(t, evs[1], map[string]any{"event.type": []string{"deletion"}, "user.target.email": "carol@example.com"})
	parsertest.Expect(t, evs[2], map[string]any{"event.outcome": "failure", "okta.outcome.reason": "INVALID_CREDENTIALS", "event.severity": int64(50)})
	parsertest.Expect(t, evs[3], map[string]any{"okta.target.app.display_name": "Payroll"})
	parsertest.Expect(t, evs[4], map[string]any{"event.type": []string{"info"}, "event.outcome": "failure"})
}

func TestDetectNegative(t *testing.T) {
	for _, s := range []string{`{"a":1}`, `{"eventVersion":"1","eventSource":"x","eventName":"y"}`, `{"RecordType":15,"CreationTime":"x","Operation":"y"}`} {
		if New().Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := New().Parse(parsertest.Input(`[]`, nil)); err == nil {
		t.Fatal("empty array should error")
	}
}
