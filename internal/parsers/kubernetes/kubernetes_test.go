package kubernetes

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func ev(stage, verb, resource, sub, extra string) string {
	return `{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"a-1","stage":"` + stage + `","requestURI":"/api/v1/namespaces/web/` + resource + `?timeout=30s","verb":"` + verb + `","user":{"username":"alice@example.com","uid":"u-1","groups":["devs","system:authenticated"],"extra":{"scopes.authorization.openshift.io":["user:full"]}},"sourceIPs":["10.0.0.5","10.0.0.1"],"userAgent":"kubectl/v1.30.0","objectRef":{"resource":"` + resource + `","subresource":"` + sub + `","namespace":"web","name":"frontend","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":201},"requestReceivedTimestamp":"2024-06-01T09:15:32.123456Z","stageTimestamp":"2024-06-01T09:15:32.200000Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by RoleBinding"}` + extra + `}`
}

func TestPodCreate(t *testing.T) {
	raw := ev("ResponseComplete", "create", "pods", "", `,"requestObject":{"kind":"Pod","spec":{"hostNetwork":true,"containers":[{"name":"web","image":"nginx:1.27","securityContext":{"privileged":false}}],"volumes":[{"name":"logs","hostPath":{"path":"/var/log/app"}}]}}`)
	e := parsertest.ParseOneHints(t, New(), raw, map[string]string{"cluster": "prod-eu"})
	parsertest.Expect(t, e, map[string]any{
		"@timestamp": "2024-06-01T09:15:32.123Z", "event.dataset": "kubernetes.audit", "event.id": "a-1-ResponseComplete",
		"event.action": "create", "event.category": []string{"configuration"}, "event.type": []string{"creation"},
		"event.outcome": "success", "user.name": "alice@example.com", "user.group.name": []string{"devs", "system:authenticated"},
		"source.ip": "10.0.0.5", "user_agent.original": "kubectl/v1.30.0", "url.path": "/api/v1/namespaces/web/pods",
		"url.query": "timeout=30s", "orchestrator.namespace": "web", "orchestrator.resource.type": "pods",
		"orchestrator.resource.name": "frontend", "orchestrator.cluster.name": "prod-eu", "container.image.name": "nginx:1.27",
		"kubernetes.audit.pod.host_network": true, "kubernetes.audit.pod.privileged": false,
		"kubernetes.audit.pod.host_path": []string{"/var/log/app"}, "kubernetes.audit.response_status.code": int64(201),
		"kubernetes.audit.annotations.authorization_k8s_io_decision": "allow",
		"kubernetes.audit.annotations.authorization_k8s_io/reason":   "RBAC: allowed by RoleBinding",
		"kubernetes.audit.request_object.spec.containers":            nil,
	})
}

func TestClassification(t *testing.T) {
	e := parsertest.ParseOne(t, New(), ev("ResponseComplete", "get", "secrets", "", ""))
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"configuration"}, "event.type": []string{"access"}})
	e = parsertest.ParseOne(t, New(), ev("ResponseComplete", "create", "clusterrolebindings", "", ""))
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"iam"}, "event.type": []string{"creation"}})
	e = parsertest.ParseOne(t, New(), ev("ResponseComplete", "create", "pods", "exec", ""))
	parsertest.Expect(t, e, map[string]any{"event.category": []string{"process"}, "event.type": []string{"start"}})
	raw := `{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"a-2","stage":"ResponseComplete","requestURI":"/api/v1/pods","verb":"list","user":{"username":"system:serviceaccount:ci:runner"},"impersonatedUser":{"username":"bob","groups":["ops"]},"sourceIPs":["10.0.0.9"],"objectRef":{"resource":"pods"},"responseStatus":{"code":403,"reason":"Forbidden"},"requestReceivedTimestamp":"2024-06-01T09:16:00Z","annotations":{"authorization.k8s.io/decision":"forbid"}}`
	e = parsertest.ParseOne(t, New(), raw)
	parsertest.Expect(t, e, map[string]any{"event.outcome": "failure", "user.effective.name": "bob", "kubernetes.audit.response_status.reason": "Forbidden"})
}

func TestStagesAndLists(t *testing.T) {
	list := `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[` + ev("RequestReceived", "delete", "deployments", "", "") + `,` + ev("ResponseComplete", "delete", "deployments", "", "") + `]}`
	evs, err := New().Parse(parsertest.Input(list, nil))
	if err != nil || len(evs) != 1 {
		t.Fatalf("stage filter: %d %v", len(evs), err)
	}
	parsertest.Expect(t, evs[0], map[string]any{"event.type": []string{"deletion"}})
	evs, err = New().Parse(parsertest.Input(list, map[string]string{"keep_all_stages": "true"}))
	if err != nil || len(evs) != 2 {
		t.Fatalf("keep all: %d %v", len(evs), err)
	}
	evs, err = New().Parse(parsertest.Input(ev("RequestReceived", "get", "pods", "", ""), nil))
	if err != nil || len(evs) != 0 {
		t.Fatalf("dropped stage should yield no events and no error: %d %v", len(evs), err)
	}
	e := parsertest.ParseOne(t, New(), ev("Panic", "get", "pods", "", ""))
	parsertest.Expect(t, e, map[string]any{"@timestamp": "2024-06-01T09:15:32.200Z"})
}

func TestDetect(t *testing.T) {
	for _, s := range []string{`{"a":1}`, `{"kind":"Pod","apiVersion":"v1"}`, `x`} {
		if New().Detect([]byte(s), nil) {
			t.Errorf("should not detect %q", s)
		}
	}
	if _, err := New().Parse(parsertest.Input(`{"kind":"Event"}`, nil)); err == nil {
		t.Fatal("incomplete event should error")
	}
}
