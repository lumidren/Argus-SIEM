package nginx

import (
	"testing"
	"time"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/parsers/parsertest"
	"github.com/lumidren/argus/internal/schema"
)

func input(raw string) *parsers.Input {
	return &parsers.Input{
		Raw:        []byte(raw),
		ReceivedAt: time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		Source:     parsers.Source{TenantID: "t1", SourceID: "nginx-1"},
	}
}

func TestCombinedAccess(t *testing.T) {
	line := `203.0.113.7 - alice [01/Jun/2024:09:15:32 +0000] "GET /admin/login.php?user=x HTTP/1.1" 404 512 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"`
	p := New()
	if !p.Detect([]byte(line), nil) {
		t.Fatal("detect")
	}
	evs, err := p.Parse(input(line))
	if err != nil || len(evs) != 1 {
		t.Fatalf("%v %d", err, len(evs))
	}
	e := evs[0]
	parsertest.Expect(t, e, map[string]any{
		"@timestamp":                "2024-06-01T09:15:32.000Z",
		"event.module":              "nginx",
		"event.dataset":             "nginx.access",
		"event.category":            []string{"web"},
		"event.type":                []string{"access"},
		"event.outcome":             "failure",
		"source.ip":                 "203.0.113.7",
		"source.address":            "203.0.113.7",
		"user.name":                 "alice",
		"http.request.method":       "GET",
		"url.original":              "/admin/login.php?user=x",
		"url.path":                  "/admin/login.php",
		"url.query":                 "user=x",
		"url.extension":             "php",
		"http.version":              "1.1",
		"http.response.status_code": int64(404),
		"http.response.body.bytes":  int64(512),
		"http.request.referrer":     "https://example.com/",
		"user_agent.original":       "Mozilla/5.0 (X11; Linux x86_64)",
	})
}

func TestCombinedExtendedAndVhostAndSyslog(t *testing.T) {
	line := `<190>Jun  1 09:15:32 web01 nginx: shop.example.com:443 10.0.0.9 - - [01/Jun/2024:09:15:32 +0200] "POST /api/v1/cart HTTP/2.0" 201 0 "-" "curl/8.0" "198.51.100.4, 10.0.0.9" 0.123 0.100`
	evs, err := New().Parse(input(line))
	if err != nil {
		t.Fatal(err)
	}
	e := evs[0]
	parsertest.Expect(t, e, map[string]any{
		"@timestamp":                          "2024-06-01T07:15:32.000Z",
		"host.name":                           "web01",
		"url.domain":                          "shop.example.com",
		"destination.port":                    int64(443),
		"http.request.method":                 "POST",
		"http.version":                        "2.0",
		"http.response.status_code":           int64(201),
		"http.response.body.bytes":            int64(0),
		"client.ip":                           "198.51.100.4",
		"network.forwarded_ip":                []string{"198.51.100.4", "10.0.0.9"},
		"event.duration":                      int64(123000000),
		"nginx.access.upstream_response_time": "0.100",
		"event.outcome":                       "success",
		"log.syslog.priority":                 int64(190),
	})
	if e.Has("http.request.referrer") || e.Has("user.name") {
		t.Fatalf("dash placeholders must not be stored: %v", e.Flat())
	}
}

func TestJSONAccess(t *testing.T) {
	line := `{"time_iso8601":"2024-06-01T09:15:32+00:00","remote_addr":"10.1.1.1","remote_user":"-","request":"GET /healthz HTTP/1.1","status":200,"body_bytes_sent":2,"http_referer":"-","http_user_agent":"kube-probe/1.29","request_time":0.002,"upstream_response_time":"0.001","host":"api.internal","http_x_forwarded_for":"-","request_length":120,"scheme":"https","server_port":"8443"}`
	p := New()
	if !p.Detect([]byte(line), nil) {
		t.Fatal("detect json")
	}
	evs, err := p.Parse(input(line))
	if err != nil {
		t.Fatal(err)
	}
	parsertest.Expect(t, evs[0], map[string]any{
		"@timestamp":                "2024-06-01T09:15:32.000Z",
		"source.ip":                 "10.1.1.1",
		"url.path":                  "/healthz",
		"http.response.status_code": int64(200),
		"http.response.body.bytes":  int64(2),
		"http.request.bytes":        int64(120),
		"user_agent.original":       "kube-probe/1.29",
		"url.domain":                "api.internal",
		"url.scheme":                "https",
		"destination.port":          int64(8443),
		"event.duration":            int64(2000000),
		"event.outcome":             "success",
	})
}

func TestErrorLog(t *testing.T) {
	line := `2024/06/01 09:15:32 [error] 1234#5678: *91 open() "/var/www/html/wp-login.php" failed (2: No such file or directory), client: 203.0.113.7, server: example.com, request: "GET /wp-login.php HTTP/1.1", host: "example.com:443", referrer: "http://evil.test/a,b"`
	p := New()
	if !p.Detect([]byte(line), nil) {
		t.Fatal("detect error")
	}
	evs, err := p.Parse(input(line))
	if err != nil {
		t.Fatal(err)
	}
	parsertest.Expect(t, evs[0], map[string]any{
		"@timestamp":                "2024-06-01T09:15:32.000Z",
		"event.dataset":             "nginx.error",
		"event.type":                []string{"error"},
		"log.level":                 "error",
		"process.pid":               int64(1234),
		"process.thread.id":         int64(5678),
		"nginx.error.connection_id": int64(91),
		"source.ip":                 "203.0.113.7",
		"destination.domain":        "example.com",
		"url.path":                  "/wp-login.php",
		"url.domain":                "example.com",
		"http.request.referrer":     "http://evil.test/a,b",
		"event.outcome":             "failure",
	})
}

func TestMalformedRequestLineAndGarbage(t *testing.T) {
	line := `10.0.0.1 - - [01/Jun/2024:09:15:32 +0000] "\x16\x03\x01" 400 157 "-" "-"`
	evs, err := New().Parse(input(line))
	if err != nil {
		t.Fatal(err)
	}
	if evs[0].String("url.original") != `\x16\x03\x01` || !parsertest.HasTag(evs[0], "malformed_request_line") {
		t.Fatalf("malformed handling %v", evs[0].Flat())
	}
	if _, err := New().Parse(input("total garbage")); err == nil {
		t.Fatal("garbage must error")
	}
	if New().Detect([]byte("total garbage"), nil) {
		t.Fatal("garbage detected")
	}
}

func TestRegistryIntegration(t *testing.T) {
	r := parsers.NewRegistry()
	r.Register(New())
	res := r.Parse(input(`10.0.0.1 - - [01/Jun/2024:09:15:32 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`))
	if res.Status != schema.ParseStatusOK || res.Events[0].String(schema.FieldParser) != "nginx" {
		t.Fatalf("%+v", res)
	}
}
