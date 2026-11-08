package apache

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func TestAccessFormats(t *testing.T) {
	p := New()
	e := parsertest.ParseOneHints(t, p, `192.0.2.20 - - [01/Jun/2024:09:15:32 +0000] "GET /docs/index.html HTTP/1.1" 200 5120 "https://example.org/" "Mozilla/5.0"`, map[string]string{"kind": "apache"})
	parsertest.Expect(t, e, map[string]any{
		"event.dataset": "apache.access", "source.ip": "192.0.2.20", "url.path": "/docs/index.html",
		"http.response.status_code": int64(200), "http.response.body.bytes": int64(5120), "user_agent.original": "Mozilla/5.0",
	})

	e = parsertest.ParseOne(t, p, `www.example.org:443 192.0.2.21 - bob [01/Jun/2024:09:15:32 +0000] "POST /api/items HTTP/1.1" 201 64 "-" "curl/8.0"`)
	parsertest.Expect(t, e, map[string]any{"url.domain": "www.example.org", "destination.port": int64(443), "user.name": "bob", "http.request.method": "POST"})

	e = parsertest.ParseOne(t, p, `192.0.2.22 - - [01/Jun/2024:09:15:32 +0000] "GET / HTTP/1.1" 200 10 "-" "agent" 1500`)
	parsertest.Expect(t, e, map[string]any{"event.duration": int64(1500000)})

	e = parsertest.ParseOneHints(t, p, `192.0.2.23 - - [01/Jun/2024:09:15:32 +0000] "GET /a HTTP/1.0" 304 -`, map[string]string{"kind": "apache"})
	parsertest.Expect(t, e, map[string]any{"http.response.status_code": int64(304), "http.response.body.bytes": int64(0), "http.version": "1.0"})
	parsertest.ExpectAbsent(t, e, "user_agent.original", "http.request.referrer")

	e = parsertest.ParseOneHints(t, p, `<190>Jun  1 09:15:32 web02 httpd: 192.0.2.24 - - [01/Jun/2024:09:15:31 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`, map[string]string{"kind": "apache"})
	parsertest.Expect(t, e, map[string]any{"host.name": "web02", "@timestamp": "2024-06-01T09:15:31.000Z"})
}

func TestErrorFormats(t *testing.T) {
	p := New()
	e := parsertest.ParseOne(t, p, `[Sat Jun 01 09:15:32.123456 2024] [core:error] [pid 1234:tid 140000] [client 192.0.2.25:51234] AH00128: File does not exist: /var/www/html/missing.png, referer: https://example.org/page`)
	parsertest.Expect(t, e, map[string]any{
		"event.dataset": "apache.error", "@timestamp": "2024-06-01T09:15:32.123Z", "log.level": "error", "apache.error.module": "core",
		"process.pid": int64(1234), "process.thread.id": int64(140000), "source.ip": "192.0.2.25", "source.port": int64(51234),
		"apache.error.error_code": "AH00128", "file.path": "/var/www/html/missing.png", "http.request.referrer": "https://example.org/page",
		"message": "File does not exist: /var/www/html/missing.png", "event.outcome": "failure",
	})
	e = parsertest.ParseOne(t, p, `[Sat Jun 01 09:15:32 2024] [error] [client 192.0.2.26] File does not exist: /var/www/html/x`)
	parsertest.Expect(t, e, map[string]any{"log.level": "error", "source.ip": "192.0.2.26", "file.path": "/var/www/html/x"})
	e = parsertest.ParseOne(t, p, `[Sat Jun 01 09:15:32.000001 2024] [ssl:warn] [pid 77] AH01909: server certificate does not include an ID which matches the server name`)
	parsertest.Expect(t, e, map[string]any{"apache.error.module": "ssl", "log.level": "warn", "apache.error.error_code": "AH01909"})
	parsertest.ExpectAbsent(t, e, "source.ip")
}

func TestDetectAndErrors(t *testing.T) {
	p := New()
	plain := `192.0.2.20 - - [01/Jun/2024:09:15:32 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`
	if p.Detect([]byte(plain), nil) {
		t.Fatal("plain combined without hints belongs to nginx sniffing")
	}
	if !p.Detect([]byte(plain), map[string]string{"path": "/var/log/httpd/access_log"}) {
		t.Fatal("path hint should claim it")
	}
	if p.Detect([]byte(`{"a":1}`), nil) || p.Detect(nil, nil) {
		t.Fatal("non-apache detected")
	}
	if _, err := p.Parse(parsertest.Input("garbage line", nil)); err == nil {
		t.Fatal("garbage should error")
	}
}
