package nginx

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

// FuzzParse feeds arbitrary bytes through the parser. The property under test
// is "never panics, never returns an event without module/dataset, and never
// exceeds the field cap"; the seed corpus lives in test/fuzz/corpus/nginx.
func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "nginx",
		`203.0.113.7 - alice [01/Jun/2024:09:15:32 +0000] "GET /a?b=c HTTP/1.1" 200 12 "-" "ua"`,
		`{"time_iso8601":"2024-06-01T09:15:32+00:00","remote_addr":"10.1.1.1","request":"GET / HTTP/1.1","status":200}`,
		`2024/06/01 09:15:32 [error] 1#1: *1 msg, client: 1.2.3.4, server: s, request: "GET / HTTP/1.1"`,
		`<190>Jun  1 09:15:32 web01 nginx: 10.0.0.9 - - [01/Jun/2024:09:15:32 +0200] "POST / HTTP/2.0" 201 0 "-" "-"`,
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		parsertest.FuzzOne(t, New(), data)
	})
}
