package apache

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "apache",
		`www.example.org:443 192.0.2.21 - bob [01/Jun/2024:09:15:32 +0000] "POST /api HTTP/1.1" 201 64 "-" "curl/8.0"`,
		`[Sat Jun 01 09:15:32.123456 2024] [core:error] [pid 1:tid 2] [client 192.0.2.25:51234] AH00128: File does not exist: /x`,
		`192.0.2.23 - - [01/Jun/2024:09:15:32 +0000] "GET /a HTTP/1.0" 304 -`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
