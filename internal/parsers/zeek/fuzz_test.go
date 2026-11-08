package zeek

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "zeek",
		`{"_path":"conn","ts":1717233332.1,"uid":"C1","id.orig_h":"10.0.0.5","id.orig_p":1,"id.resp_h":"10.0.0.6","id.resp_p":2,"proto":"tcp","conn_state":"SF"}`,
		`{"_path":"dns","ts":1717233332.0,"uid":"C3","query":"a.example","answers":["1.2.3.4"],"TTLs":[5]}`,
		`{"_path":"intel","ts":1.0,"seen.indicator":"x","seen.indicator_type":"Intel::ADDR"}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
