package suricata

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "suricata",
		`{"timestamp":"2024-06-01T09:15:32.1+0000","event_type":"alert","src_ip":"10.0.0.5","alert":{"signature_id":1,"severity":2,"metadata":{"a":["b"]}}}`,
		`{"timestamp":"2024-06-01T09:15:32.1+0000","event_type":"dns","src_ip":"10.0.0.5","dns":{"answers":[{"rrname":"a","rrtype":"A","rdata":"1.2.3.4"}]}}`,
		`{"event_type":"flow","src_ip":"10.0.0.5","flow":{"start":"x","end":"y"}}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
