package osquery

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "osquery",
		`{"name":"processes","hostIdentifier":"h","unixTime":1717233332,"columns":{"pid":"1","path":"/sbin/init","cmdline":"init"},"action":"added"}`,
		`{"name":"x","hostIdentifier":"h","snapshot":[{"a":"b"}],"diffResults":{"added":[{"c":"d"}]}}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
