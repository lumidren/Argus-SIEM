package paloalto

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "paloalto",
		line(trafficCols, with(base("TRAFFIC", "end"), "src", "10.0.0.5", "dst", "192.0.2.10", "action", "allow")),
		line(threatCols, with(base("THREAT", "url"), "misc", "example.org/x", "threatid", "(9999)")),
		"<14>Jun  1 09:15:33 fw 1,2024/06/01 09:15:33,012801000001,SYSTEM,general,,2024/06/01 09:15:32",
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
