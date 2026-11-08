package generic

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "generic",
		`{"@timestamp":"2024-06-01T09:15:32Z","message":"m"}`,
		`CEF:0|V|P|1|2|N|5|src=10.0.0.1 msg=a b c cs1Label=L cs1=v`,
		"LEEF:2.0|V|P|1|E|^|src=10.0.0.1^usrName=u",
		`<134>Jun  1 09:15:32 h app: text`,
		`plain`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
