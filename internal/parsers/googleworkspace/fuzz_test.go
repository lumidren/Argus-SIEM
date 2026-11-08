package googleworkspace

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "googleworkspace",
		act("login", `{"type":"login","name":"logout"}`),
		act("admin", `{"name":"X","parameters":[{"name":"a","messageValue":{"parameter":[{"name":"b","value":"c"}]}}]}`),
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
