package okta

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "okta", sessionStart, `[{"eventType":"user.lifecycle.create","published":"2024-06-01T09:15:32Z","actor":{},"target":[{"type":"User"}]}]`)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
