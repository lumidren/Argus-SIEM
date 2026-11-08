package gcp

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "gcp", setIAM,
		`{"insertId":"x","logName":"projects/p/logs/app","jsonPayload":{"message":"hi","n":1}}`,
		`{"message":{"data":"e30=","messageId":"1"}}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
