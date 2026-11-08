package cloudtrail

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "cloudtrail",
		`{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"a"},"eventTime":"2024-06-01T09:15:32Z","eventSource":"s3.amazonaws.com","eventName":"ListBuckets","sourceIPAddress":"198.51.100.1"}`,
		`{"Records":[{"eventVersion":"1.08","eventSource":"iam.amazonaws.com","eventName":"GetUser","requestParameters":{"a":{"b":[1,2]}}}]}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
