package azure

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "azure",
		`{"records":[{"time":"2024-06-01T09:15:32Z","operationName":"Sign-in activity","category":"SignInLogs","resultType":"0","properties":{"userPrincipalName":"a@example.com","location":{"geoCoordinates":{"latitude":1,"longitude":2}}}}]}`,
		`{"time":"2024-06-01T09:15:32Z","operationName":"MICROSOFT.X/Y/WRITE","resourceId":"/SUBSCRIPTIONS/s/RESOURCEGROUPS/r/PROVIDERS/A/B/c","identity":{"claims":{"appid":"x"}}}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
