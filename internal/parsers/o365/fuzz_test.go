package o365

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "o365",
		`{"CreationTime":"2024-06-01T09:15:32","Id":"1","Operation":"UserLoggedIn","RecordType":15,"UserId":"a@example.com","ExtendedProperties":[{"Name":"UserAgent","Value":"x"}]}`,
		`{"content":[{"CreationTime":"2024-06-01T09:15:32","Operation":"Set-Mailbox","RecordType":1,"Parameters":[{"Name":"Identity","Value":"a"}]}]}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
