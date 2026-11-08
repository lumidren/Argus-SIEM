package kubernetes

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "kubernetes",
		ev("ResponseComplete", "create", "pods", "", `,"requestObject":{"spec":{"containers":[{"image":"x"}],"volumes":[{"hostPath":{"path":"/"}}]}}`),
		`{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[{"auditID":"1","verb":"get","requestURI":"/"}]}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
