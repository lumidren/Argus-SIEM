package fortinet

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "fortinet",
		`date=2024-06-01 time=09:15:32 devname="F" logid="0000000013" type="traffic" srcip=10.0.0.5 action="accept" trandisp="snat" transip=1.2.3.4`,
		`<189>logver=700 eventtime=1717233332 devname="F" logid="1" type="event" subtype="system" ui="ssh(10.0.0.1)"`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
