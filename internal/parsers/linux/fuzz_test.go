package linux

import (
	"testing"

	"github.com/lumidren/argus/internal/parsers/parsertest"
)

func FuzzParse(f *testing.F) {
	parsertest.SeedCorpus(f, "linux",
		`<38>Jun  1 09:00:01 web01 sshd[2001]: Accepted publickey for alice from 10.0.0.5 port 51234 ssh2`,
		`<85>Jun  1 09:10:00 web01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update`,
		"type=SYSCALL msg=audit(1717233332.123:4567): arch=c000003e syscall=59 success=yes pid=1\ntype=EXECVE msg=audit(1717233332.123:4567): argc=1 a0=6C73",
		"type=SOCKADDR msg=audit(1717233333.000:1): saddr=020001BBC0000201",
		`{"__REALTIME_TIMESTAMP":"1717233332123456","MESSAGE":"hello","PRIORITY":"6"}`,
		`{"sequence":1,"timestamp":"1.5","messages":[{"type":1300,"data":"syscall=59"}]}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) { parsertest.FuzzOne(t, New(), data) })
}
