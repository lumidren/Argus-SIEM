package agent

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lumidren/argus/internal/pipeline"
)

type recorder struct {
	mu   sync.Mutex
	recs []pipeline.Record
}

func (r *recorder) Produce(_ context.Context, recs []pipeline.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, recs...)
	return nil
}

func (r *recorder) envelopes() []pipeline.Envelope {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]pipeline.Envelope, 0, len(r.recs))
	for _, rec := range r.recs {
		var e pipeline.Envelope
		_ = json.Unmarshal(rec.Value, &e)
		out = append(out, e)
	}
	return out
}

func TestConfigValidation(t *testing.T) {
	_, err := ParseConfig([]byte("tenant: \"\"\nunknown_key: 1\n"))
	if err == nil {
		t.Fatal("unknown keys must be rejected")
	}
	_, err = ParseConfig([]byte("data_dir: /x\n"))
	for _, want := range []string{"tenant is required", "output.brokers is required", "at least one input"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	c, err := ParseConfig([]byte("tenant: t1\ndata_dir: /var/lib/argus\noutput:\n  brokers: [k:9092]\nfiles:\n  - path: /var/log/auth.log\n    kind: linux\n"))
	if err != nil || c.Admin == "" || c.FlushInterval != time.Second {
		t.Fatalf("defaults: %+v %v", c, err)
	}
}

func TestAgentFileAndSyslogEndToEnd(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(logPath, []byte("Jun  1 09:00:01 web01 sshd[1]: Accepted publickey for alice from 10.0.0.5 port 1 ssh2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	tcpAddr := ln.Addr().String()
	ln.Close()
	cfg := &Config{Tenant: "t1", DataDir: filepath.Join(dir, "data"), Hostname: "web01", FlushInterval: 50 * time.Millisecond,
		Files:  []FileInput{{Path: logPath, Kind: "linux", SourceID: "auth"}},
		Syslog: &SyslogInput{TCP: tcpAddr, Kind: "generic", SourceID: "syslog-in"}}
	cfg.Output.Brokers = []string{"unused"}
	rec := &recorder{}
	a := &Agent{Config: cfg, Producer: rec}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	var conn net.Conn
	var err error
	for i := 0; i < 100; i++ {
		if conn, err = net.Dial("tcp", tcpAddr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("<134>Jun  1 09:00:02 fw01 app: hello\n"))
	conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for len(rec.envelopes()) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	envs := rec.envelopes()
	if len(envs) != 2 {
		t.Fatalf("got %d envelopes", len(envs))
	}
	var file, sys pipeline.Envelope
	for _, e := range envs {
		if e.Kind == "linux" {
			file = e
		} else {
			sys = e
		}
	}
	if file.TenantID != "t1" || file.ProviderID != "file:"+logPath+":0" || file.Collector.Host != "web01" || file.SourceID != "auth" {
		t.Fatalf("file envelope %+v", file)
	}
	if sys.Raw != "<134>Jun  1 09:00:02 fw01 app: hello" || sys.Collector.Address == "" || sys.Hints["transport"] != "tcp" {
		t.Fatalf("syslog envelope %+v", sys)
	}
	// Checkpoint persisted: a restart must not replay the file line.
	b, err := os.ReadFile(filepath.Join(cfg.DataDir, "checkpoints.json"))
	if err != nil || !strings.Contains(string(b), "offset") {
		t.Fatalf("checkpoint file: %s %v", b, err)
	}
}
