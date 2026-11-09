package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/lumidren/argus/internal/agent/ship"
	"github.com/lumidren/argus/internal/agent/syslogin"
	"github.com/lumidren/argus/internal/agent/tail"
	"github.com/lumidren/argus/internal/agent/wal"
	"github.com/lumidren/argus/internal/agent/winevt"
	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/pipeline"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// Version is the agent version stamped into envelopes.
var Version = "dev"

// Agent runs inputs, the WAL and the shipper.
type Agent struct {
	Config   *Config
	Log      *slog.Logger
	Producer pipeline.Producer // nil: a Kafka producer is built from Config.Output

	wal      *wal.WAL
	hostname string
	appendMu sync.Mutex
}

func (a *Agent) collector(kind string) parsers.Collector {
	return parsers.Collector{Name: "argus-agent", Type: "argus-agent", Version: Version, ID: a.hostname, Host: a.hostname}
}

// buffer writes one envelope to the WAL, retrying while the buffer is full
// (back-pressure on the input).
func (a *Agent) buffer(ctx context.Context, env pipeline.Envelope) error {
	b, err := env.Encode()
	if err != nil {
		return err
	}
	for {
		a.appendMu.Lock()
		err = a.wal.Append(b)
		a.appendMu.Unlock()
		if !errors.Is(err, wal.ErrFull) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// Run starts every configured input and the shipper; it returns when ctx
// ends or a component fails.
func (a *Agent) Run(ctx context.Context) error {
	c := a.Config
	a.hostname = c.Hostname
	if a.hostname == "" {
		a.hostname, _ = os.Hostname()
	}
	w, err := wal.Open(filepath.Join(c.DataDir, "wal"), wal.Options{MaxBytes: c.Buffer.MaxBytes, SegmentBytes: c.Buffer.SegmentBytes})
	if err != nil {
		return err
	}
	a.wal = w
	defer w.Close()
	if a.Producer == nil {
		kc := pipeline.KafkaConfig{Brokers: c.Output.Brokers, ClientID: "argus-agent-" + a.hostname, Username: c.Output.Username}
		if c.Output.PasswordFile != "" {
			pw, err := os.ReadFile(c.Output.PasswordFile)
			if err != nil {
				return err
			}
			kc.Password = string(bytes.TrimSpace(pw))
		}
		if c.Output.TLS {
			kc.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		p, err := pipeline.NewKafkaProducer(kc)
		if err != nil {
			return err
		}
		defer p.Close()
		a.Producer = p
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 8)
	var wg sync.WaitGroup
	start := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil && ctx.Err() == nil {
				errc <- errors.New(name + ": " + err.Error())
			}
		}()
	}
	shipper := &ship.Shipper{WAL: w, Producer: a.Producer, Log: a.Log}
	start("shipper", func() error { return shipper.Run(ctx) })
	start("sync", func() error {
		t := time.NewTicker(c.FlushInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-t.C:
				a.appendMu.Lock()
				_ = w.Sync()
				a.appendMu.Unlock()
			}
		}
	})
	if len(c.Files) > 0 {
		cps, err := tail.LoadCheckpoints(filepath.Join(c.DataDir, "checkpoints.json"))
		if err != nil {
			return err
		}
		for _, f := range c.Files {
			f := f
			start("file "+f.Path, func() error { return a.runFile(ctx, cps, f) })
		}
		start("checkpoints", func() error {
			t := time.NewTicker(c.FlushInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return cps.Save()
				case <-t.C:
					a.appendMu.Lock()
					_ = w.Sync() // checkpoints must never get ahead of synced WAL data
					a.appendMu.Unlock()
					if err := cps.Save(); err != nil {
						return err
					}
				}
			}
		})
	}
	if c.Syslog != nil {
		start("syslog", func() error { return a.runSyslog(ctx, c.Syslog) })
	}
	for _, wi := range c.Windows {
		wi := wi
		start("windows "+wi.Channel, func() error { return a.runWindows(ctx, wi) })
	}
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
		cancel()
	}
	wg.Wait()
	return runErr
}

func (a *Agent) runFile(ctx context.Context, cps *tail.Checkpoints, f FileInput) error {
	lines := make(chan tail.Line, 256)
	fl := &tail.Follower{Path: f.Path, Checkpoints: cps, StartAtEnd: f.StartAtEnd}
	done := make(chan error, 1)
	go func() { done <- fl.Run(ctx, lines) }()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			return err
		case l := <-lines:
			env := pipeline.Envelope{TenantID: a.Config.Tenant, SourceID: f.SourceID, Kind: f.Kind, Collector: a.collector(f.Kind),
				ReceivedAt: time.Now().UTC(), Hints: map[string]string{"path": f.Path}, ProviderID: "file:" + f.Path + ":" + strconv.FormatInt(l.Offset, 10), Raw: string(l.Text)}
			if len(l.Text) == 0 {
				continue
			}
			if err := a.buffer(ctx, env); err != nil {
				return err
			}
		}
	}
}

func (a *Agent) runSyslog(ctx context.Context, s *SyslogInput) error {
	allow, err := syslogin.ParseAllow(s.Allow)
	if err != nil {
		return err
	}
	srv := &syslogin.Server{UDPAddr: s.UDP, TCPAddr: s.TCP, TLSAddr: s.TLS, Allow: allow, Log: a.Log}
	if s.TLS != "" {
		cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return err
		}
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	msgs := make(chan syslogin.Message, 1024)
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx, msgs) }()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			return err
		case m := <-msgs:
			c := a.collector(s.Kind)
			c.Address = m.Remote
			env := pipeline.Envelope{TenantID: a.Config.Tenant, SourceID: s.SourceID, Kind: s.Kind, Collector: c, ReceivedAt: m.Received,
				Hints: map[string]string{"transport": m.Transport}, Tags: []string{"transport:" + m.Transport}, Raw: string(m.Data)}
			if err := a.buffer(ctx, env); err != nil {
				return err
			}
		}
	}
}

func (a *Agent) runWindows(ctx context.Context, wi WindowsInput) error {
	sub := &winevt.Subscription{Channel: wi.Channel, Query: wi.Query, FromOldest: wi.FromOldest, BookmarkDir: filepath.Join(a.Config.DataDir, "bookmarks")}
	events := make(chan winevt.Event, 256)
	done := make(chan error, 1)
	go func() { done <- sub.Run(ctx, events) }()
	pending := ""
	tick := time.NewTicker(a.Config.FlushInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return sub.SaveBookmark(pending)
		case err := <-done:
			_ = sub.SaveBookmark(pending)
			return err
		case <-tick.C:
			if pending != "" {
				a.appendMu.Lock()
				err := a.wal.Sync()
				a.appendMu.Unlock()
				if err == nil {
					_ = sub.SaveBookmark(pending)
					pending = ""
				}
			}
		case ev := <-events:
			env := pipeline.Envelope{TenantID: a.Config.Tenant, SourceID: wi.SourceID, Kind: "windows", Collector: a.collector("windows"),
				ReceivedAt: time.Now().UTC(), Hints: map[string]string{"channel": ev.Channel}, Raw: ev.XML}
			if err := a.buffer(ctx, env); err != nil {
				return err
			}
			pending = ev.Bookmark
		}
	}
}
