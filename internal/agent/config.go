// Package agent assembles the argus-agent: inputs (files, syslog, Windows
// Event Log) feed a disk WAL; a shipper drains the WAL to the bus.
package agent

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the agent configuration file (YAML).
type Config struct {
	Tenant  string `yaml:"tenant"`
	DataDir string `yaml:"data_dir"`
	// Hostname overrides os.Hostname for collector identity.
	Hostname string `yaml:"hostname"`
	Buffer   struct {
		MaxBytes     int64 `yaml:"max_bytes"`
		SegmentBytes int64 `yaml:"segment_bytes"`
	} `yaml:"buffer"`
	Output struct {
		Brokers  []string `yaml:"brokers"`
		Username string   `yaml:"username"`
		// PasswordFile holds the SASL password; inline passwords are not
		// supported so configs can be shared safely.
		PasswordFile string `yaml:"password_file"`
		TLS          bool   `yaml:"tls"`
	} `yaml:"output"`
	Files   []FileInput    `yaml:"files"`
	Syslog  *SyslogInput   `yaml:"syslog"`
	Windows []WindowsInput `yaml:"windows"`
	Admin   string         `yaml:"admin_addr"`
	// FlushInterval forces a WAL sync on idle inputs.
	FlushInterval time.Duration `yaml:"flush_interval"`
}

// FileInput tails one file.
type FileInput struct {
	Path       string `yaml:"path"`
	Kind       string `yaml:"kind"`      // parser kind, e.g. linux, nginx; empty = sniff
	SourceID   string `yaml:"source_id"` // registered data source id
	StartAtEnd bool   `yaml:"start_at_end"`
}

// SyslogInput receives syslog.
type SyslogInput struct {
	UDP      string   `yaml:"udp"`
	TCP      string   `yaml:"tcp"`
	TLS      string   `yaml:"tls"`
	CertFile string   `yaml:"cert_file"`
	KeyFile  string   `yaml:"key_file"`
	Allow    []string `yaml:"allow"`
	Kind     string   `yaml:"kind"`
	SourceID string   `yaml:"source_id"`
}

// WindowsInput subscribes to one event log channel.
type WindowsInput struct {
	Channel    string `yaml:"channel"`
	Query      string `yaml:"query"`
	SourceID   string `yaml:"source_id"`
	FromOldest bool   `yaml:"from_oldest"`
}

// LoadConfig reads and validates a config file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(b)
}

// ParseConfig parses and validates YAML.
func ParseConfig(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("agent config: %w", err)
	}
	var errs []error
	if c.Tenant == "" {
		errs = append(errs, errors.New("tenant is required"))
	}
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir is required"))
	}
	if len(c.Output.Brokers) == 0 {
		errs = append(errs, errors.New("output.brokers is required"))
	}
	if len(c.Files) == 0 && c.Syslog == nil && len(c.Windows) == 0 {
		errs = append(errs, errors.New("at least one input (files, syslog, windows) is required"))
	}
	for i, f := range c.Files {
		if f.Path == "" {
			errs = append(errs, fmt.Errorf("files[%d].path is required", i))
		}
	}
	for i, w := range c.Windows {
		if w.Channel == "" {
			errs = append(errs, fmt.Errorf("windows[%d].channel is required", i))
		}
	}
	if s := c.Syslog; s != nil {
		if s.UDP == "" && s.TCP == "" && s.TLS == "" {
			errs = append(errs, errors.New("syslog needs udp, tcp or tls"))
		}
		if s.TLS != "" && (s.CertFile == "" || s.KeyFile == "") {
			errs = append(errs, errors.New("syslog.tls needs cert_file and key_file"))
		}
	}
	if c.Admin == "" {
		c.Admin = "127.0.0.1:9101"
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = time.Second
	}
	return &c, errors.Join(errs...)
}
