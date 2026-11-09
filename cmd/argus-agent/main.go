// Command argus-agent collects host logs (files, syslog, Windows Event Log),
// buffers them in a disk WAL, and ships them to the Argus bus with
// at-least-once delivery.
//
//	argus-agent -config /etc/argus/agent.yaml
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/lumidren/argus/internal/agent"
	"github.com/lumidren/argus/internal/telemetry"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "agent.yaml", "path to the agent configuration file")
	logLevel := flag.String("log-level", "info", "debug, info, warn or error")
	check := flag.Bool("check", false, "validate the configuration and exit")
	flag.Parse()
	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "argus-agent:", err)
		os.Exit(2)
	}
	if *check {
		fmt.Println("configuration ok")
		return
	}
	agent.Version = version
	log := telemetry.NewLogger(os.Stdout, "argus-agent", version, *logLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := &agent.Agent{Config: cfg, Log: log}
	log.Info("agent starting", "tenant", cfg.Tenant, "files", len(cfg.Files), "windows_channels", len(cfg.Windows), "syslog", cfg.Syslog != nil)
	if err := a.Run(ctx); err != nil {
		log.Error("agent stopped", "error", err)
		os.Exit(1)
	}
	log.Info("agent stopped")
}
