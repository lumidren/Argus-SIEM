// Package telemetry sets up structured logging and the Prometheus metrics
// endpoint shared by every Argus service.
package telemetry

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewLogger returns a JSON slog logger tagged with the service name and
// version. level is one of debug, info, warn, error.
func NewLogger(w io.Writer, service, version, level string) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})
	return slog.New(h).With("service", service, "version", version)
}

// Health tracks liveness (the main loop is making progress) and readiness
// (dependencies are reachable).
type Health struct {
	lastBeat atomic.Int64
	ready    atomic.Bool
	// MaxStall is how long the loop may go without a heartbeat before the
	// liveness probe fails.
	MaxStall time.Duration
}

// Beat records progress.
func (h *Health) Beat() { h.lastBeat.Store(time.Now().UnixNano()) }

// SetReady flips readiness.
func (h *Health) SetReady(ok bool) { h.ready.Store(ok) }

// Live reports whether the last heartbeat is recent enough.
func (h *Health) Live() bool {
	last := h.lastBeat.Load()
	if last == 0 {
		return true // not started yet; startup probes cover this window
	}
	stall := h.MaxStall
	if stall <= 0 {
		stall = 2 * time.Minute
	}
	return time.Since(time.Unix(0, last)) < stall
}

// Ready reports readiness.
func (h *Health) Ready() bool { return h.ready.Load() }

// NewRegistry returns a Prometheus registry with Go runtime and process
// collectors already registered.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return reg
}

// AdminMux serves /metrics, /healthz and /readyz.
func AdminMux(reg *prometheus.Registry, h *Health) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !h.Live() {
			http.Error(w, "stalled", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !h.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// ServeAdmin runs the admin server until ctx ends.
func ServeAdmin(ctx context.Context, addr string, mux *http.ServeMux, log *slog.Logger) {
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("admin server stopped", "error", err)
	}
}
