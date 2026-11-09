package telemetry

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoggerJSONAndLevel(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, "processor", "1.2.3", "warn")
	log.Info("hidden")
	log.Warn("shown", "k", 1)
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("not one JSON line: %q", buf.String())
	}
	if rec["msg"] != "shown" || rec["service"] != "processor" || rec["version"] != "1.2.3" {
		t.Fatalf("record %v", rec)
	}
}

func TestHealthEndpoints(t *testing.T) {
	h := &Health{MaxStall: 50 * time.Millisecond}
	mux := AdminMux(NewRegistry(), h)
	get := func(path string) int {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		return rr.Code
	}
	if get("/healthz") != 200 || get("/readyz") != 503 {
		t.Fatal("initial state")
	}
	h.SetReady(true)
	h.Beat()
	if get("/readyz") != 200 || get("/healthz") != 200 {
		t.Fatal("ready and live")
	}
	time.Sleep(80 * time.Millisecond)
	if get("/healthz") != 503 {
		t.Fatal("stall must fail liveness")
	}
	if get("/metrics") != 200 {
		t.Fatal("metrics")
	}
}
