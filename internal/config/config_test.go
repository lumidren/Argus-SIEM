package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(vals map[string]string) *Env {
	e := New("ARGUS_")
	e.Lookup = func(k string) (string, bool) { v, ok := vals[k]; return v, ok }
	return e
}

func TestTypedValues(t *testing.T) {
	e := env(map[string]string{
		"ARGUS_NAME": " processor ", "ARGUS_WORKERS": "8", "ARGUS_DEBUG": "true",
		"ARGUS_TIMEOUT": "45s", "ARGUS_BROKERS": "a:9092, b:9092,,", "ARGUS_EMPTY": "  ",
	})
	if e.String("NAME", "x") != "processor" || e.Int("WORKERS", 1) != 8 || !e.Bool("DEBUG", false) {
		t.Fatal("basic values")
	}
	if e.Duration("TIMEOUT", time.Second) != 45*time.Second {
		t.Fatal("duration")
	}
	if got := e.List("BROKERS", nil); len(got) != 2 || got[1] != "b:9092" {
		t.Fatalf("list %v", got)
	}
	if e.String("EMPTY", "def") != "def" || e.Int("MISSING", 3) != 3 {
		t.Fatal("defaults")
	}
	if e.Err() != nil {
		t.Fatalf("unexpected errors: %v", e.Err())
	}
}

func TestErrorsCollected(t *testing.T) {
	e := env(map[string]string{"ARGUS_WORKERS": "many", "ARGUS_DEBUG": "maybe", "ARGUS_TIMEOUT": "soon"})
	e.Int("WORKERS", 1)
	e.Bool("DEBUG", false)
	e.Duration("TIMEOUT", 0)
	e.Require("URL", "")
	err := e.Err()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"ARGUS_WORKERS", "ARGUS_DEBUG", "ARGUS_TIMEOUT", "ARGUS_URL is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestFileValues(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "value")
	if err := os.WriteFile(p, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := env(map[string]string{"ARGUS_DSN_FILE": p, "ARGUS_OTHER": "direct"})
	if e.File("DSN", "") != "from-file" || e.File("OTHER", "") != "direct" {
		t.Fatal("file lookup")
	}
	e = env(map[string]string{"ARGUS_DSN_FILE": filepath.Join(dir, "missing")})
	e.File("DSN", "")
	if e.Err() == nil {
		t.Fatal("missing file must be reported")
	}
}
