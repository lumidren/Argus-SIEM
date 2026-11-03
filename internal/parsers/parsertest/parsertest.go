// Package parsertest holds assertion and fuzzing helpers shared by every
// parser's tests.
package parsertest

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lumidren/argus/internal/parsers"
	"github.com/lumidren/argus/internal/schema"
)

// Expect asserts that every key in want is present in e with an equal value.
// Values are compared after normalizing ints to int64 and single strings vs
// []string. Missing or different keys are reported together.
func Expect(t testing.TB, e *schema.Event, want map[string]any) {
	t.Helper()
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var problems []string
	for _, k := range keys {
		wantV := normalize(want[k])
		got, ok := e.Get(k)
		if !ok {
			problems = append(problems, fmt.Sprintf("  missing %s (want %v)", k, wantV))
			continue
		}
		gotV := normalize(got)
		if !reflect.DeepEqual(gotV, wantV) {
			problems = append(problems, fmt.Sprintf("  %s: got %#v want %#v", k, gotV, wantV))
		}
	}
	if len(problems) > 0 {
		t.Fatalf("event mismatch:\n%s\nall fields:\n%s", strings.Join(problems, "\n"), Dump(e))
	}
}

// ExpectAbsent asserts that none of the keys are set.
func ExpectAbsent(t testing.TB, e *schema.Event, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if e.Has(k) {
			t.Fatalf("field %s should be absent, got %v\n%s", k, e.String(k), Dump(e))
		}
	}
}

func normalize(v any) any {
	switch t := v.(type) {
	case int:
		return int64(t)
	case int32:
		return int64(t)
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
		return out
	case []string:
		return t
	case time.Time:
		return t.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return v
}

// Dump renders the event's fields one per line for failure messages.
func Dump(e *schema.Event) string {
	var b strings.Builder
	for _, k := range e.Keys() {
		if k == schema.FieldEventOriginal {
			continue
		}
		v, _ := e.Get(k)
		fmt.Fprintf(&b, "  %s = %#v\n", k, v)
	}
	return b.String()
}

// HasTag reports whether tag is in tags.
func HasTag(e *schema.Event, tag string) bool {
	for _, t := range e.Strings(schema.FieldTags) {
		if t == tag {
			return true
		}
	}
	return false
}

// Input builds a parser input with a fixed receive time and tenant.
func Input(raw string, hints map[string]string) *parsers.Input {
	return &parsers.Input{
		Raw:        []byte(raw),
		ReceivedAt: time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		Source:     parsers.Source{TenantID: "t1", SourceID: "src-1"},
		Hints:      hints,
	}
}

// ParseOne parses raw and requires exactly one event and no error.
func ParseOne(t testing.TB, p parsers.Parser, raw string) *schema.Event {
	t.Helper()
	evs, err := p.Parse(Input(raw, nil))
	if err != nil {
		t.Fatalf("parse error: %v\nraw: %s", err, raw)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d\nraw: %s", len(evs), raw)
	}
	return evs[0]
}

// ParseOneHints is ParseOne with hints.
func ParseOneHints(t testing.TB, p parsers.Parser, raw string, hints map[string]string) *schema.Event {
	t.Helper()
	evs, err := p.Parse(Input(raw, hints))
	if err != nil {
		t.Fatalf("parse error: %v\nraw: %s", err, raw)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d\nraw: %s", len(evs), raw)
	}
	return evs[0]
}

// SeedCorpus adds the given seeds and every file under
// test/fuzz/corpus/<parser>/ to the fuzz target.
func SeedCorpus(f *testing.F, parser string, seeds ...string) {
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	dir := filepath.Join(repoRoot(), "test", "fuzz", "corpus", parser)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err == nil && len(b) > 0 {
			f.Add(b)
		}
	}
}

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	// internal/parsers/parsertest/parsertest.go -> repo root is four levels up
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(file))))
}

// FuzzOne runs one fuzz iteration: the parser must not panic, and any event
// it returns must carry module and dataset and survive sanitization and
// JSON rendering.
func FuzzOne(t *testing.T, p parsers.Parser, data []byte) {
	t.Helper()
	in := &parsers.Input{Raw: data, ReceivedAt: time.Unix(1700000000, 0).UTC(), Source: parsers.Source{TenantID: "fz", SourceID: "fz"}}
	_ = p.Detect(data, nil)
	evs, _ := p.Parse(in)
	for _, e := range evs {
		if e == nil {
			t.Fatal("nil event returned")
		}
		if e.String(schema.FieldEventModule) == "" || e.String(schema.FieldEventDataset) == "" {
			t.Fatalf("event without module/dataset: %s", Dump(e))
		}
		parsers.Stamp(e, in, p, schema.ParseStatusOK, nil)
		schema.Finalize(e, in.ReceivedAt)
		if _, err := e.MarshalJSON(); err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if e.Len() > 2000 {
			t.Fatalf("field explosion: %d fields", e.Len())
		}
	}
}
