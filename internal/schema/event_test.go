package schema

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSetIgnoresEmpties(t *testing.T) {
	e := New()
	e.Set("a", "")
	e.Set("b", nil)
	e.Set("c", []string{})
	e.Set("d", map[string]any{})
	var p *string
	e.Set("e", p)
	if e.Len() != 0 {
		t.Fatalf("expected no fields, got %v", e.Keys())
	}
	e.Set("n", 5)
	if v, _ := e.Int64("n"); v != 5 {
		t.Fatalf("int conversion failed")
	}
	e.Set("t", time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC))
	if e.String("t") != "2024-01-02T03:04:05Z" {
		t.Fatalf("time formatting: %s", e.String("t"))
	}
}

func TestAppendDedupes(t *testing.T) {
	e := New()
	e.Append("related.ip", "10.0.0.1", "", "10.0.0.1", "10.0.0.2")
	got := e.Strings("related.ip")
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Fatalf("unexpected %v", got)
	}
}

func TestNestedAndRoundTrip(t *testing.T) {
	e := New()
	e.Set("@timestamp", "2024-01-01T00:00:00.000Z")
	e.Set("process.name", "cmd.exe")
	e.Set("process.pid", int64(42))
	e.Set("process.args", []string{"a", "b"})
	e.Set("event.category", []string{"process"})
	e.Set("winlog.event_data.Hashes", "SHA256=ab")
	n := e.Nested()
	proc, ok := n["process"].(map[string]any)
	if !ok || proc["name"] != "cmd.exe" {
		t.Fatalf("nested conversion wrong: %#v", n)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var back Event
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.String("process.name") != "cmd.exe" {
		t.Fatalf("round trip lost process.name: %s", string(b))
	}
	if pid, _ := back.Int64("process.pid"); pid != 42 {
		t.Fatalf("round trip pid: %v", back.String("process.pid"))
	}
	if got := back.Strings("process.args"); len(got) != 2 {
		t.Fatalf("round trip args: %v", got)
	}
}

func TestNestedConflict(t *testing.T) {
	e := New()
	e.Set("process", "scalar")
	e.Set("process.name", "x")
	n := e.Nested()
	proc := n["process"].(map[string]any)
	if proc["value"] != "scalar" || proc["name"] != "x" {
		t.Fatalf("conflict resolution wrong: %#v", n)
	}
}

func TestFlattenArraysOfObjects(t *testing.T) {
	var e Event
	in := `{"dns":{"answers":[{"data":"1.1.1.1","ttl":30},{"data":"2.2.2.2","ttl":30}]},"n":1.5,"big":12345678901234}`
	if err := json.Unmarshal([]byte(in), &e); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Get("dns.answers"); !ok {
		t.Fatalf("expected dns.answers kept as array, keys=%v", e.Keys())
	}
	if f, _ := e.Float64("n"); f != 1.5 {
		t.Fatalf("float lost")
	}
	if n, _ := e.Int64("big"); n != 12345678901234 {
		t.Fatalf("int64 precision lost: %v", n)
	}
}

func TestParseTime(t *testing.T) {
	cases := map[string]string{
		"2024-03-01T12:00:00Z":            "2024-03-01T12:00:00Z",
		"2024-03-01T12:00:00.123456789Z":  "2024-03-01T12:00:00.123456789Z",
		"2024-03-01T12:00:00+02:00":       "2024-03-01T10:00:00Z",
		"2024-03-01 12:00:00":             "2024-03-01T12:00:00Z",
		"01/Mar/2024:12:00:00 +0000":      "2024-03-01T12:00:00Z",
		"1709294400":                      "2024-03-01T12:00:00Z",
		"1709294400000":                   "2024-03-01T12:00:00Z",
		"1709294400000000":                "2024-03-01T12:00:00Z",
		"1709294400000000000":             "2024-03-01T12:00:00Z",
		"1709294400.5":                    "2024-03-01T12:00:00.5Z",
		"Fri Mar  1 12:00:00 2024 UTC":    "2024-03-01T12:00:00Z",
		"2024/03/01 12:00:00":             "2024-03-01T12:00:00Z",
		"Fri Mar 01 12:00:00.123456 2024": "2024-03-01T12:00:00.123456Z",
		"2024-03-01T12:00:00.1234567Z":    "2024-03-01T12:00:00.1234567Z",
	}
	for in, want := range cases {
		got, ok := ParseTime(in)
		if !ok {
			t.Errorf("%q: not parsed", in)
			continue
		}
		if got.UTC().Format(time.RFC3339Nano) != want {
			t.Errorf("%q: got %s want %s", in, got.UTC().Format(time.RFC3339Nano), want)
		}
	}
	if _, ok := ParseTime("not a time"); ok {
		t.Error("garbage parsed")
	}
	if _, ok := ParseTime("-"); ok {
		t.Error("dash parsed")
	}
}

func TestParseSyslogTimeRollover(t *testing.T) {
	ref := time.Date(2025, 1, 1, 0, 30, 0, 0, time.UTC)
	got, ok := ParseSyslogTime("Dec 31 23:59:00", ref)
	if !ok || got.Year() != 2024 {
		t.Fatalf("expected previous year, got %v", got)
	}
	got, ok = ParseSyslogTime("Jan  1 00:10:00", ref)
	if !ok || got.Year() != 2025 {
		t.Fatalf("expected same year, got %v", got)
	}
}

func TestSanitize(t *testing.T) {
	e := New()
	e.Set("message", "hello\x1b[31mworld\x00\ttab")
	e.Set("big", strings.Repeat("a", MaxFieldBytes+10))
	e.Set("arr", []string{"ok", "\x07bell"})
	e.Set("bad", "caf\xff")
	Sanitize(e)
	if e.String("message") != "hello[31mworld\ttab" {
		t.Fatalf("control strip wrong: %q", e.String("message"))
	}
	if len(e.String("big")) != MaxFieldBytes {
		t.Fatalf("truncation wrong: %d", len(e.String("big")))
	}
	if tr := e.Strings(FieldTruncatedFields); len(tr) != 1 || tr[0] != "big" {
		t.Fatalf("truncated fields: %v", tr)
	}
	if got := e.Strings("arr"); got[1] != "bell" {
		t.Fatalf("array sanitize: %v", got)
	}
	if !strings.Contains(e.String("bad"), "�") {
		t.Fatalf("invalid utf8 not repaired: %q", e.String("bad"))
	}
}

func TestFinalizeRelatedAndEntity(t *testing.T) {
	e := New()
	e.Set(FieldTenantID, "t1")
	e.Set("host.name", "WS01")
	e.Set("source.ip", "::ffff:10.0.0.5")
	e.Set("destination.ip", "not-an-ip")
	e.Set("user.name", "Alice")
	e.Set("user.domain", "CORP")
	e.Set("process.hash.sha256", "ABCD")
	Finalize(e, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	if e.String("host.name") != "ws01" {
		t.Fatalf("host not lowercased")
	}
	if ip := e.Strings(FieldRelatedIP); len(ip) != 1 || ip[0] != "10.0.0.5" {
		t.Fatalf("related.ip %v", ip)
	}
	if u := e.Strings(FieldRelatedUser); len(u) != 1 || u[0] != "Alice" {
		t.Fatalf("related.user %v", u)
	}
	if h := e.Strings(FieldRelatedHash); h[0] != "abcd" {
		t.Fatalf("related.hash %v", h)
	}
	if e.String(FieldEntityKey) != "t1|user:corp\\alice" {
		t.Fatalf("entity key %q", e.String(FieldEntityKey))
	}
	if e.String(FieldEventKind) != KindEvent {
		t.Fatalf("kind default missing")
	}
	if v, _ := e.Int64(FieldSchemaVersion); v != Version {
		t.Fatalf("schema version missing")
	}
}

func TestComputeHashSeparators(t *testing.T) {
	a := ComputeHash("t", "s", []byte("ab"), "c")
	b := ComputeHash("t", "s", []byte("a"), "bc")
	if a == b {
		t.Fatal("separator failure: moving bytes between inputs collided")
	}
	if ComputeHash("t", "s", []byte("x\n"), "") != ComputeHash("t", "s", []byte("x"), "") {
		t.Fatal("trailing whitespace should not change the hash")
	}
}
