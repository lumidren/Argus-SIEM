package parsers

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lumidren/argus/internal/schema"
)

type fakeParser struct {
	name   string
	detect func([]byte) bool
	parse  func(*Input) ([]*schema.Event, error)
}

func (f fakeParser) Name() string                                { return f.name }
func (f fakeParser) Version() string                             { return "1.0.0" }
func (f fakeParser) Datasets() []string                          { return []string{f.name + ".x"} }
func (f fakeParser) Detect(raw []byte, _ map[string]string) bool { return f.detect(raw) }
func (f fakeParser) Parse(in *Input) ([]*schema.Event, error)    { return f.parse(in) }

func TestRegistryRoutingAndStamp(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeParser{
		name:   "alpha",
		detect: func(b []byte) bool { return strings.HasPrefix(string(b), "A") },
		parse: func(in *Input) ([]*schema.Event, error) {
			e := Base(in, "alpha", "alpha.x")
			e.Set("host.name", "payloadhost")
			e.Set(schema.FieldTenantID, "evil-tenant")
			return []*schema.Event{e}, nil
		},
	})
	r.Register(fakeParser{
		name:   "beta",
		detect: func(b []byte) bool { return strings.HasPrefix(string(b), "B") },
		parse:  func(in *Input) ([]*schema.Event, error) { panic("boom") },
	})
	in := &Input{
		Raw:        []byte("A hello"),
		ReceivedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Source: Source{TenantID: "t1", SourceID: "s1", Tags: []string{"prod"},
			Collector: Collector{Name: "argus-agent", Type: "argus-agent", Host: "agenthost", Version: "0.1"}},
	}
	res := r.Parse(in)
	if res.Status != schema.ParseStatusOK || len(res.Events) != 1 {
		t.Fatalf("status %s events %d err %v", res.Status, len(res.Events), res.Err)
	}
	e := res.Events[0]
	if e.String(schema.FieldTenantID) != "t1" {
		t.Fatalf("payload tenant must be overwritten, got %s", e.String(schema.FieldTenantID))
	}
	if v, _ := e.Bool(schema.FieldHostMismatch); !v {
		t.Fatalf("host mismatch should be flagged")
	}
	if e.String(schema.FieldParser) != "alpha" || e.String(schema.FieldParserVersion) != "1.0.0" {
		t.Fatalf("parser provenance missing")
	}
	if e.String(schema.FieldTimeSource) != "processing" || e.String(schema.FieldTimestamp) == "" {
		t.Fatalf("timestamp fallback missing: %v", e.Keys())
	}
	if got := e.Strings(schema.FieldTags); len(got) != 1 || got[0] != "prod" {
		t.Fatalf("tags %v", got)
	}

	// panic recovery
	res = r.Parse(&Input{Raw: []byte("B"), ReceivedAt: in.ReceivedAt, Source: in.Source})
	if !res.Panic || res.Status != schema.ParseStatusFailed || !errors.Is(res.Err, ErrPanic) {
		t.Fatalf("panic not recovered: %+v", res)
	}
	if res.Events[0].String(schema.FieldEventDataset) != "generic.unparsed" {
		t.Fatalf("raw event missing")
	}
	if !strings.Contains(res.Events[0].String(schema.FieldEventOriginal), "B") {
		t.Fatalf("raw preserved")
	}

	// unrecognized
	res = r.Parse(&Input{Raw: []byte("zzz"), ReceivedAt: in.ReceivedAt, Source: in.Source})
	if res.Status != schema.ParseStatusFailed || !errors.Is(res.Err, ErrUnrecognized) {
		t.Fatalf("unrecognized handling: %+v", res)
	}
	if res.Events[0].String(schema.FieldParseStatus) != schema.ParseStatusFailed || res.Events[0].String(schema.FieldTenantID) != "t1" {
		t.Fatalf("unrecognized raw event must be stamped: %v", res.Events[0].Keys())
	}

	// explicit kind wins over sniffing
	res = r.Parse(&Input{Raw: []byte("zzz"), ReceivedAt: in.ReceivedAt, Source: Source{TenantID: "t", Kind: "alpha"}})
	if res.Status != schema.ParseStatusOK {
		t.Fatalf("explicit kind: %+v", res)
	}
}

func TestSniffOrder(t *testing.T) {
	r := NewRegistry()
	all := func([]byte) bool { return true }
	r.Register(fakeParser{name: "generic", detect: all})
	r.Register(fakeParser{name: "specific", detect: all})
	r.SetSniffOrder("specific", "generic")
	p, ok := r.Sniff([]byte("x"), nil)
	if !ok || p.Name() != "specific" {
		t.Fatalf("sniff order not honoured: %v", p)
	}
}

func TestIPHelpers(t *testing.T) {
	cases := map[string]string{
		"::ffff:10.0.0.1": "10.0.0.1",
		"[2001:db8::1]":   "2001:db8::1",
		"fe80::1%eth0":    "fe80::1",
		"-":               "",
		"N/A":             "",
		"10.0.0.300":      "",
		" 8.8.8.8 ":       "8.8.8.8",
	}
	for in, want := range cases {
		if got := NormalizeIP(in); got != want {
			t.Errorf("NormalizeIP(%q)=%q want %q", in, got, want)
		}
	}
	if !IsPublicIP("8.8.8.8") || IsPublicIP("10.1.2.3") || IsPublicIP("100.64.1.1") || IsPublicIP("127.0.0.1") || IsPublicIP("fe80::1") {
		t.Fatal("IsPublicIP wrong")
	}
	e := schema.New()
	if SetPort(e, "p", "70000") || !SetPort(e, "p", "443") {
		t.Fatal("port validation")
	}
}

func TestUserAndPathHelpers(t *testing.T) {
	u, d := SplitDomainUser(`CORP\alice`)
	if u != "alice" || d != "CORP" {
		t.Fatalf("backslash split %s %s", u, d)
	}
	u, d = SplitDomainUser("bob@example.com")
	if u != "bob" || d != "example.com" {
		t.Fatalf("at split %s %s", u, d)
	}
	u, d = SplitDomainUser("plain")
	if u != "plain" || d != "" {
		t.Fatalf("plain split")
	}
	if BaseName(`C:\Windows\System32\cmd.exe`) != "cmd.exe" || BaseName("/usr/bin/bash") != "bash" {
		t.Fatal("basename")
	}
	if Extension("evil.PS1") != "ps1" || Extension("noext") != "" || Extension(".bashrc") != "" {
		t.Fatal("extension")
	}
	e := schema.New()
	SetHashes(e, "process.hash", "SHA1=ABC,MD5=def,SHA256=0123,IMPHASH=ff")
	if e.String("process.hash.sha1") != "abc" || e.String("process.hash.imphash") != "ff" {
		t.Fatalf("hashes %v", e.Flat())
	}
	e = schema.New()
	SetHashByLength(e, "file.hash", strings.Repeat("a", 64))
	if !e.Has("file.hash.sha256") {
		t.Fatal("sha256 by length")
	}
	e = schema.New()
	SetURL(e, "https://user:pw@example.com:8443/path/to/file.php?q=1#frag")
	if e.String("url.domain") != "example.com" || e.String("url.path") != "/path/to/file.php" || e.String("url.query") != "q=1" || e.String("url.fragment") != "frag" || e.String("url.extension") != "php" || e.String("url.username") != "user" {
		t.Fatalf("url parse %v", e.Flat())
	}
	if p, _ := e.Int64("url.port"); p != 8443 {
		t.Fatal("url port")
	}
	e = schema.New()
	SetURL(e, "/index.html?a=b")
	if e.String("url.path") != "/index.html" || e.Has("url.domain") {
		t.Fatalf("relative url %v", e.Flat())
	}
}

func TestJSONLimits(t *testing.T) {
	deep := strings.Repeat("[", MaxJSONDepth+1) + strings.Repeat("]", MaxJSONDepth+1)
	if _, err := DecodeJSONAny([]byte(deep)); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("depth limit: %v", err)
	}
	big := `{"a":"` + strings.Repeat("x", MaxJSONBytes) + `"}`
	if _, err := DecodeJSON([]byte(big)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size limit: %v", err)
	}
	obj, err := DecodeJSON([]byte(`{"a":{"b":[1,2]},"n":12345678901234567,"s":"x\"{"}`))
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := GetInt(obj, "n"); n != 12345678901234567 {
		t.Fatalf("precision %d", n)
	}
	if GetString(obj, "a.b") != "" || GetString(obj, "s") != `x"{` {
		t.Fatal("GetString")
	}
}

func TestSnakeAndFlatten(t *testing.T) {
	cases := map[string]string{
		"userIdentity":      "user_identity",
		"callerIPAddress":   "caller_ip_address",
		"MFAUsed":           "mfa_used",
		"already_snake":     "already_snake",
		"HTTPMethod":        "http_method",
		"ipv6Address":       "ipv6_address",
		"Request-Id":        "request_id",
		"a":                 "a",
		"userPrincipalName": "user_principal_name",
	}
	for in, want := range cases {
		if got := Snake(in); got != want {
			t.Errorf("Snake(%q)=%q want %q", in, got, want)
		}
	}
	e := schema.New()
	obj, _ := DecodeJSON([]byte(`{"userIdentity":{"sessionContext":{"mfaAuthenticated":"true"}},"list":["a","b"]}`))
	FlattenInto(e, "aws.cloudtrail", obj, true)
	if e.String("aws.cloudtrail.user_identity.session_context.mfa_authenticated") != "true" {
		t.Fatalf("flatten snake %v", e.Flat())
	}
	if got := e.Strings("aws.cloudtrail.list"); len(got) != 2 {
		t.Fatal("array kept")
	}
}

func TestParseKVAndCSV(t *testing.T) {
	keys, kv := ParseKV(`date=2024-01-01 devname="FGT 60E" msg="a \"quoted\" value" empty= action=accept`)
	if kv["devname"] != "FGT 60E" || kv["msg"] != `a "quoted" value` || kv["empty"] != "" || kv["action"] != "accept" {
		t.Fatalf("kv %v", kv)
	}
	if keys[0] != "date" || len(keys) != 5 {
		t.Fatalf("keys %v", keys)
	}
	cols := SplitCSVLine(`a,"b,c",d,"e ""q"" f",`)
	if len(cols) != 5 || cols[1] != "b,c" || cols[3] != `e "q" f` || cols[4] != "" {
		t.Fatalf("csv %q", cols)
	}
}

func TestSeverity(t *testing.T) {
	for in, want := range map[string]int64{"informational": 10, "Low": 25, "medium": 50, "HIGH": 75, "critical": 100, "3": 75} {
		got, ok := Severity0to100(in)
		if !ok || got != want {
			t.Errorf("sev %q = %d", in, got)
		}
	}
	if _, ok := Severity0to100("bogus"); ok {
		t.Error("bogus severity accepted")
	}
}
