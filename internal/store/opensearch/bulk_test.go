package opensearch

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lumidren/argus/internal/pipeline"
	"github.com/lumidren/argus/internal/schema"
)

// fakeCluster is an httptest server implementing just enough of the _bulk
// API: create with conflict detection, plus injectable per-call statuses.
type fakeCluster struct {
	mu       sync.Mutex
	docs     map[string]map[string]json.RawMessage // index -> id -> source
	statuses []int                                 // forced status per item for the next call
	user     string
	calls    int
}

func (f *fakeCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	u, _, _ := r.BasicAuth()
	f.user = u
	if r.URL.Path != "/_bulk" || r.Header.Get("Content-Type") != "application/x-ndjson" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"type":"not_found","reason":"no route"}}`))
		return
	}
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	var items []map[string]any
	i := 0
	for sc.Scan() {
		var action map[string]struct {
			Index string `json:"_index"`
			ID    string `json:"_id"`
		}
		if err := json.Unmarshal(sc.Bytes(), &action); err != nil {
			w.WriteHeader(400)
			return
		}
		if !sc.Scan() {
			break
		}
		src := append(json.RawMessage(nil), sc.Bytes()...)
		a := action["create"]
		status := 201
		if i < len(f.statuses) && f.statuses[i] != 0 {
			status = f.statuses[i]
		} else if _, exists := f.docs[a.Index][a.ID]; exists {
			status = 409
		} else {
			if f.docs[a.Index] == nil {
				f.docs[a.Index] = map[string]json.RawMessage{}
			}
			f.docs[a.Index][a.ID] = src
		}
		items = append(items, map[string]any{"create": map[string]any{"_index": a.Index, "_id": a.ID, "status": status}})
		i++
	}
	f.statuses = nil
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": false, "items": items})
}

func doc(tenant, id, msg string) pipeline.Doc {
	e := schema.New()
	e.Set("message", msg)
	e.Set("source.ip", "10.0.0.1")
	return pipeline.Doc{ID: id, TenantID: tenant, Dataset: "generic", Event: e}
}

func TestBulkCreateConflictAndRetry(t *testing.T) {
	fc := &fakeCluster{docs: map[string]map[string]json.RawMessage{}}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, Username: "argus", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	s := &BulkSink{Client: c}
	ctx := context.Background()
	res, err := s.Bulk(ctx, []pipeline.Doc{doc("Acme Corp", "h1", "a"), doc("Acme Corp", "h2", "b")})
	if err != nil || res[0] != pipeline.ItemCreated || res[1] != pipeline.ItemCreated {
		t.Fatalf("create: %v %v", res, err)
	}
	if fc.user != "argus" {
		t.Fatal("basic auth not sent")
	}
	if _, ok := fc.docs["argus-acme_corp-generic-write"]["h1"]; !ok {
		t.Fatalf("wrong index naming: %v", fc.docs)
	}
	var got map[string]any
	_ = json.Unmarshal(fc.docs["argus-acme_corp-generic-write"]["h1"], &got)
	if src, ok := got["source"].(map[string]any); !ok || src["ip"] != "10.0.0.1" {
		t.Fatalf("document must be nested JSON: %v", got)
	}
	res, err = s.Bulk(ctx, []pipeline.Doc{doc("Acme Corp", "h1", "a")})
	if err != nil || res[0] != pipeline.ItemDuplicate {
		t.Fatalf("conflict: %v %v", res, err)
	}
	fc.statuses = []int{429, 400, 503}
	res, err = s.Bulk(ctx, []pipeline.Doc{doc("t", "x1", ""), doc("t", "x2", ""), doc("t", "x3", "")})
	if err != nil || res[0] != pipeline.ItemRetry || res[1] != pipeline.ItemRejected || res[2] != pipeline.ItemRetry {
		t.Fatalf("statuses: %v %v", res, err)
	}
}

func TestErrorsAndNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":{"type":"index_not_found_exception","reason":"no such index [x]"}}`))
	}))
	defer srv.Close()
	c, _ := New(Config{URL: srv.URL})
	err := c.Do(context.Background(), http.MethodGet, "/x/_search?size=1", nil, "", nil)
	if !IsNotFound(err) || !strings.Contains(err.Error(), "no such index") {
		t.Fatalf("error decoding: %v", err)
	}
	if _, err := New(Config{URL: "not a url"}); err == nil {
		t.Fatal("bad URL accepted")
	}
	if SanitizeName("Tenant-A/Prod") != "tenant_a_prod" || SanitizeName("***") != "default" {
		t.Fatal("sanitize")
	}
}
