package opensearch

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lumidren/argus/internal/pipeline"
)

// IndexNamer maps a tenant and dataset family to the write alias.
type IndexNamer func(tenant, dataset string) string

// WriteAlias is the default naming: argus-{tenant}-{dataset}-write
// (docs/adr/0002-hot-storage-opensearch.md).
func WriteAlias(tenant, dataset string) string {
	return "argus-" + SanitizeName(tenant) + "-" + SanitizeName(dataset) + "-write"
}

// SanitizeName lower-cases and replaces characters OpenSearch forbids in
// index names.
func SanitizeName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "default"
	}
	return out
}

// BulkSink implements pipeline.IndexSink with idempotent "create" actions
// keyed by event.hash (ADR-0004).
type BulkSink struct {
	Client *Client
	Namer  IndexNamer
}

// Bulk implements pipeline.IndexSink.
func (s *BulkSink) Bulk(ctx context.Context, docs []pipeline.Doc) ([]pipeline.ItemResult, error) {
	if len(docs) == 0 {
		return nil, nil
	}
	namer := s.Namer
	if namer == nil {
		namer = WriteAlias
	}
	var buf bytes.Buffer
	for _, d := range docs {
		action := map[string]any{"create": map[string]any{"_index": namer(d.TenantID, d.Dataset), "_id": d.ID}}
		a, err := json.Marshal(action)
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(d.Event)
		if err != nil {
			return nil, err
		}
		buf.Write(a)
		buf.WriteByte('\n')
		buf.Write(b)
		buf.WriteByte('\n')
	}
	var resp struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
			Error  *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := s.Client.Do(ctx, http.MethodPost, "/_bulk", buf.Bytes(), "application/x-ndjson", &resp); err != nil {
		return nil, err
	}
	out := make([]pipeline.ItemResult, len(docs))
	for i := range docs {
		if i >= len(resp.Items) {
			out[i] = pipeline.ItemRetry
			continue
		}
		var status int
		for _, it := range resp.Items[i] {
			status = it.Status
		}
		out[i] = classify(status)
	}
	return out, nil
}

func classify(status int) pipeline.ItemResult {
	switch {
	case status >= 200 && status < 300:
		return pipeline.ItemCreated
	case status == http.StatusConflict:
		return pipeline.ItemDuplicate
	case status == http.StatusTooManyRequests || status >= 500 || status == 0:
		return pipeline.ItemRetry
	default:
		return pipeline.ItemRejected
	}
}
