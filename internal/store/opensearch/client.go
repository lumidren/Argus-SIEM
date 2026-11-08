// Package opensearch is a small, dependency-free OpenSearch client covering
// what Argus needs: bulk indexing with idempotent create, search, index
// templates, ISM policies, snapshots and index settings.
package opensearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config holds connection settings.
type Config struct {
	URL      string // e.g. https://opensearch:9200
	Username string
	Password string
	TLS      *tls.Config
	Timeout  time.Duration
	// MaxResponseBytes caps a decoded response body.
	MaxResponseBytes int64
}

// Client talks to one OpenSearch cluster.
type Client struct {
	base    *url.URL
	cfg     Config
	http    *http.Client
	maxBody int64
}

// New creates a client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.URL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("opensearch: invalid URL %q", cfg.URL)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 64
	if cfg.TLS != nil {
		tr.TLSClientConfig = cfg.TLS
	}
	max := cfg.MaxResponseBytes
	if max <= 0 {
		max = 64 << 20
	}
	return &Client{base: u, cfg: cfg, http: &http.Client{Timeout: cfg.Timeout, Transport: tr}, maxBody: max}, nil
}

// Error is a non-2xx response.
type Error struct {
	Status int
	Type   string
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("opensearch: %d %s: %s", e.Status, e.Type, e.Reason)
}

// IsNotFound reports a 404.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// Do performs a request with a JSON (or NDJSON) body and decodes the JSON
// response into out when non-nil.
func (c *Client) Do(ctx context.Context, method, path string, body []byte, contentType string, out any) error {
	u := *c.base
	p, q, _ := strings.Cut(path, "?")
	u.Path = c.base.Path + p
	u.RawQuery = q
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), r)
	if err != nil {
		return err
	}
	if contentType == "" {
		contentType = "application/json"
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if c.cfg.Username != "" {
		req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var eb struct {
			Error struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &eb)
		reason := eb.Error.Reason
		if reason == "" {
			reason = strings.TrimSpace(string(data))
			if len(reason) > 300 {
				reason = reason[:300]
			}
		}
		return &Error{Status: resp.StatusCode, Type: eb.Error.Type, Reason: reason}
	}
	if out != nil && len(data) > 0 {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		return dec.Decode(out)
	}
	return nil
}

// PutJSON sends v as JSON with PUT.
func (c *Client) PutJSON(ctx context.Context, path string, v any, out any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Do(ctx, http.MethodPut, path, b, "", out)
}

// PostJSON sends v as JSON with POST.
func (c *Client) PostJSON(ctx context.Context, path string, v any, out any) error {
	var b []byte
	if v != nil {
		var err error
		if b, err = json.Marshal(v); err != nil {
			return err
		}
	}
	return c.Do(ctx, http.MethodPost, path, b, "", out)
}

// Ping checks connectivity.
func (c *Client) Ping(ctx context.Context) error {
	return c.Do(ctx, http.MethodGet, "/", nil, "", nil)
}
