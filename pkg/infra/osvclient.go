package infra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------- public types used by scan.go ----------

type OSVVuln struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`  // e.g. "CVSS_V3"
		Score string `json:"score"` // numeric string as string, e.g. "7.5"
	} `json:"severity"`
}

type OSVQueryResponse struct {
	Vulns []OSVVuln `json:"vulns"`
}

// ---------- client ----------

type OSVClient struct {
	http     *http.Client
	cache    *osvFileCache
	endpoint string
}

// NewOSV returns an OSV client using a file cache under CacheDir().
func NewOSV() *OSVClient {
	dir := CacheDir()
	_ = os.MkdirAll(dir, 0o755)
	return &OSVClient{
		http:     &http.Client{Timeout: 15 * time.Second},
		cache:    &osvFileCache{path: filepath.Join(dir, "osv_cache.json")},
		endpoint: "https://api.osv.dev/v1/query",
	}
}

// SetOSVEndpoint overrides the default endpoint (useful for tests).
func (c *OSVClient) SetOSVEndpoint(url string) {
	if strings.TrimSpace(url) != "" {
		c.endpoint = url
	}
}

type osvQuery struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version string `json:"version"`
}

// Query looks up ecosystem/name@version with simple 3x retry + jitter and a JSON file cache.
func (c *OSVClient) Query(ctx context.Context, ecosystem, name, version string) (OSVQueryResponse, error) {
	k := strings.ToLower(ecosystem + ":" + name + "@" + version)

	// 1) Cache
	if out, ok := c.cache.get(k); ok {
		return out, nil
	}

	// 2) Network with retries
	var lastErr error
	delay := 200 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		out, err := c.queryOnce(ctx, ecosystem, name, version)
		if err == nil {
			c.cache.put(k, out)
			return out, nil
		}
		lastErr = err
		// jittered backoff
		jit := time.Duration(rand.Int63n(int64(delay / 2)))
		select {
		case <-time.After(delay + jit):
			delay *= 2
		case <-ctx.Done():
			return OSVQueryResponse{}, ctx.Err()
		}
	}
	return OSVQueryResponse{}, fmt.Errorf("osv query failed after retries: %w", lastErr)
}

func (c *OSVClient) queryOnce(ctx context.Context, ecosystem, name, version string) (OSVQueryResponse, error) {
	var q osvQuery
	q.Package.Ecosystem = ecosystem
	q.Package.Name = name
	q.Version = version

	body, _ := json.Marshal(q)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(string(body)))
	if err != nil {
		return OSVQueryResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return OSVQueryResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return OSVQueryResponse{}, errors.New("server error")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var dump struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&dump)
		return OSVQueryResponse{}, fmt.Errorf("bad status %d: %s", resp.StatusCode, dump.Error)
	}

	var out OSVQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return OSVQueryResponse{}, err
	}
	return out, nil
}

// ---------- tiny JSON file cache ----------

type osvFileCache struct {
	path string
}

func (f *osvFileCache) get(k string) (OSVQueryResponse, bool) {
	m, err := f.readAll()
	if err != nil {
		return OSVQueryResponse{}, false
	}
	if raw, ok := m[k]; ok {
		var out OSVQueryResponse
		if err := json.Unmarshal(raw, &out); err == nil {
			return out, true
		}
	}
	return OSVQueryResponse{}, false
}

func (f *osvFileCache) put(k string, v OSVQueryResponse) {
	m, _ := f.readAll()
	if m == nil {
		m = map[string]json.RawMessage{}
	}
	b, _ := json.Marshal(v)
	m[k] = b
	_ = f.writeAll(m)
}

func (f *osvFileCache) readAll() (map[string]json.RawMessage, error) {
	b, err := os.ReadFile(f.path)
	if err != nil {
		return map[string]json.RawMessage{}, nil // treat missing as empty cache
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (f *osvFileCache) writeAll(m map[string]json.RawMessage) error {
	tmp := f.path + ".tmp"
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}
