package infra

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestOSVClient_RetryAndCache(t *testing.T) {
	// Fake OSV: first call -> 500, second+ -> 200 with one vuln
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		resp := OSVQueryResponse{
			Vulns: []OSVVuln{{ID: "TEST-1", Summary: "ok"}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(ts.Close)

	// Use a temp cache directory so we don't touch the user's cache
	tmp := t.TempDir()
	t.Setenv("KEYSTONE_CACHE_DIR", tmp)

	c := NewOSV()
	c.SetOSVEndpoint(ts.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1st Query: should retry once and succeed
	out, err := c.Query(ctx, "npm", "lodash", "4.17.19")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(out.Vulns) != 1 || out.Vulns[0].ID != "TEST-1" {
		t.Fatalf("unexpected response: %+v", out)
	}

	// 2nd Query: should be served from cache (no new server hit)
	hBefore := atomic.LoadInt32(&hits)
	_, err = c.Query(ctx, "npm", "lodash", "4.17.19")
	if err != nil {
		t.Fatalf("Query (cached) failed: %v", err)
	}
	hAfter := atomic.LoadInt32(&hits)
	if hAfter != hBefore {
		t.Fatalf("expected cache hit; server was called again (before=%d after=%d)", hBefore, hAfter)
	}

	// Ensure cache file was written
	if _, err := os.ReadFile(tmp + "/osv_cache.json"); err != nil {
		t.Fatalf("cache file not written: %v", err)
	}
}
