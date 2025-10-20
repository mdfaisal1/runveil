package infra

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type apiClient struct {
	base string
	tok  string
	http *http.Client
}

func newAPI() *apiClient {
	return &apiClient{
		base: APIBaseURL(), // from config_api.go (Step 1)
		tok:  APIToken(),
		http: &http.Client{Timeout: 20 * time.Second},
	}
}

// ScanIngestPayload matches the API ingest contract.
type ScanIngestPayload struct {
	ProjectSlug string          `json:"project_slug"`
	Source      string          `json:"source"` // "cli"
	Report      json.RawMessage `json:"report"` // JSON report bytes
}

// PostScan posts a JSON report to /v1/projects/:slug/scans/ingest.
func PostScan(ctx context.Context, projectSlug string, reportJSON []byte) error {
	if len(reportJSON) == 0 {
		return fmt.Errorf("empty report payload")
	}
	c := newAPI()
	body, err := json.Marshal(ScanIngestPayload{
		ProjectSlug: projectSlug,
		Source:      "cli",
		Report:      reportJSON,
	})
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/v1/projects/%s/scans/ingest", c.base, projectSlug)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.tok != "" {
		req.Header.Set("Authorization", "Bearer "+c.tok)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ingest failed: status=%d", resp.StatusCode)
	}
	return nil
}
