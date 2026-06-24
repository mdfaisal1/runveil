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
	Source      string          `json:"source"`              // "cli"
	Component   string          `json:"component,omitempty"` // optional manifest-declared component key
	Report      json.RawMessage `json:"report"`              // JSON report bytes
}

// PostScan posts a JSON report to /v1/projects/:slug/scans/ingest. When
// component is non-empty the scan is attached to that (pre-registered) component.
func PostScan(ctx context.Context, projectSlug, component string, reportJSON []byte) error {
	if len(reportJSON) == 0 {
		return fmt.Errorf("empty report payload")
	}
	c := newAPI()
	body, err := json.Marshal(ScanIngestPayload{
		ProjectSlug: projectSlug,
		Source:      "cli",
		Component:   component,
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

// AuthedGet issues a GET to a full URL, attaching the Runveil API token as a
// Bearer credential when one is configured. Read routes are org-scoped, so CLI
// read commands must present a key (RUNVEIL_API_TOKEN) just like ingest.
func AuthedGet(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if tok := APIToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return (&http.Client{Timeout: 20 * time.Second}).Do(req)
}
