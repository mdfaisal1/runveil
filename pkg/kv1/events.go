package kv1

type Vuln struct {
	ID           string `json:"id"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixedVersion,omitempty"`
}

type Dep struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vulns   []Vuln `json:"vulns"`
}

type ScanRequest struct {
	ScanID    string `json:"scanId"`
	ProjectID string `json:"projectId"`
	Ecosystem string `json:"ecosystem"`
	Lockfile  string `json:"lockfile"`
	Source    string `json:"source"`
}

type ScanResult struct {
	ScanID    string `json:"scanId"`
	ProjectID string `json:"projectId"`
	Deps      []Dep  `json:"deps"`
}
