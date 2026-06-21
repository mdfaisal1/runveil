package main

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// FindingDetail is the overview shown at the top of a finding's detail page.
type FindingDetail struct {
	ID            string     `json:"id"`
	Package       string     `json:"package"`
	Version       string     `json:"version"`
	Ecosystem     string     `json:"ecosystem"`
	VulnID        string     `json:"vuln_id"`
	Summary       string     `json:"summary"`
	Severity      string     `json:"severity"`
	Reachable     bool       `json:"reachable"`
	IsDev         bool       `json:"is_dev"`
	IsDirect      bool       `json:"is_direct"`
	FixedVersion  string     `json:"fixed_version,omitempty"`
	IntroducedVia string     `json:"introduced_via,omitempty"`
	EvidenceCount int64      `json:"evidence_count"`
	FirstSeenAt   *time.Time `json:"first_seen_at,omitempty"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	RuntimeState  string     `json:"runtime_state"`
}

type EvidenceEvent struct {
	OccurredAt     time.Time `json:"occurred_at"`
	Environment    string    `json:"environment,omitempty"`
	PackageName    string    `json:"package_name"`
	PackageVersion string    `json:"package_version"`
}

// registerEvidence serves a single finding's overview plus its runtime evidence.
//
//	GET /v1/projects/:slug/findings/:id/evidence?environment=&limit=&offset=
func registerEvidence(r *gin.Engine, db *sql.DB) {
	r.GET("/v1/projects/:slug/findings/:id/evidence", func(c *gin.Context) {
		ctx := c.Request.Context()
		slug := c.Param("slug")
		id := c.Param("id")

		// --- finding overview (scoped to the project) ---
		var d FindingDetail
		var fixed, intro sql.NullString
		err := db.QueryRowContext(ctx, `
SELECT f.id, p.name, p.version, p.ecosystem,
       v.vuln_id, v.summary, v.severity,
       f.reachable, f.is_dev, f.is_direct,
       f.fixed_version, f.introduced_via,
       f.evidence_count, f.first_seen_at, f.last_seen_at
FROM findings f
JOIN packages p        ON p.id = f.package_id
JOIN scans s           ON s.id = p.scan_id
JOIN projects proj     ON proj.id = s.project_id
JOIN vulnerabilities v ON v.id = f.vulnerability_id
WHERE proj.slug = $1 AND f.id = $2
`, slug, id).Scan(
			&d.ID, &d.Package, &d.Version, &d.Ecosystem,
			&d.VulnID, &d.Summary, &d.Severity,
			&d.Reachable, &d.IsDev, &d.IsDirect,
			&fixed, &intro,
			&d.EvidenceCount, &d.FirstSeenAt, &d.LastSeenAt,
		)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load finding", "details": err.Error()})
			return
		}
		d.FixedVersion = fixed.String
		d.IntroducedVia = intro.String
		d.RuntimeState = deriveRuntimeState(d.EvidenceCount, d.LastSeenAt)

		// --- evidence events (filterable, paginated) ---
		env := strings.TrimSpace(c.Query("environment"))
		limit := clampInt(c.Query("limit"), 100, 1, 500)
		offset := clampInt(c.Query("offset"), 0, 0, 1_000_000)

		q := `
SELECT occurred_at, COALESCE(environment, ''), package_name, package_version
FROM evidence_events
WHERE finding_id = $1`
		args := []any{id}
		if env != "" {
			args = append(args, env)
			q += " AND environment = $2"
		}
		q += " ORDER BY occurred_at DESC LIMIT " + strconv.Itoa(limit) + " OFFSET " + strconv.Itoa(offset)

		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load evidence", "details": err.Error()})
			return
		}
		defer rows.Close()

		events := make([]EvidenceEvent, 0)
		for rows.Next() {
			var e EvidenceEvent
			if err := rows.Scan(&e.OccurredAt, &e.Environment, &e.PackageName, &e.PackageVersion); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan evidence"})
				return
			}
			events = append(events, e)
		}

		c.JSON(http.StatusOK, gin.H{
			"finding":  d,
			"evidence": events,
		})
	})
}

func clampInt(s string, def, lo, hi int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}
