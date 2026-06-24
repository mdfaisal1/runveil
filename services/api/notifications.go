package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// slackFinding is the minimal shape needed to describe a finding in a Slack message.
type slackFinding struct {
	Severity string
	Package  string
	Version  string
	VulnID   string
}

// registerNotifications exposes endpoints to configure per-project Slack alerts.
//
//	PUT /v1/projects/:slug/settings   { "slack_webhook_url": "https://hooks.slack.com/..." }
//	GET /v1/projects/:slug/settings   -> { "slack_webhook_configured": bool }
func registerNotifications(r *gin.Engine, db *sql.DB) {
	r.PUT("/v1/projects/:slug/settings", requireProjectOrg(db), requireRole("admin"), func(c *gin.Context) {
		ctx := c.Request.Context()
		slug := c.Param("slug")

		var body struct {
			SlackWebhookURL string `json:"slack_webhook_url"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json body"})
			return
		}
		url := strings.TrimSpace(body.SlackWebhookURL)
		if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "slack_webhook_url must be an http(s) URL"})
			return
		}

		res, err := db.ExecContext(ctx,
			`UPDATE projects SET slack_webhook_url = NULLIF($2, ''), updated_at = now() WHERE slug = $1`,
			slug, url)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save settings", "details": err.Error()})
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "slack_webhook_configured": url != ""})
	})

	r.GET("/v1/projects/:slug/settings", requireProjectOrg(db), func(c *gin.Context) {
		ctx := c.Request.Context()
		slug := c.Param("slug")
		var url sql.NullString
		err := db.QueryRowContext(ctx, `SELECT slack_webhook_url FROM projects WHERE slug = $1`, slug).Scan(&url)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read settings"})
			return
		}
		// Never echo the secret webhook URL back; just whether it's set.
		c.JSON(http.StatusOK, gin.H{"slack_webhook_configured": url.Valid && url.String != ""})
	})
}

// projectSlackWebhook returns the configured webhook URL for a project ("" if none).
func projectSlackWebhook(ctx context.Context, db *sql.DB, slug string) string {
	var url sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT slack_webhook_url FROM projects WHERE slug = $1`, slug).Scan(&url); err != nil {
		return ""
	}
	if url.Valid {
		return url.String
	}
	return ""
}

// notifySlackNewReachable posts a message about newly-reachable high/critical
// findings. Best-effort: it logs and swallows errors so it never breaks ingest.
func notifySlackNewReachable(webhookURL, slug string, findings []slackFinding) {
	if webhookURL == "" || len(findings) == 0 {
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, ":fire: *Runveil:* %d new reachable finding%s in `%s`\n",
		len(findings), plural(len(findings)), slug)
	max := len(findings)
	if max > 10 {
		max = 10
	}
	for _, f := range findings[:max] {
		fmt.Fprintf(&b, "• *%s* %s@%s — %s\n", strings.ToUpper(f.Severity), f.Package, f.Version, f.VulnID)
	}
	if len(findings) > max {
		fmt.Fprintf(&b, "…and %d more\n", len(findings)-max)
	}

	payload, _ := json.Marshal(map[string]string{"text": b.String()})

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("slack notify: build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		log.Printf("slack notify: post failed for %s: %v", slug, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("slack notify: webhook returned %d for %s", resp.StatusCode, slug)
		return
	}
	log.Printf("slack notify: sent %d finding(s) for %s", len(findings), slug)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
