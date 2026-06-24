package main

import (
	"database/sql"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type ProjectView struct {
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	RepoURL   *string   `json:"repo_url,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CreateProjectRequest struct {
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	RepoURL string `json:"repo_url"`
}

// registerProjects registers list/get/create endpoints for projects. Every
// route is org-scoped: LIST/CREATE act on the caller's current org (requireAuth),
// and GET :slug is guarded by requireProjectOrg so a slug from another tenant 404s.
func registerProjects(r *gin.Engine, db *sql.DB) {

	// ----------------------------
	// LIST projects (caller's org)
	// ----------------------------
	r.GET("/v1/projects", requireAuth(db), func(c *gin.Context) {
		ctx := c.Request.Context()
		orgID := c.GetString(ctxOrgID)

		rows, err := db.QueryContext(ctx, `
			SELECT slug, name, repo_url, updated_at
			FROM projects
			WHERE org_id = $1
			ORDER BY updated_at DESC
		`, orgID)
		if err != nil {
			log.Printf("list projects query failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list projects"})
			return
		}
		defer rows.Close()

		out := []ProjectView{}
		for rows.Next() {
			var p ProjectView
			var repo sql.NullString
			if err := rows.Scan(&p.Slug, &p.Name, &repo, &p.UpdatedAt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan projects"})
				return
			}
			if repo.Valid {
				p.RepoURL = &repo.String
			}
			out = append(out, p)
		}
		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error iterating projects"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"projects": out})
	})

	// ----------------------------
	// GET single project
	// ----------------------------
	r.GET("/v1/projects/:slug", requireProjectOrg(db), func(c *gin.Context) {
		ctx := c.Request.Context()
		slug := c.Param("slug")

		var p ProjectView
		var repo sql.NullString
		err := db.QueryRowContext(ctx, `
			SELECT slug, name, repo_url, updated_at
			FROM projects WHERE slug = $1 LIMIT 1
		`, slug).Scan(&p.Slug, &p.Name, &repo, &p.UpdatedAt)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			return
		}
		if err != nil {
			log.Printf("get project query failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get project"})
			return
		}
		if repo.Valid {
			p.RepoURL = &repo.String
		}
		c.JSON(http.StatusOK, p)
	})

	// ----------------------------
	// CREATE project (in caller's org)
	// ----------------------------
	r.POST("/v1/projects", requireAuth(db), func(c *gin.Context) {
		ctx := c.Request.Context()
		orgID := c.GetString(ctxOrgID)

		var req CreateProjectRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json body"})
			return
		}

		req.Slug = strings.TrimSpace(strings.ToLower(req.Slug))
		req.Name = strings.TrimSpace(req.Name)
		req.RepoURL = strings.TrimSpace(req.RepoURL)

		if req.Slug == "" || req.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "slug and name are required"})
			return
		}
		slugOk, _ := regexp.MatchString(`^[a-z0-9]+(?:-[a-z0-9]+)*$`, req.Slug)
		if !slugOk {
			c.JSON(http.StatusBadRequest, gin.H{"error": "slug must be lowercase letters, numbers, hyphens only"})
			return
		}

		var repo sql.NullString
		repo.Valid = req.RepoURL != ""
		repo.String = req.RepoURL

		var created ProjectView
		err := db.QueryRowContext(ctx, `
			INSERT INTO projects (slug, name, repo_url, org_id, updated_at)
			VALUES ($1, $2, $3, $4, NOW())
			RETURNING slug, name, repo_url, updated_at
		`, req.Slug, req.Name, repo, orgID).Scan(&created.Slug, &created.Name, &repo, &created.UpdatedAt)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "sqlstate 23505") {
				c.JSON(http.StatusConflict, gin.H{"error": "slug already exists"})
				return
			}
			log.Printf("create project failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create project"})
			return
		}

		if repo.Valid {
			created.RepoURL = &repo.String
		}
		auditCtx(c, db, "project.created", created.Slug, nil)
		c.JSON(http.StatusCreated, created)
	})
}
