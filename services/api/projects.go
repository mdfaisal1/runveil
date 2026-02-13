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

// repoURLColumnMissing detects Postgres "undefined_column" for repo_url.
// Postgres uses SQLSTATE 42703 for undefined_column.
// Example error:
//
//	ERROR: column "repo_url" of relation "projects" does not exist (SQLSTATE 42703)
func repoURLColumnMissing(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "repo_url") && strings.Contains(s, "sqlstate 42703")
}

// registerProjects registers list/get/create endpoints for projects.
func registerProjects(r *gin.Engine, db *sql.DB) {

	// ----------------------------
	// LIST projects
	// ----------------------------
	r.GET("/v1/projects", func(c *gin.Context) {
		ctx := c.Request.Context()

		// Try repo_url first (if column exists), else fall back.
		queryWithRepo := `
SELECT slug, name, repo_url, updated_at
FROM projects
ORDER BY updated_at DESC
`
		rows, err := db.QueryContext(ctx, queryWithRepo)
		if err != nil {
			if repoURLColumnMissing(err) {
				queryNoRepo := `
SELECT slug, name, updated_at
FROM projects
ORDER BY updated_at DESC
`
				rows2, err2 := db.QueryContext(ctx, queryNoRepo)
				if err2 != nil {
					log.Printf("list projects query failed: %v", err2)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list projects"})
					return
				}
				defer rows2.Close()

				var out []ProjectView
				for rows2.Next() {
					var p ProjectView
					if err := rows2.Scan(&p.Slug, &p.Name, &p.UpdatedAt); err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan projects"})
						return
					}
					out = append(out, p)
				}
				if err := rows2.Err(); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "error iterating projects"})
					return
				}

				c.JSON(http.StatusOK, gin.H{"projects": out})
				return
			}

			log.Printf("list projects query failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list projects"})
			return
		}
		defer rows.Close()

		var out []ProjectView
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
	r.GET("/v1/projects/:slug", func(c *gin.Context) {
		ctx := c.Request.Context()
		slug := c.Param("slug")

		queryWithRepo := `
SELECT slug, name, repo_url, updated_at
FROM projects
WHERE slug = $1
LIMIT 1
`
		var p ProjectView
		var repo sql.NullString

		err := db.QueryRowContext(ctx, queryWithRepo, slug).Scan(&p.Slug, &p.Name, &repo, &p.UpdatedAt)
		if err != nil {
			if repoURLColumnMissing(err) {
				queryNoRepo := `
SELECT slug, name, updated_at
FROM projects
WHERE slug = $1
LIMIT 1
`
				err2 := db.QueryRowContext(ctx, queryNoRepo, slug).Scan(&p.Slug, &p.Name, &p.UpdatedAt)
				if err2 == sql.ErrNoRows {
					c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
					return
				}
				if err2 != nil {
					log.Printf("get project query failed: %v", err2)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get project"})
					return
				}
				c.JSON(http.StatusOK, p)
				return
			}

			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
				return
			}
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
	// CREATE project ✅
	// ----------------------------
	r.POST("/v1/projects", func(c *gin.Context) {
		ctx := c.Request.Context()

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

		var created ProjectView

		// Try insert with repo_url first; fall back if column missing.
		insertWithRepo := `
INSERT INTO projects (slug, name, repo_url, updated_at)
VALUES ($1, $2, $3, NOW())
RETURNING slug, name, repo_url, updated_at
`
		var repo sql.NullString
		repo.Valid = req.RepoURL != ""
		repo.String = req.RepoURL

		err := db.QueryRowContext(ctx, insertWithRepo, req.Slug, req.Name, repo).
			Scan(&created.Slug, &created.Name, &repo, &created.UpdatedAt)

		if err != nil {
			// fallback if repo_url column doesn't exist
			if repoURLColumnMissing(err) {
				insertNoRepo := `
INSERT INTO projects (slug, name, updated_at)
VALUES ($1, $2, NOW())
RETURNING slug, name, updated_at
`
				err2 := db.QueryRowContext(ctx, insertNoRepo, req.Slug, req.Name).
					Scan(&created.Slug, &created.Name, &created.UpdatedAt)

				if err2 != nil {
					// unique constraint / duplicates
					if strings.Contains(strings.ToLower(err2.Error()), "duplicate") || strings.Contains(err2.Error(), "sqlstate 23505") {
						c.JSON(http.StatusConflict, gin.H{"error": "slug already exists"})
						return
					}
					log.Printf("create project failed: %v", err2)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create project"})
					return
				}

				c.JSON(http.StatusCreated, created)
				return
			}

			// unique constraint / duplicates
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

		c.JSON(http.StatusCreated, created)
	})
}
