package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/mdfaisal1/runveil/pkg/infra"
)

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s not set", key)
	}
	return v
}

func main() {
	infra.MustLoad()
	dsn := mustEnv("POSTGRES_URL") // e.g. postgres://Runveil:Runveil@localhost:5432/Runveil?sslmode=disable

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	r := gin.Default()
	registerIngest(r, db)
	registerRuntime(r, db)
	registerFindings(r, db)
	registerEvidence(r, db)
	registerProjects(r, db)

	// GET /health → { ok: true } if DB is reachable
	r.GET("/health", func(c *gin.Context) {
		if err := db.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"ok": false, "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	log.Println("api listening on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
