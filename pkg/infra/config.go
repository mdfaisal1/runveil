package infra

import (
	"log"
	"os"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	// host|internal. If "internal", use Docker DNS (postgres, neo4j, nats).
	RuntimeNet string `env:"RUNTIME_NET" envDefault:"host"`

	// Postgres
	PgHostURL     string `env:"PG_URL_HOST" envDefault:"postgres://keystone:keystone@localhost:5432/keystone?sslmode=disable"`
	PgInternalURL string `env:"PG_URL_INTERNAL" envDefault:"postgres://keystone:keystone@postgres:5432/keystone?sslmode=disable"`

	// Neo4j
	Neo4jHostURI     string `env:"NEO4J_URI_HOST" envDefault:"bolt://localhost:7687"`
	Neo4jInternalURI string `env:"NEO4J_URI_INTERNAL" envDefault:"bolt://neo4j:7687"`
	Neo4jUser        string `env:"NEO4J_USER" envDefault:"neo4j"`
	Neo4jPass        string `env:"NEO4J_PASS" envDefault:"keystone"`

	// NATS
	NatsHostURL     string `env:"NATS_URL_HOST" envDefault:"nats://localhost:4222"`
	NatsInternalURL string `env:"NATS_URL_INTERNAL" envDefault:"nats://nats:4222"`
}

// MustLoad parses env and also exposes resolved URLs via POSTGRES_URL/NEO4J_URL/NATS_URL.
func MustLoad() Config {
	var c Config
	if err := env.Parse(&c); err != nil {
		log.Fatalf("config: %v", err)
	}

	hostMode := c.RuntimeNet != "internal"
	if hostMode {
		os.Setenv("POSTGRES_URL", c.PgHostURL)
		os.Setenv("NEO4J_URL", c.Neo4jHostURI)
		os.Setenv("NATS_URL", c.NatsHostURL)
	} else {
		os.Setenv("POSTGRES_URL", c.PgInternalURL)
		os.Setenv("NEO4J_URL", c.Neo4jInternalURI)
		os.Setenv("NATS_URL", c.NatsInternalURL)
	}
	return c
}
