// neo4j.go
package infra

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func OpenNeo4j(_ context.Context, uri, user, pass string) (neo4j.DriverWithContext, error) {
	return neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, pass, ""))
}
