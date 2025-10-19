// nats.go
package infra

import (
	"time"

	"github.com/nats-io/nats.go"
)

func ConnectNATS(url string) (*nats.Conn, error) {
	return nats.Connect(url,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(750*time.Millisecond),
	)
}
