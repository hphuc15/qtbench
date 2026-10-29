package benchmark

import (
	"context"
)

// DeliveryHandler is invoked when a subscriber receives a benchmark message.
type DeliveryHandler func(metric *DeliveryMetric)

// Client defines the common benchmarking client interface for both TCP/TLS and QUIC.
type Client interface {
	// Connect connects to the broker and returns connection/handshake metrics.
	Connect(ctx context.Context) (*HandshakeResult, error)

	// Publish publishes a message with specified QoS and payload, returning publish latency metric.
	Publish(ctx context.Context, topic string, qos byte, payload []byte) (*PublishMetric, error)

	// Subscribe subscribes to a topic filter with QoS and attaches the delivery handler.
	Subscribe(ctx context.Context, topic string, qos byte, handler DeliveryHandler) error

	// Disconnect sends DISCONNECT packet and cleanly closes network connections.
	Disconnect(ctx context.Context) error
}

// ClientOptions contains runtime parameters for benchmark clients.
type ClientOptions struct {
	BrokerAddr     string
	ClientID       string
	CleanSession   bool
	KeepaliveSec   uint16
	InsecureTLS    bool
	ServerName     string
	SSLKeyLogPath  string
	EnableMultiStream bool
}
