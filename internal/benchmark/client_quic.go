package benchmark

import (
	"context"
	"fmt"
	"time"

	mqttclient "github.com/hphuc15/mqttOQ/client"
	"qtbench/internal/transport"
)

// QUICClient adapts the mqttOQ client library to the benchmark Client interface.
type QUICClient struct {
	opts   ClientOptions
	client *mqttclient.Client
}

// NewQUICClient creates a benchmark client using the mqttOQ library.
func NewQUICClient(opts ClientOptions) *QUICClient {
	if opts.ClientID == "" {
		opts.ClientID = fmt.Sprintf("bench-quic-%d", time.Now().UnixNano()%1000000)
	}
	if opts.KeepaliveSec == 0 {
		opts.KeepaliveSec = 60
	}

	return &QUICClient{
		opts: opts,
	}
}

// Connect initializes the mqttOQ client with TLS 1.3 configuration and measures handshake duration.
func (c *QUICClient) Connect(ctx context.Context) (*HandshakeResult, error) {
	tlsCfg, err := transport.NewBenchmarkTLSConfig(c.opts.ServerName, c.opts.InsecureTLS, c.opts.SSLKeyLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS 1.3 for QUIC: %w", err)
	}

	cfg := mqttclient.ClientConfig{
		Broker: mqttclient.ClientBroker{
			Address: c.opts.BrokerAddr,
		},
		Credentials: mqttclient.ClientCredentials{
			ClientID: c.opts.ClientID,
		},
		Session: mqttclient.ClientSession{
			KeepAlive:    c.opts.KeepaliveSec,
			CleanSession: c.opts.CleanSession,
		},
		Network: mqttclient.ClientNetwork{
			ConnectTimeout:    15 * time.Second,
			EnableMultiStream: c.opts.EnableMultiStream,
		},
		TLSConfig: tlsCfg,
	}

	c.client = mqttclient.NewClient(cfg)

	t0 := time.Now()
	err = c.client.Connect(ctx)
	handshakeDuration := time.Since(t0)

	if err != nil {
		return &HandshakeResult{
			Protocol:   ProtocolQUIC,
			BrokerAddr: c.opts.BrokerAddr,
			Success:    false,
			Error:      err.Error(),
			Timestamp:  t0,
		}, err
	}

	return &HandshakeResult{
		Protocol:   ProtocolQUIC,
		BrokerAddr: c.opts.BrokerAddr,
		Duration:   handshakeDuration,
		DurationMs: float64(handshakeDuration.Microseconds()) / 1000.0,
		Success:    true,
		Timestamp:  t0,
	}, nil
}

// Publish publishes a message via mqttOQ and returns publish metrics.
func (c *QUICClient) Publish(ctx context.Context, topic string, qos byte, payload []byte) (*PublishMetric, error) {
	if c.client == nil || !c.client.IsConnected() {
		return nil, fmt.Errorf("quic client is not connected")
	}

	t0 := time.Now()
	sendNs := time.Now().UnixNano()

	err := c.client.Publish(ctx, topic, qos, false, payload)
	ackNs := time.Now().UnixNano()
	durMs := float64(ackNs-sendNs) / 1e6

	if err != nil {
		return &PublishMetric{
			QoS:       qos,
			SendNs:    sendNs,
			Success:   false,
			Error:     err.Error(),
			Timestamp: t0,
		}, err
	}

	return &PublishMetric{
		QoS:        qos,
		SendNs:     sendNs,
		AckNs:      ackNs,
		DurationMs: durMs,
		Success:    true,
		Timestamp:  t0,
	}, nil
}

// Subscribe subscribes to a topic via mqttOQ and processes incoming messages.
func (c *QUICClient) Subscribe(ctx context.Context, topic string, qos byte, handler DeliveryHandler) error {
	if c.client == nil || !c.client.IsConnected() {
		return fmt.Errorf("quic client is not connected")
	}

	return c.client.Subscribe(ctx, topic, qos, func(_ *mqttclient.Client, msg mqttclient.Message) {
		recvNs := time.Now().UnixNano()
		hdr, err := DecodePayload(msg.Payload)
		if err == nil && handler != nil {
			latencyMs := float64(recvNs-hdr.SendNs) / 1e6
			handler(&DeliveryMetric{
				Seq:        hdr.Seq,
				QoS:        msg.QoS,
				SendNs:     hdr.SendNs,
				RecvNs:     recvNs,
				LatencyMs:  latencyMs,
				PayloadLen: len(msg.Payload),
				Timestamp:  time.Now(),
			})
		}
	})
}

// Disconnect gracefully disconnects the mqttOQ client.
func (c *QUICClient) Disconnect(ctx context.Context) error {
	if c.client == nil || !c.client.IsConnected() {
		return nil
	}
	return c.client.Disconnect(ctx)
}
